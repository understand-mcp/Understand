"""Command line interface for UNDERSTAND.

Grammar
-------

    understand scan SOURCE [FEATURE ...] [OPTIONS]
    understand report show SCAN_ID [OPTIONS]
    understand report list [OPTIONS]
    understand finding show FINDING_ID [--scan-id SCAN_ID]
    understand config show
    understand capabilities
    understand version

``scan`` accepts *positional feature tokens* and *long options* interleaved in
one command, which is the primary calling convention::

    understand scan ./project security bugs --deep --cross-module report --format json
    understand scan https://github.com/owner/repo security --deep bugs --cross-module report --format json

The normalized all-flags spelling is accepted as well::

    understand scan ./project --security --bugs --deep --cross-module --format json

Rules
-----

* ``stdout`` carries the requested output only (JSON document, SARIF document,
  text report, or a short human line). Progress and diagnostic logging always go
  to ``stderr`` so ``understand ... --format json | jq`` is always safe.
* ``--help`` never scans anything.
* Exit codes are stable and documented in ``EXIT_CODES`` and in ``--help``.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import sys
from collections.abc import Sequence
from typing import Any

from understand import __version__
from understand.application import FindingService, ReportService, ScanService, finding_to_dict
from understand.config import RuntimeConfig, load_config
from understand.engine import language_detection
from understand.errors import UnderstandError, UnsupportedFormatError, ValidationError
from understand.logging_config import get_logger, setup_logging
from understand.models import Check, Profile, ScanRequest, Severity
from understand.reporting import (
    SUPPORTED_FORMATS,
    normalize_format,
    render_map_html,
    render_report,
    safe_map_output_path,
    safe_output_path,
    write_report,
)

logger = get_logger("cli")

PROGRAM = "understand"

EXIT_CODES: dict[int, str] = {
    0: "success",
    1: "unexpected internal error",
    63: "the requested output format is not supported",
    64: "invalid usage or invalid input",
    65: "the scan source could not be interpreted (missing, not a directory, malformed URL)",
    66: "the requested scan id does not exist",
    67: "the requested finding id does not exist",
    69: "the repository could not be acquired (clone failed, size limits)",
    70: "a resource limit was exceeded",
    71: "analysis failed",
    72: "the source was blocked by network policy",
    74: "the scan store could not be read or written",
    77: "access denied",
    78: "configuration error",
    130: "the scan was cancelled (SIGINT)",
}

# Maps the error `code` reported by a failed scan job onto its exit code. A scan
# failure is reported as a structured error, so the process status has to be
# derived from the code rather than hard-coded to a single "analysis failed".
_EXIT_CODE_BY_ERROR: dict[str, int] = {
    "configuration_error": 78,
    "invalid_source": 65,
    "access_denied": 77,
    "network_policy": 72,
    "acquisition_failed": 69,
    "resource_limit_exceeded": 70,
    "analysis_error": 71,
    "scan_cancelled": 130,
    "scan_not_found": 66,
    "finding_not_found": 67,
    "unsupported_format": 63,
    "storage_error": 74,
    "validation_error": 64,
}

# Positional feature tokens accepted inside ``scan``.
_FEATURE_TOKENS: dict[str, tuple[str, ...]] = {
    "security": ("security",),
    "bugs": ("bugs",),
    "bug": ("bugs",),
    "architecture": ("architecture",),
    "arch": ("architecture",),
    "dependencies": ("dependencies",),
    "deps": ("dependencies",),
    "reliability": ("reliability",),
    "all": ("security", "bugs", "architecture", "dependencies", "reliability"),
}

_FLAG_FEATURES: dict[str, Check] = {
    "--security": Check.SECURITY,
    "--bugs": Check.BUGS,
    "--architecture": Check.ARCHITECTURE,
    "--dependencies": Check.DEPENDENCIES,
    "--reliability": Check.RELIABILITY,
}


# --------------------------------------------------------------------------- #
# Argument model
# --------------------------------------------------------------------------- #
@dataclasses.dataclass
class ScanArgs:
    """Fully resolved ``scan`` arguments."""

    source: str = ""
    features: tuple[str, ...] = ()
    deep: bool = False
    cross_module: bool = False
    emit_report: bool = True
    report_format: str = "text"
    output: str | None = None
    use_cache: bool = True
    offline: bool = False
    include_evidence: bool = True
    include_execution_paths: bool = True
    fail_on: str = "none"
    max_files: int | None = None
    max_file_bytes: int | None = None
    max_total_bytes: int | None = None
    max_seconds: int | None = None
    max_workers: int | None = None
    timeout: int | None = None
    allow_remote: bool | None = None
    wait: bool = True
    storage: str | None = None
    mode: str | None = None
    local_root: tuple[str, ...] = ()


_SCAN_VALUE_FLAGS = {
    "--format": "report_format",
    "--output": "output",
    "-o": "output",
    "--out": "output",
    # "config", not "__config": the branch in parse_scan_tokens that
    # assigns config_path tests for the plain name. The underscore-prefixed
    # form never matched it, so --config and -c silently landed on the args
    # namespace as an unread attribute and the file was ignored.
    "--config": "config",
    "--storage": "storage",
    "--mode": "mode",
    "--fail-on": "fail_on",
    "--max-files": "max_files",
    "--max-file-bytes": "max_file_bytes",
    "--max-total-bytes": "max_total_bytes",
    "--max-seconds": "max_seconds",
    "--timeout": "timeout",
    "--max-workers": "max_workers",
    "--local-root": "local_root",
    "--profile": "__profile",
}

_SCAN_BOOL_FLAGS = {
    "--deep": "deep",
    "--cross-module": "cross_module",
    "--no-report": "__no_report",
    "--no-cache": "__no_cache",
    "--cache": "__cache",
    "--offline": "offline",
    "--online": "__online",
    "--no-evidence": "__no_evidence",
    "--evidence": "__evidence",
    "--no-execution-paths": "__no_exec",
    "--execution-paths": "__exec",
    "--allow-remote": "__allow_remote",
    "--no-allow-remote": "__no_allow_remote",
    "--json": "__json",
}

_SCAN_SHORTHAND_FLAGS = {
    "-d": "--deep",
    "-x": "--cross-module",
    "-q": "--quiet",
    "-v": "--verbose",
    "-c": "--config",
    "-f": "--format",
}


def _fail(message: str, *, code: str = "invalid_arguments", hint: str = "") -> None:
    """Raise a usage error (exit code 64) with a machine-readable detail block."""

    detail: dict[str, Any] = {"code": code, "hint": hint or f"see `{PROGRAM} --help`"}
    raise ValidationError(message, detail=detail)


def _as_int(raw: str, name: str) -> int:
    try:
        value = int(raw)
    except ValueError:
        _fail(f"{name} expects an integer, got {raw!r}")
    if value <= 0:
        _fail(f"{name} must be greater than zero, got {value}")
    return value


def parse_scan_tokens(argv: Sequence[str]) -> tuple[ScanArgs, argparse.Namespace, str | None]:
    """Parse the interleaved token/option grammar of ``understand scan``.

    Returns ``(scan_args, global_flags, config_path)``.
    """

    args = ScanArgs()
    flags = argparse.Namespace(quiet=False, verbose=False, help=False)
    config_path: str | None = None
    positionals: list[str] = []
    pending: list[str] = []
    emit_report_set = False
    index = 0

    def flush_pending() -> None:
        # config_path is rebound below, so this needs the declaration. Without
        # it the assignment made a LOCAL of the same name inside this nested
        # function, the outer one stayed None, and `--config` / `-c` were
        # accepted and then ignored: the scan silently ran on defaults.
        nonlocal config_path
        while pending:
            token = pending.pop()
            if token == "--":
                continue
            name = token.lstrip("-").replace("-", "_")
            if name == "format":
                name = "report_format"
            if name in ("o", "out"):
                name = "output"
            if name == "report_format":
                args.report_format = pending.pop() if pending else ""
                continue
            if name == "fail_on":
                args.fail_on = pending.pop() if pending else ""
                continue
            if name == "storage":
                args.storage = pending.pop() if pending else ""
                continue
            if name == "mode":
                args.mode = pending.pop() if pending else ""
                continue
            if name == "profile":
                raw = pending.pop() if pending else ""
                if raw == "deep":
                    args.deep = True
                elif raw in ("standard", "standard-ish"):
                    args.deep = False
                else:
                    _fail(f"--profile expects 'standard' or 'deep', got {raw!r}")
                continue
            if name == "local_root":
                root = pending.pop() if pending else ""
                args.local_root = (*args.local_root, os.path.abspath(os.path.expanduser(root)))
                continue
            if name == "output":
                args.output = pending.pop() if pending else ""
                continue
            if name == "config":
                config_path = pending.pop() if pending else ""
                continue
            setattr(args, name, _as_int(pending.pop() if pending else "", token))

    while index < len(argv):
        token = argv[index]
        index += 1

        if token in ("-h", "--help"):
            flags.help = True
            continue

        if token == "--":
            pending.extend(argv[index:])
            break

        if token.startswith("-") and token != "-":
            shorthand = _SCAN_SHORTHAND_FLAGS.get(token)
            if shorthand is not None:
                token = shorthand
            elif len(token) > 2 and token[:2] == "--" and not token.startswith("--no-"):
                # --flag=value
                head, sep, tail = token.partition("=")
                if sep and head in _SCAN_VALUE_FLAGS:
                    pending.extend([tail, head])
                    flush_pending()
                    continue

            if token in _FLAG_FEATURES:
                positionals.append(token.lstrip("-"))
                continue

            if token in _SCAN_BOOL_FLAGS:
                name = _SCAN_BOOL_FLAGS[token]
                if name == "__no_report":
                    args.emit_report = False
                    emit_report_set = True
                elif name == "__no_cache":
                    args.use_cache = False
                elif name == "__cache":
                    args.use_cache = True
                elif name == "__no_evidence":
                    args.include_evidence = False
                elif name == "__evidence":
                    args.include_evidence = True
                elif name == "__no_exec":
                    args.include_execution_paths = False
                elif name == "__exec":
                    args.include_execution_paths = True
                elif name == "__allow_remote":
                    args.allow_remote = True
                elif name == "__no_allow_remote":
                    args.allow_remote = False
                elif name == "__online":
                    args.offline = False
                elif name == "__json":
                    args.report_format = "json"
                else:
                    setattr(args, name, True)
                continue

            if token in ("--quiet",):
                flags.quiet = True
                continue
            if token in ("--verbose",):
                flags.verbose = True
                continue

            if token in _SCAN_VALUE_FLAGS:
                value = argv[index] if index < len(argv) else ""
                index += 1
                pending.extend([value, token])
                flush_pending()
                continue

            _fail(f"unknown option {token!r}", hint=f"`{PROGRAM} scan --help` lists every supported option")

        lowered = token.lower()
        if lowered == "report":
            args.emit_report = True
            emit_report_set = True
            continue
        if lowered in _FEATURE_TOKENS:
            positionals.extend(_FEATURE_TOKENS[lowered])
            continue
        if not args.source:
            args.source = token
            continue
        _fail(f"unexpected positional argument {token!r}", hint="SOURCE must be the first positional token")

    del emit_report_set

    if flags.help:
        return args, flags, config_path

    if not args.source:
        _fail("a SOURCE is required", hint=f"example: {PROGRAM} scan ./project security --deep")

    args.features = tuple(dict.fromkeys(positionals))
    unknown = [f for f in args.features if f not in {v for vals in _FEATURE_TOKENS.values() for v in vals}]
    if unknown:
        _fail(f"unknown feature token(s): {', '.join(sorted(unknown))}")

    if args.report_format:
        try:
            args.report_format = normalize_format(args.report_format)
        except UnderstandError as exc:
            _fail(exc.message, code="unsupported_format")

    if args.fail_on and args.fail_on.lower() != "none":
        try:
            Severity.parse(args.fail_on.lower())
        except ValueError:
            # Only a bad value may be reported as a bad value: a defect inside
            # parse() must surface as itself, not as a misleading usage error.
            _fail(f"--fail-on expects one of none/info/low/medium/high/critical, got {args.fail_on!r}")

    if args.mode and args.mode not in ("local", "hosted"):
        _fail(f"--mode expects 'local' or 'hosted', got {args.mode!r}")

    return args, flags, config_path


# --------------------------------------------------------------------------- #
# Help / capability documents
# --------------------------------------------------------------------------- #
def scan_help() -> str:
    return f"""
{PROGRAM} scan - analyse a repository or a remote git URL

USAGE
  {PROGRAM} scan SOURCE [FEATURE ...] [OPTIONS]

SOURCE
  A local directory, or a remote git URL (https://github.com/owner/repo.git,
  git@github.com:owner/repo.git). Remote sources require --allow-remote and a
  host that is permitted by security policy.

FEATURE TOKENS (positional, order independent, repeatable)
  security        run the security analyzers
  bugs            run the bug-pattern analyzers
  architecture    run the architecture analyzers (cycles, coupling, layers)
  dependencies    parse manifests and report dependency inventory
  reliability     run the reliability analyzers (retries, sleeps, cleanup)
  all             every check
  report          request a rendered report (the default for --format)
  Omitting all feature tokens keeps the default check set.

  Each token also has a normalized flag spelling: --security --bugs
  --architecture --dependencies --reliability.

OPTIONS
  -d, --deep                 use the deep profile (data flow + deeper rules)
  -x, --cross-module         follow calls and data flow across module boundaries
      --profile NAME         'standard' (default) or 'deep'
      --format FORMAT        text (default), json, or sarif
  -o, --output PATH          write the report to PATH instead of stdout
      --no-report            compute the scan but do not render a report
      --fail-on SEVERITY     exit 2 when a finding at or above SEVERITY exists
                             (info, low, medium, high, critical)
      --no-evidence          omit evidence blocks from the rendered report
      --no-execution-paths   omit execution-path traces from the report
  -c, --config PATH          configuration file (JSON). Also UNDERSTAND_CONFIG.
      --storage PATH         override the scan store path
      --mode MODE            'local' (default) or 'hosted'
      --local-root PATH      additional allowed root for local sources (repeatable)
      --allow-remote         permit remote git URLs for this invocation
      --offline              never consult the cache or the network
      --no-cache             do not read or write the incremental cache
      --max-files N          maximum files to read
      --max-file-bytes N     skip individual files larger than N bytes
      --max-total-bytes N    stop after N bytes of source
      --max-seconds N        stop the analysis after N seconds
      --timeout N            wall-clock wait limit for the scan
  -q, --quiet                suppress progress logging on stderr
  -v, --verbose              verbose progress logging on stderr
  -h, --help                 show this help and exit without scanning

EXIT CODES
""" + "\n".join(f"  {code:<4} {text}" for code, text in sorted(EXIT_CODES.items()))


MAIN_HELP = f"""
{PROGRAM} {__version__} - evidence-driven repository intelligence

USAGE
  {PROGRAM} scan SOURCE [FEATURE ...] [OPTIONS]
  {PROGRAM} report show SCAN_ID [--format json] [--limit N] [--offset N]
  {PROGRAM} report list [--limit N] [--offset N] [--status STATUS]
  {PROGRAM} finding show FINDING_ID [--scan-id SCAN_ID] [--format json]
  {PROGRAM} map show SCAN_ID [--view module] [--root PATH] [--depth N]
  {PROGRAM} map views
  {PROGRAM} config show
  {PROGRAM} capabilities
  {PROGRAM} version

QUICK START
  {PROGRAM} scan ./my-project security bugs --deep --cross-module report --format json
  {PROGRAM} scan ./my-project --security --bugs --format text
  {PROGRAM} scan https://github.com/owner/repo security --deep --cross-module report --format json

TWO INTERFACES, ONE ENGINE
  The MCP server (`python -m understand.mcp_server`) exposes the identical
  analysis services over the Model Context Protocol. Both interfaces share the
  same configuration models, pipeline, findings, and reporting.

Run `{PROGRAM} scan --help` for the complete scan grammar and exit codes.
"""


def capabilities_document() -> dict[str, Any]:
    languages = []
    for name in language_detection.all_languages():
        spec = language_detection._NAME_MAP.get(name)
        if spec is None:  # pragma: no cover - defensive
            continue
        support = getattr(spec.support, "value", spec.support)
        languages.append(
            {
                "language": spec.name,
                "support": support,
                "analyzers": list(spec.analyzers),
                "limitations": list(spec.limitations),
            }
        )
    languages.sort(key=lambda item: (item["support"], item["language"]))
    return {
        "tool": PROGRAM,
        "version": __version__,
        "interfaces": {
            "cli": {"entry_point": f"{PROGRAM} scan SOURCE ...", "help": f"{PROGRAM} scan --help"},
            "mcp": {
                "entry_point": "python -m understand.mcp_server",
                "transport": "stdio",
                "tools": [
                    "scan_repository",
                    "get_scan_report",
                    "inspect_finding",
                    "trace_execution",
                    "trace_data_flow",
                    "analyze_change_impact",
                    "query_codebase",
                    "get_scan_status",
                ],
            },
        },
        "checks": [check.value for check in Check],
        "profiles": [profile.value for profile in Profile],
        "report_formats": list(SUPPORTED_FORMATS),
        "languages": languages,
        "evidence_model": {
            "verification_statuses": [
                "static_evidence",
                "cross_module_trace",
                "test_backed",
                "reproduced",
                "inconclusive",
                "not_verified",
            ],
            "rule": "every finding carries real file/line/symbol evidence; nothing is fabricated",
        },
        "llm_required": False,
        "telemetry": False,
        "dependency_vulnerability_lookup": "not_performed unless a trusted advisory source is configured",
        "exit_codes": {str(code): text for code, text in EXIT_CODES.items()},
    }


def _config_document(config: RuntimeConfig) -> dict[str, Any]:
    def dump(obj: Any) -> Any:
        if dataclasses.is_dataclass(obj):
            return {f.name: dump(getattr(obj, f.name)) for f in dataclasses.fields(obj)}
        if isinstance(obj, (list, tuple)):
            return [dump(item) for item in obj]
        if isinstance(obj, dict):
            return {key: dump(value) for key, value in obj.items()}
        if hasattr(obj, "value") and hasattr(obj, "name"):
            return obj.value
        return obj

    document = dump(config)
    from understand.security.redaction import redact_obj

    return redact_obj(document)


# --------------------------------------------------------------------------- #
# Output helpers
# --------------------------------------------------------------------------- #
def _emit_json(payload: Any) -> None:
    json.dump(payload, sys.stdout, indent=2, default=str)
    sys.stdout.write("\n")


_RENDER_KWARGS: dict[str, frozenset[str]] = {
    "json": frozenset({"pretty", "redact"}),
    "sarif": frozenset({"pretty", "redact"}),
    "text": frozenset({"max_findings", "color"}),
}


def _render_and_write(report, fmt: str, output: str | None, **kwargs: Any) -> None:
    allowed = _RENDER_KWARGS[fmt]
    options = {key: value for key, value in kwargs.items() if key in allowed}
    if "redact" in allowed:
        options.setdefault("redact", True)
    if not output:
        sys.stdout.write(render_report(report, fmt, **options))
        if fmt != "json":
            sys.stdout.write("\n")
        return
    try:
        path = safe_output_path(output, fmt=fmt)
    except UnsupportedFormatError as exc:
        # A rejected destination is a usage problem (bad --output), not an
        # unsupported report format, so it must not exit with the format code.
        _fail(f"refusing to write the report: {exc.message}", code="unsafe_output_path")
    written = write_report(report, fmt, path, **options)
    logger.info("report written to %s", written)


def _severity_at_or_above(report, threshold: str) -> list[str]:
    if not threshold or threshold.lower() == "none":
        return []
    limit = Severity.parse(threshold.lower()).rank
    return [
        finding.finding_id
        for finding in report.findings
        if not finding.suppressed and finding.severity.rank <= limit
    ]


def _build_request(args: ScanArgs, config: RuntimeConfig, profile: Profile) -> ScanRequest:
    from understand.models import ResourceLimits

    limits = ResourceLimits()
    if args.max_files:
        limits.max_files = args.max_files
    if args.max_file_bytes:
        limits.max_file_bytes = args.max_file_bytes
    if args.max_total_bytes:
        limits.max_total_bytes = args.max_total_bytes
    if args.max_seconds:
        limits.max_seconds = args.max_seconds

    known_checks = {c.value for c in Check}
    checks = tuple(Check(token) for token in args.features if token in known_checks)

    allowed_roots = tuple(os.path.abspath(os.path.expanduser(root)) for root in args.local_root)
    allowed_roots = allowed_roots or tuple(os.path.abspath(os.path.expanduser(r)) for r in config.local_roots)

    allow_remote = config.security.allow_remote if args.allow_remote is None else args.allow_remote

    return ScanRequest(
        repository=args.source,
        profile=profile,
        checks=checks,
        cross_module=args.cross_module,
        report_format=args.report_format,
        emit_report=args.emit_report,
        include_evidence=args.include_evidence,
        include_execution_paths=args.include_execution_paths,
        limits=limits,
        allowed_roots=allowed_roots,
        allow_remote=allow_remote,
        use_cache=args.use_cache and not args.offline,
        offline=args.offline,
    )


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #
def _cmd_scan(argv: Sequence[str]) -> int:
    args, flags, config_path = parse_scan_tokens(argv)
    if flags.help:
        sys.stdout.write(scan_help().strip() + "\n")
        return 0

    level = "INFO"
    if flags.quiet:
        level = "ERROR"
    elif flags.verbose:
        level = "DEBUG"
    setup_logging(level)

    config = load_config(config_path)
    # RuntimeConfig is frozen, so command-line overrides go through with_overrides.
    overrides: dict[str, object] = {}
    if args.storage:
        overrides["storage_path"] = args.storage
    if args.mode:
        overrides["mode"] = args.mode
        if args.mode == "hosted":
            overrides["security"] = dataclasses.replace(
                config.security, allow_http=False, allow_ssh=False, block_private_networks=True
            )
    if overrides:
        config = config.with_overrides(**overrides)

    profile = Profile.DEEP if args.deep else Profile.STANDARD
    request = _build_request(args, config, profile)

    service = ScanService(config)
    try:
        service.open()
        logger.info("scanning %s (profile=%s, checks=%s)", request.repository, profile.value, ",".join(request.checks) or "default")
        job = service.run_sync(request, timeout=args.timeout, use_cache=request.use_cache)
    finally:
        service.close()

    if job.error is not None:
        _emit_error(job.error)
        # Map the failure onto the documented exit codes rather than collapsing
        # everything into 70, so callers can tell "bad source" from "analysis
        # blew up" without parsing stderr.
        code = _EXIT_CODE_BY_ERROR.get(str(job.error.get("code", "")), 70)
        return code

    report = job.report
    if report is None:
        _emit_error({"code": "internal_error", "message": "scan finished without a report"})
        return 1

    # A scan that failed or was cancelled still produces a report (so the caller
    # can see how far it got); the process status must still reflect the failure.
    if report.status in ("failed", "cancelled"):
        first = report.errors[0] if report.errors else None
        _emit_error(
            {
                "code": (first.code if first and first.code else "analysis_error"),
                "message": (first.message if first else f"scan {report.status}"),
                "scan_id": report.scan_id,
                "hint": "re-run with -v/--verbose for a traceback on stderr",
            }
        )
        return _EXIT_CODE_BY_ERROR.get(
            (first.code if first and first.code else "analysis_error"),
            70 if report.status == "failed" else 130,
        )

    if args.emit_report:
        _render_and_write(
            report,
            args.report_format,
            args.output,
            redact=True,
        )
    elif args.output:
        _emit_json(
            {
                "scan_id": report.scan_id,
                "status": report.status,
                "findings": report.findings_by_severity,
                "written": False,
                "note": "--no-report was requested; no output file was produced",
            }
        )
    else:
        _emit_json(job.public())

    breached = _severity_at_or_above(report, args.fail_on)
    if breached:
        logger.info("fail-on %s triggered by %d finding(s)", args.fail_on, len(breached))
        return 2
    return 0


def _cmd_report(argv: Sequence[str]) -> int:
    argv = list(argv)
    if argv and argv[0] in ("-h", "--help"):
        sys.stdout.write(
            f"USAGE\n  {PROGRAM} report show SCAN_ID [--format json] [--output PATH] [--limit N] [--offset N]\n"
            f"  {PROGRAM} report list [--limit N] [--offset N] [--status STATUS] [--format json]\n"
        )
        return 0

    # A leading `--storage/--config PATH` pair may precede the action word
    # because global options are allowed anywhere before the command.
    if len(argv) >= 2 and argv[0] in ("--storage", "--config", "-c"):
        action = argv[2]
        rest = [argv[0], argv[1], *argv[3:]]
    else:
        action = argv[0] if argv else ""
        rest = list(argv[1:])

    fmt = "text"
    output: str | None = None
    limit = 50
    offset = 0
    status = ""
    severity = ""
    category = ""
    rule_id = ""
    file_filter = ""
    text_query = ""
    config_path: str | None = None
    storage: str | None = None
    scan_id = ""
    show_help = False

    index = 0
    while index < len(rest):
        token = rest[index]
        index += 1
        if token in ("-h", "--help"):
            show_help = True
        elif token in ("-q", "--quiet", "-v", "--verbose"):
            continue
        elif token in ("--format", "-f") and index < len(rest):
            fmt = normalize_format(rest[index])
            index += 1
        elif token in ("--output", "-o") and index < len(rest):
            output = rest[index]
            index += 1
        elif token == "--json":
            fmt = "json"
        elif token == "--limit" and index < len(rest):
            # 0 means "no cap": the text renderer treats a large limit as
            # effectively unlimited, and a bare 0 would silently print an empty
            # findings block, which reads as a clean bill of health on a
            # repository with thousands of findings.
            if rest[index] == "0":
                limit = 1_000_000
            else:
                limit = _as_int(rest[index], "--limit")
            index += 1
        elif token == "--offset" and index < len(rest):
            offset = max(0, int(rest[index]))
            index += 1
        elif token == "--status" and index < len(rest):
            status = rest[index]
            index += 1
        elif token == "--severity" and index < len(rest):
            severity = rest[index]
            index += 1
        elif token == "--category" and index < len(rest):
            category = rest[index]
            index += 1
        elif token == "--rule" and index < len(rest):
            rule_id = rest[index]
            index += 1
        elif token == "--file" and index < len(rest):
            file_filter = rest[index]
            index += 1
        elif token == "--query" and index < len(rest):
            text_query = rest[index]
            index += 1
        elif token in ("--config", "-c") and index < len(rest):
            config_path = rest[index]
            index += 1
        elif token in ("--storage",) and index < len(rest):
            storage = rest[index]
            index += 1
        elif token.startswith("-"):
            _fail(f"unknown option {token!r} for `report`")
        elif not scan_id:
            scan_id = token
        else:
            _fail(f"unexpected argument {token!r} for `report`")

    if show_help:
        sys.stdout.write(
            f"USAGE\n  {PROGRAM} report show SCAN_ID [--format json] [--output PATH] [--limit N] [--offset N]\n"
            f"  {PROGRAM} report list [--limit N] [--offset N] [--status STATUS] [--format json]\n"
        )
        return 0

    setup_logging("ERROR")
    config = load_config(config_path)
    if storage:
        config = config.with_overrides(storage_path=storage)
    with ScanService(config) as service:
        reports = ReportService(service.store)
        if action == "list":
            page = reports.list(limit=limit, offset=offset, status=status or None)
            if fmt == "json":
                _emit_json(
                    {
                        "scans": page.items,
                        "total": page.total,
                        "offset": page.offset,
                        "limit": page.limit,
                        "next_offset": page.next_offset,
                    }
                )
            else:
                for item in page.items:
                    sys.stdout.write(
                        f"{item.get('scan_id', ''):<28} {item.get('status', ''):<10} "
                        f"{item.get('finding_count', 0):>4} findings  {item.get('repository', '')}\n"
                    )
            return 0

        if action != "show":
            _fail(f"unknown report action {action!r}", hint="use `show` or `list`")
        if not scan_id:
            _fail("a SCAN_ID is required", hint=f"example: {PROGRAM} report list")

        report = reports.get(scan_id)
        if fmt == "json":
            filtered = FindingService(service.store).query_report(
                report,
                severity=severity or None,
                category=category or None,
                rule_id=rule_id or None,
                file=file_filter or None,
                query=text_query or None,
                limit=limit,
                offset=offset,
            )
            _emit_json(
                reports.payload(
                    report,
                    findings=filtered,
                    include_stages=True,
                    include_dependencies=True,
                )
            )
            return 0
        _render_and_write(report, fmt, output, redact=True, max_findings=limit)
        return 0


def _cmd_finding(argv: Sequence[str]) -> int:
    if not argv or argv[0] in ("-h", "--help"):
        sys.stdout.write(f"USAGE\n  {PROGRAM} finding show FINDING_ID [--scan-id SCAN_ID] [--format json]\n")
        return 0
    # A leading `--storage/--config PATH` pair may precede the action word.
    if len(argv) >= 2 and argv[0] in ("--storage", "--config", "-c"):
        action = argv[2]
        rest = [argv[0], argv[1], *argv[3:]]
    else:
        action = argv[0] if argv else ""
        rest = list(argv[1:])
    finding_id = ""
    scan_id: str | None = None
    fmt = "text"
    show_help = False
    config_path: str | None = None
    storage: str | None = None

    index = 0
    while index < len(rest):
        token = rest[index]
        index += 1
        if token in ("-h", "--help"):
            show_help = True
        elif token in ("-q", "--quiet", "-v", "--verbose"):
            continue
        elif token in ("--scan-id",) and index < len(rest):
            scan_id = rest[index]
            index += 1
        elif token in ("--format", "-f") and index < len(rest):
            fmt = normalize_format(rest[index])
            index += 1
        elif token == "--json":
            fmt = "json"
        elif token in ("--config", "-c") and index < len(rest):
            config_path = rest[index]
            index += 1
        elif token in ("--storage",) and index < len(rest):
            storage = rest[index]
            index += 1
        elif token.startswith("-"):
            _fail(f"unknown option {token!r} for `finding`")
        elif not finding_id:
            finding_id = token
        else:
            _fail(f"unexpected argument {token!r} for `finding`")

    if show_help:
        sys.stdout.write(f"USAGE\n  {PROGRAM} finding show FINDING_ID [--scan-id SCAN_ID] [--format json]\n")
        return 0
    if action != "show":
        _fail(f"unknown finding action {action!r}", hint="use `show`")
    if not finding_id:
        _fail("a FINDING_ID is required")

    setup_logging("ERROR")
    config = load_config(config_path)
    if storage:
        config = config.with_overrides(storage_path=storage)
    with ScanService(config) as service:
        findings = FindingService(service.store)
        finding = findings.get(finding_id, scan_id=scan_id)
        document = finding_to_dict(finding, include_evidence=True)
    if fmt == "json":
        _emit_json(document)
    else:
        severity = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
        confidence = finding.confidence.value if hasattr(finding.confidence, "value") else str(finding.confidence)
        verification = finding.verification_status.value if hasattr(finding.verification_status, "value") else str(finding.verification_status)
        sys.stdout.write(f"{finding.finding_id}  [{severity.upper()}]  {finding.rule_id}\n")
        sys.stdout.write(f"{finding.title}\n\n")
        location = finding.evidence[0] if finding.evidence else None
        if location is not None:
            sys.stdout.write(f"location : {location.file}:{location.start_line}\n")
        sys.stdout.write(f"category : {finding.category}\n")
        sys.stdout.write(f"language : {finding.language}\n")
        sys.stdout.write(f"confidence: {confidence}  ({finding.confidence_rationale})\n")
        sys.stdout.write(f"verified : {verification}\n\n")
        sys.stdout.write(f"summary  : {finding.summary}\n")
        sys.stdout.write(f"impact   : {finding.impact}\n")
        sys.stdout.write(f"fix      : {finding.remediation}\n")
    return 0


def _cmd_config(argv: Sequence[str]) -> int:
    action: str | None = None
    config_path: str | None = None
    storage: str | None = None

    index = 0
    rest = list(argv)
    while index < len(rest):
        token = rest[index]
        index += 1
        if token in ("-h", "--help"):
            sys.stdout.write(
                f"USAGE\n  {PROGRAM} config show [--format json] [--config PATH] [--storage PATH]\n"
            )
            return 0
        if token in ("-q", "--quiet", "-v", "--verbose"):
            continue
        if token in ("--config", "-c") and index < len(rest):
            config_path = rest[index]
            index += 1
            continue
        if token in ("--storage",) and index < len(rest):
            storage = rest[index]
            index += 1
            continue
        if token.startswith("-"):
            _fail(f"unknown option {token!r} for `config`")
        if action is None:
            action = token
            continue
        _fail(f"unexpected argument {token!r} for `config`")

    if action not in (None, "show"):
        _fail(f"unknown config action {action!r}", hint="use `show`")

    setup_logging("ERROR")
    config = load_config(config_path)
    if storage:
        config = config.with_overrides(storage_path=storage)
    _emit_json(_config_document(config))
    return 0


MAP_HELP = f"""
USAGE
  {PROGRAM} map show SCAN_ID [OPTIONS]
  {PROGRAM} map views
  {PROGRAM} map explain FINDING_ID [--scan-id SCAN_ID] [--depth N] [--json]
  {PROGRAM} map explain FINDING_ID [--scan-id SCAN_ID] --output PATH

  Build an interactive, single-file map of a stored scan. The output is one
  HTML file that opens from disk with no server, no CDN and no network access.

  `map explain` answers the question a map cannot: not "what is this node" but
  "how did untrusted input reach this sink, and what stops it". It prints the
  path source to sink, the evidence under each step, what must be true for the
  finding to matter, and — as its own section — what this analysis did NOT
  prove. A rule_id is accepted anywhere a finding_id is.

OPTIONS
   --view NAME          module | call | inheritance | dependency | test
                        event | obligation | influence | data_flow | finding
                        (default: module)
  --root PATH          a file, directory, symbol name, or `file::symbol` id
  --depth N            traversal depth for the symbol views, 1..6 (default: 3)
  --direction DIR      out | in | both (default: both)
  --kind KIND          restrict to a relation kind (repeatable)
  --no-findings        omit per-file finding counts
  --max-nodes N        node ceiling (default: 2000)
  --max-edges N        edge ceiling (default: 8000)
  --scan-id SCAN_ID    which scan to read; `explain` searches the 25 most
                        recent when this is omitted
  --json               emit the model (or the explanation) as JSON
  --open               try to open the written file with the OS handler
  --output PATH        destination .html file
  --storage PATH       scan store to read

EXIT CODES are the same as every other command.
"""


def map_views_document() -> dict[str, Any]:
    from understand.engine.code_map import (
        EDGE_STYLES,
        FINDING_VIEWS,
        NODE_SHAPES,
        SEVERITY_ORDER,
        VIEW_KINDS,
        VIEW_QUESTIONS,
        VIEWS,
    )

    shipped = VIEWS
    planned: tuple[str, ...] = ()
    return {
        "tool": PROGRAM,
        "version": __version__,
        "views": [
            {
                "view": name,
                "question": VIEW_QUESTIONS.get(name, ""),
                "kinds": sorted(VIEW_KINDS.get(name, ())),
                "granularity": (
                    "file"
                    if name == "module"
                    else "finding-derived"
                    if name in FINDING_VIEWS
                    else "symbol"
                ),
                "status": "available" if name in VIEWS else "planned",
            }
            for name in shipped + planned
        ],
        "node_shapes": NODE_SHAPES,
        "edge_styles": EDGE_STYLES,
        "severity_order": list(SEVERITY_ORDER),
        "note": (
            "Every view listed here is implemented. The `data_flow` and `finding` "
            "views are drawn from the findings themselves rather than from the "
            "graph, because a traced path and a severity cluster only exist on "
            "the finding; see docs/interactive-map.md."
        ),
    }


def _cmd_map(argv: Sequence[str]) -> int:
    from understand.engine.code_map import MapBudget, MapSpec, build_map

    argv = list(argv)
    if argv and argv[0] in ("-h", "--help"):
        sys.stdout.write(MAP_HELP.strip() + "\n")
        return 0
    # A leading `--storage/--config PATH` pair may precede the action word.
    if len(argv) >= 2 and argv[0] in ("--storage", "--config", "-c"):
        action = argv[2]
        rest = [argv[0], argv[1], *argv[3:]]
    else:
        action = argv[0] if argv else ""
        rest = list(argv[1:])

    if action == "views":
        _emit_json(map_views_document())
        return 0
    if action not in ("show", "explain"):
        _fail(f"unknown map action {action!r}", hint=f"run `{PROGRAM} map --help`")

    view = "module"
    root = ""
    depth = 3
    direction = "both"
    kinds: set[str] = set()
    include_findings = True
    max_nodes = 2_000
    max_edges = 8_000
    fmt = "html"
    output: str | None = None
    config_path: str | None = None
    storage: str | None = None
    scan_id = ""
    target = ""
    do_open = False
    show_help = False

    index = 0
    while index < len(rest):
        token = rest[index]
        index += 1
        if token in ("-h", "--help"):
            show_help = True
        elif token in ("-q", "--quiet", "-v", "--verbose"):
            continue
        elif token == "--view" and index < len(rest):
            view = rest[index]
            index += 1
        elif token == "--root" and index < len(rest):
            root = rest[index]
            index += 1
        elif token == "--depth" and index < len(rest):
            depth = _as_int(rest[index], "--depth")
            index += 1
        elif token == "--direction" and index < len(rest):
            direction = rest[index]
            index += 1
        elif token == "--kind" and index < len(rest):
            kinds.add(rest[index])
            index += 1
        elif token == "--no-findings":
            include_findings = False
        elif token == "--max-nodes" and index < len(rest):
            max_nodes = _as_int(rest[index], "--max-nodes")
            index += 1
        elif token == "--max-edges" and index < len(rest):
            max_edges = _as_int(rest[index], "--max-edges")
            index += 1
        elif token == "--json":
            fmt = "json"
        elif token == "--open":
            do_open = True
        elif token in ("--output", "-o") and index < len(rest):
            output = rest[index]
            index += 1
        elif token in ("--config", "-c") and index < len(rest):
            config_path = rest[index]
            index += 1
        elif token == "--storage" and index < len(rest):
            storage = rest[index]
            index += 1
        elif token == "--scan-id" and index < len(rest):
            scan_id = rest[index]
            index += 1
        elif token.startswith("-"):
            _fail(f"unknown option {token!r} for `map`")
        elif not target:
            target = token
        else:
            _fail(f"unexpected argument {token!r} for `map`")

    if show_help:
        sys.stdout.write(MAP_HELP.strip() + "\n")
        return 0
    if not target:
        _fail("a SCAN_ID or FINDING_ID is required", hint=f"run `{PROGRAM} map --help`")
    if action == "explain":
        # explain has its own target: a finding id, not a scan id.
        return _cmd_map_explain(target, scan_id, depth, fmt, output, config_path, storage)

    setup_logging("ERROR")
    config = load_config(config_path)
    if storage:
        config = config.with_overrides(storage_path=storage)

    with ScanService(config) as service:
        report = ReportService(service.store).get(scan_id or target)

    spec = MapSpec(
        scan_id=report.scan_id,
        view=view,
        root=root,
        depth=depth,
        direction=direction,
        kinds=frozenset(kinds),
        include_findings=include_findings,
        budget=MapBudget(max_nodes=max_nodes, max_edges=max_edges),
    )
    model = build_map(report, spec)

    if fmt == "json":
        _emit_json(model)
        return 0

    text = render_map_html(model)
    if output is None:
        # stdout is the map document; nothing else is written to it.
        sys.stdout.write(text)
        return 0

    target_path = safe_map_output_path(output)
    encoded = len(text.encode("utf-8"))
    from understand.reporting.html_map import MAX_MAP_BYTES

    if encoded > MAX_MAP_BYTES:
        _fail(
            f"map would be {encoded} bytes, past the {MAX_MAP_BYTES} byte ceiling",
            code="resource_limit_exceeded",
            hint="narrow the view, lower --depth, or lower --max-nodes",
        )
    target_path.parent.mkdir(parents=True, exist_ok=True)
    target_path.write_text(text, encoding="utf-8")
    _emit_json(
        {
            "scan_id": report.scan_id,
            "view": spec.view,
            "written": str(target_path),
            "bytes": encoded,
            "nodes": model["stats"]["nodes"],
            "edges": model["stats"]["edges"],
            "omitted_nodes": model["stats"]["omitted_nodes"],
            "budget_omitted": model["stats"]["budget_omitted"],
            "caveats": model["honesty"]["caveats"],
        }
    )
    if do_open:
        _best_effort_open(target_path)
    return 0


def _cmd_map_explain(
    finding_id: str,
    scan_id: str,
    depth: int,
    fmt: str,
    output: str | None,
    config_path: str | None,
    storage: str | None,
) -> int:
    """``understand map explain FINDING_ID`` — the causal account of one finding.

    The account is prose because the question is an argument ("how did untrusted
    input reach this sink, and what stops it"), not a picture. The map request
    that would accompany it is embedded in the JSON output and referenced in
    the text, so a reader can go from the argument to the picture with one
    command instead of re-deriving which symbol the account is about.
    """

    from understand.engine.code_map import MapBudget, explain_finding

    setup_logging("ERROR")
    config = load_config(config_path)
    if storage:
        config = config.with_overrides(storage_path=storage)

    with ScanService(config) as service:
        if not scan_id:
            # Without an explicit scan, take the newest scan that contains this
            # finding. Guessing "the latest scan" outright would explain the
            # wrong report.
            page = service.store.list_scans(limit=25)
            rows = page.items if hasattr(page, "items") else list(page)
            resolved = ""
            for row in rows:
                candidate = row.get("scan_id") if isinstance(row, dict) else None
                if not candidate:
                    continue
                try:
                    probe = ReportService(service.store).get(candidate)
                except Exception:
                    continue
                if any(
                    f.finding_id == finding_id or f.rule_id == finding_id
                    for f in probe.findings
                ):
                    resolved = candidate
                    break
            if not resolved:
                _fail(
                    f"finding {finding_id!r} was not found in the 25 most recent scans",
                    code="finding_not_found",
                    hint="pass --scan-id to name the scan explicitly",
                )
            scan_id = resolved
        report = ReportService(service.store).get(scan_id)
        account = explain_finding(
            report, finding_id, depth=depth, budget=MapBudget()
        )

    if fmt == "json":
        _emit_json(account)
        return 0

    lines: list[str] = []
    lines.append(f"{account['severity'].upper()}  {account['title']}")
    lines.append("=" * min(72, len(account["title"]) + 12))
    lines.append(f"rule      {account['rule_id']}   ({account['category']})")
    lines.append(f"finding   {account['finding_id']}")
    lines.append(f"scan      {account['scan_id']}")
    lines.append(f"where     {account['where']}")
    lines.append(
        f"evidence  confidence {account['confidence']}, verification "
        f"{account['verification_status']}"
    )
    if account["analysis_method"]:
        lines.append(f"method    {account['analysis_method']}")
    lines.append("")

    if account["what"]:
        lines.append("What was found")
        lines.append("-" * 15)
        lines.append(account["what"])
        lines.append("")
    if account["how"]:
        lines.append("Why it matters")
        lines.append("-" * 15)
        lines.append(account["how"])
        lines.append("")
    if account["impact"]:
        lines.append("Impact if it is real")
        lines.append("-" * 22)
        lines.append(account["impact"])
        lines.append("")

    if account["chain"]:
        lines.append("The path from source to sink")
        lines.append("-" * 28)
        for step in account["chain"]:
            role = step["role"]
            marker = {"source": "SOURCE", "sink": "SINK"}.get(role, "  ...  ")
            lines.append(f"  {step['step']}. [{marker}] {step['hop']}")
        lines.append("")

    if account["evidence"]:
        lines.append("Evidence")
        lines.append("-" * 8)
        for item in account["evidence"]:
            location = f"{item['file']}:{item['start_line']}"
            if item.get("end_line") and item["end_line"] != item["start_line"]:
                location += f"-{item['end_line']}"
            if item.get("symbol"):
                location += f"  in {item['symbol']}"
            origin = f"  [{item['kind']}, {item['origin']}]" if item.get("origin") else ""
            lines.append(f"  {location}{origin}")
            if item.get("snippet"):
                for snippet_line in str(item["snippet"]).splitlines():
                    lines.append(f"      {snippet_line}")
        lines.append("")

    if account["must_be_true"]:
        lines.append("What must be true for this to matter")
        lines.append("-" * 37)
        for item in account["must_be_true"]:
            lines.append(f"  - {item}")
        lines.append("")

    if account["not_proven"]:
        lines.append("What this analysis did NOT prove")
        lines.append("-" * 34)
        for item in account["not_proven"]:
            lines.append(f"  - {item}")
        lines.append("")

    if account["confidence_rationale"]:
        lines.append("Why this confidence")
        lines.append("-" * 20)
        lines.append(f"  {account['confidence_rationale']}")
        lines.append("")

    if account["remediation"]:
        lines.append("How to fix it")
        lines.append("-" * 14)
        lines.append(f"  {account['remediation']}")
        lines.append("")

    if account["references"]:
        lines.append("References")
        lines.append("-" * 10)
        for item in account["references"]:
            lines.append(f"  {item}")
        lines.append("")

    if account["caveats"]:
        lines.append("Read this before acting")
        lines.append("-" * 22)
        for item in account["caveats"]:
            lines.append(f"  - {item}")
        lines.append("")

    view = account["map"]["view"]
    root = account["map"]["root"] or "<the blamed symbol>"
    lines.append("To see it as a map")
    lines.append("-" * 17)
    command = f"{PROGRAM} map show {account['scan_id']} --view {view} --depth {account['map']['depth']}"
    if account["map"]["root"]:
        command += f" --root {account['map']['root']}"
    lines.append(f"  {command} -o map.html --open")
    lines.append(f"  (centred on {root})")

    text = "\n".join(lines) + "\n"
    if output:
        path = safe_output_path(output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        _emit_json({"written": str(path), "finding_id": account["finding_id"],
                    "scan_id": account["scan_id"]})
    else:
        sys.stdout.write(text)
    return 0


def _best_effort_open(path: Any) -> None:
    """Open a file with the OS handler, never raising.

    ``--open`` is a convenience. On a headless box it will simply do nothing,
    and it must never turn a successful map build into a failed command.
    """

    import subprocess
    import sys as _sys

    try:
        if _sys.platform == "darwin":
            subprocess.Popen(["open", str(path)])
        elif os.name == "nt":
            os.startfile(str(path))  # type: ignore[attr-defined]
        else:
            subprocess.Popen(["xdg-open", str(path)])
    except Exception:
        logger.debug("could not open %s", path, exc_info=True)


def _cmd_version(_argv: Sequence[str]) -> int:
    _emit_json({"tool": PROGRAM, "version": __version__, "python": sys.version.split()[0]})
    return 0


def _emit_error(error: dict[str, Any]) -> None:
    json.dump({"error": error}, sys.stderr, indent=2, default=str)
    sys.stderr.write("\n")


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #
_COMMANDS = {
    "scan": _cmd_scan,
    "report": _cmd_report,
    "finding": _cmd_finding,
    "map": _cmd_map,
    "config": _cmd_config,
    "capabilities": lambda argv: (_emit_json(capabilities_document()) or 0),
    "version": _cmd_version,
}

# Options that carry a value and may therefore appear *before* the command word.
_GLOBAL_VALUE_FLAGS = frozenset(
    {"--storage", "--config", "-c", "--mode", "--local-root", "--format", "-f", "--out", "--output", "-o"}
)


def _split_command(argv: list[str]) -> tuple[str, list[str]]:
    """Split ``argv`` into (command, remainder) allowing global options first.

    ``understand --storage ./s.db report list`` is accepted so that a caller can
    pin the scan store once for a whole command chain without repeating the flag
    on every subcommand. Returns ``("", argv)`` when no command word is present.
    """

    index = 0
    while index < len(argv):
        token = argv[index]
        if token == "--":
            index += 1
            continue
        if token.startswith("-") and token != "-":
            head, sep, _tail = token.partition("=")
            if not sep and head in _GLOBAL_VALUE_FLAGS:
                index += 2
                continue
            index += 1
            continue
        return token, [*argv[:index], *argv[index + 1 :]]
    return "", argv


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI. Returns a process exit code; never raises for known failures."""

    argv = list(sys.argv[1:] if argv is None else argv)

    command, argv = _split_command(argv)

    if not argv or not command:
        sys.stdout.write(MAIN_HELP.strip() + "\n")
        return 0

    if command in ("-V", "--version"):
        return _cmd_version(argv)

    try:
        # Inside the try so that a usage failure is reported as an error
        # envelope on stderr rather than escaping as an exception.
        if command not in _COMMANDS:
            _fail(f"unknown command {command!r}", hint=f"run `{PROGRAM} --help`")
        return _COMMANDS[command](argv)
    except UnderstandError as exc:
        _emit_error(exc.to_dict())
        return exc.exit_code
    except KeyboardInterrupt:
        _emit_error({"code": "cancelled", "message": "interrupted", "hint": "scan cancelled"})
        return 130
    except BrokenPipeError:  # pragma: no cover - depends on the consumer
        return 0
    except Exception as exc:
        logger.debug("unhandled error", exc_info=True)
        _emit_error(
            {
                "code": "internal_error",
                "message": f"{type(exc).__name__}: {exc}",
                "hint": "re-run with -v/--verbose for a traceback on stderr",
            }
        )
        return 1


def run() -> None:
    """Console-script entry point."""

    raise SystemExit(main())


if __name__ == "__main__":  # pragma: no cover
    run()
