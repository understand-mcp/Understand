"""Integration tests for the CLI grammar, exit codes and stdout purity."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from understand import cli


def run(capsys, argv: list[str], storage: Path) -> tuple[int, str, str]:
    code = cli.main(["--storage", str(storage), *argv])
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_help_works_without_scanning(capsys, tmp_path: Path) -> None:
    code, out, _err = run(capsys, ["--help"], tmp_path / "db.sqlite")
    assert code == 0
    assert "scan" in out


def test_scan_help_works(capsys, tmp_path: Path) -> None:
    code, out, _err = run(capsys, ["scan", "--help"], tmp_path / "db.sqlite")
    assert code == 0
    assert "--cross-module" in out
    assert "--deep" in out


def test_version_command(capsys, tmp_path: Path) -> None:
    from understand import __version__

    code, out, _err = run(capsys, ["version"], tmp_path / "db.sqlite")
    assert code == 0
    assert __version__ in out


def test_capabilities_command(capsys, tmp_path: Path) -> None:
    code, out, _err = run(capsys, ["capabilities", "--format", "json"], tmp_path / "db.sqlite")
    assert code == 0
    document = json.loads(out)
    assert document["checks"]
    assert document["llm_required"] is False


def test_config_show(capsys, tmp_path: Path) -> None:
    code, out, _err = run(capsys, ["config", "show"], tmp_path / "db.sqlite")
    assert code == 0
    assert "security" in out or "allow_remote" in out


def test_combined_token_grammar(capsys, risky_repo: str, tmp_path: Path) -> None:
    code, out, err = run(
        capsys,
        ["scan", risky_repo, "security", "bugs", "--deep", "--cross-module", "report",
         "--format", "json"],
        tmp_path / "db.sqlite",
    )
    assert code == 0, err
    payload = json.loads(out)
    assert payload["status"] == "completed"
    assert payload["findings"]


def test_normalised_flag_grammar(capsys, risky_repo: str, tmp_path: Path) -> None:
    code, out, err = run(
        capsys,
        ["scan", risky_repo, "--security", "--bugs", "--deep", "--cross-module",
         "--format", "json"],
        tmp_path / "db.sqlite",
    )
    assert code == 0, err
    assert json.loads(out)["findings"]


def test_equals_form_is_accepted(capsys, risky_repo: str, tmp_path: Path) -> None:
    code, out, err = run(
        capsys, ["scan", risky_repo, "security", "--format=json"], tmp_path / "db.sqlite"
    )
    assert code == 0, err
    assert json.loads(out)["scan_id"]


def test_stdout_is_pure_json_even_when_verbose(
    capsys, risky_repo: str, tmp_path: Path
) -> None:
    code, out, _err = run(
        capsys,
        ["scan", risky_repo, "security", "--deep", "-v", "--format", "json"],
        tmp_path / "db.sqlite",
    )
    assert code == 0
    json.loads(out)  # must parse cleanly; logs went to stderr


def test_quiet_suppresses_logs(capsys, risky_repo: str, tmp_path: Path) -> None:
    code, out, err = run(
        capsys,
        ["scan", risky_repo, "security", "--deep", "-q", "--format", "json"],
        tmp_path / "db.sqlite",
    )
    assert code == 0
    json.loads(out)
    assert err.strip() == ""


def test_text_format(capsys, risky_repo: str, tmp_path: Path) -> None:
    code, out, _err = run(
        capsys, ["scan", risky_repo, "security", "--format", "text"], tmp_path / "db.sqlite"
    )
    assert code == 0
    assert "UNDERSTAND" in out or "Findings" in out or "SEC-PY-SHELL-001" in out


def test_sarif_output_file(capsys, risky_repo: str, tmp_path: Path) -> None:
    target = tmp_path / "report.sarif"
    code, _out, err = run(
        capsys,
        ["scan", risky_repo, "security", "--format", "sarif", "--output", str(target)],
        tmp_path / "db.sqlite",
    )
    assert code == 0, err
    document = json.loads(target.read_text(encoding="utf-8"))
    assert document["version"] == "2.1.0"


def test_output_path_traversal_is_refused(
    capsys, risky_repo: str, tmp_path: Path
) -> None:
    code, _out, err = run(
        capsys,
        ["scan", risky_repo, "security", "--format", "json", "--output", "../escape.json"],
        tmp_path / "db.sqlite",
    )
    assert code == 64
    assert "error" in err


def test_fail_on_severity(capsys, risky_repo: str, minimal_repo: str, tmp_path: Path) -> None:
    risky = run(
        capsys,
        ["scan", risky_repo, "security", "--fail-on", "high", "--format", "json"],
        tmp_path / "a.sqlite",
    )
    assert risky[0] == 2

    clean = run(
        capsys,
        ["scan", minimal_repo, "security", "--fail-on", "high", "--format", "json"],
        tmp_path / "b.sqlite",
    )
    assert clean[0] == 0


def test_unknown_format_exits_64(capsys, risky_repo: str, tmp_path: Path) -> None:
    code, _out, _err = run(
        capsys, ["scan", risky_repo, "--format", "pdf"], tmp_path / "db.sqlite"
    )
    assert code == 64


def test_missing_source_exits_65(capsys, tmp_path: Path) -> None:
    code, _out, err = run(
        capsys, ["scan", str(tmp_path / "missing"), "--format", "json"], tmp_path / "db.sqlite"
    )
    assert code == 65
    assert "error" in err


def test_access_denied_outside_root_exits_77(capsys, risky_repo: str, tmp_path: Path) -> None:
    code, _out, err = run(
        capsys,
        ["scan", risky_repo, "--format", "json", "--local-root", str(tmp_path / "other")],
        tmp_path / "db.sqlite",
    )
    assert code == 77
    assert "error" in err


def test_remote_blocked_when_disabled(capsys, tmp_path: Path) -> None:
    code, _out, err = run(
        capsys,
        ["scan", "https://github.com/owner/repo", "--format", "json"],
        tmp_path / "db.sqlite",
    )
    assert code in {64, 77}
    assert "error" in err


def test_report_list_and_show(capsys, risky_repo: str, tmp_path: Path) -> None:
    db = tmp_path / "db.sqlite"
    run(capsys, ["scan", risky_repo, "security", "--format", "json"], db)

    code, out, _err = run(capsys, ["report", "list", "--format", "json"], db)
    assert code == 0
    scans = json.loads(out)["scans"]
    assert scans

    scan_id = scans[0]["scan_id"]
    code, out, _err = run(capsys, ["report", "show", scan_id, "--format", "json"], db)
    assert code == 0
    assert json.loads(out)["scan_id"] == scan_id


def test_report_show_filters(capsys, risky_repo: str, tmp_path: Path) -> None:
    db = tmp_path / "db.sqlite"
    _code, out, _err = run(capsys, ["scan", risky_repo, "security", "--deep", "--format", "json"], db)
    scan_id = json.loads(out)["scan_id"]
    code, out, _err = run(
        capsys, ["report", "show", scan_id, "--severity", "critical", "--format", "json"], db
    )
    assert code == 0
    payload = json.loads(out)
    assert all(f["severity"] == "critical" for f in payload["findings"])


def test_report_show_unknown_scan_exits_66(capsys, tmp_path: Path) -> None:
    code, _out, err = run(capsys, ["report", "show", "scan-nope"], tmp_path / "db.sqlite")
    assert code == 66
    assert "error" in err


def test_finding_show(capsys, risky_repo: str, tmp_path: Path) -> None:
    db = tmp_path / "db.sqlite"
    _code, out, _err = run(capsys, ["scan", risky_repo, "security", "--format", "json"], db)
    scan_id = json.loads(out)["scan_id"]
    code, out, _err = run(
        capsys, ["report", "show", scan_id, "--format", "json", "--limit", "1"], db
    )
    finding_id = json.loads(out)["findings"][0]["finding_id"]
    code, out, _err = run(capsys, ["finding", "show", finding_id, "--format", "json"], db)
    assert code == 0
    assert json.loads(out)["finding_id"] == finding_id


def test_finding_show_unknown_exits_67(capsys, tmp_path: Path) -> None:
    # FindingNotFound has its own exit code so a mistyped finding id is
    # distinguishable from a mistyped scan id (66) in scripts.
    code, _out, err = run(capsys, ["finding", "show", "NOPE-000000"], tmp_path / "db.sqlite")
    assert code == 67
    assert "error" in err


def test_unknown_command_exits_64(capsys, tmp_path: Path) -> None:
    code, _out, _err = run(capsys, ["frobnicate"], tmp_path / "db.sqlite")
    assert code == 64


def test_scan_without_source_exits_64(capsys, tmp_path: Path) -> None:
    code, _out, _err = run(capsys, ["scan"], tmp_path / "db.sqlite")
    assert code == 64


@pytest.mark.parametrize("flag", ["--security", "--bugs", "--architecture", "--dependencies", "--reliability"])
def test_each_check_flag_is_accepted(capsys, flag: str, risky_repo: str, tmp_path: Path) -> None:
    code, out, err = run(
        capsys, ["scan", risky_repo, flag, "--format", "json"], tmp_path / f"{flag}.sqlite"
    )
    assert code == 0, err
    assert json.loads(out)["findings"] is not None


def test_no_cache_flag(capsys, risky_repo: str, tmp_path: Path) -> None:
    code, out, err = run(
        capsys, ["scan", risky_repo, "security", "--no-cache", "--format", "json"],
        tmp_path / "db.sqlite",
    )
    assert code == 0, err
    assert json.loads(out)["from_cache"] is False


def test_exit_codes_documented() -> None:
    from understand.errors import (
        ConfigurationError,
        InvalidSourceError,
        ScanNotFound,
        UnderstandError,
        ValidationError,
    )

    # EXIT_CODES is the user-facing table (printed in --help and emitted in the
    # JSON schema doc), keyed by the numeric code the process actually exits with.
    for error_cls in (
        UnderstandError,
        ConfigurationError,
        InvalidSourceError,
        ScanNotFound,
        ValidationError,
    ):
        assert error_cls.exit_code in cli.EXIT_CODES
        assert cli.EXIT_CODES[error_cls.exit_code]


def _scan_and_explain(capsys, risky_repo: str, tmp_path: Path, extra: list[str]) -> tuple[int, str, str]:
    """Scan once, then explain the first finding that scan produced."""

    storage = tmp_path / "explain.sqlite"
    code, out, err = run(
        capsys, ["scan", risky_repo, "security", "--format", "json"], storage
    )
    assert code == 0, err
    scan_id = json.loads(out)["scan_id"]
    detail = json.loads(out)["findings"][0]["finding_id"]
    return run(capsys, ["map", "explain", detail, "--scan-id", scan_id, *extra], storage)


def test_map_explain_prints_the_whole_argument(capsys, risky_repo: str, tmp_path: Path) -> None:
    code, out, err = _scan_and_explain(capsys, risky_repo, tmp_path, [])
    assert code == 0, err
    for heading in (
        "What was found",
        "Evidence",
        "How to fix it",
        "References",
        "Read this before acting",
        "To see it as a map",
    ):
        assert heading in out, heading


def test_map_explain_says_what_was_not_proven(capsys, risky_repo: str, tmp_path: Path) -> None:
    # An impact statement with no gap beside it is how a heuristic gets acted
    # on as if it were a demonstrated defect.
    code, out, _err = _scan_and_explain(capsys, risky_repo, tmp_path, [])
    assert code == 0
    assert "Read this before acting" in out
    caveats = out.split("Read this before acting", 1)[1]
    assert caveats.strip()


def test_map_explain_json_is_machine_readable(capsys, risky_repo: str, tmp_path: Path) -> None:
    code, out, err = _scan_and_explain(capsys, risky_repo, tmp_path, ["--json"])
    assert code == 0, err
    payload = json.loads(out)
    assert payload["finding_id"]
    assert payload["map"]["view"]
    assert isinstance(payload["chain"], list)


def test_map_explain_finds_the_scan_itself(capsys, risky_repo: str, tmp_path: Path) -> None:
    storage = tmp_path / "noscanid.sqlite"
    code, out, err = run(
        capsys, ["scan", risky_repo, "security", "--format", "json"], storage
    )
    assert code == 0, err
    detail = json.loads(out)["findings"][0]["finding_id"]
    # No --scan-id: the command must search rather than default to whatever scan
    # happened to be newest, which would explain the wrong report.
    code, text, err = run(capsys, ["map", "explain", detail, "--json"], storage)
    assert code == 0, err
    assert json.loads(text)["finding_id"] == detail


def test_map_explain_unknown_finding_exits_67(capsys, risky_repo: str, tmp_path: Path) -> None:
    storage = tmp_path / "unknown.sqlite"
    code, out, err = run(
        capsys, ["scan", risky_repo, "security", "--format", "json"], storage
    )
    assert code == 0, err
    scan_id = json.loads(out)["scan_id"]
    code, _out, err = run(
        capsys, ["map", "explain", "SEC-DOES-NOT-EXIST", "--scan-id", scan_id], storage
    )
    assert code == 67
    assert "finding_not_found" in err
