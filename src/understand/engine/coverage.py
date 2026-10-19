"""Coverage accounting: what was analyzed, what was skipped, and why."""

from __future__ import annotations

from collections import Counter

from understand.engine import language_detection as lang
from understand.engine.repository_inventory import Inventory
from understand.engine.symbol_index import SymbolIndex, parse_module
from understand.logging_config import get_logger
from understand.models import (
    CoverageRecord,
    LanguageRecord,
    SupportLevel,
)

log = get_logger("engine.coverage")


def parse_all(inv: Inventory, index: SymbolIndex, *, max_symbols: int) -> tuple[list[str], int, list[str]]:
    """Parse every readable file into the symbol index.

    Returns ``(failed_files, symbol_count, generated_skipped)``.  Generated and
    vendored files are read only when policy explicitly allows them: reporting
    defects in machine-generated code buries the defects a human can fix.
    """

    failed: list[str] = []
    generated: list[str] = []
    symbols = 0
    allow_generated = bool(inv.policy.analysis.allow_generated) if inv.policy is not None else False
    for path, text in sorted(inv.contents.items()):
        record = inv.files.get(path)
        if record is None or record.is_binary:
            continue
        if (record.is_generated or record.is_vendored) and not allow_generated:
            generated.append(path)
            continue
        detection = lang.detect(path)
        try:
            module = parse_module(path, text, detection.language)
        except Exception as exc:  # noqa: BLE001 - a malformed file must not kill the scan
            failed.append(path)
            log.debug("parse failed for %s: %s", path, exc)
            continue
        if module.parse_error:
            failed.append(path)
            log.debug("parse error in %s: %s", path, module.parse_error)
        if symbols + len(module.symbols) > max_symbols:
            continue
        symbols += len(module.symbols)
        index.add(module)
    return failed, symbols, generated


def build_coverage(
    inv: Inventory,
    index: SymbolIndex,
    *,
    failed_parses: list[str],
    unresolved_calls: int,
    graph_edge_count: int,
    truncated: bool,
    exclusions: dict[str, str],
    unsupported: list[str],
    notes: list[str],
    generated_skipped: list[str] | None = None,
) -> CoverageRecord:
    generated_skipped = generated_skipped or []
    lang_stats: dict[str, list[int]] = {}
    lang_files: Counter[str] = Counter()
    analyzed = 0
    # Files the policy refused to inventory are skipped too: coverage must
    # account for every file the walk saw, not only the ones it could read.
    skipped = int(inv.skipped)
    for path, record in inv.files.items():
        if record.is_binary:
            skipped += 1
            continue
        if path in inv.contents and path not in set(generated_skipped):
            analyzed += 1
            lang_files[record.language] += 1
            lang_stats.setdefault(record.language, [0, 0])[1] += record.lines
        else:
            skipped += 1

    languages: list[LanguageRecord] = []
    for language, count in sorted(lang_files.items(), key=lambda kv: -kv[1]):
        spec_analyzers = lang.analyzers_for(language)
        limitations = list(lang.limitations_for(language))
        support = lang.support_for(language)
        if language == "unknown":
            limitations.append("No registered analyzer matched this file extension.")
        # Count this language's own failures. Using the global list here stamped
        # every language with the repository-wide total, which reads as if each
        # language had that many broken files.
        own_failures = sum(
            1 for path in failed_parses
            if path in inv.files and inv.files[path].language == language
        )
        if own_failures:
            limitations.append(
                f"{own_failures} file(s) of this language failed to parse and were "
                "indexed structurally only."
            )
        languages.append(LanguageRecord(
            language=language,
            support=support,
            files=count,
            lines=lang_stats.get(language, [0, 0])[1],
            analyzers=list(spec_analyzers),
            limitations=sorted(dict.fromkeys(limitations)),
        ))

    notes_out = list(notes)
    if generated_skipped:
        notes_out.append(
            f"{len(generated_skipped)} generated or vendored file(s) were read but not analyzed "
            "(set analysis.allow_generated to include them)."
        )
    if unresolved_calls:
        notes_out.append(
            f"{unresolved_calls} call target(s) could not be resolved statically; "
            "dynamic dispatch is not invented."
        )
    if truncated:
        notes_out.append("File enumeration stopped at a configured budget; results are partial.")

    return CoverageRecord(
        files_total=len(inv.files) + inv.skipped,
        files_analyzed=analyzed,
        files_skipped=skipped,
        files_failed=len(failed_parses),
        bytes_read=inv.total_bytes,
        symbols=len(index.by_id),
        edges=graph_edge_count,
        unresolved_calls=unresolved_calls,
        languages=languages,
        exclusions=dict(sorted(exclusions.items())),
        unsupported_features=sorted(dict.fromkeys(unsupported)),
        truncated=truncated,
        notes=notes_out,
    )


def summarize(coverage: CoverageRecord) -> str:
    pct = (coverage.files_analyzed / coverage.files_total * 100) if coverage.files_total else 0.0
    return (
        f"{coverage.files_analyzed}/{coverage.files_total} files ({pct:.1f}%), "
        f"{coverage.symbols} symbols, {coverage.edges} edges, "
        f"{coverage.unresolved_calls} unresolved calls"
    )


SUPPORT_LABELS = {
    SupportLevel.FULL: "full",
    SupportLevel.PARTIAL: "partial",
    SupportLevel.TEXT_ONLY: "text-only",
    SupportLevel.UNSUPPORTED: "unsupported",
}