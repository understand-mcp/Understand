"""Architecture analysis: dependency cycles, layer violations, coupling, entry points."""

from __future__ import annotations

import re
from collections import defaultdict

from understand.engine.analyzers.base import AnalysisContext
from understand.models import (
    Check,
    Confidence,
    Evidence,
    EvidenceKind,
    Finding,
    Severity,
    VerificationStatus,
)

MANIFEST_ENTRY_HINTS = (
    ("package.json", "node_main"),
    ("pyproject.toml", "python_entry"),
    ("go.mod", "go_module"),
    ("Cargo.toml", "cargo_bin"),
    ("setup.py", "python_legacy_entry"),
)

_URL_RE = re.compile(r"""["']([^"']*(?:api|rpc|service|endpoint)[^"']*)["']""", re.I)


class ArchitectureAnalyzer:
    name = "architecture"
    check = Check.ARCHITECTURE
    applies_to = ("*",)

    def run(self, ctx: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._cycles(ctx))
        findings.extend(self._god_modules(ctx))
        findings.extend(self._layer_violations(ctx))
        return findings

    # ------------------------------------------------------------------ cycles
    def _cycles(self, ctx: AnalysisContext) -> list[Finding]:
        out: list[Finding] = []
        for cycle in ctx.graph.cycles(limit=25):
            files = [ctx.index.by_id[n].file for n in cycle if n in ctx.index.by_id]
            unique = sorted(dict.fromkeys(f for f in files if f))
            if len(unique) < 2:
                continue
            out.append(Finding(
                title=f"Dependency cycle across {len(unique)} files",
                category="circular-dependency",
                rule_id="ARCH-CYCLE-001",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                verification_status=VerificationStatus.STATIC_EVIDENCE,
                summary="A dependency cycle was detected: " + " -> ".join(
                    n.split("::")[-1] for n in cycle),
                technical_explanation=(
                    "The module dependency graph contains a cycle spanning "
                    f"{len(unique)} files: {', '.join(unique)}. Cycles make a component "
                    "hard to change in isolation and frequently hide layering violations."
                ),
                evidence=[
                    Evidence(kind=EvidenceKind.MANIFEST, file=f, start_line=0, end_line=0,
                             note="module participating in the cycle")
                    for f in unique[:6]
                ],
                affected_symbols=[n.split("::")[-1] for n in cycle][:8],
                call_chains=[[n.split("::")[-1] for n in cycle]],
                assumptions=["Cycle detection is over the statically resolved graph only."],
                impact="Increases change cost and can cause partial initialisation bugs.",
                remediation="Extract the shared contract into a lower-level module both sides depend on.",
                references=["https://en.wikipedia.org/wiki/Circular_dependency"],
                analysis_method="cycle detection over the call/import graph",
                fingerprint="cycle:" + "|".join(unique),
                confidence_rationale=f"deterministic cycle over {len(unique)} files",
            ))
        return out

    # ------------------------------------------------------------- god modules
    def _god_modules(self, ctx: AnalysisContext) -> list[Finding]:
        out: list[Finding] = []
        stats = []
        for path, module in ctx.index.modules.items():
            symbols = [s for s in module.symbols if s.kind in {"function", "method", "class"}]
            if len(symbols) < 40:
                continue
            longest = max((s.end_line - s.start_line for s in symbols), default=0)
            stats.append((len(symbols), longest, path, module))
        for count, longest, path, module in sorted(stats, reverse=True)[:10]:
            out.append(Finding(
                title=f"{path} concentrates {count} symbols",
                category="high-coupling",
                rule_id="ARCH-COUPLING-001",
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                verification_status=VerificationStatus.STATIC_EVIDENCE,
                summary=f"{path} declares {count} symbols; the longest spans {longest} lines.",
                technical_explanation=(
                    "Large modules raise the blast radius of any change and are a common "
                    "source of hidden coupling. This is a structural signal, not a defect."
                ),
                evidence=[Evidence(kind=EvidenceKind.SOURCE_RANGE, file=path, start_line=1,
                                   end_line=module.lines and len(module.lines) or 1,
                                   note=f"{count} symbols in one file")],
                assumptions=["The file is a real source file rather than a generated or vendored file."],
                impact="Higher maintenance and regression risk.",
                remediation="Split by responsibility along the boundaries visible in the call graph.",
                analysis_method="symbol density analysis",
                fingerprint=f"coupling:{path}",
                confidence_rationale=f"symbols={count} longest={longest}",
            ))
        return out

    # -------------------------------------------------------- layer violations
    def _layer_violations(self, ctx: AnalysisContext) -> list[Finding]:
        """Heuristic layering: a `test` or `scripts` module must not be imported by `src`."""
        out: list[Finding] = []
        forward: dict[str, set[str]] = defaultdict(set)
        for path, imports in ctx.index.imports.items():
            for raw, line, _t in imports:
                target = ctx.index.resolve_import(path, raw)
                if target and target != path:
                    forward[path].add(target)

        def layer_of(path: str) -> str:
            low = path.lower()
            if "/test" in low or low.startswith("test") or "/spec" in low:
                return "test"
            if low.startswith(("scripts/", "tools/", "bin/", "hack/")):
                return "tooling"
            if low.startswith(("src/", "lib/", "app/", "internal/", "pkg/")):
                return "production"
            return "other"

        for path, targets in forward.items():
            src_layer = layer_of(path)
            if src_layer != "production":
                continue
            for target in targets:
                t_layer = layer_of(target)
                if t_layer == "test":
                    out.append(Finding(
                        title=f"Production module {path} imports test code ({target})",
                        category="layering",
                        rule_id="ARCH-LAYER-001",
                        severity=Severity.LOW,
                        confidence=Confidence.MEDIUM,
                        verification_status=VerificationStatus.STATIC_EVIDENCE,
                        summary="A production-layer file imports from the test layer.",
                        technical_explanation=(
                            "Importing test helpers into production code ships test-only "
                            "behaviour and fixtures into the deployed artifact."
                        ),
                        evidence=[Evidence(kind=EvidenceKind.SOURCE_RANGE, file=path, start_line=0,
                                           end_line=0, note=f"imports {target}")],
                        affected_symbols=[f"{path}::<module>"],
                        assumptions=["The directory layout reflects the intended layering.",
                                     "The import is not behind a test-only build tag."],
                        impact="Unnecessary coupling; test data may reach production.",
                        remediation="Move the shared helper into a neutral library module.",
                        analysis_method="layer inference over the import graph",
                        fingerprint=f"layer:{path}->{target}",
                        confidence_rationale="inferred layers from path conventions",
                    ))
        return out[:50]

    # ------------------------------------------------------------ entry points
    @staticmethod
    def entry_points(ctx: AnalysisContext) -> list[dict[str, object]]:
        """Report entry points discovered from the call graph and manifests."""
        found: list[dict[str, object]] = []
        for path, module in sorted(ctx.index.modules.items()):
            if not any(path.endswith(suffix) for suffix in
                       ("main.py", "__main__.py", "app.py", "index.js", "index.ts",
                        "main.go", "main.rs", "Program.cs", "cli.py", "server.py", "wsgi.py")):
                continue
            found.append({
                "file": path,
                "kind": "convention_entrypoint",
                "symbols": [s.id for s in module.symbols if s.kind in {"function", "method"}][:10],
                "origin": "inferred",
            })
        for sid, sym in ctx.index.by_id.items():
            if sym.name in {"main", "handler", "lambda_handler", "onRequest"}:
                found.append({
                    "file": sym.file,
                    "kind": "convention_handler",
                    "symbol": sid,
                    "line": sym.start_line,
                    "origin": "inferred",
                })
        seen = set()
        deduped = []
        for item in found:
            key = (item.get("file"), item.get("symbol"), item.get("kind"))
            if key in seen:
                continue
            seen.add(key)
            deduped.append(item)
        return deduped[:200]