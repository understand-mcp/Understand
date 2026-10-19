"""Repository access policy: what may be read, what is excluded, what is forbidden."""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from pathlib import Path

from understand.config import AnalysisPolicy, RuntimeConfig
from understand.errors import AccessDeniedError
from understand.security.path_validation import (
    is_hostile_filename,
    normalize_relpath,
    resolve_within,
)

# Never read these even if the include rules would allow them. Absolute.
FORBIDDEN_NAMES = frozenset({
    ".env", ".env.local", ".env.production", ".netrc", "_netrc", ".htpasswd",
    "shadow", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
})


@dataclass(frozen=True)
class ExclusionDecision:
    excluded: bool
    reason: str = ""
    pattern: str = ""


class RepositoryPolicy:
    """Decides file inclusion/exclusion and enforces root containment."""

    def __init__(self, analysis: AnalysisPolicy, *, allowed_roots: tuple[str, ...] = ()) -> None:
        self.analysis = analysis
        self.allowed_roots = tuple(allowed_roots)
        self.exclusion_reasons: dict[str, str] = {}

    # ---------------------------------------------------------------- naming
    def classify_name(self, name: str) -> str:
        lowered = name.lower()
        if name in FORBIDDEN_NAMES or lowered in FORBIDDEN_NAMES:
            return "sensitive"
        for pattern in self.analysis.sensitive_globs:
            if fnmatch.fnmatch(lowered, pattern.lower()):
                return "sensitive"
        return "normal"

    def is_generated_path(self, relpath: str) -> bool:
        markers = (
            "/generated/", "/__generated__/", "/gen/", ".generated.", "/vendor/",
            "/third_party/", "/thirdparty/", "/node_modules/", "/.yarn/",
            "/proto/", "/migrations/",
        )
        low = "/" + relpath.lower()
        base = relpath.rsplit("/", 1)[-1].lower()
        if any(m in low for m in markers):
            return True
        return base.endswith((".g.dart", ".pb.go", "_pb2.py", ".pb.cc", ".pb.h", ".designer.cs"))

    def is_test_path(self, relpath: str) -> bool:
        low = "/" + relpath.lower()
        base = relpath.rsplit("/", 1)[-1].lower()
        if any(seg in low for seg in ("/test/", "/tests/", "/spec/", "/specs/", "/testing/",
                                      "/__tests__/", "/e2e/", "/fixtures/", "/testdata/")):
            return True
        return base.startswith(("test_", "spec_")) or base.endswith(("_test.go", "_test.py", "_test.rb",
                                                                    "_spec.rb", ".test.ts", ".test.tsx",
                                                                    ".spec.ts", ".spec.tsx", ".test.js"))

    # ------------------------------------------------------------- decisions
    def decide(self, relpath: str) -> ExclusionDecision:
        """Return whether a repository-relative path should be read."""
        try:
            rel = normalize_relpath(relpath)
        except Exception as exc:  # noqa: BLE001
            return ExclusionDecision(True, str(exc), "<invalid>")

        parts = rel.split("/")
        for part in parts[:-1]:
            if part in self.analysis.exclude_dirs or part.startswith("."):
                return ExclusionDecision(True, "excluded directory", part)
        name = parts[-1]
        if is_hostile_filename(name):
            return ExclusionDecision(True, "hostile or unportable filename", name)
        if name.startswith("."):
            return ExclusionDecision(True, "hidden file excluded by policy", name)

        # ``assets`` means two different things. Under ``src`` it is a source
        # directory like any other and is analysed; anywhere else it holds
        # shipped artefacts -- a browserified copy of a library, a bundle, a
        # fixture's expected output. Analysing the latter reports another
        # project's code as this repository's code, so it is excluded there and
        # only there. A blanket entry for the name in exclude_dirs would have
        # thrown away ``src/assets/icons.ts`` along with it, which is why this
        # rule lives here rather than there.
        if "assets" in parts[:-1] and "src" not in parts[:-1]:
            return ExclusionDecision(True, "vendored asset bundle, not repository source", name)
        if not self.analysis.allow_generated and self.is_generated_path(rel):
            return ExclusionDecision(True, "generated or vendored file excluded by policy", name)
        if self.classify_name(name) == "sensitive":
            return ExclusionDecision(True, "sensitive file excluded by policy", name)
        low = name.lower()
        for pattern in self.analysis.exclude_globs:
            if fnmatch.fnmatch(low, pattern.lower()):
                return ExclusionDecision(True, "excluded by pattern", pattern)
        return ExclusionDecision(False)

    def note_exclusion(self, reason: str, pattern: str = "") -> None:
        key = reason if not pattern else f"{reason}: {pattern}"
        self.exclusion_reasons[key] = key

    # -------------------------------------------------------------- guarding
    def guard(self, root: Path, path: Path) -> str:
        """Prove `path` is readable under policy and return its repo-relative form."""
        resolved = resolve_within(root, path, allow_symlinks=self.analysis.follow_symlinks)
        if not self.analysis.follow_symlinks and resolved.is_symlink():
            raise AccessDeniedError(f"symlinks are not followed by policy: {path}")
        decision = self.decide(path.name)
        if decision.excluded:
            raise AccessDeniedError(f"{path.name}: {decision.reason}")
        rel = resolved.relative_to(Path(root).resolve())
        full_rel = "/".join(rel.parts)
        decision = self.decide(full_rel)
        if decision.excluded:
            raise AccessDeniedError(f"{full_rel}: {decision.reason}")
        return full_rel

    @classmethod
    def for_config(cls, config: RuntimeConfig, *, allowed_roots: tuple[str, ...] = ()) -> "RepositoryPolicy":
        roots = tuple(dict.fromkeys(config.local_roots + tuple(allowed_roots)))
        return cls(config.analysis, allowed_roots=roots)