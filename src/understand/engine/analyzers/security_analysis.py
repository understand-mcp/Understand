"""Security analysis.

Two layers:

  1. PATTERN RULES - deterministic, language-scoped rules over sanitized source
     lines. Each rule declares what it proves, what it assumes and when it must
     downgrade confidence. Rules never assert a vulnerability on a name alone.

  2. FLOW RULES - data-flow driven findings built from the taint engine: a
     source-to-sink path whose hops are all proven becomes a high-confidence
     finding; any inferred hop downgrades it and the reasoning is recorded.

No exploit payloads are generated and no CVE/CVSS value is ever invented.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from understand.engine.analyzers.base import AnalysisContext
from understand.engine.data_flow import (  # noqa: F401 - re-exported constants
    SINK_RULES,
    SRC_RULES,
    VAL_RULES,
)
from understand.models import (
    Check,
    Confidence,
    Evidence,
    EvidenceKind,
    Finding,
    Severity,
    VerificationStatus,
)
from understand.security.redaction import looks_like_secret, redact_snippet

SEVERITY_CONVENTION = (
    "Severity uses a custom 5-level convention aligned with common practice: "
    "critical (remote code execution or auth bypass with minimal preconditions), "
    "high (data exfiltration or privilege impact with realistic preconditions), "
    "medium (impact requiring specific conditions or a non-default configuration), "
    "low (defence-in-depth weakness), info (hardening observation). No CVSS score "
    "is computed because UNDERSTAND does not model full exploitability."
)


@dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    category: str
    pattern: re.Pattern[str]
    languages: tuple[str, ...]
    severity: Severity
    confidence: Confidence
    explanation: str
    impact: str
    remediation: str
    assumptions: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    exclude_context: tuple[re.Pattern[str], ...] = ()
    deep_only: bool = False


def _r(*parts: str) -> re.Pattern[str]:
    return re.compile("|".join(parts))


RULES: tuple[Rule, ...] = (
    # ------------------------------------------------------------ injection
    Rule(
        rule_id="SEC-PY-SHELL-001",
        title="Shell command built from non-constant input",
        category="command-injection",
        pattern=_r(r"\bsubprocess\s*\.\s*(?:run|call|check_output|check_call|Popen)\s*\(",
                   r"\bos\s*\.\s*system\s*\(", r"\bos\s*\.\s*popen\s*\("),
        languages=("python",),
        severity=Severity.CRITICAL,
        confidence=Confidence.MEDIUM,
        explanation=(
            "A process is spawned through the shell-oriented API family. If any argument "
            "originates outside the module constants it can be used to inject additional "
            "shell syntax. The pattern alone does not prove injection: constant argument "
            "lists and argv-array invocation are safe."
        ),
        impact="Arbitrary command execution with the privileges of the process.",
        remediation=(
            "Pass an explicit argument list with shell=False, validate every interpolated "
            "value against an allow-list, and avoid invoking a shell for the operation."
        ),
        assumptions=("The interpreter reaches this call with attacker-influenceable data.",),
        references=("https://cwe.mitre.org/data/definitions/78.html",),
    ),
    Rule(
        rule_id="SEC-JS-SHELL-001",
        title="Shell command execution API used",
        category="command-injection",
        pattern=_r(r"child_process\s*\.\s*(?:exec|execSync)\s*\(",
                   r"\bexec\s*\(\s*`", r"\brequire\s*\(\s*['\"]child_process['\"]"),
        languages=("javascript", "typescript"),
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        explanation=(
            "exec/execSync spawn a shell and concatenate their argument into a command "
            "string. Template literals and concatenation with request data are the usual "
            "injection vector."
        ),
        impact="Arbitrary command execution on the host running the Node process.",
        remediation="Use execFile/spawn with an argument array and validate inputs.",
        assumptions=("Some argument value is derived from a request or external source.",),
        references=("https://cwe.mitre.org/data/definitions/78.html",),
    ),
    Rule(
        rule_id="SEC-SQL-001",
        title="SQL query built by string interpolation",
        category="sql-injection",
        pattern=_r(r"(?:execute|query|raw|Query|Exec)\s*\(\s*(?:f['\"]|[^,)]*\+|[^,)]*\$\{)",
                   r"(?:SELECT|INSERT|UPDATE|DELETE)\b[^;]*?(?:%s|\{\}|\$\{|['\"]\s*\+)"),
        languages=("python", "javascript", "typescript", "php", "ruby", "java", "csharp", "go"),
        severity=Severity.CRITICAL,
        confidence=Confidence.MEDIUM,
        explanation=(
            "A SQL statement is assembled from non-constant text. If any fragment is "
            "externally controlled this permits SQL injection. Detection is syntactic; a "
            "constant query or a properly parameterised statement will not match."
        ),
        impact="Database read/write access, and often full database compromise.",
        remediation="Use parameterised queries / prepared statements and bind values.",
        assumptions=("An interpolated fragment is attacker-influenceable.",),
        references=("https://cwe.mitre.org/data/definitions/89.html",
                    "https://owasp.org/Top10/A03_2021-Injection/"),
    ),
    Rule(
        rule_id="SEC-PY-EVAL-001",
        title="Dynamic evaluation of non-literal code",
        category="code-injection",
        pattern=_r(
            r"\beval\s*\(",
            # A raw or byte string is still a literal, so ``exec(r"ls")`` is not
            # dynamic evaluation. The string PREFIX has to be excluded as well
            # as the quote: the character after ``(`` in ``re.compile(r"...")``
            # is ``r``, and a naive "must not be a quote" test matches it --
            # which made every regex table in this repository report itself as
            # a code-injection site before the rule was corrected.
            # "Is the whole argument one string literal?" A plain literal is a
            # quote, anything without a quote or a plus, the closing quote, and
            # then the closing paren. Testing only for a leading quote missed
            # ``exec("ls " + d)``, which is a concatenation and executes
            # exactly as much attacker code as a bare ``eval``.
            r"\bexec\s*\(\s*(?![rRbBuUfF]{0,2}['\"][^'+]*['\"]\s*\))",
            # ``compile`` is deliberately absent. ``re.compile`` is a regex
            # compiler; the builtin ``compile()`` only produces a code object
            # when its mode argument says exec/eval/single, and this pattern
            # cannot see arguments. The same trap is already handled in
            # ``data_flow.py``, where ``compile(`` is excluded for the same
            # reason.
            r"\b__import__\s*\(\s*(?![rRbBuUfF]{0,2}['\"][^'+]*['\"]\s*\))",
    ),
        languages=("python",),
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        explanation="eval/exec/__import__ on a computed string executes code in the current process.",
        impact="Arbitrary code execution.",
        remediation="Replace dynamic execution with an explicit dispatch table.",
        assumptions=("The evaluated string is not a fixed constant from the codebase.",),
        references=("https://cwe.mitre.org/data/definitions/95.html",),
    ),
    Rule(
        rule_id="SEC-PY-COMPILE-001",
        title="Code object built from a computed string",
        category="code-injection",
        # ``compile`` had to leave SEC-PY-EVAL-001 because the character after
        # ``(`` in ``re.compile(r"...")`` is the raw-string prefix and a naive
        # test matches it -- which made every regex table in this repository
        # report itself as a code-injection site. But builtin ``compile`` with
        # an exec/eval/single mode DOES build a code object, so dropping it
        # silently was a hole. It gets its own rule, keyed on the mode
        # argument, with lookbehinds so a regex module never matches.
        pattern=_r(r"(?<![A-Za-z0-9_.])(?<!re\.)(?<!regex\.)compile\s*\([^)]*['\"](?:exec|eval|single)['\"]"),
        languages=("python",),
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        explanation="compile() with an exec, eval or single mode builds a code object from a string.",
        impact="A code object built from a computed string can be executed later with arbitrary effect.",
        remediation="Build the function from a fixed table of allowed code, not from a string.",
        references=("https://cwe.mitre.org/data/definitions/95.html",),
    ),
    Rule(
        rule_id="SEC-PY-PICKLE-001",
        title="Unsafe deserialization with pickle",
        category="deserialization",
        pattern=_r(r"\bpickle\s*\.\s*loads?\s*\(", r"\bmarshal\s*\.\s*loads?\s*\(",
                   r"\bdill\s*\.\s*loads?\s*\(", r"\byaml\s*\.\s*load\s*\((?![^)]*Loader)"),
        languages=("python",),
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        explanation=(
            "pickle/marshal/dill reconstruct arbitrary Python objects and execute their "
            "__reduce__ hook. yaml.load without an explicit safe Loader is equivalent."
        ),
        impact="Arbitrary code execution when the payload is attacker controlled.",
        remediation="Use json, or yaml.safe_load, and never unpickle untrusted input.",
        assumptions=("The serialized data can originate outside the trust boundary.",),
        references=("https://cwe.mitre.org/data/definitions/502.html",),
    ),
    Rule(
        rule_id="SEC-PY-PATH-001",
        title="Filesystem path built from unvalidated input",
        category="path-traversal",
        pattern=_r(r"os\s*\.\s*path\s*\.\s*join\s*\(\s*[^)]{0,200}?\b(?:request|args|params|input|body|query)\b"),
        languages=("python",),
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        explanation=(
            "A path is composed from request-derived data. Without normalisation and a "
            "containment check against an allowed root, '../' sequences escape the "
            "intended directory."
        ),
        impact="Arbitrary file read or write outside the intended directory.",
        remediation=(
            "Resolve the candidate path and assert it is inside an allowed root "
            "(os.path.realpath + Path.is_relative_to) before opening it."
        ),
        assumptions=("No effective containment check exists later in the function.",),
        references=("https://cwe.mitre.org/data/definitions/22.html",),
    ),
    Rule(
        rule_id="SEC-PY-SSRF-001",
        title="Outbound request with request-derived URL",
        category="ssrf",
        pattern=_r(r"requests\s*\.\s*(?:get|post|put|delete|head)\s*\(\s*(?:f['\"]|[^,)]*%)",
                   r"httpx\s*\.\s*(?:get|post)\s*\(\s*(?:f['\"]|[^,)]*%)"),
        languages=("python",),
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        explanation=(
            "The destination URL is composed from data. If that data is externally "
            "controlled, the server can be induced to reach internal services or "
            "cloud metadata endpoints."
        ),
        impact="Internal network reconnaissance, credential theft via metadata services.",
        remediation=(
            "Parse the URL, require an https scheme, resolve the host and reject private, "
            "loopback, link-local and metadata ranges, and pin the final connection address."
        ),
        assumptions=("The URL host is not restricted to an allow-list elsewhere.",),
        references=("https://cwe.mitre.org/data/definitions/918.html",),
    ),
    Rule(
        rule_id="SEC-JS-XSS-001",
        title="Unescaped HTML sink",
        category="cross-site-scripting",
        pattern=_r(r"\.\s*innerHTML\s*=", r"dangerouslySetInnerHTML", r"document\s*\.\s*write\s*\(",
                   r"\|\s*safe\b"),
        languages=("javascript", "typescript"),
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        explanation=(
            "HTML is assigned without escaping. When the value contains externally "
            "supplied markup this becomes reflected or stored XSS."
        ),
        impact="Script execution in the victim's origin; session theft, UI redress.",
        remediation="Use textContent, or sanitise with a vetted HTML sanitiser first.",
        # The precondition already says the value must be attacker-controlled.
        # Repeating it here as an "assumption" produced two identical blocks in
        # the report, and the one that matters — that no untrusted input was
        # traced to this assignment — is the thing this rule genuinely did not
        # establish.
        assumptions=(
            "No untrusted input was traced to this assignment. The rule matched the "
            "sink construct; it did not prove attacker reachability, so this is a "
            "place where dangerous markup could be assigned, not a demonstrated XSS.",
        ),
        references=("https://cwe.mitre.org/data/definitions/79.html",),
    ),
    Rule(
        rule_id="SEC-TEMPLATE-001",
        title="Server-side template built from a string",
        category="template-injection",
        pattern=_r(r"render_template_string\s*\(", r"Template\s*\(\s*f['\"]",
                   r"new\s+Template\s*\([^)]*\+"),
        languages=("python", "javascript", "typescript", "go", "java", "csharp"),
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        explanation=(
            "A template is compiled from a runtime string rather than a static file, so "
            "template syntax in user input may be evaluated."
        ),
        impact="Server-side template injection leading to code execution.",
        remediation="Render from static templates and pass data as context variables.",
        assumptions=("The template string includes non-constant content.",),
        references=("https://cwe.mitre.org/data/definitions/1336.html",),
    ),
    Rule(
        rule_id="SEC-PY-ASSERT-001",
        title="assert used for security-relevant validation",
        category="improper-validation",
        pattern=_r(r"^\s*assert\s+"),
        languages=("python",),
        severity=Severity.MEDIUM,
        confidence=Confidence.LOW,
        explanation=(
            "assert statements are removed when Python runs with -O / PYTHONOPTIMIZE, so "
            "any security check implemented with assert silently disappears in production."
        ),
        impact="Validation bypass in optimized deployments.",
        remediation="Raise an explicit exception instead of asserting.",
        assumptions=("The assertion enforces a security or correctness invariant.",),
        references=("https://cwe.mitre.org/data/definitions/617.html",),
    ),
    Rule(
        rule_id="SEC-REDIRECT-001",
        title="Redirect target taken from request data",
        category="open-redirect",
        pattern=_r(r"(?:sendRedirect|redirect\s*\(|RedirectResponse\s*\()\s*\(\s*(?:f['\"]|request|req\.|params|[^,)]*\+)"),
        languages=("java", "python", "javascript", "typescript", "php", "csharp", "go", "ruby"),
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        explanation="A redirect target derived from input can send users to an attacker site.",
        impact="Credential phishing via an apparently trusted origin.",
        remediation="Allow-list redirect targets or use opaque relative paths.",
        assumptions=("The redirect parameter is externally controlled.",),
        references=("https://cwe.mitre.org/data/definitions/601.html",),
    ),
    # ------------------------------------------------------------ crypto/secrets
    Rule(
        rule_id="SEC-CRYPTO-WEAK-001",
        title="Weak or non-cryptographic algorithm used",
        category="weak-crypto",
        pattern=_r(r"hashlib\s*\.\s*(?:md5|sha1)\s*\(", r"\bMD5\s*\.\s*new\s*\(",
                   r"\bSHA1\s*\(", r"\bDES\b|\bRC4\b", r"createHash\s*\(\s*['\"](?:md5|sha1)['\"]",
                   r"MD5\s*\.\s*(?:Create|ComputeHash)"),
        languages=("python", "javascript", "typescript", "java", "csharp", "php", "go", "ruby"),
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        explanation=(
            "MD5/SHA-1 are collision-broken and unsuitable for signatures, integrity or "
            "password hashing. Non-cryptographic RNGs are unsuitable for tokens."
        ),
        impact="Forged tokens or signatures; predictable secrets.",
        remediation="Use SHA-256+ for digests, bcrypt/scrypt/argon2 for passwords, secrets module for tokens.",
        references=("https://cwe.mitre.org/data/definitions/327.html",
                    "https://cwe.mitre.org/data/definitions/338.html"),
    ),
    Rule(
        rule_id="SEC-RAND-001",
        title="Non-cryptographic randomness for security value",
        category="weak-randomness",
        pattern=_r(r"\brandom\s*\.\s*(?:random|randint|choice|randrange)\s*\([^)]*\)\s*\)?\s*(?:#.*)?$",
                   r"Math\s*\.\s*random\s*\("),
        languages=("python", "javascript", "typescript"),
        severity=Severity.LOW,
        confidence=Confidence.LOW,
        explanation=(
            "Predictable randomness must not be used for session identifiers, reset tokens "
            "or nonces. The pattern is reported with low confidence because legitimate "
            "non-security uses are extremely common."
        ),
        impact="Token prediction if the value is a security control.",
        remediation="Use os.urandom / secrets.token_* / crypto.getRandomValues.",
        references=("https://cwe.mitre.org/data/definitions/338.html",),
        assumptions=("The generated value is a security-relevant token.",),
    ),
    Rule(
        rule_id="SEC-TLS-001",
        title="TLS certificate verification disabled",
        category="insecure-transport",
        pattern=_r(r"verify\s*=\s*False", r"rejectUnauthorized\s*:\s*false",
                   r"InsecureSkipVerify\s*:\s*true", r"CURLOPT_SSL_VERIFYPEER\s*,\s*(?:0|false)",
                   r"ssl\._create_unverified_context", r"NODE_TLS_REJECT_UNAUTHORIZED"),
        languages=("python", "javascript", "typescript", "go", "java", "csharp", "php"),
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        explanation="Certificate verification is switched off, enabling machine-in-the-middle attacks.",
        impact="Trivial interception and modification of TLS traffic.",
        remediation="Leave verification enabled; pin a private CA certificate if required.",
        references=("https://cwe.mitre.org/data/definitions/295.html",),
    ),
    Rule(
        rule_id="SEC-WEB-DEBUG-001",
        title="Debug mode enabled in a shipped application",
        category="insecure-configuration",
        pattern=_r(r"^\s*DEBUG\s*=\s*True", r"app\.run\s*\([^)]*debug\s*=\s*True",
                   r"FastAPI\s*\([^)]*debug\s*=\s*True"),
        languages=("python",),
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        explanation=(
            "Debug/traceback exposure commonly leaks stack traces, configuration and "
            "internal paths to unauthenticated clients."
        ),
        impact="Information disclosure; in some frameworks an interactive code console is exposed.",
        remediation="Drive DEBUG from the environment and default it to False.",
        references=("https://cwe.mitre.org/data/definitions/489.html",),
    ),
    Rule(
        rule_id="SEC-CORS-001",
        title="Wildcard CORS policy",
        category="insecure-configuration",
        pattern=_r(r"Access-Control-Allow-Origin['\"]?\s*[:,]\s*['\"]?\*",
                   r"origin\s*:\s*['\"]\*['\"]", r"AllowAnyOrigin\s*\("),
        languages=("python", "javascript", "typescript", "java", "csharp", "go", "php"),
        severity=Severity.MEDIUM,
        confidence=Confidence.LOW,
        explanation=(
            "A wildcard origin lets any site read authenticated responses. Confidence is "
            "low because the combination with credentials is what makes it exploitable."
        ),
        impact="Cross-origin data theft when credentials are also allowed.",
        remediation="Allow-list specific origins and never combine '*' with credentials.",
        references=("https://developer.mozilla.org/docs/Web/HTTP/CORS",),
        assumptions=("Credentialed cross-origin requests are accepted.",),
    ),
    Rule(
        rule_id="SEC-COOKIE-001",
        title="Cookie security attributes missing",
        category="session-management",
        pattern=_r(r"(?:set_cookie|SESSION_COOKIE_)\w*\s*\([^)]*\)"),
        languages=("python", "javascript", "typescript"),
        severity=Severity.MEDIUM,
        confidence=Confidence.LOW,
        explanation=(
            "Cookie issuance without HttpOnly/Secure/SameSite weakens session protection "
            "against XSS theft and CSRF."
        ),
        impact="Session hijacking via script access or cross-site requests.",
        remediation="Set HttpOnly, Secure and SameSite=Lax/Strict on session cookies.",
        references=("https://cwe.mitre.org/data/definitions/1004.html",),
    ),
    # ------------------------------------------------------------- resources
    Rule(
        rule_id="SEC-TEMPFILE-001",
        title="Insecure temporary file creation",
        category="insecure-tempfile",
        pattern=_r(r"\bmktemp\s*\(", r"tempfile\s*\.\s*mktemp\s*\("),
        languages=("python", "javascript", "typescript", "ruby", "shell"),
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        explanation=(
            "Predictable temporary paths are vulnerable to symlink races, allowing an "
            "attacker to read or overwrite the file."
        ),
        impact="Local information disclosure or file overwrite.",
        remediation="Use tempfile.NamedTemporaryFile / mkstemp / mkdtemp with restrictive modes.",
        references=("https://cwe.mitre.org/data/definitions/377.html",),
    ),
    Rule(
        rule_id="SEC-DOCKER-001",
        title="Container runs as root",
        category="container-hardening",
        pattern=_r(r"^\s*USER\s+root\s*$"),
        languages=("dockerfile",),
        severity=Severity.LOW,
        confidence=Confidence.MEDIUM,
        explanation="Running the container workload as root removes a privilege boundary layer.",
        impact="Container escape becomes a full root compromise on the host namespace.",
        remediation="Add a non-root USER and use --read-only / --cap-drop where possible.",
        references=("https://cwe.mitre.org/data/definitions/250.html",),
    ),
)

# Rules applied to configuration / infra text regardless of extension.
CONFIG_RULES: tuple[Rule, ...] = (
    Rule(
        rule_id="SEC-CONFIG-SECRET-001",
        title="Secret-like value assigned in configuration",
        category="hardcoded-secret",
        pattern=re.compile(r"(?i)\b(password|passwd|secret|api[_-]?key|access[_-]?token|"
                           r"auth[_-]?token|client[_-]?secret|private[_-]?key)\b\s*[:=]"),
        languages=("yaml", "json", "toml", "text", "python", "javascript", "typescript", "shell", "go"),
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        explanation=(
            "A credential-shaped key is assigned a literal value in a tracked file. The "
            "value is redacted in this report; the location is what matters."
        ),
        impact="Credential disclosure via source control.",
        remediation="Move the value to a secret manager or environment variable and rotate it.",
        references=("https://cwe.mitre.org/data/definitions/798.html",),
        assumptions=("The value is not a placeholder or example.",),
    ),
)


@dataclass
class RuleMatch:
    rule: Rule
    file: str
    line_no: int
    text: str
    symbol: str


def _applicable(rule: Rule, language: str) -> bool:
    return not rule.languages or language in rule.languages


def run_rules(ctx: AnalysisContext) -> list[RuleMatch]:
    matches: list[RuleMatch] = []
    for path, module in sorted(ctx.index.modules.items()):
        for lineno in range(1, len(module.lines) + 1):
            text = module.dirty_lines.get(lineno, module.line(lineno))
            raw = module.line(lineno)
            if not raw.strip():
                continue
            for rule in RULES:
                if not _applicable(rule, module.language):
                    continue
                if rule.deep_only and not ctx.deep:
                    continue
                m = rule.pattern.search(text)
                if not m:
                    continue
                if any(ex.search(text) for ex in rule.exclude_context):
                    continue
                matches.append(RuleMatch(rule, path, lineno, raw.strip(), _scope(ctx, path, lineno)))
        for rule in CONFIG_RULES:
            if not _applicable(rule, module.language):
                continue
            for lineno, literals in (module.literals or {}).items():
                for key, value in literals.items():
                    if not rule.pattern.search(f"{key}="):
                        continue
                    if _is_placeholder(value):
                        continue
                    matches.append(RuleMatch(rule, path, lineno, f"{key} = <redacted>",
                                             _scope(ctx, path, lineno)))
    return matches


_PLACEHOLDER_HINTS = (
    "example", "changeme", "change-me", "your-", "your_", "placeholder", "dummy", "sample",
    "xxx", "<", "redacted", "todo", "none", "null", "test", "fake", "localhost",
    "s3cr3t", "notarealkey", "12345678", "abcdef", "insert", "replace",
)


def _is_placeholder(value: str) -> bool:
    v = value.strip().lower()
    if not v:
        return True
    if any(h in v for h in _PLACEHOLDER_HINTS):
        return True
    if v.startswith(("$", "{{", "%(", "env:", "os.environ", "${")):
        return True
    if value.strip().startswith(("<", "{")) and value.strip().endswith(("}", ">")):
        return True
    if re.fullmatch(r"[\*x\.\-]+", v):
        return True
    return not looks_like_secret(value) and len(v) < 12


def _scope(ctx: AnalysisContext, path: str, lineno: int) -> str:
    module = ctx.index.modules.get(path)
    if module is None:
        return ""
    best = ""
    best_span = 10**9
    for sym in module.symbols:
        if sym.start_line <= lineno <= sym.end_line:
            span = sym.end_line - sym.start_line
            if span < best_span:
                best, best_span = sym.id, span
    return best


def build_findings(matches: list[RuleMatch], ctx: AnalysisContext) -> list[Finding]:
    findings: list[Finding] = []
    for match in matches:
        rule = match.rule
        confidence = rule.confidence
        status = VerificationStatus.STATIC_EVIDENCE
        assumptions = list(rule.assumptions)
        # Strengthen when the surrounding symbol actually receives a source and
        # performs no validation; downgrade when validation is present nearby.
        validated_nearby = _validated_nearby(ctx, match)
        if validated_nearby:
            confidence = Confidence.LOW if confidence is Confidence.MEDIUM else confidence
            assumptions.append(
                f"Validation or escaping appears near this line ({validated_nearby}); "
                "review whether it actually covers this path."
            )
        if ctx.deep and confidence is Confidence.MEDIUM:
            status = VerificationStatus.CROSS_MODULE_TRACE
        finding = Finding(
            title=rule.title,
            category=rule.category,
            rule_id=rule.rule_id,
            severity=rule.severity,
            confidence=confidence,
            verification_status=status,
            summary=rule.title,
            technical_explanation=rule.explanation,
            evidence=[
                Evidence(kind=EvidenceKind.SOURCE_RANGE, file=match.file,
                         start_line=match.line_no, end_line=match.line_no,
                         symbol=match.symbol.split("::")[-1] if match.symbol else "",
                         snippet=redact_snippet(match.text),
                         note=f"rule {rule.rule_id}")
            ],
            affected_symbols=[match.symbol] if match.symbol else [],
            assumptions=assumptions,
            preconditions=list(assumptions),
            impact=rule.impact,
            remediation=rule.remediation,
            references=list(rule.references),
            analysis_method="pattern rule over sanitized source lines",
            language=ctx.index.modules[match.file].language if match.file in ctx.index.modules else "unknown",
            fingerprint=f"{match.file}:{match.line_no}:{rule.rule_id}",
            confidence_rationale=(
                f"Rule {rule.rule_id} matched a documented source construct at "
                f"{match.file}:{match.line_no}; severity {rule.severity.value}, "
                f"confidence {confidence.value}."
            ),
        )
        findings.append(finding)
    return findings


def _validated_nearby(ctx: AnalysisContext, match: RuleMatch) -> str:
    module = ctx.index.modules.get(match.file)
    if module is None:
        return ""
    lo = max(1, match.line_no - 25)
    hi = min(len(module.lines), match.line_no + 15)
    hits: list[str] = []
    for name, pat in VAL_RULES:
        for lineno in range(lo, hi + 1):
            text = module.dirty_lines.get(lineno, module.line(lineno))
            if text and pat.search(text):
                hits.append(f"{name}@{lineno}")
    return ", ".join(sorted(set(hits))[:4])


# --------------------------------------------------------------------------- flow findings

FLOW_SEVERITY = {
    "sql-exec": Severity.CRITICAL,
    "shell-exec": Severity.CRITICAL,
    "eval": Severity.CRITICAL,
    "deserialize": Severity.CRITICAL,
    "path-join": Severity.HIGH,
    "file-write": Severity.HIGH,
    "render-html": Severity.HIGH,
    "http-send": Severity.HIGH,
    "redirect": Severity.MEDIUM,
    "crypto-weak": Severity.MEDIUM,
    "tls-off": Severity.HIGH,
    "tempfile-insecure": Severity.MEDIUM,
}

# A flow whose source could not be attributed to an untrusted input is one
# step less severe. It is still worth a human's time — the value does reach a
# dangerous sink — but it is not a demonstrated vulnerability.
FLOW_SEVERITY_DOWNGRADE = {
    Severity.CRITICAL: Severity.HIGH,
    Severity.HIGH: Severity.MEDIUM,
    Severity.MEDIUM: Severity.LOW,
    Severity.LOW: Severity.INFO,
}

# Source kinds that mean "an attacker may control this". Anything else
# (a function parameter, or a value whose origin could not be tied to a
# source line at all) is propagation without proven attacker control.
_UNATTRIBUTED_SOURCE_KINDS = frozenset({"parameter", "unknown", "unknown-origin"})

FLOW_CATEGORY = {
    "sql-exec": "sql-injection",
    "shell-exec": "command-injection",
    "eval": "code-injection",
    "deserialize": "deserialization",
    "path-join": "path-traversal",
    "file-write": "insecure-file-operation",
    "render-html": "cross-site-scripting",
    "http-send": "ssrf",
    "redirect": "open-redirect",
    "crypto-weak": "weak-crypto",
    "tls-off": "insecure-transport",
    "tempfile-insecure": "insecure-tempfile",
}

FLOW_REMEDIATION = {
    "sql-exec": "Use a parameterised query and bind the value.",
    "shell-exec": "Use an argument array with shell disabled and validate each argument.",
    "eval": "Replace dynamic evaluation with an explicit dispatch table.",
    "deserialize": "Use a safe deserialiser (json, yaml.safe_load) that cannot execute code.",
    "path-join": "Resolve the path and assert containment inside an allowed root.",
    "file-write": "Validate and normalise the path; restrict writes to a dedicated directory.",
    "render-html": "Escape the value or sanitise the markup before rendering.",
    "http-send": "Validate the host against an allow-list and reject private ranges.",
    "redirect": "Allow-list redirect targets.",
    "crypto-weak": "Use a modern hash and a CSPRNG.",
    "tls-off": "Enable certificate verification.",
    "tempfile-insecure": "Use tempfile.mkstemp / NamedTemporaryFile.",
}


def _hop_role(hop, flow) -> str:
    if hop.file == flow.sink_file and hop.line == flow.sink_line:
        return f"sink: {hop.label} ({hop.origin})"
    if hop.file == flow.source_file and hop.line == flow.source_line:
        return f"source: {hop.label} ({hop.origin})"
    return f"propagation: {hop.label} ({hop.origin})"


def build_flow_findings(ctx: AnalysisContext) -> list[Finding]:
    """Turn data-flow paths into findings with their full evidence trail."""
    findings: list[Finding] = []
    for flow in ctx.data_flows:
        kind = flow.sink_kind
        if kind not in FLOW_SEVERITY:
            continue
        proven = flow.proven
        confidence = Confidence.HIGH if proven else Confidence.MEDIUM
        severity = FLOW_SEVERITY[kind]
        status = (
            VerificationStatus.CROSS_MODULE_TRACE
            if flow.cross_module
            else VerificationStatus.STATIC_EVIDENCE
        )
        # A value that entered as a function parameter, or whose origin could
        # not be tied to a source line at all, is not evidence of an
        # *untrusted* input. Reporting it at flow severity with a confident
        # source description is how "parameter 'outputFile' reaches file write"
        # was previously dressed up as "environment variable reaches
        # filesystem path construction". Such a flow is kept — it is real
        # propagation — but it is downgraded and marked inconclusive, because
        # proving reachability from an attacker is exactly the missing step.
        attributed = flow.source_kind not in _UNATTRIBUTED_SOURCE_KINDS
        if not attributed:
            severity = FLOW_SEVERITY_DOWNGRADE.get(severity, Severity.LOW)
            confidence = Confidence.LOW
            status = VerificationStatus.INCONCLUSIVE
        evidence = [
            Evidence(
                kind=EvidenceKind.DATA_FLOW,
                file=hop.file,
                start_line=hop.line,
                end_line=hop.line,
                symbol=hop.symbol,
                snippet=redact_snippet(hop.text),
                note=_hop_role(hop, flow),
            )
            for hop in flow.hops[-12:]
        ]
        if flow.hops:
            evidence.reverse()
        unresolved = list(flow.unresolved_hops)
        assumptions = []
        if not proven:
            assumptions.append(
                "At least one hop is inferred (positional parameter matching, "
                "name heuristic, or a structurally-parsed module), so the path requires "
                "manual verification."
            )
        if not attributed:
            assumptions.append(
                f"The origin is {flow.source_description}: the engine found propagation to "
                f"{flow.sink_description} but could not tie the value back to a line that "
                "reads untrusted input. Severity was reduced accordingly. Treat this as a "
                "suspicious path to review, not as a demonstrated vulnerability."
            )
        assumptions.extend(unresolved[:5])
        finding = Finding(
            title=f"{flow.source_description} reaches {flow.sink_description}",
            category=FLOW_CATEGORY.get(kind, "unsafe-data-flow"),
            rule_id="SEC-FLOW-001",
            severity=severity,
            confidence=confidence,
            verification_status=status,
            summary=(
                f"Data from {flow.source_description} reaches {flow.sink_description} "
                f"at {flow.sink_file}:{flow.sink_line}."
            ),
            technical_explanation=(
                f"The taint engine propagated {flow.source_kind} from "
                f"{flow.source_file}:{flow.source_line} to {flow.sink_file}:{flow.sink_line} "
                f"in {len(flow.hops)} hop(s). Proven={proven}; cross_module={flow.cross_module}. "
                + ("Unresolved hops: " + ", ".join(unresolved[:8]) if unresolved else
                   "No unresolved dynamic hops were recorded on this path.")
            ),
            evidence=evidence,
            affected_symbols=[h.symbol for h in flow.hops if h.symbol][:8],
            call_chains=[[h.label for h in flow.hops]],
            data_flows=[[h.label for h in flow.hops]],
            assumptions=assumptions,
            preconditions=["The source is reachable by an untrusted actor."],
            impact=f"Reachability of {flow.sink_description} with attacker-influenced data.",
            remediation=FLOW_REMEDIATION.get(kind, "Validate and encode the value at the sink."),
            references=["https://cwe.mitre.org/data/definitions/20.html"],
            analysis_method="interprocedural taint analysis over the call graph",
            fingerprint=f"flow:{flow.source_file}:{flow.source_line}:{flow.sink_file}:{flow.sink_line}:{kind}",
            confidence_rationale=(
                f"provenance={'proven' if proven else 'inferred'}; "
                f"hops={len(flow.hops)}; unresolved={len(unresolved)}"
            ),
        )
        findings.append(finding)
    return findings


class SecurityAnalyzer:
    name = "security"
    check = Check.SECURITY
    applies_to = ("*",)

    def run(self, ctx: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(build_findings(run_rules(ctx), ctx))
        if ctx.deep or ctx.cross_module:
            findings.extend(build_flow_findings(ctx))
        return findings
