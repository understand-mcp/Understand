"""Safe Git acquisition: URL validation, SSRF mitigation, bounded cloning.

Design rules enforced here:
  * Only https:// (and optionally ssh/git+ssh://) git URLs are accepted.
  * Credentials embedded in URLs are stripped, never logged, never forwarded.
  * Private / loopback / link-local / metadata destinations are rejected.
  * DNS is resolved and every resolved address is validated (rebinding defence),
    then re-validated for every redirect by disallowing redirects entirely.
  * git is executed with an explicit argv list, hooks disabled, no shell.
"""

from __future__ import annotations

import ipaddress
import os
import re
import shutil
import socket
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from understand.config import SecurityPolicy
from understand.errors import (
    AcquisitionError,
    NetworkPolicyError,
    ResourceLimitExceeded,
    ValidationError,
)

GIT_TIMEOUT_FLOOR = 5.0

# Well-known cloud metadata endpoints that must never be reachable.
METADATA_HOSTS = frozenset({
    "169.254.169.254",
    "metadata.google.internal",
    "metadata.goog",
    "instance-data",
    "100.100.100.200",
})

_ALLOWED_SCHEMES = {"https"}
_SSH_SCHEMES = {"ssh", "git+ssh"}

_HOST_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
_SCP_LIKE = re.compile(r"^(?:(?P<user>[A-Za-z0-9._-]+)@)?(?P<host>[^/:@]+):(?P<path>[^\s]+)$")


def _require_ssh(policy: SecurityPolicy, scheme: str) -> None:
    if not policy.allow_ssh:
        raise NetworkPolicyError(
            f"{scheme} remotes are disabled by policy (set security.allow_ssh=true to enable)"
        )


@dataclass(frozen=True)
class GitRemote:
    """A validated, credential-free remote git location."""

    original: str
    url: str            # credential-free URL, safe to log
    host: str
    path: str
    scheme: str

    @property
    def redacted_display(self) -> str:
        return self.url


def _is_prohibited_ip(ip: ipaddress._BaseAddress) -> bool:
    if isinstance(ip, ipaddress.IPv6Address):
        mapped = ip.ipv4_mapped
        if mapped is not None:
            return _is_prohibited_ip(mapped)
        if ip.sixtofour is not None:
            return _is_prohibited_ip(ip.sixtofour)
        if ip.teredo is not None:
            return _is_prohibited_ip(ip.teredo[1])
    return bool(
        ip.is_loopback
        or ip.is_private
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _validate_hostname(host: str) -> str:
    """Normalize and syntactically validate a remote host. Returns the host."""

    if not host or len(host) > 253:
        raise NetworkPolicyError(f"invalid remote host: {host!r}")
    if host in METADATA_HOSTS:
        raise NetworkPolicyError(f"destination {host!r} is a cloud metadata endpoint and is blocked")
    if host.endswith("."):
        host = host[:-1]
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    labels = host.lower().split(".")
    if len(labels) < 2:
        raise NetworkPolicyError(f"remote host must be a fully qualified name: {host!r}")
    for label in labels:
        if not _HOST_LABEL.match(label):
            raise NetworkPolicyError(f"invalid host label {label!r} in {host!r}")
    return host


def _resolve_and_check(host: str, policy: SecurityPolicy) -> list[str]:
    """Resolve the host and reject any prohibited address (DNS-rebinding defence)."""
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise NetworkPolicyError(f"cannot resolve host {host}: {exc}") from exc
    addrs = sorted({i[4][0] for i in infos})
    if not addrs:
        raise NetworkPolicyError(f"host {host} resolved to no addresses")
    if policy.block_private_networks:
        for a in addrs:
            ip = ipaddress.ip_address(a)
            if _is_prohibited_ip(ip):
                raise NetworkPolicyError(
                    f"host {host} resolves to prohibited address {a} "
                    "(loopback/private/link-local/metadata destinations are blocked)"
                )
    return addrs


def parse_git_url(raw: str, policy: SecurityPolicy) -> GitRemote:
    """Validate a remote git URL statically and return a credential-free GitRemote.

    Only static checks happen here, so validation is deterministic and needs no
    network. DNS resolution and the address checks that defend against rebinding
    run immediately before the clone, in :func:`clone_remote`.
    """
    text = raw.strip()
    if "\x00" in text or any(c.isspace() for c in text):
        raise NetworkPolicyError("remote URL must not contain whitespace or NUL bytes")
    if text.startswith("-"):
        raise NetworkPolicyError("remote URL must not start with '-' (argument injection guard)")

    parts = urlsplit(text)
    scheme = parts.scheme.lower()

    # scp-like syntax: [user@]host:path  (no scheme component)
    scp = _SCP_LIKE.match(text)
    if not scheme and scp is not None:
        scheme = "ssh"
        host = scp.group("host").lower()
        _require_ssh(policy, "ssh")
        _validate_hostname(host)
        path = "/" + scp.group("path").lstrip("/")
        return GitRemote(raw, f"ssh://{host}{path}", host, path, "ssh")

    if scheme in _SSH_SCHEMES:
        _require_ssh(policy, scheme)
        host = _validate_hostname((parts.hostname or "").lower())
        path = parts.path or "/"
        return GitRemote(raw, f"{scheme}://{host}{path}", host, path, scheme)

    if scheme not in _ALLOWED_SCHEMES:
        if scheme == "http":
            raise NetworkPolicyError("plain http:// remotes are refused; use https://")
        raise NetworkPolicyError(
            f"unsupported remote scheme {parts.scheme or '(none)'!r}; "
            "expected https://, ssh:// or git+ssh:// (ssh disabled by default)"
        )

    if parts.username or parts.password:
        raise NetworkPolicyError(
            "credentials embedded in the URL are rejected; use a credential helper or SSH agent"
        )

    host = _validate_hostname((parts.hostname or "").lower())
    if policy.allowed_hosts and host not in {h.lower() for h in policy.allowed_hosts}:
        raise NetworkPolicyError(f"host {host!r} is not in the configured outbound allowlist")

    # A literal address never needs DNS, so it can be judged right here.
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None and policy.block_private_networks and _is_prohibited_ip(literal):
        raise NetworkPolicyError(
            f"remote {host!r} is a loopback/private/link-local address and is blocked"
        )

    path = parts.path.rstrip("/")
    if not path or path == "/" or (path.endswith(".git") and len(path) <= 4):
        raise NetworkPolicyError("remote URL must point at a repository, not a host root")
    if len(path) > 512:
        raise NetworkPolicyError("remote URL path is unreasonably long")

    clean = urlunsplit(("https", host, path, "", ""))
    return GitRemote(raw, clean, host, path, "https")


def looks_like_remote(source: str) -> bool:
    s = source.strip().lower()
    return s.startswith(("http://", "https://", "ssh://", "git+ssh://", "git://", "www."))


def is_git_repo(path: Path) -> bool:
    return (path / ".git").exists() or (path / "HEAD").exists()


def _git_executable() -> str:
    exe = os.environ.get("UNDERSTAND_GIT") or shutil.which("git")
    if not exe:
        raise AcquisitionError(
            "git executable not found; remote repository scanning requires git on PATH"
        )
    return exe


def _run_git(args: list[str], cwd: Path, timeout: float, env: dict[str, str]) -> str:
    exe = _git_executable()
    if not exe:
        raise ValidationError("git executable is unavailable; remote scanning requires git on PATH")
    try:
        proc = subprocess.run(
            [exe, *args],
            cwd=str(cwd),
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ResourceLimitExceeded(f"git {args[0]} timed out after {timeout:.0f}s") from exc
    except OSError as exc:
        raise AcquisitionError(f"failed to execute git: {exc}") from exc
    if proc.returncode != 0:
        msg = (proc.stderr or proc.stdout or "").strip()
        msg = msg.replace("\n", " ")[:400]
        raise AcquisitionError(f"git {args[0]} failed with exit code {proc.returncode}: {msg}")
    return proc.stdout.strip()


def _safe_git_env(allow_private: bool = False) -> dict[str, str]:
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": os.environ.get("HOME", tempfile.gettempdir()),
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "echo",
        "GCM_INTERACTIVE": "never",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "LC_ALL": "C",
    }
    if os.name == "nt":
        for k in ("SYSTEMROOT", "SystemRoot", "TEMP", "TMP", "USERPROFILE", "APPDATA", "LOCALAPPDATA"):
            if k in os.environ:
                env[k] = os.environ[k]
    if allow_private:
        # Credentials may only come from an explicitly configured helper.
        for k in ("GIT_ASKPASS", "SSH_ASKPASS"):
            if k in os.environ:
                env[k] = os.environ[k]
    return env


def clone_remote(remote: GitRemote, policy: SecurityPolicy, dest: Path) -> dict[str, str]:
    """Shallow-clone a validated remote into `dest`. Returns git metadata."""
    if not _git_executable():
        raise ValidationError(
            "git executable is unavailable; remote scanning requires git on PATH",
            detail={"remote": remote.host},
        )
    # Resolve and vet the destination address right before connecting, so a name
    # that changed answer between validation and clone cannot reach a private host.
    _resolve_and_check(remote.host, policy)
    timeout = max(policy.clone_timeout_seconds, GIT_TIMEOUT_FLOOR)
    env = _safe_git_env(policy.allow_private_repo_credentials)
    base = [
        "-c", "protocol.ext.allow=never",
        "-c", "protocol.file.allow=never",
        "-c", "core.hooksPath=" + os.devnull,
        "-c", "advice.detachedHead=false",
        "-c", "credential.helper=",
        "-c", "http.followRedirects=false",
        "-c", "fetch.fsckObjects=true",
    ]
    args = [*base, "clone", "--depth", str(max(1, policy.clone_depth)), "--no-tags",
            "--config", f"core.hooksPath={os.devnull}", "--quiet", remote.url, str(dest)]
    if not policy.recurse_submodules:
        args.insert(-1, "--no-recurse-submodules")
    _run_git(args, cwd=dest.parent, timeout=timeout, env=env)

    meta: dict[str, str] = {}
    try:
        meta["revision"] = _run_git(
            [*base, "rev-parse", "HEAD"], cwd=dest, timeout=timeout, env=env
        )
    except (AcquisitionError, ResourceLimitExceeded):
        meta["revision"] = ""
    return meta


def local_git_metadata(root: Path) -> dict[str, str]:
    """Read revision info from a local repository without running any repo code."""
    if not is_git_repo(root):
        return {}
    try:
        exe = shutil.which("git")
        if not exe:
            return {}
        env = {
            "PATH": os.environ.get("PATH", ""),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "LC_ALL": "C",
        }
        if os.name == "nt":
            for k in ("SYSTEMROOT", "SystemRoot", "TEMP", "TMP"):
                if k in os.environ:
                    env[k] = os.environ[k]

        def run(a: list[str]) -> str:
            p = subprocess.run([exe, *a], cwd=str(root), env=env, capture_output=True,
                               text=True, timeout=10, shell=False, check=False)
            return p.stdout.strip() if p.returncode == 0 else ""

        return {
            "revision": run(["rev-parse", "HEAD"]),
            "branch": run(["rev-parse", "--abbrev-ref", "HEAD"]),
            "remote": run(["config", "--get", "remote.origin.url"]),
        }
    except (OSError, subprocess.SubprocessError):
        return {}
