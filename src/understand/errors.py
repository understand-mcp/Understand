"""Application error hierarchy with stable, machine-readable codes."""

from __future__ import annotations


class UnderstandError(Exception):
    """Base class. Every error carries a stable code for CLI/MCP consumers."""

    code = "internal_error"
    exit_code = 1

    def __init__(self, message: str, *, detail: object | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.detail = detail

    def to_dict(self) -> dict[str, object]:
        out: dict[str, object] = {"code": self.code, "message": self.message}
        if self.detail is not None:
            out["detail"] = self.detail
        out["exit_code"] = self.exit_code
        return out



class ConfigurationError(UnderstandError):
    code = "configuration_error"
    exit_code = 78


class InvalidSourceError(UnderstandError):
    """The SOURCE argument is unusable (bad path, bad URL, unsupported scheme)."""

    code = "invalid_source"
    exit_code = 65


class AccessDeniedError(UnderstandError):
    """The requested location is outside the authorized roots / blocked by policy."""

    code = "access_denied"
    exit_code = 77


class NetworkPolicyError(UnderstandError):
    code = "network_policy"
    exit_code = 72


class AcquisitionError(UnderstandError):
    code = "acquisition_failed"
    exit_code = 69


class ResourceLimitExceeded(UnderstandError):
    code = "resource_limit_exceeded"
    exit_code = 70


class ScanCancelled(UnderstandError):
    code = "scan_cancelled"
    exit_code = 130


class ScanNotFound(UnderstandError):
    code = "scan_not_found"
    exit_code = 66


class FindingNotFound(UnderstandError):
    code = "finding_not_found"
    exit_code = 67


class UnsupportedFormatError(UnderstandError):
    code = "unsupported_format"
    exit_code = 63


class StorageError(UnderstandError):
    code = "storage_error"
    exit_code = 74


class AnalysisError(UnderstandError):
    code = "analysis_error"
    exit_code = 71


class ValidationError(UnderstandError):
    """Input schema validation failure surfaced to the caller."""

    code = "validation_error"
    exit_code = 64