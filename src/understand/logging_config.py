"""Structured logging. Logs always go to stderr so stdout stays machine-readable."""

from __future__ import annotations

import logging
import os
import sys

_CONFIGURED = False


class _RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        from understand.security.redaction import redact_text

        try:
            msg = record.getMessage()
        except Exception:  # pragma: no cover
            return True
        red = redact_text(msg)
        if red != msg:
            record.msg = red
            record.args = ()
        return True


def setup_logging(level: str = "INFO", *, stream=None) -> None:
    global _CONFIGURED
    root = logging.getLogger("understand")
    if _CONFIGURED:
        root.setLevel(getattr(logging, level.upper(), logging.INFO))
        return
    handler = logging.StreamHandler(stream or sys.stderr)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s", "%H:%M:%S"))
    handler.addFilter(_RedactingFilter())
    root.addHandler(handler)
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    root.propagate = False
    _CONFIGURED = True
    if os.environ.get("UNDERSTAND_DEBUG"):
        logging.getLogger("understand").setLevel(logging.DEBUG)


def get_logger(name: str) -> logging.Logger:
    if not _CONFIGURED:
        setup_logging(os.environ.get("UNDERSTAND_LOG_LEVEL", "INFO"))
    return logging.getLogger(f"understand.{name}")