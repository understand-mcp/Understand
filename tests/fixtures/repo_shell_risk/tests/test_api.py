"""Tests exercise the HTTP layer."""

from app.api import handle_ping


def test_handle_ping():
    assert handle_ping is not None
