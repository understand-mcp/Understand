"""Build a query by concatenation."""

import sqlite3


def run_query(cursor: sqlite3.Cursor, user_id: str) -> list:
    """The value is concatenated into the statement, so it can change its meaning."""
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)
    return cursor.fetchall()
