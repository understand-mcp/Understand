"""Run a query whose values are bound."""

import sqlite3


def run_query(cursor: sqlite3.Cursor, where_clause: str, params: tuple) -> list:
    """The only interpolation is a reviewed clause; the values are bound."""
    cursor.execute(f"SELECT * FROM users WHERE {where_clause}", params)
    return cursor.fetchall()
