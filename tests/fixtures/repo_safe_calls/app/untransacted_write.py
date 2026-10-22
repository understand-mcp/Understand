"""A write with no transaction around it."""


def save(conn: object) -> None:
    """Insert a row outside any transaction."""

    cur = conn.cursor()
    cur.execute("INSERT INTO notes (body) VALUES ('hello')")
