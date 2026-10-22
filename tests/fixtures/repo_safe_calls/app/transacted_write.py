"""A write that is already atomic."""


def save(conn: object) -> None:
    """Insert a row inside a transaction."""

    with conn.transaction() as cur:
        cur.execute("INSERT INTO notes (body) VALUES ('hello')")
