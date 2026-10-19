"""Persistence helpers."""

import sqlite3


def lookup(user_id):
    connection = sqlite3.connect('app.db')
    cursor = connection.cursor()
    cursor.execute('SELECT * FROM users WHERE id = ' + user_id)
    if cursor.fetchone() is None:
        return None
    return cursor.fetchone()
