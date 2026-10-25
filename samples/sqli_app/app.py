"""Small SQLite demo containing one injectable and one parameterized query."""

import sqlite3


def _connection():
    """Create an isolated in-memory database with a small users table."""
    connection = sqlite3.connect(":memory:")
    connection.execute("CREATE TABLE users (name TEXT, role TEXT)")
    connection.executemany("INSERT INTO users VALUES (?, ?)", [("alice", "user"), ("admin", "admin")])
    return connection


def find_user_unsafe(name: str) -> list[tuple[str, str]]:
    """Look up a user using unsafe string interpolation (intentional demo flaw)."""
    connection = _connection()
    query = f"SELECT name, role FROM users WHERE name = '{name}'"
    try:
        return connection.execute(query).fetchall()
    finally:
        connection.close()


def find_user_safe(name: str) -> list[tuple[str, str]]:
    """Look up a user with a parameterized query; this is a false-positive trap."""
    connection = _connection()
    try:
        return connection.execute("SELECT name, role FROM users WHERE name = ?", (name,)).fetchall()
    finally:
        connection.close()


def list_roles() -> list[str]:
    """Return the unique roles stored in the fixture database."""
    connection = _connection()
    try:
        rows = connection.execute("SELECT DISTINCT role FROM users ORDER BY role").fetchall()
        return [row[0] for row in rows]
    finally:
        connection.close()
