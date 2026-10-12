"""SQLite-адаптер хранилища."""

import os
import sqlite3
from pathlib import Path

from passgen.ports import DuplicateName, StoredEntry

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS entries (
    id           INTEGER PRIMARY KEY,
    key          TEXT NOT NULL UNIQUE,
    name         TEXT NOT NULL,
    login        TEXT NOT NULL,
    password_enc TEXT NOT NULL,
    created_at   TEXT NOT NULL
);
"""


def connect(path: Path) -> sqlite3.Connection:
    """Открывает базу и при необходимости создаёт таблицы."""
    is_new = not path.exists()
    conn = sqlite3.connect(path)
    if is_new:
        os.chmod(path, 0o600)
    init_schema(conn)
    return conn


def init_schema(conn: sqlite3.Connection) -> None:
    with conn:
        conn.executescript(SCHEMA)


class SqliteStore:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn

    def get_meta(self, key: str) -> str | None:
        row = self.conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row[0] if row else None

    def set_meta(self, values: dict[str, str]) -> None:
        with self.conn:
            self.conn.executemany(
                "INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", values.items()
            )

    def add_entry(
        self, key: str, name: str, login: str, password_enc: str, created_at: str
    ) -> None:
        try:
            with self.conn:
                self.conn.execute(
                    "INSERT INTO entries (key, name, login, password_enc, created_at)"
                    " VALUES (?, ?, ?, ?, ?)",
                    (key, name, login, password_enc, created_at),
                )
        except sqlite3.IntegrityError as e:
            raise DuplicateName(key) from e

    def get_entry(self, key: str) -> StoredEntry | None:
        row = self.conn.execute(
            "SELECT name, login, password_enc FROM entries WHERE key = ?", (key,)
        ).fetchone()
        return StoredEntry(*row) if row else None

    def list_entries(self) -> list[tuple[str, str]]:
        return self.conn.execute("SELECT name, login FROM entries ORDER BY key").fetchall()

    def delete_entry(self, key: str) -> bool:
        with self.conn:
            cur = self.conn.execute("DELETE FROM entries WHERE key = ?", (key,))
        return cur.rowcount > 0
