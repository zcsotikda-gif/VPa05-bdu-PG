"""Что ядру нужно от хранилища.

Ключ записи (`key`) вычисляет ядро, хранилище его только сравнивает.
"""

from dataclasses import dataclass
from typing import Protocol


class DuplicateName(Exception):
    """Запись с таким ключом уже есть."""


@dataclass(frozen=True)
class StoredEntry:
    name: str
    login: str
    password_enc: str


class EntryStore(Protocol):
    def get_meta(self, key: str) -> str | None: ...

    def set_meta(self, values: dict[str, str]) -> None:
        """Записывает все значения одной транзакцией."""

    def add_entry(
        self, key: str, name: str, login: str, password_enc: str, created_at: str
    ) -> None:
        """Бросает DuplicateName, если ключ занят."""

    def get_entry(self, key: str) -> StoredEntry | None: ...

    def list_entries(self) -> list[tuple[str, str]]:
        """Пары (название, логин), упорядоченные по ключу."""

    def delete_entry(self, key: str) -> bool: ...
