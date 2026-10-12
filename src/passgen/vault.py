"""Ядро: первый запуск, вход по мастер-паролю, операции с записями."""

import os
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from cryptography.fernet import InvalidToken

from passgen import crypto
from passgen.ports import DuplicateName, EntryStore


class VaultError(Exception):
    """Ошибка, которую надо показать человеку как есть."""


class AuthError(VaultError):
    def __init__(self) -> None:
        super().__init__("Неверный мастер-пароль.")


class KeyFileMissing(VaultError):
    def __init__(self, path: Path) -> None:
        super().__init__(
            f"Хранилище создано, но файла ключа {path} нет. Без него сохранённые пароли "
            "не расшифровать; верните файл из резервной копии. Новый ключ не создаётся, "
            "чтобы не потерять записи."
        )


class KeyFileInvalid(VaultError):
    def __init__(self, path: Path) -> None:
        super().__init__(
            f"Мастер-пароль верный, но файл ключа {path} не подходит к этой базе "
            "(испорчен или взят от другого хранилища)."
        )


class KeyFileConflict(VaultError):
    def __init__(self, path: Path) -> None:
        super().__init__(
            f"База пуста, но файл ключа {path} уже существует. Он может быть нужен другой "
            "базе, поэтому не перезаписывается. Если он точно не нужен — удалите его вручную."
        )


class EntryNotFound(VaultError):
    def __init__(self, name: str) -> None:
        super().__init__(f"Запись «{name}» не найдена.")


class EntryExists(VaultError):
    def __init__(self, name: str) -> None:
        super().__init__(f"Запись «{name}» уже есть. Удалите её или выберите другое название.")


class InvalidEntry(VaultError):
    pass


def entry_key(name: str) -> str:
    """Название сравнивается без учёта регистра на любом алфавите: «Почта» и «ПОЧТА» — одно."""
    return name.strip().casefold()


def _utcnow() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


class Vault:
    def __init__(
        self,
        store: EntryStore,
        key_path: Path,
        iterations: int = crypto.ITERATIONS,
        clock: Callable[[], str] = _utcnow,
    ) -> None:
        self.store = store
        self.key_path = key_path
        self.iterations = iterations
        self.clock = clock

    def is_initialized(self) -> bool:
        return self.store.get_meta("auth_hash") is not None

    def setup(self, master: str) -> "UnlockedVault":
        auth_salt, kek_salt = crypto.new_salt(), crypto.new_salt()
        data_key = crypto.new_data_key()
        wrapped = crypto.wrap_key(
            crypto.derive_wrapping_key(master, kek_salt, self.iterations), data_key
        )
        # Сначала ключ, потом хеш: сбой между шагами оставит лишний .key при пустой базе
        # (KeyFileConflict, объяснимо), а не базу без ключа.
        try:
            # O_EXCL: файл создаётся только если его нет; права 600 сразу, без окна гонки.
            fd = os.open(self.key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError as e:
            raise KeyFileConflict(self.key_path) from e
        with os.fdopen(fd, "wb") as f:
            f.write(wrapped)
        self.store.set_meta(
            {
                "auth_hash": crypto.hash_master(master, auth_salt, self.iterations).hex(),
                "auth_salt": auth_salt.hex(),
                "kek_salt": kek_salt.hex(),
                "iterations": str(self.iterations),
            }
        )
        return UnlockedVault(self.store, data_key, self.clock)

    def unlock(self, master: str) -> "UnlockedVault":
        # Число итераций берётся из базы: его можно поднять для новых хранилищ, не ломая старые.
        iterations = int(self._meta("iterations"))
        if not crypto.verify_master(
            master,
            bytes.fromhex(self._meta("auth_salt")),
            iterations,
            bytes.fromhex(self._meta("auth_hash")),
        ):
            raise AuthError()
        if not self.key_path.exists():
            raise KeyFileMissing(self.key_path)
        wrapping = crypto.derive_wrapping_key(
            master, bytes.fromhex(self._meta("kek_salt")), iterations
        )
        try:
            data_key = crypto.unwrap_key(wrapping, self.key_path.read_bytes())
        except InvalidToken as e:
            raise KeyFileInvalid(self.key_path) from e
        return UnlockedVault(self.store, data_key, self.clock)

    def _meta(self, key: str) -> str:
        value = self.store.get_meta(key)
        if value is None:
            raise VaultError(f"В базе нет служебного поля {key!r}: хранилище повреждено.")
        return value


class UnlockedVault:
    def __init__(self, store: EntryStore, data_key: bytes, clock: Callable[[], str]) -> None:
        self.store = store
        self.data_key = data_key
        self.clock = clock

    def add(self, name: str, login: str, password: str) -> None:
        name = name.strip()
        if not name:
            raise InvalidEntry("Название не может быть пустым.")
        if not login:
            raise InvalidEntry("Логин не может быть пустым.")
        if not password:
            raise InvalidEntry("Пароль не может быть пустым.")
        try:
            self.store.add_entry(
                entry_key(name), name, login, crypto.encrypt(self.data_key, password), self.clock()
            )
        except DuplicateName as e:
            raise EntryExists(name) from e

    def get(self, name: str) -> tuple[str, str]:
        entry = self.store.get_entry(entry_key(name))
        if entry is None:
            raise EntryNotFound(name)
        return entry.login, crypto.decrypt(self.data_key, entry.password_enc)

    def list(self) -> list[tuple[str, str]]:
        return self.store.list_entries()

    def delete(self, name: str) -> None:
        if not self.store.delete_entry(entry_key(name)):
            raise EntryNotFound(name)
