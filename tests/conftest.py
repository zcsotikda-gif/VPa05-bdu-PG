import pytest

from passgen import db
from passgen.vault import Vault

# 600 000 итераций PBKDF2 — около полусекунды на вызов; тестам нужна логика, а не стойкость.
FAST_ITERATIONS = 1_000


@pytest.fixture
def store(tmp_path):
    return db.SqliteStore(db.connect(tmp_path / "vault.db"))


@pytest.fixture
def open_vault(store, tmp_path):
    """Новый объект Vault над теми же файлами — как повторный запуск программы."""
    return lambda: Vault(store, tmp_path / ".key", iterations=FAST_ITERATIONS)


@pytest.fixture
def vault(open_vault):
    return open_vault()
