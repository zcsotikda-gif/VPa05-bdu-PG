import stat

import pytest

from passgen.vault import (
    AuthError,
    EntryExists,
    EntryNotFound,
    InvalidEntry,
    KeyFileConflict,
    KeyFileInvalid,
    KeyFileMissing,
)


def test_first_run_creates_private_key_file(vault, tmp_path):
    assert not vault.is_initialized()
    vault.setup("master-pass")
    assert vault.is_initialized()
    key_file = tmp_path / ".key"
    assert stat.S_IMODE(key_file.stat().st_mode) == 0o600


def test_key_file_is_wrapped_not_raw(vault, tmp_path):
    unlocked = vault.setup("master-pass")
    # Голый ключ Fernet — 44 символа base64; обёрнутый — Fernet-токен, начинается с gAAAAA.
    assert (tmp_path / ".key").read_bytes().startswith(b"gAAAAA")
    assert unlocked.data_key not in (tmp_path / ".key").read_bytes()


def test_unlock_after_setup(vault, open_vault):
    vault.setup("master-pass").add("Google", "me@x", "s3cret")
    assert open_vault().unlock("master-pass").get("google") == ("me@x", "s3cret")


def test_wrong_password(vault):
    vault.setup("master-pass")
    with pytest.raises(AuthError):
        vault.unlock("nope")


def test_missing_key_file_is_reported_not_regenerated(vault, tmp_path):
    vault.setup("master-pass")
    (tmp_path / ".key").unlink()
    with pytest.raises(KeyFileMissing):
        vault.unlock("master-pass")
    assert not (tmp_path / ".key").exists()


def test_foreign_key_file(vault, tmp_path):
    vault.setup("master-pass")
    (tmp_path / ".key").write_bytes(b"gAAAAAgarbage")
    with pytest.raises(KeyFileInvalid):
        vault.unlock("master-pass")


def test_setup_refuses_to_overwrite_existing_key(vault, tmp_path):
    (tmp_path / ".key").write_bytes(b"old")
    with pytest.raises(KeyFileConflict):
        vault.setup("master-pass")
    assert (tmp_path / ".key").read_bytes() == b"old"


def test_password_stored_encrypted(vault, store):
    vault.setup("master-pass").add("Google", "me@x", "s3cret")
    rows = store.conn.execute("SELECT password_enc FROM entries").fetchall()
    assert "s3cret" not in rows[0][0]


def test_names_case_insensitive_including_cyrillic(vault):
    u = vault.setup("master-pass")
    u.add("Почта", "me", "pw")
    assert u.get("ПОЧТА") == ("me", "pw")
    with pytest.raises(EntryExists):
        u.add("почта", "other", "pw")


def test_list_and_delete(vault):
    u = vault.setup("master-pass")
    u.add("Google", "a", "1")
    u.add("GitHub", "b", "2")
    assert u.list() == [("GitHub", "b"), ("Google", "a")]
    u.delete("google")
    assert u.list() == [("GitHub", "b")]
    with pytest.raises(EntryNotFound):
        u.delete("google")
    with pytest.raises(EntryNotFound):
        u.get("google")


@pytest.mark.parametrize(
    "name,login,pw", [("", "a", "b"), ("  ", "a", "b"), ("n", "", "b"), ("n", "a", "")]
)
def test_empty_fields_rejected(vault, name, login, pw):
    with pytest.raises(InvalidEntry):
        vault.setup("master-pass").add(name, login, pw)
