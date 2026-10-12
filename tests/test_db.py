import pytest

from passgen import db
from passgen.ports import DuplicateName, StoredEntry


def test_init_schema_is_idempotent(tmp_path):
    conn = db.connect(tmp_path / "v.db")
    db.init_schema(conn)
    db.init_schema(conn)
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"meta", "entries"} <= tables


def test_meta_roundtrip(store):
    assert store.get_meta("auth_hash") is None
    store.set_meta({"auth_hash": "ab", "iterations": "5"})
    assert store.get_meta("auth_hash") == "ab"
    assert store.get_meta("iterations") == "5"


def test_entry_crud(store):
    store.add_entry("google", "Google", "me@x", "TOKEN", "2026-10-12T00:00:00+00:00")
    assert store.get_entry("google") == StoredEntry("Google", "me@x", "TOKEN")
    assert store.list_entries() == [("Google", "me@x")]
    assert store.delete_entry("google") is True
    assert store.get_entry("google") is None
    assert store.delete_entry("google") is False


def test_duplicate_key_rejected(store):
    store.add_entry("google", "Google", "a", "T", "t")
    with pytest.raises(DuplicateName):
        store.add_entry("google", "GOOGLE", "b", "T", "t")


def test_list_sorted_by_key(store):
    for key, name in [("b", "B"), ("a", "a"), ("c", "C")]:
        store.add_entry(key, name, "l", "T", "t")
    assert [n for n, _ in store.list_entries()] == ["a", "B", "C"]
