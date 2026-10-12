import pytest
from cryptography.fernet import InvalidToken

from passgen import crypto

IT = 1_000


def test_verify_master_accepts_right_and_rejects_wrong_password():
    salt = crypto.new_salt()
    digest = crypto.hash_master("correct horse", salt, IT)
    assert crypto.verify_master("correct horse", salt, IT, digest)
    assert not crypto.verify_master("wrong horse", salt, IT, digest)


def test_different_salts_give_different_hashes():
    assert crypto.hash_master("pw", crypto.new_salt(), IT) != crypto.hash_master(
        "pw", crypto.new_salt(), IT
    )


def test_hash_is_32_bytes_of_sha256():
    assert len(crypto.hash_master("pw", crypto.new_salt(), IT)) == 32


def test_wrapping_key_differs_from_stored_hash():
    # Хеш входа лежит в базе открыто; совпади он с ключом обёртки — .key открывался бы без пароля.
    auth_salt, kek_salt = crypto.new_salt(), crypto.new_salt()
    digest = crypto.hash_master("pw", auth_salt, IT)
    wrapping = crypto.derive_wrapping_key("pw", kek_salt, IT)
    assert crypto.b64(digest) != wrapping


def test_wrap_unwrap_roundtrip():
    wrapping = crypto.derive_wrapping_key("pw", crypto.new_salt(), IT)
    data_key = crypto.new_data_key()
    wrapped = crypto.wrap_key(wrapping, data_key)
    assert data_key not in wrapped
    assert crypto.unwrap_key(wrapping, wrapped) == data_key


def test_unwrap_with_wrong_key_fails():
    salt = crypto.new_salt()
    wrapped = crypto.wrap_key(crypto.derive_wrapping_key("pw", salt, IT), crypto.new_data_key())
    with pytest.raises(InvalidToken):
        crypto.unwrap_key(crypto.derive_wrapping_key("other", salt, IT), wrapped)


def test_encrypt_decrypt_roundtrip():
    key = crypto.new_data_key()
    token = crypto.encrypt(key, "секрет 123")
    assert "секрет" not in token
    assert crypto.decrypt(key, token) == "секрет 123"
