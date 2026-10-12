"""Шифрование и хеширование. Чистые функции: ни файлов, ни базы, ни ввода.

Схема ключей:
- мастер-пароль проверяется хешем PBKDF2-HMAC-SHA256 с солью `auth_salt`;
- из того же пароля с другой солью `kek_salt` выводится ключ обёртки;
- ключ обёртки шифрует (Fernet) случайный ключ данных — это содержимое файла `.key`;
- ключ данных шифрует (Fernet) пароли записей.

Соли разные, иначе открыто хранимый хеш входа совпал бы с ключом обёртки.
"""

import base64
import hashlib
import hmac
import os

from cryptography.fernet import Fernet

# Рекомендация OWASP (2023+) для PBKDF2-HMAC-SHA256.
ITERATIONS = 600_000
SALT_BYTES = 16


def new_salt() -> bytes:
    return os.urandom(SALT_BYTES)


def b64(raw: bytes) -> bytes:
    return base64.urlsafe_b64encode(raw)


def _pbkdf2(password: str, salt: bytes, iterations: int) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)


def hash_master(password: str, salt: bytes, iterations: int = ITERATIONS) -> bytes:
    return _pbkdf2(password, salt, iterations)


def verify_master(password: str, salt: bytes, iterations: int, expected: bytes) -> bool:
    # Сравнение за постоянное время: по длительности нельзя угадать совпавший префикс.
    return hmac.compare_digest(hash_master(password, salt, iterations), expected)


def derive_wrapping_key(password: str, salt: bytes, iterations: int = ITERATIONS) -> bytes:
    """Ключ Fernet (32 байта в urlsafe-base64), выведенный из мастер-пароля."""
    return b64(_pbkdf2(password, salt, iterations))


def new_data_key() -> bytes:
    return Fernet.generate_key()


def wrap_key(wrapping_key: bytes, data_key: bytes) -> bytes:
    return Fernet(wrapping_key).encrypt(data_key)


def unwrap_key(wrapping_key: bytes, wrapped: bytes) -> bytes:
    """Бросает cryptography.fernet.InvalidToken, если ключ обёртки не тот или файл испорчен."""
    return Fernet(wrapping_key).decrypt(wrapped)


def encrypt(data_key: bytes, text: str) -> str:
    return Fernet(data_key).encrypt(text.encode("utf-8")).decode("ascii")


def decrypt(data_key: bytes, token: str) -> str:
    return Fernet(data_key).decrypt(token.encode("ascii")).decode("utf-8")
