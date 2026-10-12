"""Генератор паролей на криптостойком источнике `secrets`."""

import secrets
import string

MIN_LENGTH = 8
DEFAULT_LENGTH = 20
# Без кавычек, обратной косой и пробела: пароль вставляется в оболочку и конфиги без экранирования.
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/"
CLASSES = (string.ascii_lowercase, string.ascii_uppercase, string.digits, SYMBOLS)
# Путаются при чтении глазами: ноль и O, единица, строчная l и заглавная I.
SIMILAR = "0O1lI"


def generate_password(length: int = DEFAULT_LENGTH, exclude_similar: bool = False) -> str:
    if length < MIN_LENGTH:
        raise ValueError(f"длина пароля должна быть не меньше {MIN_LENGTH}")
    classes = CLASSES
    if exclude_similar:
        classes = tuple("".join(c for c in cls if c not in SIMILAR) for cls in CLASSES)
    # По символу каждого класса — многие сайты отклоняют пароль без цифры или знака.
    chars = [secrets.choice(cls) for cls in classes]
    alphabet = "".join(classes)
    chars += [secrets.choice(alphabet) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)
