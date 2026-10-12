import string

import pytest

from passgen.generator import MIN_LENGTH, SIMILAR, SYMBOLS, generate_password


@pytest.mark.parametrize("length", [MIN_LENGTH, 20, 64])
def test_length(length):
    assert len(generate_password(length)) == length


def test_every_class_present():
    for _ in range(200):
        pw = generate_password(MIN_LENGTH)
        assert any(c in string.ascii_lowercase for c in pw)
        assert any(c in string.ascii_uppercase for c in pw)
        assert any(c in string.digits for c in pw)
        assert any(c in SYMBOLS for c in pw)


def test_too_short_rejected():
    with pytest.raises(ValueError):
        generate_password(MIN_LENGTH - 1)


def test_passwords_differ():
    assert generate_password() != generate_password()


def test_exclude_similar():
    for _ in range(200):
        pw = generate_password(64, exclude_similar=True)
        assert not set(pw) & set(SIMILAR)
        # Классы по-прежнему представлены: цифры и буквы остаются и без 0/1/O/l/I.
        assert any(c in string.digits for c in pw)
        assert any(c in string.ascii_uppercase for c in pw)


def test_similar_allowed_by_default():
    joined = "".join(generate_password(64) for _ in range(50))
    assert set(joined) & set(SIMILAR)
