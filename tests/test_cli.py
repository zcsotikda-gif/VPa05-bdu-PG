import pytest

from passgen import cli

MASTER = "master-pass"


@pytest.fixture
def answers(monkeypatch):
    """Очередь ответов на getpass и input — в том порядке, в каком их спросит программа."""
    queue: list[str] = []

    def take(prompt=""):
        assert queue, f"программа спросила лишнее: {prompt!r}"
        return queue.pop(0)

    monkeypatch.setattr(cli, "getpass", take)
    monkeypatch.setattr("builtins.input", take)
    yield queue
    assert not queue, f"остались неиспользованные ответы: {queue}"


def run(argv, open_vault, answers, *replies):
    answers.extend(replies)
    return cli.run(argv, open_vault)


def test_first_run_then_full_cycle(open_vault, answers, capsys):
    # Первый запуск: пароль дважды, затем add спрашивает логин, пароль и повтор.
    assert run(["add", "Google"], open_vault, answers, MASTER, MASTER, "me@x", "pw1", "pw1") == 0

    assert run(["list"], open_vault, answers, MASTER) == 0
    out = capsys.readouterr().out
    assert "Google" in out and "me@x" in out and "pw1" not in out

    assert run(["get", "google"], open_vault, answers, MASTER) == 0
    assert "pw1" in capsys.readouterr().out

    assert run(["delete", "Google"], open_vault, answers, MASTER, "y") == 0
    assert run(["get", "Google"], open_vault, answers, MASTER) == 1
    assert "не найдена" in capsys.readouterr().err


def test_first_run_mismatch_then_match(open_vault, answers):
    assert run(["list"], open_vault, answers, MASTER, "typo", MASTER, MASTER) == 0


def test_short_master_rejected(open_vault, answers, capsys):
    assert run(["list"], open_vault, answers, "short", "short", MASTER, MASTER) == 0
    assert "не короче" in capsys.readouterr().err


def test_three_wrong_passwords(open_vault, answers, capsys):
    run(["list"], open_vault, answers, MASTER, MASTER)
    assert run(["list"], open_vault, answers, "a", "b", "c") == 1
    assert "Неверный мастер-пароль" in capsys.readouterr().err


def test_wrong_then_right_password(open_vault, answers):
    run(["list"], open_vault, answers, MASTER, MASTER)
    assert run(["list"], open_vault, answers, "a", MASTER) == 0


def test_add_with_generated_password(open_vault, answers, capsys):
    run(["list"], open_vault, answers, MASTER, MASTER)
    capsys.readouterr()
    assert run(["add", "Site"], open_vault, answers, MASTER, "me", "") == 0
    out = capsys.readouterr().out
    generated = next(ln for ln in out.splitlines() if ln.startswith("Сгенерирован")).split()[-1]
    assert open_vault().unlock(MASTER).get("Site") == ("me", generated)


def test_add_confirmation_mismatch(open_vault, answers, capsys):
    run(["list"], open_vault, answers, MASTER, MASTER)
    assert run(["add", "Site"], open_vault, answers, MASTER, "me", "pw1", "pw2") == 1
    assert "не совпадают" in capsys.readouterr().err


def test_add_duplicate(open_vault, answers, capsys):
    run(["add", "Site"], open_vault, answers, MASTER, MASTER, "me", "p", "p")
    assert run(["add", "SITE"], open_vault, answers, MASTER, "me", "p", "p") == 1
    assert "уже есть" in capsys.readouterr().err


def test_delete_declined_keeps_entry(open_vault, answers):
    run(["add", "Site"], open_vault, answers, MASTER, MASTER, "me", "p", "p")
    assert run(["delete", "Site"], open_vault, answers, MASTER, "n") == 0
    assert open_vault().unlock(MASTER).get("Site") == ("me", "p")


def test_delete_yes_flag(open_vault, answers):
    run(["add", "Site"], open_vault, answers, MASTER, MASTER, "me", "p", "p")
    assert run(["delete", "Site", "--yes"], open_vault, answers, MASTER) == 0
    assert open_vault().unlock(MASTER).list() == []


def test_new_prints_password_of_requested_length(open_vault, answers, capsys):
    assert run(["new", "--length", "24"], open_vault, answers, MASTER, MASTER) == 0
    assert len(capsys.readouterr().out.strip().splitlines()[-1]) == 24


def test_new_no_similar(open_vault, answers, capsys):
    assert run(["new", "--length", "64", "--no-similar"], open_vault, answers, MASTER, MASTER) == 0
    pw = capsys.readouterr().out.strip().splitlines()[-1]
    assert len(pw) == 64 and not set(pw) & set("0O1lI")


def test_new_save(open_vault, answers, capsys):
    assert run(["new", "--save", "GitHub"], open_vault, answers, MASTER, MASTER, "me") == 0
    printed = capsys.readouterr().out.strip().splitlines()
    login, password = open_vault().unlock(MASTER).get("github")
    assert login == "me" and password in printed


def test_new_too_short_rejected_before_login(open_vault, answers):
    with pytest.raises(SystemExit):
        run(["new", "--length", "4"], open_vault, answers)


def test_list_empty(open_vault, answers, capsys):
    assert run(["list"], open_vault, answers, MASTER, MASTER) == 0
    assert "Записей нет" in capsys.readouterr().out


def test_missing_key_file(open_vault, answers, capsys, tmp_path):
    run(["list"], open_vault, answers, MASTER, MASTER)
    (tmp_path / ".key").unlink()
    assert run(["list"], open_vault, answers, MASTER) == 1
    assert ".key" in capsys.readouterr().err
