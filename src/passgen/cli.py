"""Разбор команд, диалог с человеком, вывод. Решений о данных здесь нет — они в vault."""

import argparse
import sys
from collections.abc import Callable
from getpass import getpass

from passgen.generator import DEFAULT_LENGTH, MIN_LENGTH, generate_password
from passgen.vault import AuthError, UnlockedVault, Vault, VaultError

MIN_MASTER_LENGTH = 8
ATTEMPTS = 3


def _length(value: str) -> int:
    n = int(value)
    if n < MIN_LENGTH:
        raise argparse.ArgumentTypeError(f"не меньше {MIN_LENGTH}")
    return n


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="passgen", description="Менеджер паролей с шифрованием.")
    sub = p.add_subparsers(dest="command", required=True, metavar="КОМАНДА")

    add = sub.add_parser("add", help="добавить запись")
    add.add_argument("name", metavar="НАЗВАНИЕ", help="откуда пароль, например Google")
    add.set_defaults(handler=cmd_add)

    get = sub.add_parser("get", help="показать логин и пароль записи")
    get.add_argument("name", metavar="НАЗВАНИЕ")
    get.set_defaults(handler=cmd_get)

    lst = sub.add_parser("list", help="список записей (названия и логины)")
    lst.set_defaults(handler=cmd_list)

    delete = sub.add_parser("delete", help="удалить запись")
    delete.add_argument("name", metavar="НАЗВАНИЕ")
    delete.add_argument("--yes", action="store_true", help="не спрашивать подтверждение")
    delete.set_defaults(handler=cmd_delete)

    new = sub.add_parser("new", help="сгенерировать пароль")
    new.add_argument(
        "--length",
        type=_length,
        default=DEFAULT_LENGTH,
        metavar="N",
        help=f"длина, по умолчанию {DEFAULT_LENGTH}",
    )
    new.add_argument("--no-similar", action="store_true", help="без похожих символов: 0 O 1 l I")
    new.add_argument("--save", metavar="НАЗВАНИЕ", help="сразу сохранить под этим названием")
    new.set_defaults(handler=cmd_new)
    return p


def run(argv: list[str] | None, open_vault: Callable[[], Vault]) -> int:
    # Аргументы разбираются до открытия хранилища: --help и опечатки не создают файлов.
    args = build_parser().parse_args(argv)
    try:
        unlocked = login(open_vault())
        args.handler(args, unlocked)
    except VaultError as e:
        print(f"Ошибка: {e}", file=sys.stderr)
        return 1
    except (KeyboardInterrupt, EOFError):
        print("\nПрервано.", file=sys.stderr)
        return 130
    return 0


def login(vault: Vault) -> UnlockedVault:
    if not vault.is_initialized():
        print("Первый запуск: задайте мастер-пароль. Восстановить его будет нельзя.")
        return vault.setup(_new_master())
    for attempt in range(1, ATTEMPTS + 1):
        try:
            return vault.unlock(getpass("Мастер-пароль: "))
        except AuthError:
            if attempt == ATTEMPTS:
                raise
            print("Неверный мастер-пароль, попробуйте ещё раз.", file=sys.stderr)
    raise AssertionError("недостижимо")


def _new_master() -> str:
    for _ in range(ATTEMPTS):
        master = getpass("Новый мастер-пароль: ")
        if getpass("Повторите: ") != master:
            print("Пароли не совпадают.", file=sys.stderr)
        elif len(master) < MIN_MASTER_LENGTH:
            print(
                f"Мастер-пароль должен быть не короче {MIN_MASTER_LENGTH} символов.",
                file=sys.stderr,
            )
        else:
            return master
    raise VaultError("Мастер-пароль не задан.")


def cmd_add(args: argparse.Namespace, vault: UnlockedVault) -> None:
    login_ = input("Логин: ")
    password = getpass("Пароль (Enter — сгенерировать): ")
    if not password:
        password = generate_password()
        print(f"Сгенерирован пароль: {password}")
    elif getpass("Повторите пароль: ") != password:
        raise VaultError("Пароли не совпадают, запись не сохранена.")
    vault.add(args.name, login_, password)
    print(f"Запись «{args.name.strip()}» сохранена.")


def cmd_get(args: argparse.Namespace, vault: UnlockedVault) -> None:
    login_, password = vault.get(args.name)
    print(f"Логин:  {login_}")
    print(f"Пароль: {password}")


def cmd_list(args: argparse.Namespace, vault: UnlockedVault) -> None:
    rows = vault.list()
    if not rows:
        print("Записей нет.")
        return
    width = max(len("Название"), *(len(name) for name, _ in rows))
    print(f"{'Название':<{width}}  Логин")
    for name, login_ in rows:
        print(f"{name:<{width}}  {login_}")


def cmd_delete(args: argparse.Namespace, vault: UnlockedVault) -> None:
    vault.get(args.name)  # несуществующую запись не предлагаем удалить
    if not args.yes and input(f"Удалить «{args.name}»? [y/N] ").strip().lower() not in ("y", "д"):
        print("Отменено.")
        return
    vault.delete(args.name)
    print(f"Запись «{args.name}» удалена.")


def cmd_new(args: argparse.Namespace, vault: UnlockedVault) -> None:
    password = generate_password(args.length, exclude_similar=args.no_similar)
    if args.save:
        vault.add(args.save, input("Логин: "), password)
        print(f"Запись «{args.save.strip()}» сохранена.")
    print(password)
