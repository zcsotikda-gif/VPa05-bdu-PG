"""Точка сборки: путь к данным, хранилище, ядро, CLI."""

import os
import sys
from pathlib import Path

from passgen import cli, db
from passgen.vault import Vault


def data_dir() -> Path:
    # Данные — в каталоге запуска, а не в ~/Library: удаляются вместе с проектом.
    return Path(os.environ.get("PASSGEN_DATA", "data"))


def open_vault() -> Vault:
    path = data_dir()
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    return Vault(db.SqliteStore(db.connect(path / "vault.db")), path / ".key")


def main() -> int:
    return cli.run(sys.argv[1:], open_vault)


if __name__ == "__main__":
    sys.exit(main())
