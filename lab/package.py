"""Empaqueta la CLI como zipapp mediante la biblioteca estándar de Python."""

import shutil
import tempfile
import zipapp
from pathlib import Path

from vulnminer.io import write_text

ROOT = Path(__file__).resolve().parents[1]


def package():
    target = ROOT / "dist"
    target.mkdir(exist_ok=True)
    archive = target / "vulnminer.pyz"
    with tempfile.TemporaryDirectory() as staging:
        source = Path(staging)
        shutil.copytree(ROOT / "vulnminer", source / "vulnminer", ignore=shutil.ignore_patterns("__pycache__"))
        write_text(source / "__main__.py", "from vulnminer.cli import main\n\nraise SystemExit(main())\n")
        zipapp.create_archive(
            source, archive, interpreter="/usr/bin/env python3", compressed=True
        )
    write_text(target / "vulnminer.cmd", '@echo off\r\npy "%~dp0vulnminer.pyz" %*\r\n')
    print(archive)


if __name__ == "__main__":
    package()
