#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GUI_FILE = ROOT / "rnode-halow-flasher-gui.py"


def normalize_version(raw: str) -> str:
    value = str(raw).strip()
    if not value:
        raise ValueError("empty version")

    if value.startswith(("v", "V")):
        value = value[1:].strip()

    if not re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z._+-]*", value):
        raise ValueError(f"invalid version: {raw!r}")

    return value


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: set_version.py <version>", file=sys.stderr)
        return 1

    version = normalize_version(sys.argv[1])
    text = GUI_FILE.read_text(encoding="utf-8")

    new_text, count = re.subn(
        r'(?m)^APP_VERSION = ".*"$',
        f'APP_VERSION = "{version}"',
        text,
        count=1,
    )
    if count != 1:
        raise RuntimeError("APP_VERSION constant not found in rnode-halow-flasher-gui.py")

    GUI_FILE.write_text(new_text, encoding="utf-8")
    print(f"Set APP_VERSION={version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
