#!/usr/bin/env python3
"""Copy the CLI's install scripts into the web app's static directory.

The documented Unix and Windows one-liners have to be served from the web app,
but their canonical copies belong in the CLI repository next to the thing they
install. Two hand-maintained copies would drift, and the one people actually
run would be the stale one.

Run this after changing either installer in the CLI repo:

    python scripts/sync_cli.py ../weedout-cli
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

APP_STATIC = Path(__file__).resolve().parents[1] / "app" / "static"
INSTALLERS = ("install.sh", "install.ps1")


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__)
        return 2

    cli_root = Path(argv[1]).expanduser().resolve()
    sources = [cli_root / name for name in INSTALLERS]
    missing = [source for source in sources if not source.is_file()]
    if missing:
        for source in missing:
            print(f"No installer at {source}", file=sys.stderr)
        return 1

    for source in sources:
        target = APP_STATIC / source.name
        before = target.read_text(encoding="utf-8") if target.exists() else ""
        after = source.read_text(encoding="utf-8")
        if before == after:
            print(f"{target} is already current.")
            continue
        shutil.copyfile(source, target)
        print(f"Updated {target} from {source}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
