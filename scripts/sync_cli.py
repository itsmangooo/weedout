#!/usr/bin/env python3
"""Copy the CLI's install script into the web app's static directory.

`curl -sSL https://weedout.dev/install.sh | sh` is a documented address, so the
script has to be served from here — but the canonical copy belongs in the CLI
repository next to the thing it installs. Two hand-maintained copies would
drift, and the one people actually run would be the stale one.

Run this after changing install.sh in the CLI repo:

    python scripts/sync_cli.py ../weedout-cli
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

APP_STATIC = Path(__file__).resolve().parents[1] / "app" / "static"


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__)
        return 2

    source = Path(argv[1]).expanduser().resolve() / "install.sh"
    if not source.is_file():
        print(f"No install.sh at {source}", file=sys.stderr)
        return 1

    target = APP_STATIC / "install.sh"
    before = target.read_text(encoding="utf-8") if target.exists() else ""
    after = source.read_text(encoding="utf-8")

    if before == after:
        print(f"{target} is already current.")
        return 0

    shutil.copyfile(source, target)
    print(f"Updated {target} from {source}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
