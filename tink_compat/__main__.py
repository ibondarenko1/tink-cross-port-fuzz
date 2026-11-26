"""Command-line entry point for ``python -m tink_compat``."""

from __future__ import annotations

import sys

from .check import main


if __name__ == "__main__":
    sys.exit(main())
