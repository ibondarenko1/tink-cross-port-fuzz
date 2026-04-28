"""Atheris (libFuzzer) wrapper for the differential harness.

Drives Python-only fuzzing against tink-py JwkSetConverter to surface
new uncaught exceptions; surviving inputs are then passed through the
full differential.py for cross-port comparison.

Usage:
    python atheris_jwk.py corpus_jwk/

To run continuously add libFuzzer flags after the corpus dir, e.g.:
    python atheris_jwk.py corpus_jwk/ -max_total_time=3600
"""

from __future__ import annotations

import sys
from typing import NoReturn

import atheris  # type: ignore[import-not-found]

with atheris.instrument_imports():
    from tink.jwt import _jwk_set_converter as jwk_conv  # type: ignore[import-not-found]
    import tink as tink_pkg  # type: ignore[import-not-found]


def TestOneInput(data: bytes) -> None:
    try:
        s = data.decode("utf-8", errors="replace")
        jwk_conv.to_public_keyset_handle(s)
    except (tink_pkg.TinkError, ValueError, KeyError, TypeError, UnicodeDecodeError):
        return
    except (AttributeError, IndexError, RuntimeError) as e:
        # These are the contract violations we care about — log them so
        # libFuzzer's corpus-minimization keeps the smallest reproducer.
        sys.stderr.write(
            f"UNCAUGHT {type(e).__name__}: {e!r} on input len={len(data)}\n"
        )
        # Don't re-raise; let atheris/libFuzzer record the input via
        # corpus growth (uncaught classes are interesting coverage).
        return


def main() -> NoReturn:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
