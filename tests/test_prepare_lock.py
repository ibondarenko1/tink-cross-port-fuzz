"""Concurrent consumers share the same on-disk adapter cache."""
import os
from pathlib import Path
import subprocess
import sys
import textwrap

from tink_compat.prepare import _CacheLock


def test_live_lock_survives_an_old_timestamp(tmp_path: Path):
    path = tmp_path / "runner.lock"
    attempt = textwrap.dedent("""\
        import sys
        from pathlib import Path
        from tink_compat import prepare
        prepare.LOCK_TIMEOUT_SECONDS = 0
        try:
            with prepare._CacheLock(Path(sys.argv[1])):
                pass
        except prepare.PrepareError:
            sys.exit(2)
    """)
    command = [sys.executable, "-c", attempt, str(path)]
    with _CacheLock(path):
        os.utime(path, (5, 5))
        assert subprocess.run(command).returncode == 2
    assert subprocess.run(command).returncode == 0
