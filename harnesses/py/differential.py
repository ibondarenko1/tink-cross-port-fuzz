"""Differential harness for Tink JWK Set converter across language ports.

Usage:
    python differential.py <corpus_dir> [--report-dir reports/]

Each file in the corpus directory is read as raw bytes and fed to every
configured runner. Outcomes are compared and divergences are written to
the report directory as JSON.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import time
from typing import Optional

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]


@dataclasses.dataclass
class Outcome:
    runner: str
    verdict: str  # ACCEPT / REJECT_TINK / REJECT_OTHER / TIMEOUT / UNAVAILABLE
    error_class: Optional[str] = None
    error_msg: Optional[str] = None
    keyset_shape: Optional[str] = None  # e.g., "RSA:2048,e=65537"
    elapsed_ms: Optional[int] = None


def run_python(jwk_set: bytes) -> Outcome:
    """Run tink-py JwkSetConverter via in-process import."""
    t0 = time.monotonic()
    try:
        from tink.jwt import _jwk_set_converter as jwk_conv
        import tink as tink_pkg
    except ImportError:
        return Outcome("py", "UNAVAILABLE", error_msg="tink package not installed")

    try:
        s = jwk_set.decode("utf-8", errors="replace")
        h = jwk_conv.to_public_keyset_handle(s)
        elapsed = int((time.monotonic() - t0) * 1000)
        # tink.KeysetHandle exposes nothing structured publicly; just record success
        return Outcome("py", "ACCEPT", keyset_shape="<opaque>", elapsed_ms=elapsed)
    except tink_pkg.TinkError as e:
        elapsed = int((time.monotonic() - t0) * 1000)
        return Outcome("py", "REJECT_TINK", error_class="TinkError",
                       error_msg=str(e)[:200], elapsed_ms=elapsed)
    except (UnicodeDecodeError, ValueError, KeyError, json.JSONDecodeError) as e:
        elapsed = int((time.monotonic() - t0) * 1000)
        return Outcome("py", "REJECT_TINK", error_class=type(e).__name__,
                       error_msg=str(e)[:200], elapsed_ms=elapsed)
    except Exception as e:
        elapsed = int((time.monotonic() - t0) * 1000)
        return Outcome("py", "REJECT_OTHER", error_class=type(e).__name__,
                       error_msg=str(e)[:200], elapsed_ms=elapsed)


def run_go(jwk_set: bytes, binary: pathlib.Path) -> Outcome:
    """Run tink-go via the bundled go-runner CLI.

    The binary reads JWK Set from stdin and emits one JSON line on stdout
    with {verdict, error_class, error_msg, keyset_shape}.
    """
    t0 = time.monotonic()
    if not binary.exists():
        return Outcome("go", "UNAVAILABLE",
                       error_msg=f"runner not built at {binary}")
    try:
        proc = subprocess.run(
            [str(binary)],
            input=jwk_set,
            capture_output=True,
            timeout=10,
        )
    except subprocess.TimeoutExpired:
        return Outcome("go", "TIMEOUT")

    elapsed = int((time.monotonic() - t0) * 1000)
    out = proc.stdout.decode("utf-8", errors="replace").strip()
    try:
        d = json.loads(out)
        return Outcome(
            "go", d.get("verdict", "REJECT_OTHER"),
            error_class=d.get("error_class"),
            error_msg=d.get("error_msg"),
            keyset_shape=d.get("keyset_shape"),
            elapsed_ms=elapsed,
        )
    except json.JSONDecodeError:
        # runner crashed before printing JSON
        return Outcome("go", "REJECT_OTHER",
                       error_class="runner-crash",
                       error_msg=(out + "|" + proc.stderr.decode("utf-8", errors="replace"))[:300],
                       elapsed_ms=elapsed)


def run_java(jwk_set: bytes, jar: pathlib.Path) -> Outcome:
    """Placeholder for tink-java runner. Milestone 2."""
    if not jar.exists():
        return Outcome("java", "UNAVAILABLE",
                       error_msg="java runner not built (milestone 2)")
    return Outcome("java", "UNAVAILABLE", error_msg="not implemented")


def run_cc(jwk_set: bytes, binary: pathlib.Path) -> Outcome:
    """Placeholder for tink-cc runner. Milestone 2."""
    if not binary.exists():
        return Outcome("cc", "UNAVAILABLE",
                       error_msg="cc runner not built (milestone 2)")
    return Outcome("cc", "UNAVAILABLE", error_msg="not implemented")


def is_divergence(outcomes: list[Outcome]) -> bool:
    """A divergence is when at least two AVAILABLE runners disagree on verdict.

    Notes:
    - REJECT_OTHER from any one runner is a divergence on its own (uncaught exception
      contract violation).
    - UNAVAILABLE runners are excluded from the comparison.
    """
    available = [o for o in outcomes if o.verdict != "UNAVAILABLE"]
    if not available:
        return False
    # Any REJECT_OTHER alone is a finding
    if any(o.verdict == "REJECT_OTHER" for o in available):
        return True
    # Otherwise need disagreement among ACCEPT/REJECT_TINK
    verdicts = {o.verdict for o in available}
    return "ACCEPT" in verdicts and "REJECT_TINK" in verdicts


def write_report(report_dir: pathlib.Path, input_path: pathlib.Path,
                 input_bytes: bytes, outcomes: list[Outcome]) -> pathlib.Path:
    sha = hashlib.sha1(input_bytes).hexdigest()[:16]
    out_path = report_dir / f"{sha}.json"
    payload = {
        "input_file": str(input_path),
        "input_sha1_16": sha,
        "input_bytes_b64": (
            __import__("base64").b64encode(input_bytes).decode("ascii")
        ),
        "input_preview": input_bytes[:200].decode("utf-8", errors="replace"),
        "outcomes": [dataclasses.asdict(o) for o in outcomes],
        "category": classify_divergence(outcomes),
    }
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return out_path


def classify_divergence(outcomes: list[Outcome]) -> str:
    """Bucket the divergence so reports are easy to sort by severity."""
    available = [o for o in outcomes if o.verdict != "UNAVAILABLE"]
    if any(o.verdict == "REJECT_OTHER" for o in available):
        return "UNCAUGHT_EXCEPTION"  # contract violation
    verdicts = {o.verdict for o in available}
    if "ACCEPT" in verdicts and "REJECT_TINK" in verdicts:
        return "ACCEPT_VS_REJECT"  # semantic disagreement
    return "AGREE"


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("corpus", type=pathlib.Path,
                   help="Directory of input files to feed to all runners")
    p.add_argument("--report-dir", type=pathlib.Path,
                   default=REPO_ROOT / "reports",
                   help="Where to write divergence reports")
    p.add_argument("--go-runner", type=pathlib.Path,
                   default=REPO_ROOT / "runners" / "go-runner" / "go-runner",
                   help="Path to compiled go runner binary")
    p.add_argument("--java-jar", type=pathlib.Path,
                   default=REPO_ROOT / "runners" / "java-runner.jar",
                   help="Path to java runner jar (milestone 2)")
    p.add_argument("--cc-runner", type=pathlib.Path,
                   default=REPO_ROOT / "runners" / "cc-runner" / "cc-runner",
                   help="Path to compiled cc runner (milestone 2)")
    args = p.parse_args(argv)

    args.report_dir.mkdir(parents=True, exist_ok=True)

    if not args.corpus.is_dir():
        print(f"corpus dir does not exist: {args.corpus}", file=sys.stderr)
        return 2

    files = sorted([f for f in args.corpus.iterdir() if f.is_file()])
    n_total = len(files)
    n_diverged = 0
    n_uncaught = 0

    for f in files:
        data = f.read_bytes()
        outcomes = [
            run_python(data),
            run_go(data, args.go_runner),
            run_java(data, args.java_jar),
            run_cc(data, args.cc_runner),
        ]
        if is_divergence(outcomes):
            report = write_report(args.report_dir, f, data, outcomes)
            n_diverged += 1
            if any(o.verdict == "REJECT_OTHER" for o in outcomes):
                n_uncaught += 1
            verdicts = "/".join(f"{o.runner}:{o.verdict}" for o in outcomes)
            print(f"DIVERGENCE  {f.name}  -> {verdicts}  -> {report.name}")
        else:
            verdicts = "/".join(f"{o.runner}:{o.verdict}" for o in outcomes)
            print(f"agree       {f.name}  -> {verdicts}")

    print(f"\nTotal inputs: {n_total}")
    print(f"Divergences:  {n_diverged}")
    print(f"  - of which uncaught-exception (UNCAUGHT_EXCEPTION): {n_uncaught}")
    return 0 if n_diverged == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
