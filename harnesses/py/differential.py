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
import tempfile
import time
from typing import Optional

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]


@dataclasses.dataclass
class Outcome:
    runner: str
    verdict: str  # ACCEPT / REJECT_TINK / REJECT_OTHER / TIMEOUT / UNAVAILABLE / RUNNER_ERROR
    error_class: Optional[str] = None
    error_msg: Optional[str] = None
    keyset_shape: Optional[str] = None  # e.g., "RSA:2048,e=65537"
    elapsed_ms: Optional[int] = None


def run_python(jwk_set: bytes) -> Outcome:
    """Run tink-py JwkSetConverter via in-process import."""
    t0 = time.monotonic()
    try:
        from tink import jwt
        import tink as tink_pkg
    except ImportError:
        return Outcome("py", "UNAVAILABLE", error_msg="could not load the Tink Python package")

    try:
        s = jwk_set.decode("utf-8", errors="replace")
        jwt.jwk_set_to_public_keyset_handle(s)
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
    except OSError as exc:
        return Outcome("go", "UNAVAILABLE", error_class=type(exc).__name__)

    elapsed = int((time.monotonic() - t0) * 1000)
    out = proc.stdout.decode("utf-8", errors="replace").strip()
    if proc.returncode:
        return Outcome("go", "RUNNER_ERROR", error_msg=f"runner exited {proc.returncode}")
    try:
        d = json.loads(out)
    except json.JSONDecodeError:
        d = None
    if not isinstance(d, dict) or d.get("verdict") not in ("ACCEPT", "REJECT_TINK", "REJECT_OTHER"):
        return Outcome("go", "RUNNER_ERROR", error_msg="runner returned no recognized decision")
    return Outcome("go", d["verdict"], error_class=d.get("error_class"),
                   error_msg=d.get("error_msg"), keyset_shape=d.get("keyset_shape"), elapsed_ms=elapsed)


def run_java(jwk_set: bytes, jar: pathlib.Path) -> Outcome:
    """The standalone release matrix owns Java public-key verification."""
    return Outcome("java", "UNAVAILABLE", error_msg="Java release checks run through tink-compat check")


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


def missing_ports(outcomes: list[Outcome], required: set[str]) -> list[str]:
    decided = {o.runner for o in outcomes if o.verdict in ("ACCEPT", "REJECT_TINK", "REJECT_OTHER")}
    return sorted(required - decided)


def write_summary(directory: pathlib.Path, summary: dict) -> None:
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=directory, delete=False) as f:
        temporary = pathlib.Path(f.name)
        try:
            json.dump(summary, f, indent=2)
            f.write("\n")
        except BaseException:
            f.close()
            temporary.unlink(missing_ok=True)
            raise
    try:
        os.replace(temporary, directory / "summary.json")
    finally:
        temporary.unlink(missing_ok=True)


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
                   help="Require Java in a historical corpus replay. Use tink-compat check for Java release checks.")
    p.add_argument("--cc-runner", type=pathlib.Path,
                   help="Require the C++ adapter in a historical corpus replay")
    args = p.parse_args(argv)

    if not args.corpus.is_dir():
        print(f"corpus dir does not exist: {args.corpus}", file=sys.stderr)
        return 2
    if args.report_dir.resolve() == args.corpus.resolve():
        p.error("Choose a report directory separate from the input corpus.")
    args.report_dir.mkdir(parents=True, exist_ok=True)
    required = {"py", "go"}
    if args.java_jar is not None:
        required.add("java")
    if args.cc_runner is not None:
        required.add("cc")

    files = sorted([f for f in args.corpus.iterdir() if f.is_file()])
    n_total = len(files)
    n_diverged = 0
    n_uncaught = 0
    rows = []

    for f in files:
        data = f.read_bytes()
        outcomes = [
            run_python(data),
            run_go(data, args.go_runner),
            run_java(data, args.java_jar or REPO_ROOT / "runners/java-runner.jar"),
            run_cc(data, args.cc_runner or REPO_ROOT / "runners/cc-runner/cc-runner"),
        ]
        missing = missing_ports(outcomes, required)
        differs = is_divergence(outcomes)
        state = "INCOMPLETE" if missing else "DIVERGENCE" if differs else "AGREE"
        rows.append({"input": f.name, "sha256": hashlib.sha256(data).hexdigest(),
                     "status": state, "missing": missing, "divergence": differs,
                     "verdicts": {o.runner: o.verdict for o in outcomes}})
        if differs:
            write_report(args.report_dir, f, data, outcomes)
            n_diverged += 1
            if any(o.verdict == "REJECT_OTHER" for o in outcomes):
                n_uncaught += 1
        verdicts = "/".join(f"{o.runner}:{o.verdict}" for o in outcomes)
        print(f"{state:10}  {f.name}  -> {verdicts}")

    print(f"\nTotal inputs: {n_total}")
    print(f"Divergences:  {n_diverged}")
    print(f"  - of which uncaught-exception (UNCAUGHT_EXCEPTION): {n_uncaught}")
    incomplete = not rows or any(row["missing"] for row in rows)
    status = "INCOMPLETE" if incomplete else "DIVERGENCE" if n_diverged else "AGREE"
    write_summary(args.report_dir, {"schema_version": 1, "status": status,
                                   "required_ports": sorted(required), "inputs": rows})
    return {"AGREE": 0, "DIVERGENCE": 1, "INCOMPLETE": 2}[status]


if __name__ == "__main__":
    sys.exit(main())
