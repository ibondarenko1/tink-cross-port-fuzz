"""Collect a tested distribution and its measured report into release assets."""

import argparse
from hashlib import sha256
import json
from pathlib import Path
import re
import shutil
import tarfile
import tomllib
from zipfile import ZipFile

from release_contract import validate_refs, validate_report


def collect(dist: Path, report_dir: Path, out: Path, revision: str) -> None:
    root = Path(__file__).resolve().parents[1]
    version = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
    stem = f"tink_release_compat-{version}"
    wheel = dist / f"{stem}-py3-none-any.whl"
    source = dist / f"{stem}.tar.gz"
    # Verify the installed package and the source distribution carry the same test inputs.
    with ZipFile(wheel) as archive, tarfile.open(source) as tar:
        for path in ("data/profile.json", "data/profile-v0.1.json", "data/catalog.json", "data/vectors.json"):
            key = "tink_compat/" + path
            original = (root / key).read_bytes()
            archived = tar.extractfile(f"{stem}/{key}")
            if archived is None or archived.read() != original or archive.read(key) != original:
                raise ValueError(f"Packaged fixture differs from source: {key}")
    report = json.loads((report_dir / "report.json").read_bytes())
    if not re.fullmatch(r"[0-9a-f]{40}", revision) or report["revision"] != revision:
        raise ValueError("The measured revision must match the revision being packaged.")
    validate_refs("v" + version)
    reference_profile = json.loads((root / "tink_compat/data/profile.json").read_bytes())
    validate_report(report, revision, reference_profile)
    for kind, filename in (("profile", "profile.json"), ("vectors", "vectors.json")):
        digest = sha256((root / "tink_compat/data" / filename).read_bytes()).hexdigest()
        if digest != report["hashes"][f"{kind}_sha256"]:
            raise ValueError(f"Report {kind} checksum differs from the bundled file.")
    files = [wheel, source, report_dir / "report.json", report_dir / "report.md"]
    if out.exists() and any(out.iterdir()):
        raise ValueError("Choose an empty output directory for release assets.")
    out.mkdir(parents=True, exist_ok=True)
    checksums = []
    for path in sorted(files, key=lambda item: item.name):
        shutil.copyfile(path, out / path.name)
        checksums.append(f"{sha256((out / path.name).read_bytes()).hexdigest()}  {path.name}")
    (out / "SHA256SUMS.txt").write_bytes(("\n".join(checksums) + "\n").encode("ascii"))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    args = parser.parse_args()
    collect(args.dist, args.report, args.out, args.revision)
