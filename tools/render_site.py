"""Build the public report from the checksummed files of a published release."""

import argparse
from collections import Counter
from hashlib import sha256
from html import escape
import json
from pathlib import Path
import re
import shutil
from string import Template


REPO = "https://github.com/ibondarenko1/tink-cross-port-fuzz"
HOME = "https://ibondarenko1.github.io/tink-cross-port-fuzz/"
TEMPLATES = Path(__file__).resolve().parents[1] / "site"
STATUSES = ("PASS", "FAIL", "INCOMPLETE")


def cell(value):
    return f"<td>{escape(str(value)) if value is not None else '—'}</td>"


def render(artifacts, destination, tag, expected_revision):
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", tag):
        raise ValueError("Expected a full release tag such as v0.1.0.")
    manifest = {}
    for line in (artifacts / "SHA256SUMS.txt").read_text(encoding="utf-8").splitlines():
        digest, name = line.split(maxsplit=1)
        if not re.fullmatch(r"[0-9a-f]{64}", digest) or name in manifest:
            raise ValueError("Invalid or duplicate checksum.")
        manifest[name] = digest
    for name in ("report.json", "report.md"):
        if sha256((artifacts / name).read_bytes()).hexdigest() != manifest.get(name):
            raise ValueError(f"Checksum mismatch for {name}.")
    report = json.loads((artifacts / "report.json").read_bytes())
    counts = Counter(row["status"] for row in report["rows"])
    summary = report["summary"]
    if not report["rows"] or set(counts) - set(STATUSES):
        raise ValueError("The release must include measured rows with known verdicts.")
    if [counts[s] for s in STATUSES] != [summary[k] for k in ("passed", "failed", "incomplete")]:
        raise ValueError("Reported counts do not match individual rows.")
    if summary["total"] != len(report["rows"]):
        raise ValueError("Row count disagrees with the reported total.")
    expected = "INCOMPLETE" if counts["INCOMPLETE"] else "FAIL" if counts["FAIL"] else "PASS"
    if report["status"] != expected:
        raise ValueError("Aggregate verdict disagrees with measured rows.")
    revision = report["revision"]
    if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("A published report must identify its source commit.")
    if revision != expected_revision:
        raise ValueError("The published tag points to a different source commit.")
    profile = report["profile"]
    versions = []
    for language in sorted(profile["baseline"]):
        versions.append("<tr>" + "".join(cell(v) for v in (
            language.title(), profile["baseline"][language], profile["candidate"][language])) + "</tr>")
    measured = []
    for row in report["rows"]:
        fields = row["id"].split("-")
        publisher = f'{row["producer_phase"]} · {row["producer"]}'
        verifier = f'{row["consumer_phase"]} · {row["consumer"]}'
        scenario = row["scenario"]
        if fields[0] == "rotation":
            scenario = f"{scenario} · {fields[-1]} signature"
        measured.append("<tr>" + "".join(cell(value) for value in (
            scenario, publisher, verifier, row["expected"], row["actual"], row["status"])) + "</tr>")
    html = Template((TEMPLATES / "index.html").read_text(encoding="utf-8")).substitute(
        repo=REPO, home=HOME, tag=tag, commit=revision, short=revision[:8], verdict=expected,
        total=summary["total"], passed=counts["PASS"], failed=counts["FAIL"],
        incomplete=counts["INCOMPLETE"], versions="\n".join(versions), rows="\n".join(measured))
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "index.html").write_text(html, encoding="utf-8")
    shutil.copyfile(TEMPLATES / "style.css", destination / "style.css")
    for name in ("report.json", "report.md"):
        shutil.copyfile(artifacts / name, destination / name)
    (destination / ".nojekyll").touch()
    (destination / "sitemap.xml").write_text(
        f'<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>{HOME}</loc></url></urlset>\n',
        encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--revision", required=True)
    args = parser.parse_args()
    render(args.artifacts, args.out, args.tag, args.revision)
