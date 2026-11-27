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


def render(artifacts, destination, tag, expected_revision, *, versions_file=None, permalink=False):
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
    archive = versions_file.read_text(encoding="utf-8").splitlines() if versions_file else [tag]
    if tag not in archive or any(not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", item) for item in archive):
        raise ValueError("Invalid release archive index.")
    history = " &middot; ".join(f'<a href="{HOME}{item}/">{item}</a>' for item in archive)
    orders = {
        "either": "Both rollout orders passed every required check.",
        "publisher_first": "Upgrade the Python publisher first.",
        "verifier_first": "Upgrade the verifiers first.",
        "blocked": "A required stage of both rollout orders failed.",
        "unknown": "A rollout order could not be established from the available measurements.",
    }
    recommendation = report.get("decision", {}).get("rollout", {}).get("overall")
    decision = orders.get(recommendation, "See the measured publisher and verifier combinations below.")
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
    destination.mkdir(parents=True, exist_ok=True)
    example_html = ""
    example_source = TEMPLATES.parent / "examples/reports/billing-verifier-go-2.9.0.json"
    if example_source.is_file():
        example = json.loads(example_source.read_bytes())
        if example["revision"] == revision:
            from release_contract import validate_report
            validate_report(example, revision, example["profile"])
            shutil.copyfile(example_source, destination / "example-go-upgrade.json")
            before = escape(example["profile"]["baseline"]["go"])
            after = escape(example["profile"]["candidate"]["go"])
            passed = int(example["summary"]["passed"])
            example_html = (
                "<section><h2>A dependency upgrade in a pull request</h2>"
                f"<p>The billing example upgraded Tink Go from {before} to {after}. "
                f"All {passed} project checks passed. The Go service also built and tested its selected version.</p>"
                f'<p><a href="{REPO}/pull/3">Read the upgrade PR</a> &middot; '
                '<a href="example-go-upgrade.json">Download the project report</a></p></section>'
            )
    html = Template((TEMPLATES / "index.html").read_text(encoding="utf-8")).substitute(
        repo=REPO, home=HOME + tag + "/" if permalink else HOME, tag=tag, decision=decision, history=history, example=example_html, commit=revision, short=revision[:8], verdict=expected,
        total=summary["total"], passed=counts["PASS"], failed=counts["FAIL"],
        incomplete=counts["INCOMPLETE"], versions="\n".join(versions), rows="\n".join(measured))
    (destination / "index.html").write_text(html, encoding="utf-8")
    shutil.copyfile(TEMPLATES / "style.css", destination / "style.css")
    for name in ("report.json", "report.md"):
        shutil.copyfile(artifacts / name, destination / name)
    (destination / ".nojekyll").touch()
    (destination / "sitemap.xml").write_text(
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">' +
        "".join(f"<url><loc>{url}</loc></url>" for url in [HOME] + [HOME + item + "/" for item in archive]) + "</urlset>\n",
        encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--permalink", action="store_true")
    parser.add_argument("--versions", type=Path, help="release tags, one per line")
    args = parser.parse_args()
    render(args.artifacts, args.out, args.tag, args.revision, versions_file=args.versions, permalink=args.permalink)
