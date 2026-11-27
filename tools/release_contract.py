"""Independent acceptance checks for the public wheel and action."""

import argparse
import json
from pathlib import Path
import re
import tomllib

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "tink_compat" / "data"
PHASES = ("baseline", "candidate")


def distribution_tag():
    version = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
    source = (ROOT / "tink_compat/__init__.py").read_text(encoding="utf-8")
    if f'__version__ = "{version}"' not in source:
        raise ValueError("Package metadata and runtime version disagree.")
    return f"v{version}"


def validate_refs(tag):
    if tag != distribution_tag():
        raise ValueError(f"Tag {tag} differs from package version {distribution_tag()}.")
    for relative in (".github/workflows/release-smoke.yml", "examples/consumer.yml"):
        uses = re.findall(r"^\s*(?:-\s*)?uses:\s*ibondarenko1/tink-cross-port-fuzz@(\S+)", (ROOT / relative).read_text(), re.M)
        if uses != [tag]:
            raise ValueError(f"{relative} must exercise this release's public action at {tag}.")


def required_rows(profile):
    required = {}
    for p in PHASES:
        publisher = "python@" + profile[p]["python"]
        for prefix, expected in (("rfc-python-self", "verified"), ("rfc-rsa-python-self", "verified"),
                                 ("rsa-python-self", "verified"), ("rsa-python-wrong-audience", "rejected")):
            required[f"{prefix}-{p}"] = (publisher, publisher, expected, p, p)
        for c in PHASES:
            for language in sorted(set(profile[c]) - {"python"}):
                verifier = f"{language}@{profile[c][language]}"
                lane = f"{p}-{c}-{language}"
                cases = {f"rfc-{lane}": "verified", f"rfc-rsa-{lane}": "verified",
                         f"rsa-{lane}-audience": "verified", f"rsa-{lane}-wrong-audience": "rejected"}
                for stage in ("initial", "overlap", "retired"):
                    for key in ("old", "new"):
                        rejected = (stage, key) in {("initial", "new"), ("retired", "old")}
                        cases[f"rotation-{lane}-{stage}-{key}"] = "rejected" if rejected else "verified"
                for identifier, outcome in cases.items():
                    required[identifier] = (publisher, verifier, outcome, p, c)
    return required


def validate_report(report, revision, profile):
    if report["revision"] != revision:
        raise ValueError("Checker revision differs from the expected source.")
    for phase in PHASES:
        if report["profile"][phase] != profile[phase]:
            raise ValueError(f"The report used different {phase} packages.")
        for language, version in profile[phase].items():
            evidence = report.get("attestations", {}).get(phase, {}).get(language, {})
            if evidence.get("status") != "verified" or evidence.get("adapter_version") != version:
                raise ValueError(f"Missing package version evidence for {phase} {language} {version}.")
    required = required_rows(profile)
    rows = report["rows"]
    ids = [row["id"] for row in rows]
    if set(ids) != set(required) or len(ids) != len(required):
        raise ValueError("The report has missing, duplicate or unexpected release cases.")
    for row in rows:
        values = tuple(row[k] for k in ("producer", "consumer", "expected", "producer_phase", "consumer_phase"))
        if values != required[row["id"]] or row["actual"] != row["expected"] or row["status"] != "PASS":
            raise ValueError(f"Unverified package, phase or outcome in {row['id']}.")
    if report["status"] != "PASS" or report["summary"] != dict(total=len(rows), passed=len(rows), failed=0, incomplete=0):
        raise ValueError("The release requires all measured rows to pass.")
    if report["decision"]["rollout"]["overall"] != "either":
        raise ValueError("Expected both rollout orders to pass for the reference matrix.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--revision")
    args = parser.parse_args()
    validate_refs(args.tag)
    if args.report:
        validate_report(json.loads(args.report.read_bytes()), args.revision, json.loads((DATA / "profile.json").read_bytes()))
