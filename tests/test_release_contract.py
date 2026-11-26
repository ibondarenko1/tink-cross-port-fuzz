import json

import pytest

from tools.release_contract import DATA, distribution_tag, required_rows, validate_refs, validate_report


def test_release_contract_binds_the_tag_and_exact_case_outcomes():
    profile = json.loads((DATA / "profile.json").read_bytes())
    rows = []
    for name, (producer, consumer, expected, p, c) in required_rows(profile).items():
        rows.append(dict(id=name, producer=producer, consumer=consumer, producer_phase=p, consumer_phase=c,
                         expected=expected, actual=expected, status="PASS"))
    report = dict(rows=rows, status="PASS", summary=dict(total=len(rows), passed=len(rows), failed=0, incomplete=0),
                  profile=profile, revision="release", decision={"rollout": {"overall": "either"}})
    report["attestations"] = {
        phase: {lang: {"status": "verified", "adapter_version": version} for lang, version in profile[phase].items()}
        for phase in ("baseline", "candidate")
    }
    validate_refs(distribution_tag())
    validate_report(report, "release", profile)
    with pytest.raises(ValueError):
        validate_refs("v0.0.0")
    row = next(r for r in rows if r["id"] == "rsa-baseline-candidate-go-wrong-audience")
    row.update(actual="verified", expected="verified")
    with pytest.raises(ValueError, match=row["id"]):
        validate_report(report, "release", profile)
    row.update(actual="rejected", expected="rejected", id=rows[0]["id"])
    with pytest.raises(ValueError, match="duplicate"):
        validate_report(report, "release", profile)
