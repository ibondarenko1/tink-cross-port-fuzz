import json
from pathlib import Path

import tink_compat.check as check


def test_run_check_accepts_project_provenance(monkeypatch, tmp_path: Path):
    profile = tmp_path / "profile.json"
    vectors = tmp_path / "vectors.json"
    profile.write_text("{}\n", encoding="utf-8")
    vectors.write_text("{}\n", encoding="utf-8")
    project = {
        "schema_version": 1,
        "base_revision": "base-sha",
        "head_revision": "head-sha",
        "manifest_hashes": {"baseline": ["a" * 64], "candidate": ["b" * 64]},
    }

    def fake_matrix(profile_value, vectors_value, cache, offline, revision, **kwargs):
        assert kwargs["project"] == project
        return {
            "schema_version": 1,
            "status": "PASS",
            "summary": {"total": 0, "passed": 0, "failed": 0, "incomplete": 0},
            "rows": [],
            "decision": {"schema_version": 1, "delta_summary": {}, "rollout": {"overall": "unknown", "lanes": {}}},
            "profile": profile_value,
            "revision": revision,
            "runtimes": {},
            "project": project,
            "attestations": {},
        }

    monkeypatch.setattr(check, "_run_matrix", fake_matrix)
    report, code = check.run_check(
        profile,
        vectors,
        tmp_path / "out",
        tmp_path / "cache",
        True,
        "test",
        project=project,
    )
    assert code == 0
    assert report["project"]["base_revision"] == "base-sha"
    persisted = json.loads((tmp_path / "out" / "report.json").read_text(encoding="utf-8"))
    assert persisted["project"]["head_revision"] == "head-sha"
