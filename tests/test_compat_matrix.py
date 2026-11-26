from __future__ import annotations

import json
import os
from pathlib import Path
import sys

import pytest

from tink_compat.check import (
    DEFAULT_VECTORS,
    _default_cache,
    _expected_rows,
    _rotation_sets,
    _run_matrix,
    _validate_profile,
    _validate_rfc,
    build_parser,
    run_check,
    write_report,
)


def _profile(*languages: str) -> dict:
    return {
        "schema_version": 1,
        "name": "test-matrix",
        "languages": list(languages),
        "baseline": {"python": "1.14.1", "go": "2.4.0", "java": "1.18.0"},
        "candidate": {"python": "1.15.0", "go": "2.5.0", "java": "1.18.0"},
    }


def _vectors() -> dict:
    old = {"kty": "EC", "crv": "P-256", "x": "old", "y": "old", "kid": "old"}
    new = {"kty": "EC", "crv": "P-256", "x": "new", "y": "new", "kid": "new"}
    return {
        "rfc": {"jwks": {"keys": [old]}, "compact": "a.b.c", "issuer": "issuer", "now": 1},
        "rotation": {
            "old": {"jwk": old, "compact": "old.token.value"},
            "new": {"jwk": new, "compact": "new.token.value"},
            "issuer": "issuer",
            "now": 1,
        },
    }


def _invoke(command, payload, cwd):
    language, version = command
    if payload["operation"] == "publish":
        return {"version": version, "runtime": f"{language}-runtime", "sets": payload["sets"]}
    results = []
    for check in payload["checks"]:
        if check["id"].startswith("rfc-"):
            outcome = "verified"
        elif check["id"].endswith("-initial-old") or check["id"].endswith("-overlap-old") or check["id"].endswith("-overlap-new") or check["id"].endswith("-retired-new"):
            outcome = "verified"
        else:
            outcome = "rejected"
        results.append({"id": check["id"], "outcome": outcome})
    return {"version": version, "runtime": f"{language}-runtime", "results": results}


def _prepare(language, version, cache, offline):
    return [language, version]


def test_complete_matrix_passes_with_two_verifiers(tmp_path: Path):
    report = _run_matrix(_profile("python", "go", "java"), _vectors(), tmp_path / "cache", True, "test", prepare_fn=_prepare, invoke_fn=_invoke)
    assert report["status"] == "PASS"
    assert report["summary"] == {"total": 58, "passed": 58, "failed": 0, "incomplete": 0}
    assert set(report["runtimes"]) == {"python@1.14.1", "python@1.15.0", "go@2.4.0", "go@2.5.0", "java@1.18.0"}
    assert {row["scenario"] for row in report["rows"]} == {"rfc-7515", "rotation-initial", "rotation-overlap", "rotation-retired", "rfc-7515-python-control"}
    assert sum(row["scenario"] != "rfc-7515-python-control" for row in report["rows"]) == 56
    assert {row["producer_phase"] for row in report["rows"]} == {"baseline", "candidate"}
    assert {row["consumer_phase"] for row in report["rows"]} == {"baseline", "candidate"}


def test_missing_consumer_is_incomplete(tmp_path: Path):
    def unavailable(command, payload, cwd):
        if command[0] == "go":
            raise RuntimeError("go runner unavailable")
        return _invoke(command, payload, cwd)

    report = _run_matrix(_profile("python", "go"), _vectors(), tmp_path / "cache", True, "test", prepare_fn=_prepare, invoke_fn=unavailable)
    assert report["status"] == "INCOMPLETE"
    assert report["summary"]["incomplete"] == 28
    assert report["summary"]["failed"] == 0


def test_wrong_verdict_is_failure_not_incomplete(tmp_path: Path):
    def reject_all(command, payload, cwd):
        if payload["operation"] == "publish":
            return {"version": command[1], "runtime": "test", "sets": payload["sets"]}
        return {"version": command[1], "runtime": "test", "results": [{"id": item["id"], "outcome": "rejected"} for item in payload["checks"]]}

    report = _run_matrix(_profile("python", "go"), _vectors(), tmp_path / "cache", True, "test", prepare_fn=_prepare, invoke_fn=reject_all)
    assert report["status"] == "FAIL"
    assert report["summary"]["failed"] == 22
    assert report["summary"]["incomplete"] == 0


def test_sealed_profile_has_56_rollout_rows_and_two_python_controls():
    profile_path = Path(__file__).parents[1] / "tink_compat" / "data" / "profile.json"
    vectors_path = Path(__file__).parents[1] / "tink_compat" / "data" / "vectors.json"
    profile = json.loads(profile_path.read_text())
    vectors = json.loads(vectors_path.read_text())
    languages, versions = _validate_profile(profile)
    rows = _expected_rows(languages, versions, _rotation_sets(vectors), _validate_rfc(vectors))
    assert len(rows) == 58
    assert sum(row.scenario != "rfc-7515-python-control" for row in rows) == 56
    assert sum(row.scenario == "rfc-7515-python-control" for row in rows) == 2


def test_publisher_version_mismatch_leaves_only_its_rows_incomplete(tmp_path: Path):
    def mismatch_baseline(command, payload, cwd):
        if payload["operation"] == "publish" and command[1] == "1.14.1":
            return {"version": "unexpected", "runtime": "test", "sets": payload["sets"]}
        return _invoke(command, payload, cwd)

    report = _run_matrix(_profile("python", "go"), _vectors(), tmp_path / "cache", True, "test", prepare_fn=_prepare, invoke_fn=mismatch_baseline)
    assert report["status"] == "INCOMPLETE"
    assert report["summary"] == {"total": 30, "passed": 15, "failed": 0, "incomplete": 15}
    assert all("publisher python@1.14.1 unavailable" in row.get("detail", "") for row in report["rows"] if row["status"] == "INCOMPLETE")


def test_unavailable_publisher_does_not_block_other_phase(tmp_path: Path):
    def unavailable_baseline(command, payload, cwd):
        if payload["operation"] == "publish" and command[1] == "1.14.1":
            raise RuntimeError("baseline publisher unavailable")
        return _invoke(command, payload, cwd)

    report = _run_matrix(_profile("python", "go"), _vectors(), tmp_path / "cache", True, "test", prepare_fn=_prepare, invoke_fn=unavailable_baseline)
    assert report["status"] == "INCOMPLETE"
    assert report["summary"] == {"total": 30, "passed": 15, "failed": 0, "incomplete": 15}
    assert any("baseline publisher unavailable" in row.get("detail", "") for row in report["rows"] if row["status"] == "INCOMPLETE")
    assert all(row["status"] == "PASS" for row in report["rows"] if row["producer_phase"] == "candidate")


def test_missing_or_duplicate_result_ids_are_incomplete_not_rejected(tmp_path: Path):
    def duplicate_ids(command, payload, cwd):
        response = _invoke(command, payload, cwd)
        if payload["operation"] == "verify" and command[0] == "go" and payload["checks"]:
            response["results"] = [response["results"][0], response["results"][0]]
        return response

    report = _run_matrix(_profile("python", "go"), _vectors(), tmp_path / "cache", True, "test", prepare_fn=_prepare, invoke_fn=duplicate_ids)
    assert report["status"] == "INCOMPLETE"
    assert report["summary"]["failed"] == 0
    assert report["summary"]["incomplete"] == 28
    assert all(row["actual"] != "rejected" for row in report["rows"] if row["status"] == "INCOMPLETE")


def test_config_error_has_consistent_summary_count(tmp_path: Path):
    invalid = tmp_path / "invalid.json"
    invalid.write_text("[]")
    report, code = run_check(invalid, DEFAULT_VECTORS, tmp_path / "out", tmp_path / "cache", True, "test")
    assert code == 2
    assert report["summary"] == {"total": 1, "passed": 0, "failed": 0, "incomplete": 1}
    assert len(report["rows"]) == 1
    assert report["rows"][0]["status"] == "INCOMPLETE"


def test_cli_uses_sealed_vectors_and_user_cache(monkeypatch, tmp_path: Path):
    cache_root = tmp_path / "local"
    monkeypatch.setenv("LOCALAPPDATA", str(cache_root))
    monkeypatch.setenv("XDG_CACHE_HOME", str(cache_root))
    if os.name == "nt":
        assert str(_default_cache()).startswith(str(cache_root))
    elif sys.platform == "darwin":
        monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path / "home"))
        assert _default_cache() == tmp_path / "home" / "Library" / "Caches" / "tink-cross-port-fuzz"
    else:
        assert _default_cache() == cache_root / "tink-cross-port-fuzz"
    with pytest.raises(SystemExit):
        build_parser().parse_args(["check", "--out", str(tmp_path / "out"), "--vectors", "custom.json"])


def test_report_reuses_output_without_losing_previous_snapshot(tmp_path: Path):
    report = {"schema_version": 1, "status": "PASS", "summary": {"total": 0, "passed": 0, "failed": 0, "incomplete": 0}, "rows": [], "revision": "first"}
    write_report(report, tmp_path)
    report["revision"] = "second"
    write_report(report, tmp_path)
    assert json.loads((tmp_path / "report.json").read_text())["revision"] == "second"
    snapshots = list((tmp_path / "snapshots").glob("*-report.json"))
    assert len(snapshots) == 1
    assert json.loads(snapshots[0].read_text())["revision"] == "first"
