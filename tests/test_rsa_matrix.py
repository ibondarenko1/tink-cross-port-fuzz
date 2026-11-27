from pathlib import Path

from tink_compat.check import _run_matrix, expected_case_ids


def _profile():
    return {
        "schema_version": 1,
        "name": "rsa-test",
        "languages": ["python", "go"],
        "baseline": {"python": "1.15.0", "go": "2.5.0"},
        "candidate": {"python": "1.16.1", "go": "2.9.0"},
    }


def _vectors():
    old = {"kty": "EC", "crv": "P-256", "x": "old", "y": "old", "kid": "old"}
    new = {"kty": "EC", "crv": "P-256", "x": "new", "y": "new", "kid": "new"}
    rsa = {"kty": "RSA", "n": "n", "e": "AQAB", "alg": "RS256", "use": "sig", "kid": "rsa"}
    return {
        "rfc": {"jwks": {"keys": [old]}, "compact": "a.b.c", "issuer": "issuer", "now": 1},
        "rotation": {
            "old": {"jwk": old, "compact": "old.token.value"},
            "new": {"jwk": new, "compact": "new.token.value"},
            "issuer": "issuer",
            "now": 1,
        },
        "rsa": {
            "state": {"keys": [rsa]},
            "token": "rsa.token.value",
            "issuer": "issuer",
            "now": 1,
            "audience": "billing-api",
            "other_audience": "inventory-api",
        },
        "rfc_rsa": {"jwks": {"keys": [rsa]}, "compact": "rfc.rsa.value", "issuer": "issuer", "now": 1},
    }


def _invoke(command, payload, cwd):
    language, version = command
    if payload["operation"] == "publish":
        return {"version": version, "runtime": f"{language}-runtime", "sets": payload["sets"]}
    results = []
    for check in payload["checks"]:
        identifier = check["id"]
        if identifier.endswith("-wrong-audience") or identifier.startswith("rsa-python-wrong-audience-"):
            outcome = "rejected"
        elif identifier.endswith("-initial-new") or identifier.endswith("-retired-old"):
            outcome = "rejected"
        else:
            outcome = "verified"
        results.append({"id": identifier, "outcome": outcome})
    return {"version": version, "runtime": f"{language}-runtime", "results": results}


def _prepare(language, version, cache, offline):
    return [language, version]


def test_rsa_vectors_add_rows_and_controls_without_changing_legacy_contract(tmp_path: Path):
    vectors = _vectors()
    report = _run_matrix(_profile(), vectors, tmp_path / "cache", True, "test", prepare_fn=_prepare, invoke_fn=_invoke)
    assert report["status"] == "PASS"
    assert report["summary"] == {"total": 48, "passed": 48, "failed": 0, "incomplete": 0}
    ids = {row["id"] for row in report["rows"]}
    assert "rsa-baseline-baseline-go-audience" in ids
    assert "rsa-baseline-baseline-go-wrong-audience" in ids
    assert "rfc-rsa-candidate-candidate-go" in ids
    assert "rsa-python-self-candidate" in ids
    assert "rsa-python-wrong-audience-candidate" in ids
    assert ids == expected_case_ids(_profile(), vectors)
    assert report["attestations"]["candidate"]["python"]["adapter_version"] == "1.16.1"
    assert report["attestations"]["candidate"]["go"]["adapter_version"] == "2.9.0"


def test_project_metadata_is_carried_without_becoming_version_evidence(tmp_path: Path):
    project = {
        "schema_version": 1,
        "base_revision": "base-sha",
        "head_revision": "head-sha",
        "baseline": {"manifests": [{"path": "requirements.txt", "sha256": "a" * 64}]},
        "candidate": {"manifests": [{"path": "requirements.txt", "sha256": "b" * 64}]},
    }
    report = _run_matrix(
        _profile(),
        _vectors(),
        tmp_path / "cache",
        True,
        "test",
        prepare_fn=_prepare,
        invoke_fn=_invoke,
        project=project,
    )
    assert report["project"] == project
    assert report["attestations"]["baseline"]["python"]["adapter_version"] == "1.15.0"
    assert report["attestations"]["candidate"]["python"]["requested_version"] == "1.16.1"
