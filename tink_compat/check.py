"""Run the fixed, release-version Tink compatibility matrix.

The matrix deliberately accepts only data supplied by the repository's vector
file.  Runners are prepared by :mod:`tink_compat.prepare` and communicate over
JSON on stdin/stdout.  A missing runner is an incomplete check, never an
agreement.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any, Callable, Mapping, Sequence

from . import __version__
from .decision import build_decision


PACKAGE_ROOT = pathlib.Path(__file__).resolve().parent
REPOSITORY_ROOT = PACKAGE_ROOT.parent
DEFAULT_PROFILE = PACKAGE_ROOT / "data" / "profile.json"
DEFAULT_VECTORS = PACKAGE_ROOT / "data" / "vectors.json"
RUNNER_TIMEOUT_SECONDS = 120
REQUIRED_LANGUAGES = ("python", "go", "java")

try:
    from .prepare import prepare as _prepare
except ImportError:  # The package is usable for report validation before adapters are installed.
    _prepare = None


def _default_cache() -> pathlib.Path:
    """Return a user-owned cache directory for prepared compatibility runners.

    The wheel can be installed read-only, so the cache must never default below
    the package or repository directory.  Follow the platform cache conventions
    while keeping the path stable between CLI invocations.
    """
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
        if base:
            return pathlib.Path(base) / "tink-cross-port-fuzz" / "compat"
        return pathlib.Path.home() / "AppData" / "Local" / "tink-cross-port-fuzz" / "compat"
    if sys.platform == "darwin":
        return pathlib.Path.home() / "Library" / "Caches" / "tink-cross-port-fuzz"
    base = os.environ.get("XDG_CACHE_HOME")
    if base:
        return pathlib.Path(base) / "tink-cross-port-fuzz"
    return pathlib.Path.home() / ".cache" / "tink-cross-port-fuzz"


@dataclasses.dataclass(frozen=True)
class CheckRow:
    check_id: str
    scenario: str
    producer: str
    consumer: str
    expected: str
    actual: str
    status: str
    detail: str | None = None
    producer_phase: str = ""
    consumer_phase: str = ""

    def as_dict(self) -> dict[str, str]:
        value = {
            "id": self.check_id,
            "scenario": self.scenario,
            "producer": self.producer,
            "consumer": self.consumer,
            "expected": self.expected,
            "actual": self.actual,
            "status": self.status,
            "producer_phase": self.producer_phase,
            "consumer_phase": self.consumer_phase,
        }
        if self.detail:
            value["detail"] = self.detail
        return value


@dataclasses.dataclass
class RunnerResult:
    language: str
    version: str
    response: dict[str, Any] | None
    error: str | None = None


def _read_json(path: pathlib.Path) -> tuple[dict[str, Any], bytes]:
    try:
        raw = path.read_bytes()
        value = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read JSON file {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value, raw


def _hash_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_key(value: Any, label: str) -> dict[str, Any]:
    """Return a public JWK object from either a JWK or a one-key JWK set."""
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    if isinstance(value.get("jwk"), dict):
        return _canonical_key(value["jwk"], f"{label}.jwk")
    if isinstance(value.get("keys"), list):
        if len(value["keys"]) != 1 or not isinstance(value["keys"][0], dict):
            raise ValueError(f"{label}.keys must contain one JWK")
        return dict(value["keys"][0])
    if "keys" in value:
        raise ValueError(f"{label}.keys must be a list")
    if "kty" not in value:
        raise ValueError(f"{label} must contain kty")
    return dict(value)


def _jwks(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not isinstance(value.get("keys"), list):
        raise ValueError(f"{label} must be a JWK Set with a keys list")
    if not value["keys"] or not all(isinstance(item, dict) for item in value["keys"]):
        raise ValueError(f"{label}.keys must contain JWK objects")
    return {"keys": [dict(item) for item in value["keys"]]}


def _rotation_sets(vectors: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    rotation = vectors.get("rotation")
    if not isinstance(rotation, Mapping):
        raise ValueError("vectors.rotation must be an object")
    old = _canonical_key(rotation.get("old"), "vectors.rotation.old")
    new = _canonical_key(rotation.get("new"), "vectors.rotation.new")
    return {
        "initial": {"keys": [old]},
        "overlap": {"keys": [old, new]},
        "retired": {"keys": [new]},
    }


def _rotation_compact(rotation: Mapping[str, Any], name: str) -> str:
    value = rotation.get(name)
    if isinstance(value, Mapping):
        compact = value.get("compact")
        if isinstance(compact, str) and compact.count(".") == 2:
            return compact
    raise ValueError(f"vectors.rotation.{name}.compact must be a compact JWT")


def _validate_profile(profile: Mapping[str, Any]) -> tuple[list[str], dict[str, dict[str, str]]]:
    if profile.get("schema_version") != 1:
        raise ValueError("profile.schema_version must be 1")
    if not isinstance(profile.get("name"), str) or not profile["name"].strip():
        raise ValueError("profile.name must be a non-empty string")
    selected = profile.get("languages")
    if selected is None:
        selected = list(REQUIRED_LANGUAGES)
    if not isinstance(selected, list) or not selected or not all(isinstance(item, str) for item in selected):
        raise ValueError("profile.languages must be a non-empty list")
    selected = [item.lower() for item in selected]
    if len(set(selected)) != len(selected):
        raise ValueError("profile.languages must not contain duplicates")
    unknown = sorted(set(selected) - set(REQUIRED_LANGUAGES))
    if unknown:
        raise ValueError(f"profile.languages contains unsupported language(s): {', '.join(unknown)}")
    if "python" not in selected or not ({"go", "java"} & set(selected)) or len(selected) < 2:
        raise ValueError("profile.languages must include python and go or java")
    versions: dict[str, dict[str, str]] = {}
    for phase in ("baseline", "candidate"):
        raw = profile.get(phase)
        if not isinstance(raw, Mapping):
            raise ValueError(f"profile.{phase} must be an object")
        versions[phase] = {}
        for language in selected:
            version = raw.get(language)
            if not isinstance(version, str) or not version.strip():
                raise ValueError(f"profile.{phase}.{language} must be a non-empty version")
            versions[phase][language] = version
    return selected, versions


def _validate_rfc(vectors: Mapping[str, Any]) -> dict[str, Any]:
    rfc = vectors.get("rfc")
    if not isinstance(rfc, Mapping):
        raise ValueError("vectors.rfc must be an object")
    jwks = _jwks(rfc.get("jwks"), "vectors.rfc.jwks")
    compact = rfc.get("compact")
    issuer = rfc.get("issuer")
    now = rfc.get("now")
    if not isinstance(compact, str) or compact.count(".") != 2:
        raise ValueError("vectors.rfc.compact must be a compact JWT")
    if not isinstance(issuer, str) or not issuer:
        raise ValueError("vectors.rfc.issuer must be a non-empty string")
    if not isinstance(now, int) or isinstance(now, bool):
        raise ValueError("vectors.rfc.now must be an integer")
    return {"jwks": jwks, "compact": compact, "issuer": issuer, "now": now}


def _validate_rsa(vectors: Mapping[str, Any], rfc: Mapping[str, Any]) -> dict[str, Any] | None:
    """Validate the optional fixed RS256 audience vector.

    The vector carries only public JWK material and a pre-signed compact token.
    ``state`` is accepted either as a JWK Set or as an object containing a
    ``keys`` member so the fixture remains easy to inspect and version.
    """

    raw = vectors.get("rsa")
    if raw is None:
        return None
    if not isinstance(raw, Mapping):
        raise ValueError("vectors.rsa must be an object")
    state = raw.get("state", raw.get("jwks"))
    jwks = _jwks(state, "vectors.rsa.state")
    token = raw.get("token", raw.get("compact"))
    audience = raw.get("audience")
    other_audience = raw.get("other_audience")
    issuer = raw.get("issuer", rfc["issuer"])
    now = raw.get("now", rfc["now"])
    if not isinstance(token, str) or token.count(".") != 2:
        raise ValueError("vectors.rsa.token must be a compact JWT")
    if not isinstance(audience, str) or not audience:
        raise ValueError("vectors.rsa.audience must be a non-empty string")
    if not isinstance(other_audience, str) or not other_audience or other_audience == audience:
        raise ValueError("vectors.rsa.other_audience must differ from audience")
    if not isinstance(issuer, str) or not issuer:
        raise ValueError("vectors.rsa.issuer must be a non-empty string")
    if not isinstance(now, int) or isinstance(now, bool):
        raise ValueError("vectors.rsa.now must be an integer")
    return {
        "jwks": jwks,
        "compact": token,
        "issuer": issuer,
        "now": now,
        "audience": audience,
        "other_audience": other_audience,
        "source": raw.get("source"),
    }


def _validate_rfc_rsa(vectors: Mapping[str, Any]) -> dict[str, Any] | None:
    """Validate an optional public RFC 7515 A.2 RS256 vector."""

    raw = vectors.get("rfc_rsa")
    if raw is None:
        return None
    if not isinstance(raw, Mapping):
        raise ValueError("vectors.rfc_rsa must be an object")
    jwks = _jwks(raw.get("jwks", raw.get("state")), "vectors.rfc_rsa.jwks")
    compact = raw.get("compact", raw.get("token"))
    issuer = raw.get("issuer")
    now = raw.get("now")
    if not isinstance(compact, str) or compact.count(".") != 2:
        raise ValueError("vectors.rfc_rsa.compact must be a compact JWT")
    if not isinstance(issuer, str) or not issuer:
        raise ValueError("vectors.rfc_rsa.issuer must be a non-empty string")
    if not isinstance(now, int) or isinstance(now, bool):
        raise ValueError("vectors.rfc_rsa.now must be an integer")
    return {"jwks": jwks, "compact": compact, "issuer": issuer, "now": now, "source": raw.get("source")}


def _prepare_command(
    language: str,
    version: str,
    cache: pathlib.Path,
    offline: bool,
    prepare_fn: Callable[..., Sequence[str] | str | pathlib.Path] | None = None,
) -> list[str]:
    preparer = prepare_fn or _prepare
    if preparer is None:
        raise RuntimeError("runner preparation is unavailable")
    value = preparer(language, version, cache, offline=offline)
    if isinstance(value, (str, pathlib.Path)):
        return [str(value)]
    if not isinstance(value, Sequence) or isinstance(value, (bytes, bytearray)):
        raise RuntimeError(f"runner preparation for {language} {version} returned no command")
    command = [str(item) for item in value]
    if not command or any(not item for item in command):
        raise RuntimeError(f"runner preparation for {language} {version} returned an empty command")
    return command


def _invoke(command: Sequence[str], payload: Mapping[str, Any], cwd: pathlib.Path) -> dict[str, Any]:
    try:
        process = subprocess.run(
            list(command),
            input=(json.dumps(payload, separators=(",", ":")) + "\n").encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd,
            timeout=RUNNER_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError(f"runner timed out after {RUNNER_TIMEOUT_SECONDS}s") from exc
    except OSError as exc:
        raise RuntimeError(f"runner could not start: {exc}") from exc
    if process.returncode != 0:
        detail = process.stderr.decode("utf-8", errors="replace").strip()[:400]
        raise RuntimeError(f"runner exited {process.returncode}" + (f": {detail}" if detail else ""))
    try:
        response = json.loads(process.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"runner returned invalid JSON: {exc}") from exc
    if not isinstance(response, dict):
        raise RuntimeError("runner response must be a JSON object")
    return response


def _run_runner(
    language: str,
    version: str,
    cache: pathlib.Path,
    offline: bool,
    payload: Mapping[str, Any],
    commands: dict[tuple[str, str], list[str]],
    invoke: Callable[[Sequence[str], Mapping[str, Any], pathlib.Path], dict[str, Any]],
    prepare_fn: Callable[..., Sequence[str] | str | pathlib.Path] | None = None,
) -> RunnerResult:
    key = (language, version)
    try:
        command = commands.get(key)
        if command is None:
            command = _prepare_command(language, version, cache, offline, prepare_fn)
            commands[key] = command
        response = invoke(command, payload, REPOSITORY_ROOT)
        if not isinstance(response, Mapping):
            return RunnerResult(language, version, None, "runner response must be a JSON object")
        response = dict(response)
    except Exception as exc:  # A failed adapter is an incomplete matrix cell.
        return RunnerResult(language, version, None, str(exc))
    reported = response.get("version")
    runtime = response.get("runtime")
    if not isinstance(reported, str) or reported != version:
        return RunnerResult(language, version, response, f"runner reported version {reported!r}, expected {version!r}")
    if not isinstance(runtime, str) or not runtime.strip():
        return RunnerResult(language, version, response, "runner response has no runtime")
    return RunnerResult(language, version, response)


def _row(
    check_id: str,
    scenario: str,
    producer: str,
    consumer: str,
    expected: str,
    actual: str,
    status: str,
    detail: str | None = None,
    producer_phase: str = "",
    consumer_phase: str = "",
) -> CheckRow:
    return CheckRow(
        check_id,
        scenario,
        producer,
        consumer,
        expected,
        actual,
        status,
        detail,
        producer_phase,
        consumer_phase,
    )


def _expected_rows(
    languages: list[str],
    versions: Mapping[str, Mapping[str, str]],
    rotation: Mapping[str, Any],
    rfc: Mapping[str, Any],
    rsa: Mapping[str, Any] | None = None,
    rfc_rsa: Mapping[str, Any] | None = None,
) -> list[CheckRow]:
    verifiers = [language for language in languages if language != "python"]
    rows: list[CheckRow] = []
    for producer_phase in ("baseline", "candidate"):
        producer = f"python@{versions[producer_phase]['python']}"
        for consumer_phase in ("baseline", "candidate"):
            for language in verifiers:
                consumer = f"{language}@{versions[consumer_phase][language]}"
                rows.append(
                    _row(
                        f"rfc-{producer_phase}-{consumer_phase}-{language}",
                        "rfc-7515",
                        producer,
                        consumer,
                        "verified",
                        "pending",
                        "INCOMPLETE",
                        producer_phase=producer_phase,
                        consumer_phase=consumer_phase,
                    )
                )
                for phase, expected_old, expected_new in (("initial", "verified", "rejected"), ("overlap", "verified", "verified"), ("retired", "rejected", "verified")):
                    for key_name, expected in (("old", expected_old), ("new", expected_new)):
                        rows.append(
                            _row(
                                f"rotation-{producer_phase}-{consumer_phase}-{language}-{phase}-{key_name}",
                                f"rotation-{phase}",
                                producer,
                                consumer,
                                expected,
                                "pending",
                                "INCOMPLETE",
                                producer_phase=producer_phase,
                                consumer_phase=consumer_phase,
                            )
                        )
                if rfc_rsa is not None:
                    rows.append(
                        _row(
                            f"rfc-rsa-{producer_phase}-{consumer_phase}-{language}",
                            "rfc-7515-rs256",
                            producer,
                            consumer,
                            "verified",
                            "pending",
                            "INCOMPLETE",
                            producer_phase=producer_phase,
                            consumer_phase=consumer_phase,
                        )
                    )
                if rsa is not None:
                    rows.extend(
                        (
                            _row(
                                f"rsa-{producer_phase}-{consumer_phase}-{language}-audience",
                                "rsa-jwt-audience",
                                producer,
                                consumer,
                                "verified",
                                "pending",
                                "INCOMPLETE",
                                producer_phase=producer_phase,
                                consumer_phase=consumer_phase,
                            ),
                            _row(
                                f"rsa-{producer_phase}-{consumer_phase}-{language}-wrong-audience",
                                "rsa-jwt-audience",
                                producer,
                                consumer,
                                "rejected",
                                "pending",
                                "INCOMPLETE",
                                producer_phase=producer_phase,
                                consumer_phase=consumer_phase,
                            ),
                        )
                    )
        # These two controls verify the RFC 7515 signature through Python's
        # public verifier, independently of the Go/Java consumer lanes.
        rows.append(
            _row(
                f"rfc-python-self-{producer_phase}",
                "rfc-7515-python-control",
                producer,
                producer,
                "verified",
                "pending",
                "INCOMPLETE",
                producer_phase=producer_phase,
                consumer_phase=producer_phase,
            )
        )
        if rfc_rsa is not None:
            rows.append(
                _row(
                    f"rfc-rsa-python-self-{producer_phase}",
                    "rfc-7515-rs256-python-control",
                    producer,
                    producer,
                    "verified",
                    "pending",
                    "INCOMPLETE",
                    producer_phase=producer_phase,
                    consumer_phase=producer_phase,
                )
            )
        if rsa is not None:
            rows.extend(
                (
                    _row(
                        f"rsa-python-self-{producer_phase}",
                        "rsa-jwt-audience-python-control",
                        producer,
                        producer,
                        "verified",
                        "pending",
                        "INCOMPLETE",
                        producer_phase=producer_phase,
                        consumer_phase=producer_phase,
                    ),
                    _row(
                        f"rsa-python-wrong-audience-{producer_phase}",
                        "rsa-jwt-audience-python-control",
                        producer,
                        producer,
                        "rejected",
                        "pending",
                        "INCOMPLETE",
                        producer_phase=producer_phase,
                        consumer_phase=producer_phase,
                    ),
                )
            )
    return rows


def expected_case_ids(profile: Mapping[str, Any], vectors: Mapping[str, Any]) -> set[str]:
    """Return the independent row-ID contract for release packaging.

    Packaging checks use this function instead of a formula based on the
    number of verifiers.  The contract grows when an explicitly validated
    vector is present and remains stable for the historical profile.
    """

    languages, versions = _validate_profile(profile)
    rfc = _validate_rfc(vectors)
    rsa = _validate_rsa(vectors, rfc)
    rfc_rsa = _validate_rfc_rsa(vectors)
    rotation = _rotation_sets(vectors)
    return {row.check_id for row in _expected_rows(languages, versions, rotation, rfc, rsa, rfc_rsa)}


def _response_results(response: dict[str, Any] | None, expected_ids: set[str]) -> tuple[dict[str, dict[str, Any]], str | None]:
    if response is None:
        return {}, "runner did not return a response"
    raw = response.get("results")
    if not isinstance(raw, list) or not all(isinstance(item, dict) for item in raw):
        return {}, "runner response results must be a list of objects"
    result_ids = [item.get("id") for item in raw]
    if any(not isinstance(item, str) or not item for item in result_ids):
        return {}, "runner result has a missing id"
    if len(set(result_ids)) != len(result_ids):
        return {}, "runner returned duplicate result IDs"
    if set(result_ids) != expected_ids:
        return {}, "runner result IDs do not exactly match requested checks"
    return {item["id"]: item for item in raw}, None


def _apply_consumer_results(rows: list[CheckRow], result: RunnerResult, expected_ids: set[str]) -> list[CheckRow]:
    result_map, issue = _response_results(result.response, expected_ids)
    output: list[CheckRow] = []
    for row in rows:
        item = result_map.get(row.check_id)
        if result.error:
            output.append(dataclasses.replace(row, actual="unavailable", status="INCOMPLETE", detail=result.error))
            continue
        if issue:
            output.append(dataclasses.replace(row, actual="invalid", status="INCOMPLETE", detail=issue))
            continue
        outcome = item.get("outcome") if item else None
        if outcome not in {"verified", "rejected", "error"}:
            output.append(dataclasses.replace(row, actual=str(outcome or "missing"), status="INCOMPLETE", detail="invalid outcome"))
        elif outcome == "error":
            output.append(dataclasses.replace(row, actual="error", status="INCOMPLETE", detail=str(item.get("detail") or "adapter error")))
        else:
            status = "PASS" if outcome == row.expected else "FAIL"
            output.append(dataclasses.replace(row, actual=outcome, status=status, detail=str(item.get("detail")) if item.get("detail") else None))
    return output


def _publisher_exports(
    result: RunnerResult,
    producer_label: str,
    required: Sequence[str] = ("rfc", "initial", "overlap", "retired"),
) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
    """Validate the public sets returned by one publisher.

    A response with a bad reported version is not usable merely because it also
    contains a plausible ``sets`` object.  Each missing phase is kept separate
    so the verifier can still run independent lanes and the report can explain
    exactly which rows were unavailable.
    """
    if result.error:
        reason = f"publisher {producer_label} unavailable: {result.error}"
        return {}, {name: reason for name in required}
    if result.response is None:
        reason = f"publisher {producer_label} unavailable: no response"
        return {}, {name: reason for name in required}
    raw_sets = result.response.get("sets")
    if not isinstance(raw_sets, Mapping):
        reason = f"publisher {producer_label} returned no public sets"
        return {}, {name: reason for name in required}
    exports: dict[str, dict[str, Any]] = {}
    errors: dict[str, str] = {}
    for name in required:
        try:
            exports[name] = _jwks(raw_sets.get(name), f"publisher {producer_label}.sets.{name}")
        except ValueError as exc:
            errors[name] = str(exc)
    return exports, errors


def _adapter_attestation(
    result: RunnerResult,
    language: str,
    phase: str,
    requested_version: str,
    operation: str,
) -> dict[str, Any]:
    """Record package identity only from a validated adapter response.

    The profile is the requested input.  It is never treated as proof that a
    runner installed that version.  ``_run_runner`` already rejects a response
    whose reported version differs from the request, so a ``verified`` record
    here is an attestation from the adapter process itself.
    """

    response = result.response or {}
    reported = response.get("version")
    adapter_version = reported if isinstance(reported, str) else None
    runtime = response.get("runtime")
    value: dict[str, Any] = {
        "language": language,
        "phase": phase,
        "requested_version": requested_version,
        "adapter_version": adapter_version,
        "runtime": runtime if isinstance(runtime, str) else None,
        "operation": operation,
        "source": "adapter-response",
        "status": "verified" if result.error is None and adapter_version == requested_version else "incomplete",
    }
    if result.error:
        value["error"] = result.error
    return value


def _run_matrix(
    profile: Mapping[str, Any],
    vectors: Mapping[str, Any],
    cache: pathlib.Path,
    offline: bool,
    revision: str,
    *,
    prepare_fn: Callable[..., Sequence[str] | str | pathlib.Path] | None = None,
    invoke_fn: Callable[[Sequence[str], Mapping[str, Any], pathlib.Path], dict[str, Any]] | None = None,
    project: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    invoke = invoke_fn or _invoke
    languages, versions = _validate_profile(profile)
    rfc = _validate_rfc(vectors)
    rsa = _validate_rsa(vectors, rfc)
    rfc_rsa = _validate_rfc_rsa(vectors)
    rotation = _rotation_sets(vectors)
    rotation_data = vectors["rotation"]
    if not isinstance(rotation_data, Mapping):
        raise ValueError("vectors.rotation must be an object")
    rotation_issuer = rotation_data.get("issuer", rfc["issuer"])
    rotation_now = rotation_data.get("now", rfc["now"])
    if not isinstance(rotation_issuer, str) or not rotation_issuer:
        raise ValueError("vectors.rotation.issuer must be a non-empty string")
    if not isinstance(rotation_now, int) or isinstance(rotation_now, bool):
        raise ValueError("vectors.rotation.now must be an integer")

    rows = _expected_rows(languages, versions, rotation, rfc, rsa, rfc_rsa)
    commands: dict[tuple[str, str], list[str]] = {}
    publishers: dict[str, RunnerResult] = {}
    publisher_exports: dict[str, tuple[dict[str, dict[str, Any]], dict[str, str]]] = {}
    python_controls: dict[str, RunnerResult] = {}
    python_control_expected: dict[str, set[str]] = {}
    python_control_errors: dict[str, str] = {}
    consumers: dict[tuple[str, str], RunnerResult] = {}
    for phase in ("baseline", "candidate"):
        version = versions[phase]["python"]
        publish_sets = dict(rotation)
        # The RFC 7515 row must exercise the publisher's actual export too; a
        # global fixture key would only test the verifier and mislabel the lane.
        publish_sets["rfc"] = rfc["jwks"]
        if rsa is not None:
            publish_sets["rsa"] = rsa["jwks"]
        if rfc_rsa is not None:
            publish_sets["rfc_rsa"] = rfc_rsa["jwks"]
        payload = {"operation": "publish", "sets": publish_sets}
        result = _run_runner("python", version, cache, offline, payload, commands, invoke, prepare_fn)
        publishers[phase] = result
        required_sets = ["rfc", "initial", "overlap", "retired"]
        if rsa is not None:
            required_sets.append("rsa")
        if rfc_rsa is not None:
            required_sets.append("rfc_rsa")
        publisher_exports[phase] = _publisher_exports(result, f"python@{version}", required_sets)

    # Run one actual Python verification call per publisher phase.  This is a
    # measured control for the Python API, not an inference from publishing or
    # from the verifier ports' answers.
    for phase in ("baseline", "candidate"):
        version = versions[phase]["python"]
        check_id = f"rfc-python-self-{phase}"
        exports, errors = publisher_exports[phase]
        if "rfc" not in exports:
            reason = errors.get("rfc", "publisher RFC export unavailable")
            python_control_errors[phase] = reason
            python_control_expected[phase] = set()
            python_controls[phase] = RunnerResult("python", version, None, reason)
            continue
        control_checks: list[dict[str, Any]] = [
            {
                "id": check_id,
                "jwks": exports["rfc"],
                "compact": rfc["compact"],
                "issuer": rfc["issuer"],
                "now": rfc["now"],
            }
        ]
        if rfc_rsa is not None and "rfc_rsa" in exports:
            control_checks.append(
                {
                    "id": f"rfc-rsa-python-self-{phase}",
                    "jwks": exports["rfc_rsa"],
                    "compact": rfc_rsa["compact"],
                    "issuer": rfc_rsa["issuer"],
                    "now": rfc_rsa["now"],
                }
            )
        if rsa is not None and "rsa" in exports:
            control_checks.extend(
                (
                    {
                        "id": f"rsa-python-self-{phase}",
                        "jwks": exports["rsa"],
                        "compact": rsa["compact"],
                        "issuer": rsa["issuer"],
                        "now": rsa["now"],
                        "audience": rsa["audience"],
                    },
                    {
                        "id": f"rsa-python-wrong-audience-{phase}",
                        "jwks": exports["rsa"],
                        "compact": rsa["compact"],
                        "issuer": rsa["issuer"],
                        "now": rsa["now"],
                        "audience": rsa["other_audience"],
                    },
                )
            )
        control = {
            "operation": "verify",
            "checks": control_checks,
        }
        python_controls[phase] = _run_runner("python", version, cache, offline, control, commands, invoke, prepare_fn)
        python_control_expected[phase] = {str(item["id"]) for item in control_checks}

    verifier_languages = [language for language in languages if language != "python"]
    requested_ids: dict[tuple[str, str], set[str]] = {}
    unavailable_ids: dict[tuple[str, str, str], str] = {}
    for consumer_phase in ("baseline", "candidate"):
        for language in verifier_languages:
            version = versions[consumer_phase][language]
            checks: list[dict[str, Any]] = []
            key = (consumer_phase, language)
            requested_ids[key] = set()
            for producer_phase in ("baseline", "candidate"):
                exports, errors = publisher_exports[producer_phase]
                rfc_id = f"rfc-{producer_phase}-{consumer_phase}-{language}"
                if "rfc" in exports:
                    checks.append({"id": rfc_id, "jwks": exports["rfc"], "compact": rfc["compact"], "issuer": rfc["issuer"], "now": rfc["now"]})
                    requested_ids[key].add(rfc_id)
                else:
                    unavailable_ids[(key[0], key[1], rfc_id)] = errors.get("rfc", "publisher RFC export unavailable")
                if rfc_rsa is not None:
                    rsa_rfc_id = f"rfc-rsa-{producer_phase}-{consumer_phase}-{language}"
                    if "rfc_rsa" in exports:
                        checks.append(
                            {
                                "id": rsa_rfc_id,
                                "jwks": exports["rfc_rsa"],
                                "compact": rfc_rsa["compact"],
                                "issuer": rfc_rsa["issuer"],
                                "now": rfc_rsa["now"],
                            }
                        )
                        requested_ids[key].add(rsa_rfc_id)
                    else:
                        unavailable_ids[(key[0], key[1], rsa_rfc_id)] = errors.get("rfc_rsa", "publisher RFC RSA export unavailable")
                if rsa is not None:
                    rsa_checks = (
                        (f"rsa-{producer_phase}-{consumer_phase}-{language}-audience", rsa["audience"]),
                        (f"rsa-{producer_phase}-{consumer_phase}-{language}-wrong-audience", rsa["other_audience"]),
                    )
                    for rsa_id, audience in rsa_checks:
                        if "rsa" in exports:
                            checks.append(
                                {
                                    "id": rsa_id,
                                    "jwks": exports["rsa"],
                                    "compact": rsa["compact"],
                                    "issuer": rsa["issuer"],
                                    "now": rsa["now"],
                                    "audience": audience,
                                }
                            )
                            requested_ids[key].add(rsa_id)
                        else:
                            unavailable_ids[(key[0], key[1], rsa_id)] = errors.get("rsa", "publisher RSA export unavailable")
                for rotation_phase, exported in exports.items():
                    if rotation_phase in {"rfc", "rsa", "rfc_rsa"}:
                        continue
                    for key_name in ("old", "new"):
                        check_id = f"rotation-{producer_phase}-{consumer_phase}-{language}-{rotation_phase}-{key_name}"
                        checks.append({"id": check_id, "jwks": exported, "compact": _rotation_compact(rotation_data, key_name), "issuer": rotation_issuer, "now": rotation_now})
                        requested_ids[key].add(check_id)
                for rotation_phase in ("initial", "overlap", "retired"):
                    if rotation_phase not in exports:
                        reason = errors.get(rotation_phase, "publisher rotation export unavailable")
                        for key_name in ("old", "new"):
                            check_id = f"rotation-{producer_phase}-{consumer_phase}-{language}-{rotation_phase}-{key_name}"
                            unavailable_ids[(key[0], key[1], check_id)] = reason
            consumers[key] = _run_runner(language, version, cache, offline, {"operation": "verify", "checks": checks}, commands, invoke, prepare_fn)

    control_rows = [row for row in rows if row.scenario.endswith("python-control")]
    matrix_rows = [row for row in rows if not row.scenario.endswith("python-control")]
    by_consumer: dict[tuple[str, str], list[CheckRow]] = {}
    for row in matrix_rows:
        by_consumer.setdefault((row.consumer_phase, row.consumer.split("@", 1)[0]), []).append(row)
    rendered_rows: list[CheckRow] = []
    for key, group in by_consumer.items():
        result = consumers.get(key) or RunnerResult(key[1], versions[key[0]][key[1]], None, "consumer was not run")
        expected_ids = requested_ids.get(key, set())
        requested_rows = [row for row in group if row.check_id in expected_ids]
        unavailable_rows = [row for row in group if row.check_id not in expected_ids]
        rendered_rows.extend(_apply_consumer_results(requested_rows, result, expected_ids))
        for row in unavailable_rows:
            detail = unavailable_ids.get((key[0], key[1], row.check_id), "publisher output was not submitted")
            rendered_rows.append(dataclasses.replace(row, actual="unavailable", status="INCOMPLETE", detail=detail))
    for row in control_rows:
        phase = row.producer_phase
        expected_ids = python_control_expected.get(phase, set())
        if row.check_id in expected_ids:
            rendered_rows.extend(_apply_consumer_results([row], python_controls[phase], expected_ids))
        else:
            rendered_rows.append(
                dataclasses.replace(
                    row,
                    actual="unavailable",
                    status="INCOMPLETE",
                    detail=python_control_errors.get(phase, "publisher output was not submitted"),
                )
            )
    rows = sorted(rendered_rows, key=lambda row: row.check_id)
    summary = {state.lower(): sum(row.status == state for row in rows) for state in ("PASS", "FAIL", "INCOMPLETE")}
    status = "INCOMPLETE" if summary["incomplete"] else ("FAIL" if summary["fail"] else "PASS")
    runtimes: dict[str, str] = {}
    for phase, result in publishers.items():
        version = versions[phase]["python"]
        if result.response and isinstance(result.response.get("runtime"), str):
            runtimes[f"python@{version}"] = result.response["runtime"]
    for (phase, language), result in consumers.items():
        if result.response and isinstance(result.response.get("runtime"), str):
            runtimes[f"{language}@{versions[phase][language]}"] = result.response["runtime"]
    attestations: dict[str, dict[str, dict[str, Any]]] = {"baseline": {}, "candidate": {}}
    for phase in ("baseline", "candidate"):
        python_version = versions[phase]["python"]
        attestations[phase]["python"] = _adapter_attestation(
            publishers[phase], "python", phase, python_version, "publish"
        )
        for language in verifier_languages:
            version = versions[phase][language]
            result = consumers.get((phase, language)) or RunnerResult(
                language, version, None, "consumer was not run"
            )
            attestations[phase][language] = _adapter_attestation(
                result, language, phase, version, "verify"
            )
    row_dicts = [row.as_dict() for row in rows]
    return {
        "schema_version": 1,
        "status": status,
        "summary": {
            "total": len(rows),
            "passed": summary["pass"],
            "failed": summary["fail"],
            "incomplete": summary["incomplete"],
        },
        "rows": row_dicts,
        "decision": build_decision(row_dicts),
        "profile": dict(profile),
        "project": dict(project) if isinstance(project, Mapping) else None,
        "revision": revision,
        "runtimes": runtimes,
        "attestations": attestations,
    }


def _markdown(report: Mapping[str, Any]) -> str:
    summary = report["summary"]

    def cell(value: Any) -> str:
        return str(value if value is not None else "").replace("|", "\\|").replace("\n", " ")

    rows = list(report.get("rows", []))

    def human_decision(value: Any) -> str:
        return {
            "publisher_first": "Publisher first",
            "verifier_first": "Verifier first",
            "either": "Either order",
            "mixed": "Different order by verifier",
            "blocked": "Blocked",
            "unknown": "Unknown",
        }.get(str(value), "Unknown")

    def human_delta(value: Any) -> str:
        return {
            "regression": "Regression",
            "fixed": "Fixed",
            "persistent": "Still failing",
            "unchanged": "Unchanged",
            "not_measured": "Not measured",
        }.get(str(value), "Not measured")

    def human_state(value: Any) -> str:
        return {
            "pass": "Pass",
            "fail": "Fail",
            "not_measured": "Not measured",
        }.get(str(value), "Not measured")

    decision = report.get("decision")
    rollout = decision.get("rollout") if isinstance(decision, Mapping) else None
    overall = rollout.get("overall") if isinstance(rollout, Mapping) else "unknown"
    lines = [
        f"# Tink compatibility report: {report['status']}",
        "",
        f"Rollout verdict: **{human_decision(overall)}**",
        "",
        f"Revision: `{report.get('revision') or 'unknown'}`",
        "",
        f"Passed {summary['passed']} / {summary['total']}; Failed {summary['failed']}; Incomplete {summary['incomplete']}",
    ]
    if isinstance(decision, Mapping):
        delta_summary = decision.get("delta_summary")
        if not isinstance(delta_summary, Mapping):
            delta_summary = {}
        delta_text = ", ".join(f"{human_delta(key)} {value}" for key, value in sorted(delta_summary.items())) or "none"
        lines.extend(["", f"Scenario deltas: {cell(delta_text)}"])
        lanes = rollout.get("lanes") if isinstance(rollout, Mapping) else {}
        if isinstance(lanes, Mapping) and lanes:
            lines.extend(["", "| Verifier lane | Rollout decision |", "| --- | --- |"])
            for language, lane in sorted(lanes.items()):
                value = lane.get("decision", "unknown") if isinstance(lane, Mapping) else "unknown"
                lines.append(f"| {cell(language)} | {cell(human_decision(value))} |")
    profile = report.get("profile")
    if isinstance(profile, Mapping):
        name = profile.get("name")
        if name:
            lines.extend(["", f"Profile: `{cell(name)}`"])
        baseline = profile.get("baseline")
        candidate = profile.get("candidate")
        if isinstance(baseline, Mapping) and isinstance(candidate, Mapping):
            lines.extend(["", "| Role | Baseline | Candidate |", "| --- | --- | --- |"])
            for language in ("python", "go", "java"):
                if language in baseline or language in candidate:
                    lines.append(f"| {language} | {cell(baseline.get(language, ''))} | {cell(candidate.get(language, ''))} |")

    project = report.get("project")
    if isinstance(project, Mapping):
        lines.extend(["", "## Project provenance", ""])
        for phase_name, label in (("baseline", "Baseline"), ("candidate", "Candidate")):
            side = project.get(phase_name, {})
            commit = side.get("revision") or project.get("base_revision" if phase_name == "baseline" else "head_revision")
            if commit and side.get("revision_exact") is False:
                commit = f"{commit} (working tree inputs)"
            lines.append(f"{label} revision: `{cell(commit or 'unverified')}`")
        manifests: list[tuple[str, Mapping[str, Any]]] = []
        for phase_name in ("baseline", "candidate"):
            phase_data = project.get(phase_name)
            if not isinstance(phase_data, Mapping):
                continue
            for item in phase_data.get("manifests", []):
                if isinstance(item, Mapping):
                    manifests.append((phase_name, item))
        if manifests:
            lines.extend(
                [
                    "",
                    "| Phase | Manifest | SHA-256 | Declared | Resolved |",
                    "| --- | --- | --- | --- | --- |",
                ]
            )
            for phase_name, item in manifests:
                lines.append(
                    "| "
                    + " | ".join(
                        (
                            cell(phase_name),
                            cell(item.get("path") or item.get("kind") or "unknown"),
                            cell(item.get("sha256") or ""),
                            cell(item.get("declared_version") or ""),
                            cell(item.get("resolved_version") or ""),
                        )
                    )
                    + " |"
                )

    attestations = report.get("attestations")
    if isinstance(attestations, Mapping):
        lines.extend(["", "## Adapter attestations", "", "| Phase | Language | Requested | Adapter reported | Status |", "| --- | --- | --- | --- | --- |"])
        for phase_name in ("baseline", "candidate"):
            phase_data = attestations.get(phase_name)
            if not isinstance(phase_data, Mapping):
                continue
            for language, value in sorted(phase_data.items()):
                if not isinstance(value, Mapping):
                    continue
                status = "Verified" if value.get("status") == "verified" else "Incomplete"
                lines.append(
                    "| "
                    + " | ".join(
                        (
                            cell(phase_name),
                            cell(language),
                            cell(value.get("requested_version") or ""),
                            cell(value.get("adapter_version") or "unreported"),
                            status,
                        )
                    )
                    + " |"
                )

    if isinstance(decision, Mapping):
        deltas = decision.get("deltas")
        changed = [item for item in deltas if isinstance(item, Mapping) and item.get("kind") != "unchanged"] if isinstance(deltas, list) else []
        if changed:
            lines.extend(["", "## Changed or unmeasured scenarios", "", "| Scenario | Producer | Consumer | Before | After | Result |", "| --- | --- | --- | --- | --- | --- |"])
            for item in changed:
                lines.append(
                    "| "
                    + " | ".join(
                        (
                            cell(item.get("scenario") or ""),
                            cell(item.get("producer") or ""),
                            cell(item.get("consumer") or ""),
                            cell(human_state(item.get("before"))),
                            cell(human_state(item.get("after"))),
                            cell(human_delta(item.get("kind"))),
                        )
                    )
                    + " |"
                )

    # A compact lane view makes baseline/candidate comparison readable without
    # hiding the per-vector rows below.
    lane_groups: dict[tuple[str, str, str, str], list[Mapping[str, Any]]] = {}
    for row in rows:
        key = (
            str(row.get("producer_phase", "")),
            str(row.get("consumer_phase", "")),
            str(row.get("producer", "")),
            str(row.get("consumer", "")),
        )
        lane_groups.setdefault(key, []).append(row)
    lines.extend(
        [
            "",
            "## Publisher Ã¢â€ â€™ verifier lanes",
            "",
            "Each lane is a publisher-to-verifier baseline/candidate slice of the fixed matrix.",
            "",
            "| Publisher | Verifier | Passed | Failed | Incomplete | Verdict |",
            "| --- | --- | ---: | ---: | ---: | --- |",
        ]
    )
    for (producer_phase, consumer_phase, producer, consumer), lane_rows in sorted(lane_groups.items()):
        counts = {state: sum(row.get("status") == state for row in lane_rows) for state in ("PASS", "FAIL", "INCOMPLETE")}
        verdict = "INCOMPLETE" if counts["INCOMPLETE"] else ("FAIL" if counts["FAIL"] else "PASS")
        producer_label = f"{producer} ({producer_phase})" if producer_phase else producer
        consumer_label = f"{consumer} ({consumer_phase})" if consumer_phase else consumer
        lines.append(
            "| "
            + " | ".join(
                (
                    cell(producer_label),
                    cell(consumer_label),
                    str(counts["PASS"]),
                    str(counts["FAIL"]),
                    str(counts["INCOMPLETE"]),
                    verdict,
                )
            )
            + " |"
        )

    lines.extend(
        [
            "",
            "## Signed-vector rows",
            "",
            "| ID | Scenario | Producer | Producer phase | Consumer | Consumer phase | Expected | Actual | Status | Detail |",
            "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
        ]
    )
    for row in rows:
        lines.append(
            "| "
            + " | ".join(
                cell(row.get(key, ""))
                for key in (
                    "id",
                    "scenario",
                    "producer",
                    "producer_phase",
                    "consumer",
                    "consumer_phase",
                    "expected",
                    "actual",
                    "status",
                    "detail",
                )
            )
            + " |"
        )
    return "\n".join(lines) + "\n"


def _atomic_write(path: pathlib.Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as handle:
        handle.write(content)
        temporary = pathlib.Path(handle.name)
    temporary.replace(path)


def write_report(report: Mapping[str, Any], output: pathlib.Path) -> None:
    output.mkdir(parents=True, exist_ok=True)
    snapshots = output / "snapshots"
    for name in ("report.json", "report.md"):
        old = output / name
        if old.exists():
            snapshots.mkdir(parents=True, exist_ok=True)
            stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
            destination = snapshots / f"{stamp}-{name}"
            counter = 1
            while destination.exists():
                destination = snapshots / f"{stamp}-{counter}-{name}"
                counter += 1
            shutil.copy2(old, destination)
    _atomic_write(output / "report.json", json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    _atomic_write(output / "report.md", _markdown(report))


def run_check(
    profile_path: pathlib.Path,
    vectors_path: pathlib.Path,
    output: pathlib.Path,
    cache: pathlib.Path,
    offline: bool,
    revision: str,
    *,
    project: Mapping[str, Any] | None = None,
) -> tuple[dict[str, Any], int]:
    try:
        profile, profile_raw = _read_json(profile_path)
        vectors, vectors_raw = _read_json(vectors_path)
        report = _run_matrix(profile, vectors, cache, offline, revision, project=project)
        report["hashes"] = {"profile_sha256": _hash_bytes(profile_raw), "vectors_sha256": _hash_bytes(vectors_raw)}
        write_report(report, output)
    except ValueError as exc:
        detail = str(exc)
        report = {
            "schema_version": 1,
            "status": "INCOMPLETE",
            "summary": {"total": 1, "passed": 0, "failed": 0, "incomplete": 1},
            "rows": [
                {
                    "id": "configuration",
                    "scenario": "configuration",
                    "producer": "n/a",
                    "producer_phase": "",
                    "consumer": "n/a",
                    "consumer_phase": "",
                    "expected": "valid fixture",
                    "actual": "invalid",
                    "status": "INCOMPLETE",
                    "detail": detail,
                }
            ],
            "profile": {},
            "project": dict(project) if isinstance(project, Mapping) else None,
            "revision": revision,
            "runtimes": {},
            "attestations": {},
            "hashes": {},
            "error": detail,
        }
        write_report(report, output)
        return report, 2
    return report, {"PASS": 0, "FAIL": 1, "INCOMPLETE": 2}[report["status"]]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the fixed Tink release compatibility matrix")
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("check", help="run the signed-vector compatibility matrix")
    check.add_argument("--out", required=True, type=pathlib.Path)
    check.add_argument("--profile", type=pathlib.Path, default=DEFAULT_PROFILE)
    check.add_argument("--cache", type=pathlib.Path, default=_default_cache())
    check.add_argument("--offline", action="store_true")
    check.add_argument("--revision", default=os.environ.get("TINK_COMPAT_REVISION", f"tink-release-compat@{__version__}"))
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "check":
        report, code = run_check(args.profile, DEFAULT_VECTORS, args.out, args.cache, args.offline, args.revision)
        print(f"Tink compatibility: {report['status']}")
        print(f"Report JSON: {(args.out / 'report.json').resolve()}")
        print(f"Report Markdown: {(args.out / 'report.md').resolve()}")
        return code
    return 2


__all__ = ["CheckRow", "expected_case_ids", "main", "run_check", "write_report", "_run_matrix"]
