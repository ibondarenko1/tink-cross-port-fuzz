"""Tink Python adapter for the fixed compatibility-matrix protocol.

The adapter deliberately handles only the two operations needed by the
release check.  It does not expose the fuzzing harness and it never echoes a
keyset or token in an error response.
"""

from __future__ import annotations

import datetime as _datetime
import importlib.metadata
import json
import platform
import sys
from collections.abc import Mapping
from typing import Any


def _version() -> str:
    return importlib.metadata.version("tink")


def _runtime() -> str:
    return f"python {platform.python_version()}"


def _require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{label} must be an object")
    return dict(value)


def _require_jwks(value: Any, label: str) -> dict[str, Any]:
    jwks = _require_object(value, label)
    keys = jwks.get("keys")
    if not isinstance(keys, list) or not keys or not all(isinstance(item, Mapping) for item in keys):
        raise ValueError(f"{label}.keys must be a non-empty list of objects")
    return {"keys": [dict(item) for item in keys]}


def _public_handle(jwks: Mapping[str, Any]):
    from tink import jwt

    jwt.register_jwt_signature()
    return jwt.jwk_set_to_public_keyset_handle(json.dumps(jwks, separators=(",", ":")))


def _publish(payload: Mapping[str, Any]) -> dict[str, Any]:
    from tink import jwt

    sets = _require_object(payload.get("sets"), "sets")
    exported: dict[str, dict[str, Any]] = {}
    for name, value in sets.items():
        if not isinstance(name, str) or not name:
            raise ValueError("sets contains an invalid phase name")
        handle = _public_handle(_require_jwks(value, f"sets.{name}"))
        exported_text = jwt.jwk_set_from_public_keyset_handle(handle)
        exported[name] = _require_jwks(json.loads(exported_text), f"exported sets.{name}")
    return {"version": _version(), "runtime": _runtime(), "sets": exported}


def _verify(payload: Mapping[str, Any]) -> dict[str, Any]:
    from tink import TinkError
    from tink import jwt

    checks = payload.get("checks")
    if not isinstance(checks, list) or not all(isinstance(item, Mapping) for item in checks):
        raise ValueError("checks must be a list of objects")
    jwt.register_jwt_signature()
    results: list[dict[str, Any]] = []
    for item in checks:
        check = dict(item)
        check_id = check.get("id")
        if not isinstance(check_id, str) or not check_id:
            raise ValueError("each check must have a non-empty id")
        compact = check.get("compact")
        issuer = check.get("issuer")
        audience = check.get("audience")
        now = check.get("now")
        if not isinstance(compact, str) or not compact:
            raise ValueError(f"check {check_id} has an invalid compact JWT")
        if not isinstance(issuer, str) or not issuer:
            raise ValueError(f"check {check_id} has an invalid issuer")
        if audience is not None and (not isinstance(audience, str) or not audience):
            raise ValueError(f"check {check_id} has an invalid audience")
        if not isinstance(now, int) or isinstance(now, bool):
            raise ValueError(f"check {check_id} has an invalid now value")
        try:
            handle = _public_handle(_require_jwks(check.get("jwks"), f"check {check_id}.jwks"))
            verifier = handle.primitive(jwt.JwtPublicKeyVerify)
            validator = jwt.new_validator(
                expected_issuer=issuer,
                expected_audience=audience,
                fixed_now=_datetime.datetime.fromtimestamp(now, _datetime.timezone.utc),
            )
        except Exception as exc:
            results.append({"id": check_id, "outcome": "error", "detail": f"key setup failed: {type(exc).__name__}"})
            continue
        try:
            verifier.verify_and_decode(compact, validator)
        except TinkError:
            results.append({"id": check_id, "outcome": "rejected"})
        except Exception as exc:
            # A runtime error from the verification API is an adapter error,
            # not a cryptographic rejection.
            results.append({"id": check_id, "outcome": "error", "detail": f"verification failed: {type(exc).__name__}"})
        else:
            results.append({"id": check_id, "outcome": "verified"})
    return {"version": _version(), "runtime": _runtime(), "results": results}


def dispatch(payload: Mapping[str, Any]) -> dict[str, Any]:
    operation = payload.get("operation")
    if operation == "publish":
        return _publish(payload)
    if operation == "verify":
        return _verify(payload)
    raise ValueError("operation must be publish or verify")


def main() -> int:
    try:
        raw = sys.stdin.read()
        payload = json.loads(raw)
        if not isinstance(payload, Mapping):
            raise ValueError("request must be a JSON object")
        response = dispatch(payload)
    except Exception as exc:
        # Keep setup/protocol failures machine-readable and free of input data.
        response = {"error": f"{type(exc).__name__}: compatibility request rejected"}
        print(json.dumps(response, separators=(",", ":")))
        return 2
    print(json.dumps(response, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
