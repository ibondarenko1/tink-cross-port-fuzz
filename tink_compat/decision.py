"""Interpret compatibility rows as upgrade and rollout decisions.

The matrix deliberately keeps every signed-vector row.  This module adds a
small, deterministic view over those rows so a reviewer can answer two
different questions without inspecting the raw table:

* did the candidate release regress, fix, or preserve a matched scenario?
* can a publisher or verifier be upgraded first for each consumer lane?

An incomplete row never counts as a successful intermediate state.  This is
important for release automation because a missing adapter must not turn into
an apparently safe rollout order.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Iterable, Mapping


_COMPLETE = {"PASS", "FAIL"}


def _phase(value: Any) -> str:
    return value if isinstance(value, str) else ""


def _language(value: Any) -> str:
    """Return ``go`` from ``go@2.9.0`` while preserving unknown labels."""

    if not isinstance(value, str):
        return ""
    return value.split("@", 1)[0]


def _case_name(row: Mapping[str, Any]) -> str:
    """Normalize a row ID while retaining vector/key identity.

    The scenario label alone is insufficient for rotation because ``old`` and
    ``new`` are two independent checks under the same scenario.  Removing only
    the two phase components from the stable ID gives each vector its own key.
    """

    identifier = str(row.get("id") or "")
    for producer_phase in ("baseline", "candidate"):
        for consumer_phase in ("baseline", "candidate"):
            marker = f"-{producer_phase}-{consumer_phase}-"
            if marker in identifier:
                return identifier.replace(marker, "-", 1)
            suffix = f"-{producer_phase}-{consumer_phase}"
            if identifier.endswith(suffix):
                return identifier[: -len(suffix)]
    for phase in ("baseline", "candidate"):
        suffix = f"-{phase}"
        if identifier.endswith(suffix):
            return identifier[: -len(suffix)]
    # Compact synthetic reports often use 00/01/10/11 for the four phase
    # pairs.  Accept those labels without weakening the real matrix IDs.
    for suffix in ("-00", "-01", "-10", "-11"):
        if identifier.endswith(suffix):
            return identifier[: -len(suffix)]
    if identifier in {"00", "01", "10", "11"}:
        return ""
    return identifier


def _logical_key(row: Mapping[str, Any]) -> tuple[str, str, str, str]:
    """Build a phase-independent identity for one matrix row."""

    scenario = str(row.get("scenario") or row.get("id") or "")
    producer = _language(row.get("producer"))
    consumer = _language(row.get("consumer"))
    return scenario, producer, consumer, _case_name(row) or scenario


def _state(row: Mapping[str, Any] | None) -> str:
    if row is None:
        return "not_measured"
    status = row.get("status")
    if status == "PASS":
        return "pass"
    if status == "FAIL":
        return "fail"
    return "not_measured"


def _delta_kind(before: str, after: str) -> str:
    if before == "pass" and after == "fail":
        return "regression"
    if before == "fail" and after == "pass":
        return "fixed"
    if before == "pass" and after == "pass":
        return "unchanged"
    if before == "fail" and after == "fail":
        return "persistent"
    return "not_measured"


def scenario_deltas(rows: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Compare baseline/baseline and candidate/candidate matched scenarios.

    Rows with a non-``PASS``/``FAIL`` status are represented as
    ``not_measured``.  The returned records include row IDs and the complete
    phase states, which lets report consumers link a summary back to the raw
    rows without reconstructing the matching logic.
    """

    groups: dict[tuple[str, str, str, str], dict[tuple[str, str], Mapping[str, Any]]] = defaultdict(dict)
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        key = _logical_key(row)
        producer_phase = _phase(row.get("producer_phase"))
        consumer_phase = _phase(row.get("consumer_phase"))
        if producer_phase and consumer_phase:
            groups[key][(producer_phase, consumer_phase)] = row

    output: list[dict[str, Any]] = []
    for key, phases in sorted(groups.items()):
        before_row = phases.get(("baseline", "baseline"))
        after_row = phases.get(("candidate", "candidate"))
        before = _state(before_row)
        after = _state(after_row)
        output.append(
            {
                "scenario": key[0],
                "producer": key[1],
                "consumer": key[2],
                "before": before,
                "after": after,
                "kind": _delta_kind(before, after),
                "before_id": before_row.get("id") if before_row else None,
                "after_id": after_row.get("id") if after_row else None,
            }
        )
    return output


def _lane_state(rows: Iterable[Mapping[str, Any]], producer_phase: str, consumer_phase: str) -> str:
    """Aggregate all required scenarios for one phase pair conservatively."""

    material = list(rows)
    required_keys = {_logical_key(row) for row in material}
    selected = {
        _logical_key(row): row
        for row in material
        if _phase(row.get("producer_phase")) == producer_phase
        and _phase(row.get("consumer_phase")) == consumer_phase
    }
    if not selected or set(selected) != required_keys or any(row.get("status") not in _COMPLETE for row in selected.values()):
        return "unknown"
    if any(row.get("status") == "FAIL" for row in selected.values()):
        return "blocked"
    return "pass"


def _lane_decision(states: Mapping[str, str]) -> str:
    """Name the safe first-upgrade order from four phase-pair aggregates."""

    baseline = states["baseline"]
    publisher_first = states["publisher_first"]
    verifier_first = states["verifier_first"]
    final = states["final"]
    if baseline != "pass" or final != "pass":
        return "blocked" if baseline == "blocked" or final == "blocked" else "unknown"
    publisher_ok = publisher_first == "pass"
    verifier_ok = verifier_first == "pass"
    if publisher_ok and verifier_ok:
        return "either"
    if publisher_ok:
        return "publisher_first"
    if verifier_ok:
        return "verifier_first"
    if publisher_first == "blocked" and verifier_first == "blocked":
        return "blocked"
    return "unknown"


def rollout_decisions(rows: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Compute per-verifier and overall rollout decisions.

    ``publisher_first`` means candidate publisher with baseline verifier
    (P1/V0).  ``verifier_first`` means baseline publisher with candidate
    verifier (P0/V1).  Every row in a phase pair is required to pass.  Missing
    rows and incomplete adapter results therefore produce ``unknown`` rather
    than an optimistic recommendation.
    """

    material = [row for row in rows if isinstance(row, Mapping)]
    by_consumer: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    controls: list[Mapping[str, Any]] = []
    for row in material:
        consumer = _language(row.get("consumer"))
        producer = _language(row.get("producer"))
        if consumer and consumer == producer:
            controls.append(row)
        elif consumer:
            by_consumer[consumer].append(row)

    lanes: dict[str, dict[str, Any]] = {}
    for consumer, lane_rows in sorted(by_consumer.items()):
        # Python controls are same-version checks, so they constrain the two
        # diagonal states (P0/V0 and P1/V1).  They have no meaningful mixed
        # phase equivalent and must not make an otherwise measured P1/V0 or
        # P0/V1 lane appear missing.
        states = {
            "baseline": _lane_state(lane_rows + controls, "baseline", "baseline"),
            "publisher_first": _lane_state(lane_rows, "candidate", "baseline"),
            "verifier_first": _lane_state(lane_rows, "baseline", "candidate"),
            "final": _lane_state(lane_rows + controls, "candidate", "candidate"),
        }
        lanes[consumer] = {"states": states, "decision": _lane_decision(states)}

    decisions = {value["decision"] for value in lanes.values()}
    if not lanes:
        overall = "unknown"
    elif decisions == {"publisher_first"}:
        overall = "publisher_first"
    elif decisions == {"verifier_first"}:
        overall = "verifier_first"
    elif decisions <= {"either", "publisher_first"} and "publisher_first" in decisions:
        overall = "publisher_first"
    elif decisions <= {"either", "verifier_first"} and "verifier_first" in decisions:
        overall = "verifier_first"
    elif decisions <= {"publisher_first", "verifier_first"}:
        overall = "mixed"
    elif decisions == {"either"}:
        overall = "either"
    elif "blocked" in decisions:
        overall = "blocked"
    else:
        overall = "unknown"
    return {"overall": overall, "lanes": lanes}


def build_decision(rows: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Return the additive decision section embedded in compatibility reports."""

    material = [dict(row) for row in rows if isinstance(row, Mapping)]
    deltas = scenario_deltas(material)
    counts: dict[str, int] = defaultdict(int)
    for item in deltas:
        counts[item["kind"]] += 1
    return {
        "schema_version": 1,
        "deltas": deltas,
        "delta_summary": dict(sorted(counts.items())),
        "rollout": rollout_decisions(material),
    }


__all__ = ["build_decision", "rollout_decisions", "scenario_deltas"]
