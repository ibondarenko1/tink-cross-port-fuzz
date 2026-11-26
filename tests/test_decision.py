from tink_compat.decision import build_decision, rollout_decisions, scenario_deltas


def _row(identifier, scenario, producer_phase, consumer_phase, status, consumer="go@2.9.0"):
    producer = "python@1.16.1" if producer_phase == "candidate" else "python@1.15.0"
    return {
        "id": identifier,
        "scenario": scenario,
        "producer": producer,
        "consumer": consumer,
        "producer_phase": producer_phase,
        "consumer_phase": consumer_phase,
        "status": status,
    }


def test_scenario_deltas_distinguish_fixed_regression_persistent_and_unknown():
    rows = [
        _row("fixed-00", "fixed", "baseline", "baseline", "FAIL"),
        _row("fixed-11", "fixed", "candidate", "candidate", "PASS"),
        _row("reg-00", "regression", "baseline", "baseline", "PASS"),
        _row("reg-11", "regression", "candidate", "candidate", "FAIL"),
        _row("same-00", "same", "baseline", "baseline", "PASS"),
        _row("same-11", "same", "candidate", "candidate", "PASS"),
        _row("persist-00", "persistent", "baseline", "baseline", "FAIL"),
        _row("persist-11", "persistent", "candidate", "candidate", "FAIL"),
        _row("unknown-00", "unknown", "baseline", "baseline", "INCOMPLETE"),
        _row("unknown-11", "unknown", "candidate", "candidate", "PASS"),
    ]
    values = {item["scenario"]: item["kind"] for item in scenario_deltas(rows)}
    assert values == {
        "fixed": "fixed",
        "regression": "regression",
        "same": "unchanged",
        "persistent": "persistent",
        "unknown": "not_measured",
    }


def test_rollout_reports_publisher_first_when_verifier_first_is_blocked():
    rows = []
    for producer_phase, consumer_phase, status in (
        ("baseline", "baseline", "PASS"),
        ("candidate", "baseline", "PASS"),
        ("baseline", "candidate", "FAIL"),
        ("candidate", "candidate", "PASS"),
    ):
        rows.append(_row(f"row-{producer_phase}-{consumer_phase}", "signed", producer_phase, consumer_phase, status))
    report = rollout_decisions(rows)
    assert report["overall"] == "publisher_first"
    assert report["lanes"]["go"]["decision"] == "publisher_first"
    assert report["lanes"]["go"]["states"] == {
        "baseline": "pass",
        "publisher_first": "pass",
        "verifier_first": "blocked",
        "final": "pass",
    }


def test_missing_intermediate_row_is_unknown_and_does_not_recommend_order():
    rows = [
        _row("00", "signed", "baseline", "baseline", "PASS"),
        _row("11", "signed", "candidate", "candidate", "PASS"),
    ]
    report = rollout_decisions(rows)
    assert report["overall"] == "unknown"
    assert report["lanes"]["go"]["decision"] == "unknown"
    assert report["lanes"]["go"]["states"]["publisher_first"] == "unknown"


def test_build_decision_keeps_additive_machine_readable_shape():
    rows = [
        _row("00", "signed", "baseline", "baseline", "PASS"),
        _row("01", "signed", "baseline", "candidate", "PASS"),
        _row("10", "signed", "candidate", "baseline", "PASS"),
        _row("11", "signed", "candidate", "candidate", "PASS"),
    ]
    report = build_decision(rows)
    assert report["schema_version"] == 1
    assert report["delta_summary"] == {"unchanged": 1}
    assert report["rollout"]["overall"] == "either"


def test_rotation_old_and_new_vectors_are_matched_independently():
    rows = [
        _row("rotation-baseline-baseline-go-initial-old", "rotation-initial", "baseline", "baseline", "PASS"),
        _row("rotation-candidate-candidate-go-initial-old", "rotation-initial", "candidate", "candidate", "PASS"),
        _row("rotation-baseline-baseline-go-initial-new", "rotation-initial", "baseline", "baseline", "FAIL"),
        _row("rotation-candidate-candidate-go-initial-new", "rotation-initial", "candidate", "candidate", "PASS"),
    ]
    deltas = scenario_deltas(rows)
    assert {(item["before_id"], item["kind"]) for item in deltas} == {
        ("rotation-baseline-baseline-go-initial-old", "unchanged"),
        ("rotation-baseline-baseline-go-initial-new", "fixed"),
    }


def test_legacy_57_plus_control_cases_remain_distinct():
    rows = []
    for index in range(57):
        rows.extend(
            (
                _row(f"case-{index}-baseline-baseline-go", f"case-{index}", "baseline", "baseline", "PASS"),
                _row(f"case-{index}-candidate-candidate-go", f"case-{index}", "candidate", "candidate", "PASS"),
            )
        )
    rows.extend(
        (
            _row("rfc-python-self-baseline", "python-control", "baseline", "baseline", "PASS", consumer="python@1.15.0"),
            _row("rfc-python-self-candidate", "python-control", "candidate", "candidate", "PASS", consumer="python@1.16.1"),
        )
    )
    deltas = scenario_deltas(rows)
    assert len(deltas) == 58
    assert len({item["scenario"] for item in deltas}) == 58
    assert sum(item["kind"] == "unchanged" for item in deltas) == 58


def test_mixed_lane_and_unknown_control_do_not_produce_global_order():
    rows = []
    for language, intermediate_publisher, intermediate_verifier in (
        ("go@2.9.0", "PASS", "FAIL"),
        ("java@1.24.0", "INCOMPLETE", "INCOMPLETE"),
    ):
        for producer_phase, consumer_phase, status in (
            ("baseline", "baseline", "PASS"),
            ("candidate", "baseline", intermediate_publisher),
            ("baseline", "candidate", intermediate_verifier),
            ("candidate", "candidate", "PASS"),
        ):
            rows.append(
                _row(
                    f"lane-{language}-{producer_phase}-{consumer_phase}",
                    "signed",
                    producer_phase,
                    consumer_phase,
                    status,
                    consumer=language,
                )
            )
    for producer_phase, consumer_phase in (("baseline", "baseline"), ("candidate", "candidate")):
        rows.append(
            _row(
                f"control-{producer_phase}",
                "python-control",
                producer_phase,
                consumer_phase,
                "PASS",
                consumer="python@1.15.0" if producer_phase == "baseline" else "python@1.16.1",
            )
        )
    report = rollout_decisions(rows)
    assert report["lanes"]["go"]["decision"] == "publisher_first"
    assert report["lanes"]["java"]["decision"] == "unknown"
    assert report["overall"] == "unknown"


def test_either_lane_plus_verifier_first_resolves_to_verifier_first():
    rows = []
    for language, publisher_first, verifier_first in (
        ("go@2.9.0", "PASS", "PASS"),
        ("java@1.24.0", "FAIL", "PASS"),
    ):
        for producer_phase, consumer_phase, status in (
            ("baseline", "baseline", "PASS"),
            ("candidate", "baseline", publisher_first),
            ("baseline", "candidate", verifier_first),
            ("candidate", "candidate", "PASS"),
        ):
            rows.append(
                _row(
                    f"lane-{language}-{producer_phase}-{consumer_phase}",
                    "signed",
                    producer_phase,
                    consumer_phase,
                    status,
                    consumer=language,
                )
            )
    report = rollout_decisions(rows)
    assert report["lanes"]["go"]["decision"] == "either"
    assert report["lanes"]["java"]["decision"] == "verifier_first"
    assert report["overall"] == "verifier_first"
