from evaluation.loader import default_det_ssh_002_scenarios_path, load_scenarios
from evaluation.runner import run_scenario, run_scenarios


def _failure_events(count, source_ip="203.0.113.50", username="root", step_seconds=40):
    events = []
    for index in range(count):
        total_seconds = index * step_seconds
        minutes, seconds = divmod(total_seconds, 60)
        events.append(
            {
                "timestamp": f"2026-08-25T10:{minutes:02d}:{seconds:02d}Z",
                "auth_result": "failure",
                "source_ip": source_ip,
                "username": username,
            }
        )
    return events


def _scenario(**overrides):
    scenario = {
        "id": "controlled",
        "detector_id": "DET-SSH-001",
        "description": "Controlled runner test scenario.",
        "ground_truth": "malicious",
        "scope": "in_scope",
        "expected_alert": True,
        "notes": "Unit test fixture.",
        "events": _failure_events(15),
    }
    scenario.update(overrides)
    return scenario


def test_run_scenario_classifies_true_positive():
    result = run_scenario(
        _scenario(
            ground_truth="malicious",
            expected_alert=True,
            events=_failure_events(15),
        )
    )

    assert result["observed_alert"] is True
    assert result["behavior_matched"] is True
    assert result["classification"] == "TP"
    assert result["included_in_metrics"] is True
    assert result["exclusion_reason"] is None
    assert len(result["alerts"]) >= 1


def test_run_scenario_classifies_false_positive():
    result = run_scenario(
        _scenario(
            ground_truth="benign",
            expected_alert=True,
            events=_failure_events(15, source_ip="198.51.100.10", username="jsmith"),
        )
    )

    assert result["observed_alert"] is True
    assert result["classification"] == "FP"


def test_run_scenario_classifies_true_negative():
    result = run_scenario(
        _scenario(
            ground_truth="benign",
            expected_alert=False,
            events=_failure_events(2, source_ip="198.51.100.5", username="alice"),
        )
    )

    assert result["observed_alert"] is False
    assert result["classification"] == "TN"


def test_run_scenario_classifies_false_negative():
    result = run_scenario(
        _scenario(
            ground_truth="malicious",
            expected_alert=False,
            events=_failure_events(14),
        )
    )

    assert result["observed_alert"] is False
    assert result["classification"] == "FN"


def test_limitation_scenario_excluded_from_primary_classification():
    events = []
    for ip in ("203.0.113.101", "203.0.113.102", "203.0.113.103"):
        events.extend(_failure_events(10, source_ip=ip))

    result = run_scenario(
        _scenario(
            ground_truth="malicious",
            scope="limitation",
            expected_alert=False,
            events=events,
        )
    )

    assert result["scope"] == "limitation"
    assert result["observed_alert"] is False
    assert result["classification"] is None
    assert result["included_in_metrics"] is False
    assert result["exclusion_reason"] == "scope_limitation"


def test_expected_alert_mismatch_is_represented():
    # Detector will alert (15 failures), but scenario expects no alert.
    result = run_scenario(
        _scenario(
            ground_truth="malicious",
            expected_alert=False,
            events=_failure_events(15),
        )
    )

    assert result["observed_alert"] is True
    assert result["expected_alert"] is False
    assert result["behavior_matched"] is False
    assert result["classification"] == "TP"


def test_run_scenarios_returns_one_result_per_scenario():
    scenarios = [
        _scenario(id="one", events=_failure_events(15)),
        _scenario(
            id="two",
            ground_truth="benign",
            expected_alert=False,
            events=_failure_events(2),
        ),
    ]

    results = run_scenarios(scenarios)

    assert [result["scenario_id"] for result in results] == ["one", "two"]
    assert results[0]["classification"] == "TP"
    assert results[1]["classification"] == "TN"


def _ssh_002_events(failures, source_ip="203.0.113.50", username="admin"):
    events = [
        {
            "timestamp": f"2026-08-25T10:{index:02d}:00Z",
            "auth_result": "failure",
            "source_ip": source_ip,
            "username": username,
        }
        for index in range(failures)
    ]
    events.append(
        {
            "timestamp": f"2026-08-25T10:{failures:02d}:00Z",
            "auth_result": "success",
            "source_ip": source_ip,
            "username": username,
        }
    )
    return events


def test_det_ssh_002_dispatch_classifies_true_positive():
    result = run_scenario(
        _scenario(
            detector_id="DET-SSH-002",
            ground_truth="malicious",
            expected_alert=True,
            events=_ssh_002_events(3),
        )
    )

    assert result["detector_id"] == "DET-SSH-002"
    assert result["observed_alert"] is True
    assert result["behavior_matched"] is True
    assert result["classification"] == "TP"
    assert result["alerts"][0]["detection"] == "SSH_FAILURES_FOLLOWED_BY_SUCCESS"


def test_det_ssh_002_dispatch_classifies_false_negative():
    result = run_scenario(
        _scenario(
            detector_id="DET-SSH-002",
            ground_truth="malicious",
            expected_alert=False,
            events=_ssh_002_events(2),
        )
    )

    assert result["observed_alert"] is False
    assert result["behavior_matched"] is True
    assert result["classification"] == "FN"


def test_bundled_det_ssh_002_corpus_matches_expected_behavior():
    results = run_scenarios(load_scenarios(default_det_ssh_002_scenarios_path()))

    mismatched = [r["scenario_id"] for r in results if not r["behavior_matched"]]
    assert mismatched == []
