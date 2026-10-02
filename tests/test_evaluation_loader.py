import pytest
import yaml

from evaluation.loader import (
    ScenarioValidationError,
    default_det_ssh_001_scenarios_path,
    default_det_ssh_002_scenarios_path,
    load_scenarios,
    validate_scenario,
)


def _valid_scenario(**overrides):
    scenario = {
        "id": "DET-SSH-001-TEST",
        "detector_id": "DET-SSH-001",
        "description": "Controlled loader test scenario.",
        "ground_truth": "malicious",
        "scope": "in_scope",
        "expected_alert": True,
        "notes": "Unit test fixture.",
        "events": [
            {
                "timestamp": "2026-08-25T10:00:00Z",
                "auth_result": "failure",
                "source_ip": "203.0.113.10",
                "username": "root",
            }
        ],
    }
    scenario.update(overrides)
    return scenario


def test_validate_scenario_accepts_valid_scenario():
    scenario = _valid_scenario()

    assert validate_scenario(scenario) is scenario


def test_load_scenarios_from_yaml_file(tmp_path):
    path = tmp_path / "scenarios.yml"
    path.write_text(yaml.dump([_valid_scenario()]))

    scenarios = load_scenarios(path)

    assert len(scenarios) == 1
    assert scenarios[0]["id"] == "DET-SSH-001-TEST"


def test_load_bundled_det_ssh_001_corpus():
    scenarios = load_scenarios(default_det_ssh_001_scenarios_path())

    assert len(scenarios) == 8
    assert [s["id"] for s in scenarios] == [
        "DET-SSH-001-S01",
        "DET-SSH-001-S02",
        "DET-SSH-001-S03",
        "DET-SSH-001-S04",
        "DET-SSH-001-S05",
        "DET-SSH-001-S06",
        "DET-SSH-001-S07",
        "DET-SSH-001-S08",
    ]


def test_validate_scenario_accepts_det_ssh_002():
    scenario = _valid_scenario(id="DET-SSH-002-TEST", detector_id="DET-SSH-002")

    assert validate_scenario(scenario) is scenario


def test_load_bundled_det_ssh_002_corpus():
    scenarios = load_scenarios(default_det_ssh_002_scenarios_path())

    assert [s["id"] for s in scenarios] == [
        f"DET-SSH-002-S{index:02d}" for index in range(1, 11)
    ]
    assert all(s["detector_id"] == "DET-SSH-002" for s in scenarios)


def test_invalid_ground_truth_rejected():
    with pytest.raises(ScenarioValidationError, match="ground_truth"):
        validate_scenario(_valid_scenario(ground_truth="suspicious"))


def test_invalid_scope_rejected():
    with pytest.raises(ScenarioValidationError, match="scope"):
        validate_scenario(_valid_scenario(scope="experimental"))


def test_non_boolean_expected_alert_rejected():
    with pytest.raises(ScenarioValidationError, match="expected_alert"):
        validate_scenario(_valid_scenario(expected_alert="true"))


def test_empty_events_rejected():
    with pytest.raises(ScenarioValidationError, match="events"):
        validate_scenario(_valid_scenario(events=[]))


def test_missing_required_fields_rejected():
    scenario = _valid_scenario()
    del scenario["id"]

    with pytest.raises(ScenarioValidationError, match="missing required fields"):
        validate_scenario(scenario)


def test_empty_scenario_id_rejected():
    with pytest.raises(ScenarioValidationError, match="id"):
        validate_scenario(_valid_scenario(id="   "))


def test_unsupported_detector_id_rejected():
    with pytest.raises(ScenarioValidationError, match="detector_id"):
        validate_scenario(_valid_scenario(detector_id="DET-UNKNOWN"))


def test_non_list_yaml_rejected(tmp_path):
    path = tmp_path / "bad.yml"
    path.write_text(yaml.dump({"id": "not-a-list"}))

    with pytest.raises(ScenarioValidationError, match="top-level list"):
        load_scenarios(path)
