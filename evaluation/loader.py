"""Load and validate detection quality evaluation scenarios."""

from pathlib import Path

import yaml

SUPPORTED_DETECTOR_IDS = frozenset({"DET-SSH-001"})
VALID_GROUND_TRUTH = frozenset({"malicious", "benign"})
VALID_SCOPES = frozenset({"in_scope", "limitation"})

REQUIRED_FIELDS = (
    "id",
    "detector_id",
    "description",
    "ground_truth",
    "scope",
    "expected_alert",
    "notes",
    "events",
)


class ScenarioValidationError(ValueError):
    """Raised when a scenario fails validation."""


def validate_scenario(scenario):
    """Validate a single scenario dictionary.

    Returns the scenario unchanged when valid.
    Raises ScenarioValidationError for malformed input.
    """
    if not isinstance(scenario, dict):
        raise ScenarioValidationError(
            f"Scenario must be a mapping, got {type(scenario).__name__}"
        )

    missing = [field for field in REQUIRED_FIELDS if field not in scenario]
    if missing:
        raise ScenarioValidationError(
            f"Scenario missing required fields: {', '.join(missing)}"
        )

    scenario_id = scenario["id"]
    if not isinstance(scenario_id, str) or not scenario_id.strip():
        raise ScenarioValidationError("Scenario id must be a non-empty string")

    detector_id = scenario["detector_id"]
    if detector_id not in SUPPORTED_DETECTOR_IDS:
        raise ScenarioValidationError(
            f"Unsupported detector_id {detector_id!r}; "
            f"supported: {sorted(SUPPORTED_DETECTOR_IDS)}"
        )

    ground_truth = scenario["ground_truth"]
    if ground_truth not in VALID_GROUND_TRUTH:
        raise ScenarioValidationError(
            f"Invalid ground_truth {ground_truth!r}; "
            f"valid values: {sorted(VALID_GROUND_TRUTH)}"
        )

    scope = scenario["scope"]
    if scope not in VALID_SCOPES:
        raise ScenarioValidationError(
            f"Invalid scope {scope!r}; "
            f"valid values: {sorted(VALID_SCOPES)}"
        )

    expected_alert = scenario["expected_alert"]
    if not isinstance(expected_alert, bool):
        raise ScenarioValidationError(
            f"expected_alert must be a boolean, got {type(expected_alert).__name__}"
        )

    events = scenario["events"]
    if not isinstance(events, list) or len(events) == 0:
        raise ScenarioValidationError("events must be a non-empty list")

    return scenario


def load_scenarios(path):
    """Load and validate scenarios from a YAML file.

    The file must contain a top-level YAML list of scenario mappings.
    """
    scenario_path = Path(path)
    if not scenario_path.is_file():
        raise ScenarioValidationError(f"Scenario file not found: {scenario_path}")

    with scenario_path.open() as handle:
        data = yaml.safe_load(handle)

    if data is None:
        raise ScenarioValidationError(
            f"Scenario file is empty: {scenario_path}"
        )

    if not isinstance(data, list):
        raise ScenarioValidationError(
            f"Scenario file must contain a top-level list, "
            f"got {type(data).__name__}: {scenario_path}"
        )

    if len(data) == 0:
        raise ScenarioValidationError(
            f"Scenario file contains no scenarios: {scenario_path}"
        )

    validated = []
    for index, scenario in enumerate(data):
        try:
            validated.append(validate_scenario(scenario))
        except ScenarioValidationError as exc:
            raise ScenarioValidationError(
                f"Invalid scenario at index {index}: {exc}"
            ) from exc

    return validated


def default_det_ssh_001_scenarios_path():
    """Return the path to the bundled DET-SSH-001 scenario corpus."""
    return Path(__file__).resolve().parent / "scenarios" / "det_ssh_001.yml"
