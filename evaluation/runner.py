"""Run evaluation scenarios against existing detectors."""

from detections.ssh_bruteforce import detect_ssh_bruteforce
from detections.ssh_compromise import detect_ssh_compromise

from evaluation.loader import SUPPORTED_DETECTOR_IDS


class UnsupportedDetectorError(ValueError):
    """Raised when a scenario references an unsupported detector."""


def _run_detector(detector_id, events):
    if detector_id == "DET-SSH-001":
        return detect_ssh_bruteforce(events)
    if detector_id == "DET-SSH-002":
        return detect_ssh_compromise(events)

    raise UnsupportedDetectorError(
        f"Unsupported detector_id {detector_id!r}; "
        f"supported: {sorted(SUPPORTED_DETECTOR_IDS)}"
    )


def _classify(ground_truth, observed_alert, scope):
    """Classify in-scope outcomes; limitation scenarios return None."""
    if scope == "limitation":
        return None

    if ground_truth == "malicious" and observed_alert:
        return "TP"
    if ground_truth == "malicious" and not observed_alert:
        return "FN"
    if ground_truth == "benign" and observed_alert:
        return "FP"
    if ground_truth == "benign" and not observed_alert:
        return "TN"

    raise ValueError(
        f"Unable to classify ground_truth={ground_truth!r} "
        f"observed_alert={observed_alert!r} scope={scope!r}"
    )


def run_scenario(scenario):
    """Execute one validated scenario and return an inspectable result dict.

    TP/FP/TN/FN classification uses ground_truth + observed detector behavior.
    expected_alert is compared separately via behavior_matched.
    """
    detector_id = scenario["detector_id"]
    alerts = _run_detector(detector_id, scenario["events"])
    observed_alert = len(alerts) > 0
    expected_alert = scenario["expected_alert"]
    scope = scenario["scope"]
    ground_truth = scenario["ground_truth"]

    return {
        "scenario_id": scenario["id"],
        "detector_id": detector_id,
        "ground_truth": ground_truth,
        "scope": scope,
        "expected_alert": expected_alert,
        "observed_alert": observed_alert,
        "behavior_matched": expected_alert == observed_alert,
        "classification": _classify(ground_truth, observed_alert, scope),
        "included_in_metrics": scope == "in_scope",
        "exclusion_reason": None if scope == "in_scope" else "scope_limitation",
        "alerts": alerts,
    }


def run_scenarios(scenarios):
    """Run multiple scenarios and return a list of result dicts."""
    return [run_scenario(scenario) for scenario in scenarios]
