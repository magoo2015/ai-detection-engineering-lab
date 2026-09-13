"""Deterministic investigation packaging for structured detection alerts.

This module consumes already-fired alerts only. It must never call detection
functions and must never decide whether an alert should fire.
"""

from copy import deepcopy
from pathlib import Path

import yaml


SUPPORTED_DETECTION = "SSH_FAILURES_FOLLOWED_BY_SUCCESS"

# Runtime detection names map to metadata files (IDs differ: DET-SSH-*).
DETECTION_METADATA_FILES = {
    SUPPORTED_DETECTION: "ssh_failures_followed_by_success.yml",
}

METADATA_DIR = Path(__file__).resolve().parent.parent / "detections" / "metadata"


def _load_detection_metadata(detection_name):
    filename = DETECTION_METADATA_FILES.get(detection_name)
    if filename is None:
        raise ValueError(
            f"Unsupported detection for investigation: {detection_name}"
        )

    metadata_path = METADATA_DIR / filename
    with metadata_path.open() as handle:
        return yaml.safe_load(handle)


def _evidence_is_complete(evidence):
    if not isinstance(evidence, dict):
        return False

    failed = evidence.get("failed_authentications")
    success = evidence.get("successful_authentication")

    if not isinstance(failed, list) or len(failed) == 0:
        return False

    if not isinstance(success, dict):
        return False

    return True


def _timeline_summary(alert):
    failure_count = alert.get("failure_count")
    username = alert.get("username")
    source_ip = alert.get("source_ip")
    first_failure = alert.get("first_failure")
    last_failure = alert.get("last_failure")
    success_time = alert.get("success_time")
    window_minutes = alert.get("window_minutes")

    return (
        f"{failure_count} failed authentications for {username} from "
        f"{source_ip} between {first_failure} and {last_failure}, "
        f"followed by successful authentication at {success_time} "
        f"(configured window {window_minutes} minutes)."
    )


def _evidence_summary(alert, evidence_complete):
    if not evidence_complete:
        return (
            "Expected compromise evidence is incomplete. "
            "Raw evidence is preserved when present for analyst review."
        )

    failure_count = alert.get("failure_count")
    return (
        f"Correlated {failure_count} prior failures with matching source IP "
        "and username, then one successful authentication. "
        "Raw failed and successful authentication events are preserved "
        "under raw_evidence."
    )


def _likely_attack_behavior():
    return (
        "Credential guessing against a single account that may have "
        "succeeded. This is a hypothesis for investigation, not a "
        "confirmed compromise."
    )


def _evidence_completeness(evidence_complete):
    """Whether expected evidence is present — not malice confidence."""
    if evidence_complete:
        return "complete"
    return "incomplete"


def build_investigation(alert):
    """Build an analyst-oriented investigation object from a fired alert."""
    detection_name = alert.get("detection")
    if detection_name != SUPPORTED_DETECTION:
        raise ValueError(
            f"Unsupported detection for investigation: {detection_name}"
        )

    metadata = _load_detection_metadata(detection_name)
    evidence = alert.get("evidence")
    evidence_complete = _evidence_is_complete(evidence)

    if evidence is None:
        raw_evidence = None
    else:
        raw_evidence = deepcopy(evidence)

    return {
        "detection": detection_name,
        "severity": alert.get("severity"),
        "source_ip": alert.get("source_ip"),
        "username": alert.get("username"),
        "timeline_summary": _timeline_summary(alert),
        "evidence_summary": _evidence_summary(alert, evidence_complete),
        "likely_attack_behavior": _likely_attack_behavior(),
        "mitre_attack": metadata.get("mitre_attack"),
        "recommended_analyst_checks": metadata.get("response"),
        "evidence_completeness": _evidence_completeness(evidence_complete),
        "disposition": None,
        "raw_evidence": raw_evidence,
    }
