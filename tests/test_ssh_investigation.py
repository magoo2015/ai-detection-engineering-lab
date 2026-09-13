from copy import deepcopy

from investigation.build_investigation import build_investigation


def _complete_compromise_alert():
    return {
        "detection": "SSH_FAILURES_FOLLOWED_BY_SUCCESS",
        "severity": "high",
        "source_ip": "203.0.113.50",
        "username": "admin",
        "failure_count": 3,
        "first_failure": "2026-08-25T10:00:00Z",
        "last_failure": "2026-08-25T10:02:00Z",
        "success_time": "2026-08-25T10:03:00Z",
        "window_minutes": 5,
        "evidence": {
            "failed_authentications": [
                {
                    "timestamp": "2026-08-25T10:00:00Z",
                    "auth_result": "failure",
                    "source_ip": "203.0.113.50",
                    "username": "admin",
                },
                {
                    "timestamp": "2026-08-25T10:01:00Z",
                    "auth_result": "failure",
                    "source_ip": "203.0.113.50",
                    "username": "admin",
                },
                {
                    "timestamp": "2026-08-25T10:02:00Z",
                    "auth_result": "failure",
                    "source_ip": "203.0.113.50",
                    "username": "admin",
                },
            ],
            "successful_authentication": {
                "timestamp": "2026-08-25T10:03:00Z",
                "auth_result": "success",
                "source_ip": "203.0.113.50",
                "username": "admin",
            },
        },
    }


def test_complete_compromise_alert_investigation():
    alert = _complete_compromise_alert()
    investigation = build_investigation(alert)

    assert investigation["detection"] == "SSH_FAILURES_FOLLOWED_BY_SUCCESS"
    assert investigation["severity"] == "high"
    assert investigation["source_ip"] == "203.0.113.50"
    assert investigation["username"] == "admin"
    assert "3 failed authentications" in investigation["timeline_summary"]
    assert "203.0.113.50" in investigation["timeline_summary"]
    assert "admin" in investigation["timeline_summary"]
    assert "Correlated 3 prior failures" in investigation["evidence_summary"]
    assert "hypothesis for investigation" in investigation[
        "likely_attack_behavior"
    ]


def test_pass_through_fields():
    alert = _complete_compromise_alert()
    alert["severity"] = "critical"
    alert["source_ip"] = "198.51.100.10"
    alert["username"] = "sysadmin"

    investigation = build_investigation(alert)

    assert investigation["severity"] == "critical"
    assert investigation["source_ip"] == "198.51.100.10"
    assert investigation["username"] == "sysadmin"
    assert investigation["detection"] == alert["detection"]


def test_mitre_metadata_from_yaml():
    investigation = build_investigation(_complete_compromise_alert())

    assert investigation["mitre_attack"]["tactic"] == ["Credential Access"]
    assert investigation["mitre_attack"]["technique"][0]["id"] == "T1110"
    assert investigation["mitre_attack"]["technique"][0]["name"] == "Brute Force"


def test_recommended_analyst_checks_from_yaml():
    investigation = build_investigation(_complete_compromise_alert())
    checks = investigation["recommended_analyst_checks"]

    assert isinstance(checks, list)
    assert len(checks) >= 1
    assert any("successful authentication was expected" in check for check in checks)
    assert any("source IP" in check for check in checks)


def test_complete_evidence_completeness():
    investigation = build_investigation(_complete_compromise_alert())
    assert investigation["evidence_completeness"] == "complete"
    assert "confidence" not in investigation


def test_incomplete_evidence_completeness():
    alert = _complete_compromise_alert()
    alert["evidence"] = {
        "failed_authentications": [],
        "successful_authentication": {
            "timestamp": "2026-08-25T10:03:00Z",
            "auth_result": "success",
        },
    }

    investigation = build_investigation(alert)
    assert investigation["evidence_completeness"] == "incomplete"

    alert_missing = _complete_compromise_alert()
    del alert_missing["evidence"]

    investigation_missing = build_investigation(alert_missing)
    assert investigation_missing["evidence_completeness"] == "incomplete"
    assert investigation_missing["raw_evidence"] is None


def test_disposition_is_none():
    investigation = build_investigation(_complete_compromise_alert())
    assert investigation["disposition"] is None


def test_raw_evidence_preserved():
    alert = _complete_compromise_alert()
    expected_evidence = deepcopy(alert["evidence"])

    investigation = build_investigation(alert)

    assert investigation["raw_evidence"] == expected_evidence
    # Investigation keeps an independent copy of evidence.
    investigation["raw_evidence"]["failed_authentications"].clear()
    assert len(alert["evidence"]["failed_authentications"]) == 3
