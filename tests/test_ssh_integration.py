from pathlib import Path

from normalization.ssh_parser import parse_ssh_event
from detections.ssh_compromise import detect_ssh_compromise


def test_raw_ssh_logs_trigger_compromise_detection():
    fixture_path = Path("tests/fixtures_ssh_compromise.log")

    raw_logs = fixture_path.read_text().splitlines()

    events = [
        parse_ssh_event(line)
        for line in raw_logs
        if line.strip()
    ]

    alerts = detect_ssh_compromise(
        events,
        failure_threshold=3,
        window_minutes=5,
    )

    assert len(alerts) == 1
    assert alerts[0]["detection"] == "SSH_FAILURES_FOLLOWED_BY_SUCCESS"
    assert alerts[0]["source_ip"] == "203.0.113.50"
    assert alerts[0]["username"] == "sysadmin"
    assert alerts[0]["failure_count"] == 3