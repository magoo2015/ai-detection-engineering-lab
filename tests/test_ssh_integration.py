from normalization.ssh_parser import parse_ssh_event
from detections.ssh_compromise import detect_ssh_compromise


def test_raw_ssh_logs_trigger_compromise_detection():
    raw_logs = [
        (
            "Aug 25 10:00:00 detection-lab sshd[20001]: "
            "Failed publickey for sysadmin from 203.0.113.50 port 45001 ssh2"
        ),
        (
            "Aug 25 10:01:00 detection-lab sshd[20002]: "
            "Failed publickey for sysadmin from 203.0.113.50 port 45002 ssh2"
        ),
        (
            "Aug 25 10:02:00 detection-lab sshd[20003]: "
            "Failed publickey for sysadmin from 203.0.113.50 port 45003 ssh2"
        ),
        (
            "Aug 25 10:03:00 detection-lab sshd[20004]: "
            "Accepted publickey for sysadmin from 203.0.113.50 "
            "port 45004 ssh2: ED25519 SHA256:TESTFINGERPRINT"
        ),
    ]

    events = [parse_ssh_event(line) for line in raw_logs]

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
