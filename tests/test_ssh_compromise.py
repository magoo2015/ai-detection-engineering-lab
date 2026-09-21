from detections.ssh_compromise import (
    DEFAULT_FAILURE_THRESHOLD,
    DEFAULT_WINDOW_MINUTES,
    detect_ssh_compromise,
)


def test_failures_followed_by_success():
    events = [
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
        {
            "timestamp": "2026-08-25T10:03:00Z",
            "auth_result": "success",
            "source_ip": "203.0.113.50",
            "username": "admin",
        },
    ]

    alerts = detect_ssh_compromise(
        events,
        failure_threshold=3,
        window_minutes=5,
    )

    assert len(alerts) == 1

    alert = alerts[0]

    # Detection identity (severity lives in metadata YAML, not raw alerts)
    assert alert["detection"] == "SSH_FAILURES_FOLLOWED_BY_SUCCESS"
    assert "severity" not in alert

    # Correlation fields
    assert alert["source_ip"] == "203.0.113.50"
    assert alert["username"] == "admin"
    assert alert["failure_count"] == 3

    # Timeline
    assert alert["first_failure"] == "2026-08-25T10:00:00Z"
    assert alert["last_failure"] == "2026-08-25T10:02:00Z"
    assert alert["success_time"] == "2026-08-25T10:03:00Z"
    assert alert["window_minutes"] == 5

    # Evidence
    assert len(
        alert["evidence"]["failed_authentications"]
    ) == 3

    assert (
        alert["evidence"]["successful_authentication"]["auth_result"]
        == "success"
    )

    assert (
        alert["evidence"]["successful_authentication"]["username"]
        == "admin"
    )


def test_default_window_is_ten_minutes():
    """Runtime defaults use DEFAULT_WINDOW_MINUTES (10), not lab overrides."""
    assert DEFAULT_FAILURE_THRESHOLD == 3
    assert DEFAULT_WINDOW_MINUTES == 10

    events = [
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
        # Success at 9 minutes: outside a 5-minute lab window, inside default 10.
        {
            "timestamp": "2026-08-25T10:09:00Z",
            "auth_result": "success",
            "source_ip": "203.0.113.50",
            "username": "admin",
        },
    ]

    alerts = detect_ssh_compromise(events)

    assert len(alerts) == 1
    assert alerts[0]["window_minutes"] == DEFAULT_WINDOW_MINUTES
    assert "severity" not in alerts[0]


def test_success_from_different_source_ip_does_not_alert():
    events = [
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
        {
            "timestamp": "2026-08-25T10:03:00Z",
            "auth_result": "success",
            "source_ip": "203.0.113.99",
            "username": "admin",
        },
    ]

    alerts = detect_ssh_compromise(
        events,
        failure_threshold=3,
        window_minutes=5,
    )

    assert len(alerts) == 0


def test_success_outside_time_window_does_not_alert():
    events = [
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
        {
            "timestamp": "2026-08-25T10:20:00Z",
            "auth_result": "success",
            "source_ip": "203.0.113.50",
            "username": "admin",
        },
    ]

    alerts = detect_ssh_compromise(
        events,
        failure_threshold=3,
        window_minutes=5,
    )

    assert len(alerts) == 0


def test_success_for_different_username_does_not_alert():
    events = [
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
        {
            "timestamp": "2026-08-25T10:03:00Z",
            "auth_result": "success",
            "source_ip": "203.0.113.50",
            "username": "sysadmin",
        },
    ]

    alerts = detect_ssh_compromise(
        events,
        failure_threshold=3,
        window_minutes=5,
    )

    assert len(alerts) == 0


def test_missing_usernames_do_not_alert():
    events = [
        {
            "timestamp": "2026-08-25T10:00:00Z",
            "auth_result": "failure",
            "source_ip": "203.0.113.50",
            "username": None,
        },
        {
            "timestamp": "2026-08-25T10:01:00Z",
            "auth_result": "failure",
            "source_ip": "203.0.113.50",
            "username": None,
        },
        {
            "timestamp": "2026-08-25T10:02:00Z",
            "auth_result": "failure",
            "source_ip": "203.0.113.50",
            "username": None,
        },
        {
            "timestamp": "2026-08-25T10:03:00Z",
            "auth_result": "success",
            "source_ip": "203.0.113.50",
            "username": None,
        },
    ]

    alerts = detect_ssh_compromise(
        events,
        failure_threshold=3,
        window_minutes=5,
    )

    assert len(alerts) == 0
