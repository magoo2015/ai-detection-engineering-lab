from detections.ssh_compromise import detect_ssh_compromise


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
    assert alerts[0]["detection"] == "SSH_FAILURES_FOLLOWED_BY_SUCCESS"
    assert alerts[0]["source_ip"] == "203.0.113.50"
    assert alerts[0]["username"] == "admin"
    assert alerts[0]["failure_count"] == 3


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