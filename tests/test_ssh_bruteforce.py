from detections.ssh_bruteforce import (
    get_failed_ssh_events,
    group_events_by_source_ip,
    detect_ssh_bruteforce,
)


def test_get_failed_ssh_events():
    events = [
        {
            "auth_result": "failure",
            "source_ip": "203.0.113.10",
        },
        {
            "auth_result": "failure",
            "source_ip": "203.0.113.10",
        },
        {
            "auth_result": "success",
            "source_ip": "203.0.113.20",
        },
    ]

    failed_events = get_failed_ssh_events(events)

    assert len(failed_events) == 2

def test_group_events_by_source_ip():
    events = [
        {
            "source_ip": "203.0.113.10",
            "auth_result": "failure",
        },
        {
            "source_ip": "203.0.113.10",
            "auth_result": "failure",
        },
        {
            "source_ip": "203.0.113.20",
            "auth_result": "failure",
        },
    ]

    grouped_events = group_events_by_source_ip(events)

    assert len(grouped_events["203.0.113.10"]) == 2
    assert len(grouped_events["203.0.113.20"]) == 1

def test_detect_ssh_bruteforce():
    events = [
        {
            "timestamp": "2026-08-25T10:00:00Z",
            "auth_result": "failure",
            "source_ip": "203.0.113.50",
        },
        {
            "timestamp": "2026-08-25T10:01:00Z",
            "auth_result": "failure",
            "source_ip": "203.0.113.50",
        },
        {
            "timestamp": "2026-08-25T10:02:00Z",
            "auth_result": "failure",
            "source_ip": "203.0.113.50",
        },
    ]

    alerts = detect_ssh_bruteforce(
        events,
        threshold=3,
        window_minutes=5,
    )

    assert len(alerts) == 1
    assert alerts[0]["detection"] == "SSH_BRUTE_FORCE"
    assert alerts[0]["source_ip"] == "203.0.113.50"
    assert alerts[0]["failure_count"] == 3

def test_ssh_bruteforce_outside_time_window():
    events = [
        {
            "timestamp": "2026-08-25T10:00:00Z",
            "auth_result": "failure",
            "source_ip": "203.0.113.50",
        },
        {
            "timestamp": "2026-08-25T10:06:00Z",
            "auth_result": "failure",
            "source_ip": "203.0.113.50",
        },
        {
            "timestamp": "2026-08-25T10:12:00Z",
            "auth_result": "failure",
            "source_ip": "203.0.113.50",
        },
    ]

    alerts = detect_ssh_bruteforce(
        events,
        threshold=3,
        window_minutes=5,
    )

    assert len(alerts) == 0

def test_ssh_bruteforce_different_source_ips():
    events = [
        {
            "timestamp": "2026-08-25T10:00:00Z",
            "auth_result": "failure",
            "source_ip": "203.0.113.10",
        },
        {
            "timestamp": "2026-08-25T10:01:00Z",
            "auth_result": "failure",
            "source_ip": "203.0.113.20",
        },
        {
            "timestamp": "2026-08-25T10:02:00Z",
            "auth_result": "failure",
            "source_ip": "203.0.113.30",
        },
    ]

    alerts = detect_ssh_bruteforce(
        events,
        threshold=3,
        window_minutes=5,
    )

    assert len(alerts) == 0