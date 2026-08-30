from normalization.ssh_parser import parse_ssh_event


def test_invalid_user_event():
    line = (
        "Aug 25 10:15:01 detection-lab sshd[10001]: "
        "Invalid user admin from 203.0.113.10 port 45001"
    )

    event = parse_ssh_event(line)

    assert event["host"] == "detection-lab"
    assert event["service"] == "sshd"
    assert event["process_id"] == "10001"

    assert event["event_type"] == "invalid_user"
    assert event["auth_result"] == "failure"

    assert event["username"] == "admin"
    assert event["source_ip"] == "203.0.113.10"
    assert event["source_port"] == "45001"


def test_connection_reset_event():
    line = (
        "Aug 25 10:16:10 detection-lab sshd[10003]: "
        "Connection reset by authenticating user root "
        "203.0.113.12 port 45003 [preauth]"
    )

    event = parse_ssh_event(line)

    assert event["event_type"] == "connection_reset"
    assert event["auth_result"] == "unknown"
    assert event["auth_stage"] == "preauth"

    assert event["username"] == "root"
    assert event["source_ip"] == "203.0.113.12"
    assert event["source_port"] == "45003"


def test_successful_publickey_authentication():
    line = (
        "Aug 25 10:17:20 detection-lab sshd[10004]: "
        "Accepted publickey for sysadmin from 203.0.113.13 "
        "port 45004 ssh2: ED25519 SHA256:TESTFINGERPRINT"
    )

    event = parse_ssh_event(line)

    assert event["event_type"] == "authentication_success"
    assert event["auth_result"] == "success"
    assert event["auth_method"] == "publickey"
    assert event["auth_stage"] == "authenticated"

    assert event["username"] == "sysadmin"
    assert event["source_ip"] == "203.0.113.13"
    assert event["source_port"] == "45004"


def test_invalid_user_without_username():
    line = (
        "Aug 25 10:15:05 detection-lab sshd[10002]: "
        "Invalid user  from 203.0.113.11 port 45002"
    )

    event = parse_ssh_event(line)

    assert event["event_type"] == "invalid_user"
    assert event["auth_result"] == "failure"
    assert event["username"] is None
    assert event["source_ip"] == "203.0.113.11"
    assert event["source_port"] == "45002"