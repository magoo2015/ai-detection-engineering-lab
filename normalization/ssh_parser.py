from datetime import datetime, timezone


def normalize_timestamp(month, day, time_value):
    current_year = datetime.now(timezone.utc).year

    parsed = datetime.strptime(
        f"{current_year} {month} {day} {time_value}",
        "%Y %b %d %H:%M:%S",
    )

    return parsed.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")


def parse_ssh_event(line):
    event = {
        "timestamp": None,
        "host": None,
        "service": None,
        "process_id": None,
        "event_type": None,
        "auth_result": None,
        "auth_method": None,
        "auth_stage": None,
        "source_ip": None,
        "source_port": None,
        "username": None,
        "raw_message": line.strip(),
    }

    parts = line.split()

    if len(parts) < 6:
        return event

    event["timestamp"] = normalize_timestamp(
        parts[0],
        parts[1],
        parts[2],
    )

    event["host"] = parts[3]

    process = parts[4]

    if "[" in process:
        service_part, pid_part = process.split("[", 1)
        event["service"] = service_part
        event["process_id"] = pid_part.rstrip("]:")

    message = " ".join(parts[5:])

    if message.startswith("Invalid user"):
        event["event_type"] = "invalid_user"
        event["auth_result"] = "failure"

        message_parts = message.split()

        if len(message_parts) >= 6 and message_parts[2] != "from":
            event["username"] = message_parts[2]

        if "from" in message_parts:
            from_index = message_parts.index("from")
            if from_index + 1 < len(message_parts):
                event["source_ip"] = message_parts[from_index + 1]

        if "port" in message_parts:
            port_index = message_parts.index("port")
            if port_index + 1 < len(message_parts):
                event["source_port"] = message_parts[port_index + 1]

    elif message.startswith("Connection reset"):
        event["event_type"] = "connection_reset"
        event["auth_result"] = "unknown"

        message_parts = message.split()

        if "user" in message_parts:
            user_index = message_parts.index("user")
            if user_index + 1 < len(message_parts):
                event["username"] = message_parts[user_index + 1]

        if "port" in message_parts:
            port_index = message_parts.index("port")

            if port_index - 1 >= 0:
                event["source_ip"] = message_parts[port_index - 1]

            if port_index + 1 < len(message_parts):
                event["source_port"] = message_parts[port_index + 1]

        if "[preauth]" in message:
            event["auth_stage"] = "preauth"

    elif message.startswith("Accepted publickey"):
        event["event_type"] = "authentication_success"
        event["auth_result"] = "success"
        event["auth_method"] = "publickey"
        event["auth_stage"] = "authenticated"

        message_parts = message.split()

        if "for" in message_parts:
            for_index = message_parts.index("for")
            if for_index + 1 < len(message_parts):
                event["username"] = message_parts[for_index + 1]

        if "from" in message_parts:
            from_index = message_parts.index("from")
            if from_index + 1 < len(message_parts):
                event["source_ip"] = message_parts[from_index + 1]

        if "port" in message_parts:
            port_index = message_parts.index("port")
            if port_index + 1 < len(message_parts):
                event["source_port"] = message_parts[port_index + 1]

    return event