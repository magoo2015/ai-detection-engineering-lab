from datetime import datetime


def get_failed_ssh_events(events):
    failed_events = []

    for event in events:
        if event["auth_result"] == "failure":
            failed_events.append(event)

    return failed_events

def group_events_by_source_ip(events):
    grouped_events = {}

    for event in events:
        source_ip = event["source_ip"]

        if source_ip is None:
            continue

        if source_ip not in grouped_events:
            grouped_events[source_ip] = []

        grouped_events[source_ip].append(event)

    return grouped_events

def detect_ssh_bruteforce(events, threshold=15, window_minutes=10):
    failed_events = get_failed_ssh_events(events)
    grouped_events = group_events_by_source_ip(failed_events)

    alerts = []

    for source_ip, source_events in grouped_events.items():
        if len(source_events) < threshold:
            continue

        sorted_events = sorted(
            source_events,
            key=lambda event: event["timestamp"],
        )

        for index in range(len(sorted_events) - threshold + 1):
            window_events = sorted_events[index:index + threshold]

            start_time = datetime.fromisoformat(
                window_events[0]["timestamp"].replace("Z", "+00:00")
            )

            end_time = datetime.fromisoformat(
                window_events[-1]["timestamp"].replace("Z", "+00:00")
            )

            duration_minutes = (end_time - start_time).total_seconds() / 60

            if duration_minutes <= window_minutes:
                alerts.append(
                    {
                        "detection": "SSH_BRUTE_FORCE",
                        "source_ip": source_ip,
                        "failure_count": len(window_events),
                        "window_minutes": duration_minutes,
                        "first_seen": window_events[0]["timestamp"],
                        "last_seen": window_events[-1]["timestamp"],
                    }
                )

                break

    return alerts
