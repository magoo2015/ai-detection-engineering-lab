from datetime import datetime


def detect_ssh_compromise(events, failure_threshold=3, window_minutes=10):
    failures_by_ip = {}
    success_events = []

    for event in events:
        source_ip = event.get("source_ip")
        auth_result = event.get("auth_result")

        if source_ip is None:
            continue

        if auth_result == "failure":
            if source_ip not in failures_by_ip:
                failures_by_ip[source_ip] = []

            failures_by_ip[source_ip].append(event)

        elif auth_result == "success":
            success_events.append(event)

    alerts = []

    for success_event in success_events:
        source_ip = success_event["source_ip"]

        if source_ip not in failures_by_ip:
            continue

        success_time = datetime.fromisoformat(
            success_event["timestamp"].replace("Z", "+00:00")
        )

        prior_failures = []

        for failure_event in failures_by_ip[source_ip]:
            failure_time = datetime.fromisoformat(
                failure_event["timestamp"].replace("Z", "+00:00")
            )

            time_difference = (
                success_time - failure_time
            ).total_seconds() / 60

            failure_username = failure_event.get("username")
            success_username = success_event.get("username")

            same_username = (
                failure_username is not None
                and success_username is not None
                and failure_username == success_username
            )

            if same_username and 0 <= time_difference <= window_minutes:
                prior_failures.append(failure_event)

        if len(prior_failures) >= failure_threshold:
            alerts.append(
                {
                    "detection": "SSH_FAILURES_FOLLOWED_BY_SUCCESS",
                    "source_ip": source_ip,
                    "username": success_event.get("username"),
                    "failure_count": len(prior_failures),
                    "success_time": success_event["timestamp"],
                    "window_minutes": window_minutes,
                }
            )

    return alerts
