from datetime import datetime


DEFAULT_FAILURE_THRESHOLD = 3
DEFAULT_WINDOW_MINUTES = 10


def detect_ssh_compromise(
    events,
    failure_threshold=DEFAULT_FAILURE_THRESHOLD,
    window_minutes=DEFAULT_WINDOW_MINUTES,
):
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
        success_username = success_event.get("username")

        # Do not correlate a successful authentication
        # if we do not know which account authenticated.
        if not success_username:
            continue

        if source_ip not in failures_by_ip:
            continue

        success_time = datetime.fromisoformat(
            success_event["timestamp"].replace("Z", "+00:00")
        )

        prior_failures = []

        for failure_event in failures_by_ip[source_ip]:
            failure_username = failure_event.get("username")

            # Ignore failure events where the username is missing.
            if not failure_username:
                continue

            failure_time = datetime.fromisoformat(
                failure_event["timestamp"].replace("Z", "+00:00")
            )

            time_difference = (
                success_time - failure_time
            ).total_seconds() / 60

            same_username = (
                failure_username == success_username
            )

            if same_username and 0 <= time_difference <= window_minutes:
                prior_failures.append(failure_event)

        prior_failures = sorted(
            prior_failures,
            key=lambda event: event["timestamp"],
        )

        if len(prior_failures) >= failure_threshold:
            alerts.append(
                {
                    "detection": "SSH_FAILURES_FOLLOWED_BY_SUCCESS",
                    "source_ip": source_ip,
                    "username": success_username,
                    "failure_count": len(prior_failures),
                    "first_failure": prior_failures[0]["timestamp"],
                    "last_failure": prior_failures[-1]["timestamp"],
                    "success_time": success_event["timestamp"],
                    "window_minutes": window_minutes,
                    "evidence": {
                        "failed_authentications": prior_failures,
                        "successful_authentication": success_event,
                    },
                }
            )

    return alerts