import json
import sys
from pathlib import Path

from normalization.ssh_parser import parse_ssh_event
from detections.ssh_compromise import detect_ssh_compromise
from investigation.build_investigation import build_investigation
from ai.assist import attach_ai_assistance


def load_events(log_path):
    raw_logs = Path(log_path).read_text().splitlines()

    events = []

    for line in raw_logs:
        if not line.strip():
            continue

        events.append(parse_ssh_event(line))

    return events


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 run_detection.py <log_file>")
        sys.exit(1)

    log_path = sys.argv[1]

    events = load_events(log_path)

    alerts = detect_ssh_compromise(
        events,
        failure_threshold=3,
        window_minutes=5,
    )

    if not alerts:
        print("No alerts detected.")
        return

    # provider=None keeps AI disabled; StubProvider can be passed for offline demos.
    investigations = [
        attach_ai_assistance(build_investigation(alert), provider=None)
        for alert in alerts
    ]

    print(json.dumps(investigations, indent=2))


if __name__ == "__main__":
    main()
