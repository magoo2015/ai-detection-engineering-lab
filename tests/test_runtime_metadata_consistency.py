"""YAML threshold/window docs must mirror Python DEFAULT_* constants.

This is a consistency check only. Detectors do not load YAML at runtime.
"""

from pathlib import Path

import yaml

from detections.ssh_bruteforce import (
    DEFAULT_THRESHOLD as BRUTEFORCE_DEFAULT_THRESHOLD,
    DEFAULT_WINDOW_MINUTES as BRUTEFORCE_DEFAULT_WINDOW_MINUTES,
)
from detections.ssh_compromise import (
    DEFAULT_FAILURE_THRESHOLD as COMPROMISE_DEFAULT_FAILURE_THRESHOLD,
    DEFAULT_WINDOW_MINUTES as COMPROMISE_DEFAULT_WINDOW_MINUTES,
)

METADATA_DIR = Path(__file__).resolve().parent.parent / "detections" / "metadata"


def _load_metadata(filename):
    with (METADATA_DIR / filename).open() as handle:
        return yaml.safe_load(handle)


def test_compromise_yaml_mirrors_python_defaults():
    metadata = _load_metadata("ssh_failures_followed_by_success.yml")
    detection = metadata["detection"]

    assert detection["failure_threshold"] == COMPROMISE_DEFAULT_FAILURE_THRESHOLD
    assert detection["window_minutes"] == COMPROMISE_DEFAULT_WINDOW_MINUTES


def test_bruteforce_yaml_mirrors_python_defaults():
    metadata = _load_metadata("ssh_bruteforce.yml")
    detection = metadata["detection"]

    assert detection["threshold"] == BRUTEFORCE_DEFAULT_THRESHOLD
    assert detection["window_minutes"] == BRUTEFORCE_DEFAULT_WINDOW_MINUTES
