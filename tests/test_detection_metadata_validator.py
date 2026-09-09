from pathlib import Path

from scripts.validate_detection_metadata import validate_detection_file


def write_metadata(tmp_path, content):
    path = tmp_path / "detection.yml"
    path.write_text(content)
    return path


def test_valid_detection_metadata_passes(tmp_path):
    path = write_metadata(
        tmp_path,
        """
id: DET-TEST-001
name: Test Detection
status: experimental
version: 1
description: Test detection metadata
threat:
  behavior: Test behavior
  objective: Test objective
mitre_attack:
  tactic:
    - Credential Access
  technique:
    - id: T1110
      name: Brute Force
data_sources:
  - source: Test
    log_type: test logs
required_fields:
  - timestamp
  - source_ip
detection:
  type: threshold
severity: medium
false_positives:
  - Test false positive
validation:
  positive_test: Test validation
response:
  - Investigate
""",
    )

    errors = validate_detection_file(path)

    assert errors == []


def test_missing_required_field_fails(tmp_path):
    path = write_metadata(
        tmp_path,
        """
id: DET-TEST-001
name: Test Detection
status: experimental
version: 1
description: Test detection metadata
threat:
  behavior: Test behavior
  objective: Test objective
mitre_attack:
  tactic:
    - Credential Access
  technique:
    - id: T1110
      name: Brute Force
data_sources:
  - source: Test
    log_type: test logs
required_fields:
  - timestamp
detection:
  type: threshold
severity: medium
false_positives:
  - Test false positive
validation:
  positive_test: Test validation
""",
    )

    errors = validate_detection_file(path)

    assert "Missing required field: response" in errors


def test_invalid_severity_fails(tmp_path):
    path = write_metadata(
        tmp_path,
        """
id: DET-TEST-001
name: Test Detection
status: experimental
version: 1
description: Test detection metadata
threat:
  behavior: Test behavior
  objective: Test objective
mitre_attack:
  tactic:
    - Credential Access
  technique:
    - id: T1110
      name: Brute Force
data_sources:
  - source: Test
    log_type: test logs
required_fields:
  - timestamp
detection:
  type: threshold
severity: severe
false_positives:
  - Test false positive
validation:
  positive_test: Test validation
response:
  - Investigate
""",
    )

    errors = validate_detection_file(path)

    assert any("Invalid severity" in error for error in errors)


def test_invalid_status_fails(tmp_path):
    path = write_metadata(
        tmp_path,
        """
id: DET-TEST-001
name: Test Detection
status: production
version: 1
description: Test detection metadata
threat:
  behavior: Test behavior
  objective: Test objective
mitre_attack:
  tactic:
    - Credential Access
  technique:
    - id: T1110
      name: Brute Force
data_sources:
  - source: Test
    log_type: test logs
required_fields:
  - timestamp
detection:
  type: threshold
severity: medium
false_positives:
  - Test false positive
validation:
  positive_test: Test validation
response:
  - Investigate
""",
    )

    errors = validate_detection_file(path)

    assert any("Invalid status" in error for error in errors)


def test_invalid_detection_id_fails(tmp_path):
    path = write_metadata(
        tmp_path,
        """
id: TEST-001
name: Test Detection
status: experimental
version: 1
description: Test detection metadata
threat:
  behavior: Test behavior
  objective: Test objective
mitre_attack:
  tactic:
    - Credential Access
  technique:
    - id: T1110
      name: Brute Force
data_sources:
  - source: Test
    log_type: test logs
required_fields:
  - timestamp
detection:
  type: threshold
severity: medium
false_positives:
  - Test false positive
validation:
  positive_test: Test validation
response:
  - Investigate
""",
    )

    errors = validate_detection_file(path)

    assert any("Detection IDs must begin with 'DET-'" in error for error in errors)


def test_required_fields_must_be_list(tmp_path):
    path = write_metadata(
        tmp_path,
        """
id: DET-TEST-001
name: Test Detection
status: experimental
version: 1
description: Test detection metadata
threat:
  behavior: Test behavior
  objective: Test objective
mitre_attack:
  tactic:
    - Credential Access
  technique:
    - id: T1110
      name: Brute Force
data_sources:
  - source: Test
    log_type: test logs
required_fields: timestamp
detection:
  type: threshold
severity: medium
false_positives:
  - Test false positive
validation:
  positive_test: Test validation
response:
  - Investigate
""",
    )

    errors = validate_detection_file(path)

    assert "required_fields must be a list" in errors


def test_required_fields_must_not_be_empty(tmp_path):
    path = write_metadata(
        tmp_path,
        """
id: DET-TEST-001
name: Test Detection
status: experimental
version: 1
description: Test detection metadata
threat:
  behavior: Test behavior
  objective: Test objective
mitre_attack:
  tactic:
    - Credential Access
  technique:
    - id: T1110
      name: Brute Force
data_sources:
  - source: Test
    log_type: test logs
required_fields: []
detection:
  type: threshold
severity: medium
false_positives:
  - Test false positive
validation:
  positive_test: Test validation
response:
  - Investigate
""",
    )

    errors = validate_detection_file(path)

    assert "required_fields must not be empty" in errors
