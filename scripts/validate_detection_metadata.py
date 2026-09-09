from pathlib import Path
import sys
import yaml


METADATA_DIR = Path("detections/metadata")

REQUIRED_TOP_LEVEL_FIELDS = {
    "id",
    "name",
    "status",
    "version",
    "description",
    "threat",
    "mitre_attack",
    "data_sources",
    "required_fields",
    "detection",
    "severity",
    "false_positives",
    "validation",
    "response",
}

VALID_STATUSES = {
    "experimental",
    "test",
    "stable",
    "deprecated",
}

VALID_SEVERITIES = {
    "low",
    "medium",
    "high",
    "critical",
}


def validate_detection_file(path):
    errors = []

    try:
        with path.open() as file:
            metadata = yaml.safe_load(file)
    except yaml.YAMLError as error:
        return [f"Invalid YAML: {error}"]

    if not isinstance(metadata, dict):
        return ["Metadata must contain a YAML mapping/object"]

    missing_fields = REQUIRED_TOP_LEVEL_FIELDS - metadata.keys()

    for field in sorted(missing_fields):
        errors.append(f"Missing required field: {field}")

    status = metadata.get("status")

    if status is not None and status not in VALID_STATUSES:
        errors.append(
            f"Invalid status '{status}'. "
            f"Expected one of: {', '.join(sorted(VALID_STATUSES))}"
        )

    severity = metadata.get("severity")

    if severity is not None and severity not in VALID_SEVERITIES:
        errors.append(
            f"Invalid severity '{severity}'. "
            f"Expected one of: {', '.join(sorted(VALID_SEVERITIES))}"
        )

    detection_id = metadata.get("id")

    if detection_id is not None and not detection_id.startswith("DET-"):
        errors.append(
            f"Invalid detection ID '{detection_id}'. "
            "Detection IDs must begin with 'DET-'"
        )

    required_fields = metadata.get("required_fields")

    if required_fields is not None:
        if not isinstance(required_fields, list):
            errors.append("required_fields must be a list")
        elif not required_fields:
            errors.append("required_fields must not be empty")

    false_positives = metadata.get("false_positives")

    if false_positives is not None and not isinstance(false_positives, list):
        errors.append("false_positives must be a list")

    response = metadata.get("response")

    if response is not None and not isinstance(response, list):
        errors.append("response must be a list")

    return errors


def main():
    if not METADATA_DIR.exists():
        print(f"ERROR: Metadata directory not found: {METADATA_DIR}")
        return 1

    metadata_files = sorted(METADATA_DIR.glob("*.yml"))

    if not metadata_files:
        print(f"ERROR: No detection metadata files found in {METADATA_DIR}")
        return 1

    failures = 0

    for path in metadata_files:
        errors = validate_detection_file(path)

        if errors:
            failures += 1
            print(f"[FAIL] {path}")

            for error in errors:
                print(f"  - {error}")
        else:
            print(f"[PASS] {path}")

    print()
    print(
        f"Validated {len(metadata_files)} detection metadata file(s): "
        f"{len(metadata_files) - failures} passed, {failures} failed"
    )

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
