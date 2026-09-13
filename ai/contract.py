"""AI investigation request/response contract and output validation.

Deterministic investigation fields are authoritative. Validated AI output is
advisory only and must live under a nested ``ai_assistance`` object.
"""

from copy import deepcopy

SCHEMA_VERSION = "1.0"
OUTPUT_SCHEMA = "ai_assistance_v1"
MODE = "advisory_investigation"

RAW_MESSAGE_MAX_LENGTH = 512

HYPOTHESIS_CONFIDENCE_VALUES = frozenset({"low", "medium", "high"})
HYPOTHESIS_STATUS = "unconfirmed"

AI_STATUS_OK = "ok"
AI_STATUS_UNAVAILABLE = "unavailable"
AI_STATUS_ERROR = "error"
AI_STATUS_REJECTED = "rejected"

CONTENT_REQUIRED_KEYS = frozenset(
    {
        "analyst_summary",
        "why_suspicious",
        "hypotheses",
        "investigation_pivots",
        "analyst_questions",
        "evidence_to_collect_next",
        "suggested_false_positive_checks",
    }
)

# Fields that AI output must never set or attempt to override.
FORBIDDEN_AUTHORITATIVE_KEYS = frozenset(
    {
        "detection",
        "severity",
        "source_ip",
        "username",
        "timeline_summary",
        "evidence_summary",
        "likely_attack_behavior",
        "mitre_attack",
        "recommended_analyst_checks",
        "evidence_completeness",
        "confidence",
        "disposition",
        "raw_evidence",
    }
)

DETERMINISTIC_INVESTIGATION_KEYS = frozenset(
    {
        "detection",
        "severity",
        "source_ip",
        "username",
        "timeline_summary",
        "evidence_summary",
        "likely_attack_behavior",
        "mitre_attack",
        "recommended_analyst_checks",
        "evidence_completeness",
        "disposition",
        "raw_evidence",
    }
)


def build_unavailable_assistance(provider_name=None, reason="AI disabled"):
    """Return a stable unavailable ai_assistance object."""
    return {
        "schema_version": SCHEMA_VERSION,
        "status": AI_STATUS_UNAVAILABLE,
        "provider": provider_name,
        "model": None,
        "generated_at": None,
        "advisory": True,
        "content": None,
        "error": {
            "code": "unavailable",
            "message": reason,
        },
    }


def build_error_assistance(provider_name, message):
    """Return an error ai_assistance object after a provider failure."""
    return {
        "schema_version": SCHEMA_VERSION,
        "status": AI_STATUS_ERROR,
        "provider": provider_name,
        "model": None,
        "generated_at": None,
        "advisory": True,
        "content": None,
        "error": {
            "code": "provider_error",
            "message": str(message),
        },
    }


def build_rejected_assistance(provider_name, message, model=None):
    """Return a rejected ai_assistance object after schema/trust validation."""
    return {
        "schema_version": SCHEMA_VERSION,
        "status": AI_STATUS_REJECTED,
        "provider": provider_name,
        "model": model,
        "generated_at": None,
        "advisory": True,
        "content": None,
        "error": {
            "code": "rejected",
            "message": str(message),
        },
    }


def _require_list_of_str(value, field_name):
    if not isinstance(value, list):
        raise ValueError(f"{field_name} must be a list of strings")
    for item in value:
        if not isinstance(item, str):
            raise ValueError(f"{field_name} must be a list of strings")


def _validate_hypotheses(hypotheses):
    if not isinstance(hypotheses, list):
        raise ValueError("hypotheses must be a list")

    for hypothesis in hypotheses:
        if not isinstance(hypothesis, dict):
            raise ValueError("each hypothesis must be an object")

        required = {
            "id",
            "statement",
            "confidence",
            "status",
            "supporting_signals",
            "contradicting_signals",
        }
        missing = required - set(hypothesis.keys())
        if missing:
            raise ValueError(f"hypothesis missing keys: {sorted(missing)}")

        if not isinstance(hypothesis["id"], str) or not hypothesis["id"]:
            raise ValueError("hypothesis id must be a non-empty string")
        if not isinstance(hypothesis["statement"], str):
            raise ValueError("hypothesis statement must be a string")

        confidence = hypothesis["confidence"]
        if confidence not in HYPOTHESIS_CONFIDENCE_VALUES:
            raise ValueError(
                "hypothesis confidence must be one of: low, medium, high"
            )

        status = hypothesis["status"]
        if status != HYPOTHESIS_STATUS:
            raise ValueError(
                "hypothesis status must be 'unconfirmed'; "
                f"got {status!r}"
            )

        _require_list_of_str(
            hypothesis["supporting_signals"], "supporting_signals"
        )
        _require_list_of_str(
            hypothesis["contradicting_signals"], "contradicting_signals"
        )


def validate_ai_assistance(payload):
    """Validate AI provider output before attachment.

    Returns ``(True, None)`` on success, or ``(False, reason)`` on rejection.
    Does not mutate the payload.
    """
    if not isinstance(payload, dict):
        return False, "ai_assistance must be an object"

    forbidden = FORBIDDEN_AUTHORITATIVE_KEYS.intersection(payload.keys())
    if forbidden:
        return (
            False,
            "AI output must not include authoritative fields: "
            f"{sorted(forbidden)}",
        )

    required_top = {
        "schema_version",
        "status",
        "provider",
        "model",
        "generated_at",
        "advisory",
        "content",
        "error",
    }
    missing = required_top - set(payload.keys())
    if missing:
        return False, f"ai_assistance missing keys: {sorted(missing)}"

    if payload.get("advisory") is not True:
        return False, "advisory must be true"

    if payload.get("schema_version") != SCHEMA_VERSION:
        return False, f"unsupported schema_version: {payload.get('schema_version')!r}"

    status = payload.get("status")
    if status not in {
        AI_STATUS_OK,
        AI_STATUS_UNAVAILABLE,
        AI_STATUS_ERROR,
        AI_STATUS_REJECTED,
    }:
        return False, f"invalid status: {status!r}"

    content = payload.get("content")
    error = payload.get("error")

    if status != AI_STATUS_OK:
        if content is not None:
            return False, "content must be null when status is not ok"
        if not isinstance(error, dict):
            return False, "error must be an object when status is not ok"
        if "code" not in error or "message" not in error:
            return False, "error must include code and message"
        return True, None

    # status == ok
    if error is not None:
        return False, "error must be null when status is ok"

    if not isinstance(content, dict):
        return False, "content must be an object when status is ok"

    content_forbidden = FORBIDDEN_AUTHORITATIVE_KEYS.intersection(content.keys())
    if content_forbidden:
        return (
            False,
            "content must not include authoritative fields: "
            f"{sorted(content_forbidden)}",
        )

    if "suggested_disposition_for_review" in content:
        return False, "suggested_disposition_for_review is not allowed"

    missing_content = CONTENT_REQUIRED_KEYS - set(content.keys())
    if missing_content:
        return False, f"content missing keys: {sorted(missing_content)}"

    if not isinstance(content["analyst_summary"], str):
        return False, "analyst_summary must be a string"

    try:
        _require_list_of_str(content["why_suspicious"], "why_suspicious")
        _require_list_of_str(
            content["investigation_pivots"], "investigation_pivots"
        )
        _require_list_of_str(content["analyst_questions"], "analyst_questions")
        _require_list_of_str(
            content["evidence_to_collect_next"], "evidence_to_collect_next"
        )
        _require_list_of_str(
            content["suggested_false_positive_checks"],
            "suggested_false_positive_checks",
        )
        _validate_hypotheses(content["hypotheses"])
    except ValueError as exc:
        return False, str(exc)

    return True, None


def extract_deterministic_fields(investigation):
    """Return a deep copy of authoritative investigation fields only."""
    result = {}
    for key in DETERMINISTIC_INVESTIGATION_KEYS:
        if key in investigation:
            result[key] = deepcopy(investigation[key])
    return result
