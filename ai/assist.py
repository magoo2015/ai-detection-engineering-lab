"""Orchestrate optional advisory AI assistance after deterministic investigation.

AI failure must never break or mutate deterministic investigation fields.
``provider=None`` means AI is disabled.
"""

from copy import deepcopy
from uuid import uuid4

from ai.contract import (
    DETERMINISTIC_INVESTIGATION_KEYS,
    MODE,
    OUTPUT_SCHEMA,
    SCHEMA_VERSION,
    build_error_assistance,
    build_rejected_assistance,
    build_unavailable_assistance,
    extract_deterministic_fields,
    validate_ai_assistance,
)
from ai.sanitize import build_evidence_for_prompt


def build_ai_request(investigation):
    """Build the AI investigation request from a deterministic investigation."""
    authoritative = extract_deterministic_fields(investigation)
    # Do not send raw_evidence as free-form prompt text; sanitize separately.
    investigation_for_prompt = {
        key: authoritative.get(key)
        for key in DETERMINISTIC_INVESTIGATION_KEYS
        if key != "raw_evidence"
    }

    return {
        "schema_version": SCHEMA_VERSION,
        "request_id": str(uuid4()),
        "mode": MODE,
        "investigation": investigation_for_prompt,
        "evidence_for_prompt": build_evidence_for_prompt(
            authoritative.get("raw_evidence")
        ),
        "constraints": {
            "must_not": [
                "decide_detection_fire",
                "modify_severity",
                "modify_raw_evidence",
                "modify_mitre_mappings",
                "assign_final_disposition",
                "recommend_or_perform_containment_actions",
                "state_hypotheses_as_confirmed_facts",
            ],
            "output_schema": OUTPUT_SCHEMA,
        },
    }


def _provider_name(provider):
    if provider is None:
        return None
    return getattr(provider, "name", type(provider).__name__)


def attach_ai_assistance(investigation, provider=None):
    """Attach validated advisory AI output without mutating deterministic fields.

    Args:
        investigation: Deterministic investigation dict.
        provider: AIProvider instance, or None to disable AI.

    Returns:
        A new investigation dict with an ``ai_assistance`` object. Original
        deterministic field values are preserved exactly.
    """
    baseline = extract_deterministic_fields(investigation)
    result = deepcopy(baseline)

    if provider is None:
        result["ai_assistance"] = build_unavailable_assistance(
            provider_name=None,
            reason="AI disabled (provider=None)",
        )
        return result

    request = build_ai_request(investigation)
    provider_name = _provider_name(provider)

    try:
        candidate = provider.generate(request)
    except Exception as exc:  # noqa: BLE001 — fail open for any provider error
        result["ai_assistance"] = build_error_assistance(
            provider_name=provider_name,
            message=exc,
        )
        return result

    ok, reason = validate_ai_assistance(candidate)
    if not ok:
        result["ai_assistance"] = build_rejected_assistance(
            provider_name=provider_name,
            message=reason,
            model=(
                candidate.get("model")
                if isinstance(candidate, dict)
                else None
            ),
        )
        return result

    result["ai_assistance"] = deepcopy(candidate)

    # Hard guarantee: never allow AI attachment to alter authoritative fields.
    for key, value in baseline.items():
        result[key] = deepcopy(value)

    return result
