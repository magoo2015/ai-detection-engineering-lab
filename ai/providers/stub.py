"""Deterministic stub provider for tests (no network, no LLM)."""

from datetime import datetime, timezone

from ai.contract import SCHEMA_VERSION
from ai.providers.base import AIProvider


class StubProvider(AIProvider):
    """Return fixed, schema-valid AI assistance for offline testing."""

    name = "stub"
    model = "stub-v1"

    def generate(self, request):
        investigation = {}
        if isinstance(request, dict):
            investigation = request.get("investigation") or {}

        detection = investigation.get("detection") or "unknown detection"
        source_ip = investigation.get("source_ip") or "unknown source"
        username = investigation.get("username") or "unknown user"

        return {
            "schema_version": SCHEMA_VERSION,
            "status": "ok",
            "provider": self.name,
            "model": self.model,
            "generated_at": datetime.now(timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z"),
            "advisory": True,
            "content": {
                "analyst_summary": (
                    f"Possible credential guessing against {username} from "
                    f"{source_ip} for {detection}. This is advisory only and "
                    "is not a confirmed compromise."
                ),
                "why_suspicious": [
                    "Repeated authentication failures preceded a success.",
                    "Failure and success share the same source IP and username.",
                ],
                "hypotheses": [
                    {
                        "id": "H1",
                        "statement": (
                            "An attacker may have guessed valid credentials "
                            "after repeated failures."
                        ),
                        "confidence": "medium",
                        "status": "unconfirmed",
                        "supporting_signals": [
                            "failure_count correlated with success",
                            "matching source_ip and username",
                        ],
                        "contradicting_signals": [
                            "Could be a legitimate user mistyping a password",
                        ],
                    }
                ],
                "investigation_pivots": [
                    "Review subsequent session activity for the successful login",
                    "Check whether the source IP is expected for this account",
                ],
                "analyst_questions": [
                    "Was the successful authentication expected by the account owner?",
                    "Is the source IP associated with known scanners or VPN egress?",
                ],
                "evidence_to_collect_next": [
                    "Post-authentication process and sudo activity",
                    "Source IP ownership and geolocation context",
                ],
                "suggested_false_positive_checks": [
                    "Confirm whether the user recently reset or mistyped credentials",
                    "Check for scheduled automation using stale credentials",
                ],
            },
            "error": None,
        }
