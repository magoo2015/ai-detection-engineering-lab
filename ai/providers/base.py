"""Provider interface for advisory AI investigation assistance."""


class AIProvider:
    """Base class for AI investigation providers.

    Implementations must return an ``ai_assistance`` dict matching the
    contract schema. They must not mutate the request or any investigation
    object.
    """

    name = "base"

    def generate(self, request):
        """Generate advisory AI assistance for an investigation request.

        Args:
            request: AI investigation request dict (read-only).

        Returns:
            dict: Candidate ``ai_assistance`` object for validation.
        """
        raise NotImplementedError
