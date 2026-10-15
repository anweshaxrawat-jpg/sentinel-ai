class MockLLMService:
    """
    Mock LLM service that simulates AI generation responses without requiring
    external API keys or incurring costs.
    Demonstrates that the LLM only ever receives the sanitized/masked prompt.
    """

    @staticmethod
    def generate_response(sanitized_prompt: str) -> str:
        prompt_lower = sanitized_prompt.lower()

        if "summary" in prompt_lower or "summarize" in prompt_lower:
            return (
                "🤖 [Mock AI]: Here is a concise summary of the sanitized input: "
                "The document details operational guidelines while preserving privacy."
            )

        if "email" in prompt_lower or "[redacted_email]" in prompt_lower:
            return (
                "🤖 [Mock AI]: I have drafted your email response. Notice that I only "
                "reference sanitized placeholders (e.g., [REDACTED_EMAIL]) to protect user confidentiality."
            )

        if "code" in prompt_lower or "python" in prompt_lower:
            return (
                "🤖 [Mock AI]: Here is a Python code snippet tailored to your request:\n"
                "```python\n"
                "# Secure processing example\n"
                "def process_data(payload):\n"
                "    return {'status': 'processed', 'data': payload}\n"
                "```"
            )

        return (
            f"🤖 [Mock AI]: I processed your request safely.\n"
            f"Prompt received by LLM: \"{sanitized_prompt}\"\n"
            f"Gateway safety status: Verified. No sensitive credentials were exposed."
        )


mock_llm_service = MockLLMService()
