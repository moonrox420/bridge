"""Tests for sensitive-output masking and secret redaction in Terminal Bridge."""

import unittest

from terminal_bridge import EventStore, SecretRedactor


class TestSecretRedaction(unittest.TestCase):
    """Verifies that API keys, tokens, credentials, and private keys are scrubbed."""

    def setUp(self) -> None:
        self.redactor = SecretRedactor()

    def test_openai_key_redaction(self) -> None:
        sample = "export OPENAI_API_KEY=sk-proj-abc1234567890abcdef1234567890"
        redacted = self.redactor.redact_text(sample)
        self.assertNotIn("sk-proj-abc1234567890abcdef1234567890", redacted)
        self.assertIn("[REDACTED_API_KEY]", redacted)

    def test_anthropic_key_redaction(self) -> None:
        sample = "ANTHROPIC_KEY=sk-ant-api03-abcdef12345678901234567890"
        redacted = self.redactor.redact_text(sample)
        self.assertNotIn("sk-ant-api03", redacted)
        self.assertIn("[REDACTED_API_KEY]", redacted)

    def test_github_token_redaction(self) -> None:
        sample = (
            "git clone https://ghp_abcdefghijklmnopqrstuvwxyz012345@github.com/repo"
        )
        redacted = self.redactor.redact_text(sample)
        self.assertNotIn("ghp_abcdefghijklmnopqrstuvwxyz012345", redacted)
        self.assertIn("[REDACTED_GITHUB_TOKEN]", redacted)

    def test_aws_key_redaction(self) -> None:
        sample = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
        redacted = self.redactor.redact_text(sample)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", redacted)
        self.assertIn("[REDACTED_AWS_KEY]", redacted)

    def test_bearer_token_redaction(self) -> None:
        sample = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-ID"
        redacted = self.redactor.redact_text(sample)
        self.assertNotIn("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", redacted)
        self.assertIn("[REDACTED_BEARER_TOKEN]", redacted)

    def test_credential_assignment_redaction(self) -> None:
        sample = "export DB_PASSWORD=superSecretPassword123"
        redacted = self.redactor.redact_text(sample)
        self.assertNotIn("superSecretPassword123", redacted)
        self.assertIn("[REDACTED_SECRET]", redacted)

    def test_pem_private_key_redaction(self) -> None:
        sample = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEA0Y1234567890abcdefghijklmnopqrstuvwxyz\n"
            "-----END RSA PRIVATE KEY-----"
        )
        redacted = self.redactor.redact_text(sample)
        self.assertNotIn("MIIEowIBAAKCAQEA0Y1234567890", redacted)
        self.assertIn("[REDACTED_PRIVATE_KEY_BLOCK]", redacted)

    def test_nested_data_structure_redaction(self) -> None:
        data = {
            "cmd": "curl -H 'Authorization: Bearer mySecretToken1234567890'",
            "nested": [
                "sk-ant-api03-abcdef12345678901234567890",
                {"token": "ghp_abcdefghijklmnopqrstuvwxyz012345"},
            ],
            "safe_num": 42,
        }
        sanitized = self.redactor.redact_data(data)
        self.assertIn("[REDACTED_BEARER_TOKEN]", sanitized["cmd"])
        self.assertIn("[REDACTED_API_KEY]", sanitized["nested"][0])
        self.assertIn("[REDACTED_GITHUB_TOKEN]", sanitized["nested"][1]["token"])
        self.assertEqual(sanitized["safe_num"], 42)


class TestEventStoreRedaction(unittest.TestCase):
    """Verifies that EventStore respects mask_secrets configuration."""

    def test_event_store_masks_secrets_by_default(self) -> None:
        store = EventStore(maximum=10, mask_secrets=True)
        event = store.add(
            "stdout", {"text": "Key is sk-proj-1234567890abcdef1234567890"}
        )
        self.assertNotIn("sk-proj-1234567890abcdef1234567890", event["data"]["text"])
        self.assertIn("[REDACTED_API_KEY]", event["data"]["text"])

    def test_event_store_raw_when_masking_disabled(self) -> None:
        store = EventStore(maximum=10, mask_secrets=False)
        raw_key = "sk-proj-1234567890abcdef1234567890"
        event = store.add("stdout", {"text": f"Key is {raw_key}"})
        self.assertEqual(event["data"]["text"], f"Key is {raw_key}")


if __name__ == "__main__":
    unittest.main()
