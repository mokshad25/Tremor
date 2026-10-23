"""
TREMOR — Redaction tests.
"""

from __future__ import annotations

from app.ingest.redact import _luhn_checksum, redact


class TestLuhnChecksum:
    def test_valid_cards(self) -> None:
        # Valid test card numbers
        assert _luhn_checksum("4111 1111 1111 1111")
        assert _luhn_checksum("4111-1111-1111-1111")
        assert _luhn_checksum("4111111111111111")
        # 15-digit Amex
        assert _luhn_checksum("378282246310005")

    def test_invalid_cards(self) -> None:
        # Simply changing one digit of a valid card
        assert not _luhn_checksum("4111 1111 1111 1112")
        # Too short, not really a card but checking algo logic
        assert not _luhn_checksum("1234")


class TestRedact:
    def test_redact_email(self) -> None:
        text = "User test@example.com logged in"
        assert redact(text) == "User <EMAIL> logged in"

    def test_redact_bearer_token(self) -> None:
        text = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
        assert redact(text) == "Authorization: Bearer <TOKEN>"

    def test_redact_api_key(self) -> None:
        text = "Key is AKIAIOSFODNN7EXAMPLE for AWS"
        assert redact(text) == "Key is <API_KEY> for AWS"

        text2 = "Using sk_live_" + "1234567890abcdef12345678 for Stripe"
        assert redact(text2) == "Using <API_KEY> for Stripe"

    def test_redact_credit_card(self) -> None:
        # Luhn valid
        text = "Payment processed for card 4111 1111 1111 1111 successfully"
        assert redact(text) == "Payment processed for card <CARD> successfully"

        # Luhn invalid - should not be redacted
        invalid_text = "Transaction ID 4111 1111 1111 1112 failed"
        assert redact(invalid_text) == invalid_text

    def test_multiple_redactions(self) -> None:
        text = "User foo@bar.com used card 4111111111111111 with Bearer abc"
        assert redact(text) == "User <EMAIL> used card <CARD> with Bearer <TOKEN>"

    def test_no_false_positives_on_long_numbers(self) -> None:
        # Luhn invalid 16-digit timestamp or ID
        text = "Generated ID 1234567890123456"
        assert redact(text) == text
