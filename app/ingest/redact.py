"""
TREMOR — PII redaction.

Responsibilities:
- Mask credit card numbers (Luhn-valid 13-19 digit sequences)
- Mask email addresses
- Mask bearer tokens (Authorization: Bearer ...)
- Mask API keys (common patterns)
- Applied BEFORE anything is stored or sent to AWS
- Fintech-grade hygiene — a differentiator

Owner: Mokshad (Phase 1)
"""

from __future__ import annotations

import re

# Regex for basic email matching
EMAIL_RE = re.compile(r"([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)")

# Regex for common API key patterns (e.g. AWS AKIA, Stripe sk_live)
API_KEY_RE = re.compile(r"(?:\b(?:AKIA|sk_live_|sk_test_|pk_live_|pk_test_)[a-zA-Z0-9]{16,32}\b)")

# Regex for Bearer tokens
BEARER_RE = re.compile(r"(Bearer\s+)[A-Za-z0-9\-\._~\+\/]+=*")

# Regex to find 13-19 digit sequences that might be credit cards
# Allowing optional spaces or dashes between groups of digits
CC_RE = re.compile(r"(?:\b|\D)((?:\d[ -]*?){13,19})(?:\b|\D)")


def _luhn_checksum(digits: str) -> bool:
    """Validate a digit string using the Luhn algorithm."""
    # Remove any non-digits
    digits = "".join(filter(str.isdigit, digits))
    if not digits:
        return False

    total = 0
    reverse_digits = digits[::-1]
    for i, char in enumerate(reverse_digits):
        d = int(char)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d

    return total % 10 == 0


def redact(text: str) -> str:
    """
    Mask PII in the given log text.
    - Emails -> <EMAIL>
    - API keys -> <API_KEY>
    - Bearer tokens -> Bearer <TOKEN>
    - Credit cards -> <CARD> (only if Luhn-valid)
    """
    if not text:
        return text

    # Mask Bearer tokens
    text = BEARER_RE.sub(r"\1<TOKEN>", text)

    # Mask API keys
    text = API_KEY_RE.sub("<API_KEY>", text)

    # Mask Emails
    text = EMAIL_RE.sub("<EMAIL>", text)

    # Mask Credit Cards (requires Luhn validation)
    # We use a loop or re.sub with a callback
    def cc_repl(match: re.Match[str]) -> str:
        # match.group(1) is the sequence of digits and separators
        candidate = match.group(1)
        if _luhn_checksum(candidate):
            # Replace the candidate within the full matched string
            # to preserve the surrounding characters captured by the regex
            full_match = match.group(0)
            return full_match.replace(candidate, "<CARD>")
        return match.group(0)

    # Apply CC redaction repeatedly in case of overlapping matches (rare but possible due to \D boundaries)
    # Re.sub with callback is sufficient here.
    text = CC_RE.sub(cc_repl, text)

    return text
