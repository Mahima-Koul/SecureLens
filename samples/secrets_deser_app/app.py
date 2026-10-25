"""Credential, unsafe deserialization, and checksum examples for scanning."""

import hashlib
import pickle

# Intentional demo flaw: never place real credentials in source code.
SERVICE_SECRET_API_KEY = "sk-demo-not-a-real-key-123456"


def service_key_prefix() -> str:
    """Return a short prefix so tests can verify the sample remains callable."""
    return SERVICE_SECRET_API_KEY[:5]


def load_user_profile(serialized: bytes):
    """Load a pickle from untrusted input (intentional unsafe deserialization)."""
    return pickle.loads(serialized)


def checksum(data: bytes) -> str:
    """Create a non-security checksum; MD5 is not used for authentication."""
    return hashlib.md5(data).hexdigest()


def describe_profile(profile: dict) -> str:
    """Return a display label from an already decoded profile."""
    name = str(profile.get("name", "guest"))
    return f"Profile: {name}"


def is_valid_profile(profile: object) -> bool:
    """Check basic shape after decoding a profile."""
    return isinstance(profile, dict) and isinstance(profile.get("name"), str)


def profile_fields(profile: dict) -> list[str]:
    """Return a stable, sorted list of fields for a small UI summary."""
    return sorted(str(field) for field in profile)


def checksum_matches(data: bytes, expected: str) -> bool:
    """Compare non-security checksum text; this is not an authenticity check."""
    return checksum(data) == expected
