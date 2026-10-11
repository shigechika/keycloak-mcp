"""Which keys hold credentials. Shared by every path that keeps values out of tool output."""

#: Credential-shaped markers, matched as substrings of the lower-cased key and of the key
#: with ``.``, ``_`` and ``-`` removed (so ``saml.signing.private.key`` matches ``privatekey``).
#: A safety net for the common naming patterns, not a guarantee: a credential named outside
#: them is not caught. Bare "key" and "otp" are left out on purpose; they also match
#: innocuous names (``totp_enabled``, ``kid``).
CREDENTIAL_KEY_SUBSTRINGS = (
    "password",
    "passwd",
    "secret",
    "token",
    "credential",
    "private_key",
    "privatekey",
    "api_key",
    "apikey",
    "keystore",
)


def normalized(key: str) -> str:
    """``key`` lower-cased with ``.``, ``_`` and ``-`` removed."""
    return key.lower().replace(".", "").replace("_", "").replace("-", "")


def looks_like_credential_key(key: str) -> bool:
    """True if ``key`` contains a credential-shaped marker (case-insensitive)."""
    lowered, flat = key.lower(), normalized(key)
    return any(m in lowered or m.replace("_", "") in flat for m in CREDENTIAL_KEY_SUBSTRINGS)
