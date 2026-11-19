"""HMAC-SHA256 signing for the Agent Games protocol.

Rules (official /build page):
  * Verify the signature of every incoming task against the RAW request
    body BEFORE parsing any JSON.
  * Sign EVERY response: header `x-agent-games-signature` = HMAC-SHA256
    over the raw response body.

The platform secret is a dashboard-generated string whose byte encoding
(UTF-8 text vs hex vs base64) is only confirmed by the first live
practice task, so verification tolerantly tries every plausible key
derivation of the configured secret and every plausible signature
encoding (hex, optional "sha256=" prefix, base64). All comparisons are
constant-time. This tolerance costs nothing in security: a request is
accepted only if it is a valid HMAC of the exact raw body under the
configured secret in *some* standard encoding.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import re

_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")
_HEX_ANY = re.compile(r"^[0-9a-fA-F]+$")


def key_candidates(secret: str) -> list[bytes]:
    """All plausible byte encodings of the configured secret string."""
    candidates: list[bytes] = []
    raw = secret.encode("utf-8")
    candidates.append(raw)
    s = secret.strip()
    if _HEX_ANY.match(s) and len(s) % 2 == 0:
        try:
            decoded = bytes.fromhex(s)
            if decoded not in candidates:
                candidates.append(decoded)
        except ValueError:
            pass
    try:
        decoded = base64.b64decode(s, validate=True)
        if len(decoded) >= 16 and decoded not in candidates:
            candidates.append(decoded)
    except (binascii.Error, ValueError):
        pass
    return candidates


def _decode_signature(header_value: str) -> bytes | None:
    v = header_value.strip()
    if v.lower().startswith("sha256="):
        v = v[len("sha256="):]
    if _HEX64.match(v):
        return bytes.fromhex(v)
    try:
        decoded = base64.b64decode(v, validate=True)
        if len(decoded) == 32:
            return decoded
    except (binascii.Error, ValueError):
        pass
    return None


def verify_signature(secret: str, raw_body: bytes, header_value: str | None) -> bool:
    """True iff the header carries a valid HMAC-SHA256 of raw_body."""
    if not header_value:
        return False
    received = _decode_signature(header_value)
    if received is None or len(received) != 32:
        return False
    for key in key_candidates(secret):
        expected = hmac.new(key, raw_body, hashlib.sha256).digest()
        if hmac.compare_digest(expected, received):
            return True
    return False


def sign_body(secret: str, raw_body: bytes) -> str:
    """Hex HMAC-SHA256 of raw_body under the secret's primary (UTF-8) key.

    The platform verifies our responses with the same secret it issued;
    the plain UTF-8 key + lowercase hex digest is the canonical form used
    by the official examples."""
    return hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
