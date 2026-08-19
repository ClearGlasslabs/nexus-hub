"""Privacy-preserving image handling primitives.

No facial embeddings, biometric templates, or raw image bytes are persisted by
these primitives. The audit identifier is a keyed, per-query digest.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
from io import BytesIO

from PIL import Image


def sanitize_image(raw: bytes, max_pixels: int = 20_000_000) -> bytes:
    """Decode and re-encode an image, dropping EXIF and unrelated metadata."""
    if not raw:
        raise ValueError("empty image")
    with Image.open(BytesIO(raw)) as image:
        image.load()
        if image.width * image.height > max_pixels:
            raise ValueError("image exceeds maximum pixel budget")
        image = image.convert("RGB")
        output = BytesIO()
        image.save(output, format="JPEG", quality=92, optimize=True)
        return output.getvalue()


def query_digest(image_bytes: bytes, query_salt: bytes | None = None) -> tuple[str, bytes]:
    """Return an audit-only digest and the ephemeral salt.

    The caller MUST destroy the returned salt after the query. This is not a
    biometric representation and is not intended for cross-query matching.
    """
    salt = query_salt or secrets.token_bytes(32)
    digest = hmac.new(salt, image_bytes, hashlib.sha256).hexdigest()
    return digest, salt


def destroy_secret(secret: bytearray) -> None:
    """Best-effort zeroization for mutable secret buffers."""
    for i in range(len(secret)):
        secret[i] = 0
