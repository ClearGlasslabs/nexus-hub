"""HTTPS adapter for an explicitly approved reverse-image provider.

The deployment must allowlist the provider hostname. Only sanitized image bytes
are transmitted. The adapter does not discover providers or follow redirects.
"""
from __future__ import annotations

import os
from urllib.parse import urlparse

import httpx

from .service import Match


class VettedHttpProvider:
    def __init__(self, url: str | None = None, token: str | None = None) -> None:
        self.url = url or os.getenv("NEXUS_PROVIDER_URL", "")
        self.token = token or os.getenv("NEXUS_PROVIDER_TOKEN", "")
        parsed = urlparse(self.url)
        allowed = {x.strip().lower() for x in os.getenv("NEXUS_PROVIDER_ALLOWED_HOSTS", "").split(",") if x.strip()}
        if parsed.scheme != "https" or not parsed.hostname or parsed.hostname.lower() not in allowed:
            raise ValueError("provider URL must be HTTPS and explicitly host-allowlisted")
        if not self.token:
            raise ValueError("NEXUS_PROVIDER_TOKEN is required")
        self.name = parsed.hostname.lower()

    def search(self, image_bytes: bytes, limit: int) -> list[Match]:
        headers = {"Authorization": f"Bearer {self.token}", "Accept": "application/json"}
        files = {"image": ("query.jpg", image_bytes, "image/jpeg")}
        with httpx.Client(timeout=20.0, follow_redirects=False, verify=True) as client:
            response = client.post(self.url, headers=headers, files=files, params={"limit": limit})
            response.raise_for_status()
            payload = response.json()
        results = payload.get("matches", [])
        output: list[Match] = []
        for item in results[:limit]:
            url = str(item.get("url", ""))
            confidence = float(item.get("confidence", 0.0))
            if url.startswith("https://") and 0.0 <= confidence <= 1.0:
                output.append(Match(url=url, confidence=confidence, source=self.name))
        return output
