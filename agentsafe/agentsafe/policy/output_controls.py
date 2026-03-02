from __future__ import annotations

import hashlib


def cap_text_bytes(text: str, max_bytes: int) -> tuple[str, bool]:
    if max_bytes <= 0:
        return "", bool(text)
    raw = text.encode("utf-8")
    if len(raw) <= max_bytes:
        return text, False
    clipped = raw[:max_bytes]
    return clipped.decode("utf-8", errors="ignore"), True


def deterministic_jitter_ms(seed: str, max_jitter_ms: int) -> int:
    if max_jitter_ms <= 0:
        return 0
    digest = hashlib.sha256(seed.encode("utf-8")).digest()
    value = int.from_bytes(digest[:4], byteorder="big")
    return value % (max_jitter_ms + 1)
