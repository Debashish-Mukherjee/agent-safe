"""Placeholder for strict OpenClaw adapter once exact gateway schema is captured."""

from __future__ import annotations


class OpenClawStrictV1NotImplemented(ValueError):
    pass


def parse_strict_v1_request(path: str, payload: dict, fallback_actor: str = "openclaw-agent"):
    _ = (path, payload, fallback_actor)
    raise OpenClawStrictV1NotImplemented("strict OpenClaw v1 adapter not implemented yet")
