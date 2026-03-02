from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import yaml

from .bundle import SigningError, verify_bundle_chain, verify_bundle_manifest, verify_bundle_signature


@dataclass(slots=True)
class TrustVerification:
    valid: bool
    issuer: str
    source_uri: str
    issued_at: str
    chain_depth: int
    signer_pubkey: str
    signer_pubkey_sha256: str
    errors: list[str]


def public_key_digest(public_key_pem: str | Path) -> str:
    return hashlib.sha256(Path(public_key_pem).read_bytes()).hexdigest()


def _load_bundle(bundle_path: str | Path) -> dict:
    payload = json.loads(Path(bundle_path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"bundle is not an object: {bundle_path}")
    return payload


def _matches_any(patterns: list[str], value: str) -> bool:
    for pattern in patterns:
        try:
            if re.search(pattern, value):
                return True
        except re.error:
            continue
    return False


def _normalize_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(v) for v in value if str(v).strip()]


def load_trust_policy(path: str | Path) -> dict:
    payload = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    if not isinstance(payload, dict):
        raise ValueError("trust policy must be a YAML map")
    return {
        "trusted_issuers": _normalize_list(payload.get("trusted_issuers", [])),
        "source_uri_allow_regex": _normalize_list(payload.get("source_uri_allow_regex", [])),
        "max_bundle_age_hours": int(payload.get("max_bundle_age_hours", 0) or 0),
        "require_signature": bool(payload.get("require_signature", False)),
        "require_parent_chain": bool(payload.get("require_parent_chain", False)),
        "trusted_pubkeys": _normalize_list(payload.get("trusted_pubkeys", [])),
        "trusted_pubkey_sha256": _normalize_list(payload.get("trusted_pubkey_sha256", [])),
    }


def verify_bundle_chain_path(bundle: str | Path, parent_bundles: list[str | Path]) -> bool:
    current = str(bundle)
    for parent in parent_bundles:
        parent_str = str(parent)
        if not verify_bundle_manifest(parent_str):
            return False
        if not verify_bundle_chain(bundle_path=current, parent_bundle_path=parent_str):
            return False
        current = parent_str
    if not verify_bundle_manifest(current):
        return False
    return True


def verify_bundle_trust(
    *,
    policy_path: str | Path,
    bundle_path: str | Path,
    trust_policy_path: str | Path,
    parent_bundles: list[str | Path] | None = None,
    pubkeys: list[str | Path] | None = None,
) -> TrustVerification:
    errors: list[str] = []
    parent_paths = parent_bundles or []
    key_paths = pubkeys or []
    trust = load_trust_policy(trust_policy_path)
    bundle = _load_bundle(bundle_path)
    provenance = bundle.get("provenance", {})
    if not isinstance(provenance, dict):
        provenance = {}

    issuer = str(provenance.get("issuer", "") or "")
    source_uri = str(provenance.get("source_uri", "") or "")
    issued_at = str(provenance.get("issued_at", "") or "")

    if not verify_bundle_manifest(bundle_path):
        errors.append("manifest_hash_mismatch")

    trusted_issuers = trust["trusted_issuers"]
    if trusted_issuers and issuer not in trusted_issuers:
        errors.append("issuer_untrusted")

    source_patterns = trust["source_uri_allow_regex"]
    if source_patterns and not _matches_any(source_patterns, source_uri):
        errors.append("source_uri_blocked")

    max_bundle_age_hours = int(trust["max_bundle_age_hours"])
    if max_bundle_age_hours > 0:
        try:
            issued_dt = datetime.fromisoformat(issued_at)
        except ValueError:
            errors.append("issued_at_invalid")
        else:
            if issued_dt.tzinfo is None:
                issued_dt = issued_dt.replace(tzinfo=timezone.utc)
            age_hours = (datetime.now(timezone.utc) - issued_dt).total_seconds() / 3600.0
            if age_hours > max_bundle_age_hours:
                errors.append("bundle_expired")

    require_parent = bool(trust["require_parent_chain"])
    if require_parent and not parent_paths:
        errors.append("parent_chain_required")
    if parent_paths and not verify_bundle_chain_path(bundle_path, list(parent_paths)):
        errors.append("parent_chain_invalid")

    require_signature = bool(trust["require_signature"])
    signer_pubkey = ""
    signer_digest = ""
    if require_signature:
        trusted_pubkeys = [*trust["trusted_pubkeys"], *[str(p) for p in key_paths]]
        allowed_digests = {d.lower() for d in trust["trusted_pubkey_sha256"]}
        if not trusted_pubkeys:
            errors.append("signature_required_no_pubkeys")
        else:
            verified = False
            for key in trusted_pubkeys:
                digest = public_key_digest(key)
                if allowed_digests and digest.lower() not in allowed_digests:
                    continue
                try:
                    ok = verify_bundle_signature(policy_path=policy_path, bundle_path=bundle_path, public_key_pem=key)
                except SigningError:
                    ok = False
                if ok:
                    signer_pubkey = str(key)
                    signer_digest = digest
                    verified = True
                    break
            if not verified:
                errors.append("signature_verification_failed")

    return TrustVerification(
        valid=not errors,
        issuer=issuer,
        source_uri=source_uri,
        issued_at=issued_at,
        chain_depth=1 + len(parent_paths),
        signer_pubkey=signer_pubkey,
        signer_pubkey_sha256=signer_digest,
        errors=errors,
    )
