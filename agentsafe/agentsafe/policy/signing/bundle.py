from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


class SigningError(ValueError):
    pass


def _canonical_hash(payload: dict) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def bundle_digest(bundle_path: str | Path) -> str:
    return hashlib.sha256(Path(bundle_path).read_bytes()).hexdigest()


def build_policy_bundle(
    policy_path: str | Path,
    signature_b64: str = "",
    issuer: str = "",
    source_uri: str = "",
    parent_bundle_sha256: str = "",
) -> dict:
    policy_file = Path(policy_path)
    content = policy_file.read_bytes()
    digest = hashlib.sha256(content).hexdigest()
    bundle = {
        "version": 2,
        "policy_file": policy_file.name,
        "policy_sha256": digest,
        "signature": {
            "algorithm": "ed25519",
            "sig_b64": signature_b64,
        },
        "provenance": {
            "issuer": issuer,
            "issued_at": datetime.now(timezone.utc).isoformat(),
            "source_uri": source_uri,
            "parent_bundle_sha256": parent_bundle_sha256,
        },
    }
    bundle["bundle_sha256"] = _canonical_hash(bundle)
    return bundle


def write_bundle(
    policy_path: str | Path,
    out_path: str | Path,
    signature_b64: str = "",
    issuer: str = "",
    source_uri: str = "",
    parent_bundle_sha256: str = "",
) -> Path:
    bundle = build_policy_bundle(
        policy_path=policy_path,
        signature_b64=signature_b64,
        issuer=issuer,
        source_uri=source_uri,
        parent_bundle_sha256=parent_bundle_sha256,
    )
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    return out


def attest_policy(
    policy_path: str | Path,
    out_path: str | Path,
    signature_b64: str = "",
    issuer: str = "",
    source_uri: str = "",
    parent_bundle_sha256: str = "",
) -> dict[str, str]:
    out = write_bundle(
        policy_path=policy_path,
        out_path=out_path,
        signature_b64=signature_b64,
        issuer=issuer,
        source_uri=source_uri,
        parent_bundle_sha256=parent_bundle_sha256,
    )
    payload = json.loads(out.read_text(encoding="utf-8"))
    return {
        "bundle_path": str(out),
        "bundle_sha256": str(payload.get("bundle_sha256", "")),
        "policy_sha256": str(payload.get("policy_sha256", "")),
    }


def verify_bundle_hash(policy_path: str | Path, bundle_path: str | Path) -> bool:
    policy_bytes = Path(policy_path).read_bytes()
    bundle = json.loads(Path(bundle_path).read_text(encoding="utf-8"))
    digest = hashlib.sha256(policy_bytes).hexdigest()
    return digest == bundle.get("policy_sha256")


def verify_bundle_manifest(bundle_path: str | Path) -> bool:
    bundle = json.loads(Path(bundle_path).read_text(encoding="utf-8"))
    stored = bundle.get("bundle_sha256")
    if not isinstance(stored, str) or not stored:
        # Legacy v1 bundles do not carry a bundle hash.
        return True
    material = {k: v for k, v in bundle.items() if k != "bundle_sha256"}
    return _canonical_hash(material) == stored


def verify_bundle_chain(bundle_path: str | Path, parent_bundle_path: str | Path = "") -> bool:
    if not verify_bundle_manifest(bundle_path):
        return False

    bundle = json.loads(Path(bundle_path).read_text(encoding="utf-8"))
    provenance = bundle.get("provenance", {})
    if not isinstance(provenance, dict):
        provenance = {}
    parent_expected = str(provenance.get("parent_bundle_sha256", "") or "")

    if not parent_bundle_path:
        return not parent_expected

    parent_actual = bundle_digest(parent_bundle_path)
    return parent_actual == parent_expected


def _load_ed25519_public_key(public_key_pem: str):
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ModuleNotFoundError as exc:
        raise SigningError("cryptography package required for ed25519 verification") from exc

    key = serialization.load_pem_public_key(Path(public_key_pem).read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise SigningError("Public key is not ed25519")
    return key


def verify_bundle_signature(policy_path: str | Path, bundle_path: str | Path, public_key_pem: str) -> bool:
    bundle = json.loads(Path(bundle_path).read_text(encoding="utf-8"))
    sig_b64 = bundle.get("signature", {}).get("sig_b64", "")
    if not sig_b64:
        raise SigningError("Bundle missing signature")

    key = _load_ed25519_public_key(public_key_pem)
    policy_bytes = Path(policy_path).read_bytes()
    signature = base64.b64decode(sig_b64)
    try:
        key.verify(signature, policy_bytes)
        return True
    except Exception:
        return False
