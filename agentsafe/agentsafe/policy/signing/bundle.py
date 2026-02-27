from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path


class SigningError(ValueError):
    pass


def build_policy_bundle(policy_path: str | Path, signature_b64: str = "") -> dict:
    policy_file = Path(policy_path)
    content = policy_file.read_bytes()
    digest = hashlib.sha256(content).hexdigest()
    return {
        "version": 1,
        "policy_file": policy_file.name,
        "policy_sha256": digest,
        "signature": {
            "algorithm": "ed25519",
            "sig_b64": signature_b64,
        },
    }


def write_bundle(policy_path: str | Path, out_path: str | Path, signature_b64: str = "") -> Path:
    bundle = build_policy_bundle(policy_path=policy_path, signature_b64=signature_b64)
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    return out


def verify_bundle_hash(policy_path: str | Path, bundle_path: str | Path) -> bool:
    policy_bytes = Path(policy_path).read_bytes()
    bundle = json.loads(Path(bundle_path).read_text(encoding="utf-8"))
    digest = hashlib.sha256(policy_bytes).hexdigest()
    return digest == bundle.get("policy_sha256")


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
