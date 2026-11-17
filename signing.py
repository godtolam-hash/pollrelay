#!/usr/bin/env python3
"""Signing helpers for the polling transport (stdlib + openssl CLI).

Two modes:
  ed25519 — agent holds a private key, relay stores only the public key.
            The relay (and anyone who runs it) cannot impersonate the PC.
  hmac    — fallback when openssl lacks ed25519 (openssl < 3.0). Uses the
            shared PAIR_SECRET. Less strong, still fine over HTTPS.

The signed message is always:  <agent_id>|<unix_ts>|<nonce>
so a captured request cannot be replayed (relay checks ts skew + nonce cache).

NOTE: this file is duplicated in bazzite-agent/ and poll-relay/ on purpose,
so each side can be deployed on its own. Keep the two copies identical.
"""
import base64
import hashlib
import hmac
import os
import secrets
import subprocess
import tempfile
import time

MAX_SKEW = 300  # seconds


def msg_for(agent_id: str, ts: int | None = None, nonce: str | None = None):
    ts = int(ts if ts is not None else time.time())
    nonce = nonce or secrets.token_hex(16)
    return f"{agent_id}|{ts}|{nonce}".encode(), ts, nonce


# --------------------------------------------------------------------- ed25519
def _openssl(*args, stdin: bytes | None = None):
    return subprocess.run(["openssl", *args], capture_output=True, input=stdin)


def have_ed25519() -> bool:
    try:
        with tempfile.TemporaryDirectory() as d:
            k = os.path.join(d, "k.pem")
            r = _openssl("genpkey", "-algorithm", "ed25519", "-out", k)
            return r.returncode == 0 and os.path.exists(k)
    except Exception:
        return False


def gen_keypair(key_path: str) -> str:
    """Create ed25519 private key at key_path; return public key PEM text."""
    os.makedirs(os.path.dirname(key_path) or ".", exist_ok=True)
    r = _openssl("genpkey", "-algorithm", "ed25519", "-out", key_path)
    if r.returncode != 0:
        raise RuntimeError(f"openssl genpkey failed: {r.stderr.decode()}")
    os.chmod(key_path, 0o600)
    r = _openssl("pkey", "-in", key_path, "-pubout")
    if r.returncode != 0:
        raise RuntimeError(f"openssl pkey failed: {r.stderr.decode()}")
    return r.stdout.decode()


def sign(key_path: str, msg: bytes) -> str:
    """Sign msg with the ed25519 private key; return base64 signature."""
    with tempfile.TemporaryDirectory() as d:
        mf, sf = os.path.join(d, "m"), os.path.join(d, "s")
        with open(mf, "wb") as f:
            f.write(msg)
        r = _openssl("pkeyutl", "-sign", "-rawin", "-inkey", key_path, "-in", mf, "-out", sf)
        if r.returncode != 0:
            raise RuntimeError(f"openssl sign failed: {r.stderr.decode()}")
        with open(sf, "rb") as f:
            return base64.b64encode(f.read()).decode()


def verify(pub_pem: str, msg: bytes, sig_b64: str) -> bool:
    """Verify an ed25519 signature (pub_pem: PEM text of the public key)."""
    try:
        sig = base64.b64decode(sig_b64)
    except Exception:
        return False
    with tempfile.TemporaryDirectory() as d:
        pf, mf, sf = (os.path.join(d, n) for n in ("p.pem", "m", "s"))
        with open(pf, "w") as f:
            f.write(pub_pem)
        with open(mf, "wb") as f:
            f.write(msg)
        with open(sf, "wb") as f:
            f.write(sig)
        r = _openssl("pkeyutl", "-verify", "-pubin", "-inkey", pf, "-rawin",
                     "-in", mf, "-sigfile", sf)
        return r.returncode == 0


# ------------------------------------------------------------------------ hmac
def hmac_sign(secret: str, msg: bytes) -> str:
    return base64.b64encode(
        hmac.new(secret.encode(), msg, hashlib.sha256).digest()
    ).decode()


def hmac_verify(secret: str, msg: bytes, sig_b64: str) -> bool:
    try:
        return hmac.compare_digest(hmac_sign(secret, msg), sig_b64)
    except Exception:
        return False


# ------------------------------------------------------------------- machinery
def make_signature(mode: str, key_path: str, secret: str, msg: bytes) -> str:
    if mode == "ed25519":
        return sign(key_path, msg)
    return hmac_sign(secret, msg)


def check_signature(mode: str, pub_pem: str, secret: str, msg: bytes, sig: str) -> bool:
    if mode == "ed25519":
        return verify(pub_pem, msg, sig)
    return hmac_verify(secret, msg, sig)


def fresh(ts: int) -> bool:
    return abs(time.time() - int(ts)) <= MAX_SKEW
