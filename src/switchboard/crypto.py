"""Keys, signatures, and DM encryption (spec sections 2.1 and 4.3).

Key encoding on the wire:

- Ed25519 public key: ``ed25519:<64 hex chars>``
- X25519 public key:  ``x25519:<64 hex chars>``
- Signatures and ciphertext fields: standard base64.

DM encryption is the construction the spec names: an ephemeral X25519 key,
ECDH against the recipient's published X25519 key, HKDF-SHA256 to derive
a message key, XChaCha20-Poly1305 for the payload. Sender authenticity comes
from the outer envelope signature, not from the box.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
from dataclasses import dataclass

from nacl import bindings
from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError

ED25519_PREFIX = "ed25519:"
X25519_PREFIX = "x25519:"
HKDF_INFO = b"switchboard-dm-v1"


class CryptoError(ValueError):
    pass


# --------------------------------------------------------------------------- #
# Encoding helpers
# --------------------------------------------------------------------------- #


def b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def b64d(text: str) -> bytes:
    try:
        return base64.b64decode(text, validate=True)
    except Exception as exc:  # noqa: BLE001
        raise CryptoError(f"invalid base64: {exc}") from exc


def encode_ed25519_pub(raw: bytes) -> str:
    if len(raw) != 32:
        raise CryptoError("ed25519 public key must be 32 bytes")
    return ED25519_PREFIX + raw.hex()


def encode_x25519_pub(raw: bytes) -> str:
    if len(raw) != 32:
        raise CryptoError("x25519 public key must be 32 bytes")
    return X25519_PREFIX + raw.hex()


def decode_ed25519_pub(text: str) -> bytes:
    return _decode_prefixed(text, ED25519_PREFIX)


def decode_x25519_pub(text: str) -> bytes:
    return _decode_prefixed(text, X25519_PREFIX)


def _decode_prefixed(text: str, prefix: str) -> bytes:
    if not isinstance(text, str) or not text.startswith(prefix):
        raise CryptoError(f"expected key with prefix {prefix!r}")
    hexpart = text[len(prefix):]
    if len(hexpart) != 64 or hexpart != hexpart.lower():
        raise CryptoError("key must be 64 lowercase hex chars")
    try:
        return bytes.fromhex(hexpart)
    except ValueError as exc:
        raise CryptoError("key is not valid hex") from exc


def is_ed25519_pub(text: str) -> bool:
    try:
        decode_ed25519_pub(text)
        return True
    except CryptoError:
        return False


def fingerprint(pubkey: str) -> str:
    """Short display fingerprint (spec 2.3): first 8 bytes of SHA-256 of the raw key."""
    raw = decode_ed25519_pub(pubkey)
    digest = hashlib.sha256(raw).digest()[:8]
    return ":".join(f"{b:02x}" for b in digest)


# --------------------------------------------------------------------------- #
# Identity (Ed25519) and encryption (X25519) keys
# --------------------------------------------------------------------------- #


@dataclass
class Keypair:
    """A full agent keypair: identity seed and encryption secret."""

    ed25519_seed: bytes
    x25519_secret: bytes

    @classmethod
    def generate(cls) -> "Keypair":
        return cls(ed25519_seed=os.urandom(32), x25519_secret=os.urandom(32))

    @property
    def signing_key(self) -> SigningKey:
        return SigningKey(self.ed25519_seed)

    @property
    def ed25519_pub(self) -> str:
        return encode_ed25519_pub(bytes(self.signing_key.verify_key))

    @property
    def x25519_pub(self) -> str:
        return encode_x25519_pub(bindings.crypto_scalarmult_base(self.x25519_secret))

    def sign(self, message: bytes) -> str:
        return b64e(self.signing_key.sign(message).signature)


def verify(pubkey: str, message: bytes, signature_b64: str) -> bool:
    try:
        VerifyKey(decode_ed25519_pub(pubkey)).verify(message, b64d(signature_b64))
        return True
    except (BadSignatureError, CryptoError, ValueError):
        return False


# --------------------------------------------------------------------------- #
# HKDF-SHA256 (RFC 5869)
# --------------------------------------------------------------------------- #


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm = b""
    block = b""
    counter = 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


# --------------------------------------------------------------------------- #
# Sealed DMs
# --------------------------------------------------------------------------- #


def seal(recipient_x25519_pub: str, plaintext: bytes) -> dict:
    """Encrypt ``plaintext`` to the recipient. Returns the wire dict."""
    recipient_raw = decode_x25519_pub(recipient_x25519_pub)
    eph_secret = os.urandom(32)
    eph_pub = bindings.crypto_scalarmult_base(eph_secret)
    try:
        shared = bindings.crypto_scalarmult(eph_secret, recipient_raw)
    except Exception as exc:  # noqa: BLE001  (libsodium rejects low-order points)
        raise CryptoError("recipient x25519 key is not a valid point") from exc
    key = hkdf_sha256(shared, salt=eph_pub + recipient_raw, info=HKDF_INFO, length=32)
    nonce = os.urandom(bindings.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)
    ciphertext = bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, None, nonce, key)
    return {"ephem_pub": b64e(eph_pub), "nonce": b64e(nonce), "ciphertext": b64e(ciphertext)}


def open_sealed(x25519_secret: bytes, box: dict) -> bytes:
    """Decrypt a wire dict produced by :func:`seal`."""
    try:
        eph_pub = b64d(box["ephem_pub"])
        nonce = b64d(box["nonce"])
        ciphertext = b64d(box["ciphertext"])
    except (KeyError, TypeError) as exc:
        raise CryptoError("malformed sealed box") from exc
    if len(eph_pub) != 32 or len(nonce) != bindings.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES:
        raise CryptoError("malformed sealed box")
    my_pub = bindings.crypto_scalarmult_base(x25519_secret)
    try:
        shared = bindings.crypto_scalarmult(x25519_secret, eph_pub)
        key = hkdf_sha256(shared, salt=eph_pub + my_pub, info=HKDF_INFO, length=32)
        return bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(ciphertext, None, nonce, key)
    except Exception as exc:  # noqa: BLE001  (low-order ephem_pub, bad tag, anything libsodium rejects)
        raise CryptoError("decryption failed") from exc


def is_sealed(payload: object) -> bool:
    return isinstance(payload, dict) and set(payload.keys()) == {"ephem_pub", "nonce", "ciphertext"}
