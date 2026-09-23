from datetime import datetime, timedelta, timezone

import pytest

from switchboard import crypto, envelope
from switchboard.canonical import CanonicalError, canonical_bytes


# ---- canonical JSON --------------------------------------------------------


def test_canonical_sorts_keys_and_strips_whitespace():
    assert canonical_bytes({"b": 1, "a": [1, {"z": None, "y": "x"}]}) == b'{"a":[1,{"y":"x","z":null}],"b":1}'


def test_canonical_keeps_utf8_and_orders_by_codepoint():
    out = canonical_bytes({"é": 1, "z": 2, "a": 3})
    assert out == '{"a":3,"z":2,"é":1}'.encode("utf-8")


def test_canonical_rejects_floats():
    with pytest.raises(CanonicalError):
        canonical_bytes({"amount": 0.05})


def test_canonical_distinguishes_null_and_absent():
    assert canonical_bytes({"a": None}) != canonical_bytes({})


# ---- crypto ----------------------------------------------------------------


def test_sign_and_verify_roundtrip():
    kp = crypto.Keypair.generate()
    sig = kp.sign(b"hello")
    assert crypto.verify(kp.ed25519_pub, b"hello", sig)
    assert not crypto.verify(kp.ed25519_pub, b"hellp", sig)
    other = crypto.Keypair.generate()
    assert not crypto.verify(other.ed25519_pub, b"hello", sig)


def test_key_encoding_roundtrip():
    kp = crypto.Keypair.generate()
    assert kp.ed25519_pub.startswith("ed25519:") and len(kp.ed25519_pub) == 8 + 64
    assert kp.x25519_pub.startswith("x25519:")
    assert crypto.encode_ed25519_pub(crypto.decode_ed25519_pub(kp.ed25519_pub)) == kp.ed25519_pub
    with pytest.raises(crypto.CryptoError):
        crypto.decode_ed25519_pub("x25519:" + "00" * 32)


def test_fingerprint_format():
    kp = crypto.Keypair.generate()
    fp = crypto.fingerprint(kp.ed25519_pub)
    assert len(fp.split(":")) == 8


def test_seal_and_open():
    alice = crypto.Keypair.generate()
    bob = crypto.Keypair.generate()
    box = crypto.seal(bob.x25519_pub, b"secret plan")
    assert crypto.is_sealed(box)
    assert crypto.open_sealed(bob.x25519_secret, box) == b"secret plan"
    with pytest.raises(crypto.CryptoError):
        crypto.open_sealed(alice.x25519_secret, box)


def test_seal_is_randomized():
    bob = crypto.Keypair.generate()
    a = crypto.seal(bob.x25519_pub, b"x")
    b = crypto.seal(bob.x25519_pub, b"x")
    assert a["ciphertext"] != b["ciphertext"]


def test_tampered_ciphertext_fails():
    bob = crypto.Keypair.generate()
    box = crypto.seal(bob.x25519_pub, b"secret")
    raw = bytearray(crypto.b64d(box["ciphertext"]))
    raw[0] ^= 0xFF
    box["ciphertext"] = crypto.b64e(bytes(raw))
    with pytest.raises(crypto.CryptoError):
        crypto.open_sealed(bob.x25519_secret, box)


def test_hkdf_rfc5869_vector():
    # RFC 5869 test case 1
    ikm = bytes.fromhex("0b" * 22)
    salt = bytes.fromhex("000102030405060708090a0b0c")
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    okm = crypto.hkdf_sha256(ikm, salt, info, 42)
    assert okm.hex() == (
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    )


# ---- envelope --------------------------------------------------------------


def _signed(kp, **overrides):
    env = envelope.build(
        type="post",
        from_handle="alice",
        from_pubkey=kp.ed25519_pub,
        to="channel:general",
        payload={"text": "hi"},
    )
    env.update(overrides)
    return envelope.sign(env, kp)


def test_envelope_roundtrip():
    kp = crypto.Keypair.generate()
    env = _signed(kp)
    envelope.verify(env)
    assert envelope.is_ulid(env["id"])


def test_envelope_tamper_detected():
    kp = crypto.Keypair.generate()
    env = _signed(kp)
    env["payload"]["text"] = "changed"
    with pytest.raises(envelope.EnvelopeError, match="bad signature"):
        envelope.verify(env)


def test_envelope_to_is_signed_so_relay_cannot_redirect():
    kp = crypto.Keypair.generate()
    env = _signed(kp)
    env["to"] = "channel:other"
    with pytest.raises(envelope.EnvelopeError, match="bad signature"):
        envelope.verify(env)


def test_sign_rejects_mismatched_key():
    kp = crypto.Keypair.generate()
    other = crypto.Keypair.generate()
    env = envelope.build(type="post", from_handle="alice", from_pubkey=kp.ed25519_pub, to="channel:x", payload={"text": "x"})
    with pytest.raises(envelope.EnvelopeError):
        envelope.sign(env, other)


def test_encrypted_type_requires_sealed_payload():
    kp = crypto.Keypair.generate()
    bob = crypto.Keypair.generate()
    env = envelope.build(type="dm", from_handle="alice", from_pubkey=kp.ed25519_pub, to=bob.ed25519_pub, payload={"text": "plain"})
    env = envelope.sign(env, kp)
    with pytest.raises(envelope.EnvelopeError, match="sealed"):
        envelope.verify(env)


def test_channel_types_must_target_channels():
    kp = crypto.Keypair.generate()
    bob = crypto.Keypair.generate()
    env = envelope.sign(
        envelope.build(type="post", from_handle="alice", from_pubkey=kp.ed25519_pub, to=bob.ed25519_pub, payload={"text": "x"}),
        kp,
    )
    with pytest.raises(envelope.EnvelopeError, match="channel"):
        envelope.verify(env)


def test_clock_skew_enforced():
    kp = crypto.Keypair.generate()
    old = (datetime.now(timezone.utc) - timedelta(minutes=10)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    env = _signed(kp, timestamp=old)
    envelope.verify(env)  # skew not checked by default
    with pytest.raises(envelope.EnvelopeError, match="skew"):
        envelope.verify(env, check_skew=True)


def test_ulid_is_monotonic_in_time_prefix():
    a = envelope.new_ulid(now_ms=1_000)
    b = envelope.new_ulid(now_ms=2_000)
    assert a[:10] < b[:10]
    assert envelope.is_ulid(a)
