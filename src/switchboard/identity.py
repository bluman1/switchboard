"""Local identity and state store (spec 2.1, 2.5).

Layout of ``$SWITCHBOARD_HOME`` (default ``~/.config/switchboard``)::

    identity.json   private seeds, mode 0600, never leaves the machine
    config.json     relay url, handle, runtime
    card.json       the published capability card
    policy.json     standing policy (spec section 9)
    state.json      inbox cursor, seen envelope ids, tasks, contacts

The encrypted backup export is an Argon2id-derived SecretBox over the
identity file, so a human can stash it somewhere safe.
"""

from __future__ import annotations

import base64
import json
import os
from urllib.parse import urlparse
from pathlib import Path
from typing import Any

from nacl import pwhash, secret, utils

from . import crypto

DEFAULT_HOME = Path.home() / ".config" / "switchboard"


class IdentityError(RuntimeError):
    pass


LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


def check_relay_url(url: str, *, insecure: bool = False) -> None:
    """Refuse a plaintext relay unless it is on this machine or explicitly allowed.

    Signatures stop a network observer from forging anything, but over plain
    HTTP it can still read DM metadata and directory lookups, and rewrite
    responses a client has not pinned yet. Local relays are fine for tests.
    """
    parsed = urlparse(url)
    if parsed.scheme == "https":
        return
    if parsed.scheme != "http":
        raise IdentityError(f"relay url must start with https:// (got {url!r})")
    host = (parsed.hostname or "").lower()
    if host in LOCAL_HOSTS or insecure:
        return
    raise IdentityError(f"relay {url!r} is plaintext http; use https, or pass --insecure if you accept the risk")


class Home:
    def __init__(self, path: str | os.PathLike | None = None):
        env = os.environ.get("SWITCHBOARD_HOME")
        self.path = Path(path or env or DEFAULT_HOME).expanduser()
        self.identity_path = self.path / "identity.json"
        self.config_path = self.path / "config.json"
        self.card_path = self.path / "card.json"
        self.policy_path = self.path / "policy.json"
        self.state_path = self.path / "state.json"
        self.previous_path = self.path / "identity.previous.json"

    # ---- generic json ----------------------------------------------------- #

    def _read(self, p: Path, default: Any) -> Any:
        if not p.exists():
            return default
        return json.loads(p.read_text("utf-8"))

    def _write(self, p: Path, value: Any, private: bool = False) -> None:
        self.path.mkdir(parents=True, exist_ok=True, mode=0o700)
        tmp = p.with_suffix(p.suffix + ".tmp")
        data = json.dumps(value, indent=2, sort_keys=True).encode("utf-8")
        if private:
            # Create with 0600 from the first byte; a chmod after write leaves a window.
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
            os.chmod(tmp, 0o600)
        else:
            tmp.write_bytes(data)
        os.replace(tmp, p)

    # ---- identity --------------------------------------------------------- #

    def exists(self) -> bool:
        return self.identity_path.exists()

    def init(self, *, relay_url: str, handle: str, runtime: str, force: bool = False, insecure: bool = False) -> crypto.Keypair:
        if self.exists() and not force:
            raise IdentityError(f"identity already exists at {self.identity_path}; use --force to overwrite")
        check_relay_url(relay_url, insecure=insecure)
        kp = crypto.Keypair.generate()
        self._write(
            self.identity_path,
            {"ed25519_seed": kp.ed25519_seed.hex(), "x25519_secret": kp.x25519_secret.hex()},
            private=True,
        )
        self.save_config({"relay_url": relay_url.rstrip("/"), "handle": handle, "runtime": runtime, "registered": False, "insecure": insecure})
        if not self.state_path.exists():
            self.save_state(self.default_state())
        return kp

    def keypair(self) -> crypto.Keypair:
        data = self._read(self.identity_path, None)
        if data is None:
            raise IdentityError(f"no identity at {self.identity_path}; run `switchboard init` first")
        return crypto.Keypair(bytes.fromhex(data["ed25519_seed"]), bytes.fromhex(data["x25519_secret"]))

    def replace_keypair(self, kp: crypto.Keypair, keep_previous: bool = False) -> None:
        if keep_previous and self.identity_path.exists():
            # Mail sealed to the old X25519 key stays readable with `previous_keypairs()`.
            old = self._read(self.identity_path, {})
            prev = self._read(self.previous_path, [])
            prev.append(old)
            self._write(self.previous_path, prev, private=True)
        self._write(
            self.identity_path,
            {"ed25519_seed": kp.ed25519_seed.hex(), "x25519_secret": kp.x25519_secret.hex()},
            private=True,
        )

    def previous_keypairs(self) -> list[crypto.Keypair]:
        return [crypto.Keypair(bytes.fromhex(d["ed25519_seed"]), bytes.fromhex(d["x25519_secret"])) for d in self._read(self.previous_path, [])]

    # ---- config / card / policy / state ---------------------------------- #

    def config(self) -> dict[str, Any]:
        cfg = self._read(self.config_path, None)
        if cfg is None:
            raise IdentityError("no config; run `switchboard init` first")
        return cfg

    def save_config(self, cfg: dict[str, Any]) -> None:
        self._write(self.config_path, cfg)

    def card(self) -> dict[str, Any]:
        return self._read(self.card_path, {"capabilities": [], "constraints": []})

    def save_card(self, card: dict[str, Any]) -> None:
        self._write(self.card_path, card)

    def policy(self) -> dict[str, Any]:
        from .policy import DEFAULT_POLICY

        stored = self._read(self.policy_path, {})
        merged = dict(DEFAULT_POLICY)
        merged.update(stored)
        return merged

    def save_policy(self, policy: dict[str, Any]) -> None:
        self._write(self.policy_path, policy)

    @staticmethod
    def default_state() -> dict[str, Any]:
        return {"cursor": 0, "seen": [], "tasks": {}, "contacts": {}, "pending": []}

    def state(self) -> dict[str, Any]:
        st = self.default_state()
        st.update(self._read(self.state_path, {}))
        return st

    def save_state(self, state: dict[str, Any]) -> None:
        # Cap the dedupe window so the file does not grow forever.
        state["seen"] = state.get("seen", [])[-5000:]
        self._write(self.state_path, state)

    # ---- encrypted backup ------------------------------------------------- #

    def export_backup(self, passphrase: str) -> str:
        kp = self.keypair()
        salt = utils.random(pwhash.argon2id.SALTBYTES)
        key = pwhash.argon2id.kdf(
            secret.SecretBox.KEY_SIZE, passphrase.encode("utf-8"), salt,
            opslimit=pwhash.argon2id.OPSLIMIT_MODERATE, memlimit=pwhash.argon2id.MEMLIMIT_MODERATE,
        )
        blob = secret.SecretBox(key).encrypt(json.dumps({"ed25519_seed": kp.ed25519_seed.hex(), "x25519_secret": kp.x25519_secret.hex(), "config": self.config()}).encode())
        return "switchboard-backup-v1:" + base64.b64encode(salt + blob).decode()

    def import_backup(self, text: str, passphrase: str, force: bool = False) -> crypto.Keypair:
        prefix = "switchboard-backup-v1:"
        if not text.startswith(prefix):
            raise IdentityError("not a switchboard backup")
        if self.exists() and not force:
            raise IdentityError(f"identity already exists at {self.identity_path}; use --force to overwrite")
        raw = base64.b64decode(text[len(prefix):])
        salt, blob = raw[: pwhash.argon2id.SALTBYTES], raw[pwhash.argon2id.SALTBYTES:]
        key = pwhash.argon2id.kdf(
            secret.SecretBox.KEY_SIZE, passphrase.encode("utf-8"), salt,
            opslimit=pwhash.argon2id.OPSLIMIT_MODERATE, memlimit=pwhash.argon2id.MEMLIMIT_MODERATE,
        )
        try:
            data = json.loads(secret.SecretBox(key).decrypt(blob))
        except Exception as exc:  # noqa: BLE001
            raise IdentityError("wrong passphrase or corrupt backup") from exc
        kp = crypto.Keypair(bytes.fromhex(data["ed25519_seed"]), bytes.fromhex(data["x25519_secret"]))
        self.replace_keypair(kp)
        self.save_config(data["config"])
        if not self.state_path.exists():
            self.save_state(self.default_state())
        return kp
