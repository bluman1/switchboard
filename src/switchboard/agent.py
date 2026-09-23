"""High-level agent operations: the reference client's brain (spec 7, 9, 11).

Everything the CLI does goes through :class:`Agent`. Inbound envelopes are
verified, decrypted, deduplicated, filtered by policy, and folded into a
digest. The digest is data for the human or the host agent; nothing in it is
ever executed.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from . import crypto, envelope
from .canonical import canonical_bytes
from .card import find_capability, validate_value
from .client import DirectoryError, RelayClient, RelayError
from .identity import Home, check_relay_url
from .policy import decide_inbound_task, decide_outbound_task, quarantine_dm

TASK_TYPES = {t for t in envelope.ENCRYPTED_TYPES if t.startswith("task_")}
OPEN_STATES = {"proposed", "accepted", "in_progress", "clarifying"}
WORKING = {"accepted", "in_progress", "clarifying"}

# State each message moves the task to (spec section 7).
TRANSITIONS = {
    "task_accept": "accepted", "task_decline": "declined", "task_update": "in_progress",
    "task_question": "clarifying", "task_answer": "in_progress", "task_result": "completed",
    "task_failed": "failed", "task_cancel": "cancelled",
}
# States a message may be sent from (and accepted in).
ALLOWED_FROM = {
    "task_accept": {"proposed"}, "task_decline": {"proposed"},
    "task_update": WORKING, "task_question": WORKING, "task_answer": {"clarifying"},
    "task_result": WORKING, "task_failed": WORKING, "task_cancel": OPEN_STATES,
}
# The role that RECEIVES each message. None means either party may receive it.
INBOUND_ROLE = {
    "task_accept": "requester", "task_decline": "requester", "task_update": "requester",
    "task_result": "requester", "task_failed": "requester",
    "task_question": None, "task_answer": None, "task_cancel": None,
}
# The role that SENDS each message, for the outbound check.
OUTBOUND_ROLE = {
    "task_accept": "seller", "task_decline": "seller", "task_update": "seller",
    "task_result": "seller", "task_failed": "seller",
    "task_question": None, "task_answer": None, "task_cancel": None,
}


class NeedsConfirmation(RuntimeError):
    """Raised when standing policy does not cover an action; the human decides."""


class AgentError(RuntimeError):
    pass


def _iso_in(hours: float = 0, days: float = 0) -> str:
    dt = datetime.now(timezone.utc) + timedelta(hours=hours, days=days)
    return dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")


@dataclass
class DigestItem:
    kind: str  # channel | dm | quarantine | task | notice | error
    summary: str
    envelope_id: str | None = None
    from_handle: str | None = None
    from_pubkey: str | None = None
    fingerprint: str | None = None
    tier: str | None = None
    data: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {k: v for k, v in self.__dict__.items() if v not in (None, {}, [])}


class Agent:
    def __init__(self, home: Home | None = None, http: Any = None):
        self.home = home or Home()
        self.cfg = self.home.config()
        self.kp = self.home.keypair()
        check_relay_url(self.cfg["relay_url"], insecure=bool(self.cfg.get("insecure", False)))
        self.relay = RelayClient(self.cfg["relay_url"], self.kp, http=http)
        self._guide: dict[str, Any] | None = None
        self._entry_cache: dict[str, dict[str, Any]] = {}

    # ---- identity --------------------------------------------------------- #

    @property
    def handle(self) -> str:
        return self.cfg["handle"]

    @property
    def pubkey(self) -> str:
        return self.kp.ed25519_pub

    def guide(self) -> dict[str, Any]:
        if self._guide is None:
            self._guide = self.relay.guide()
        return self._guide

    @property
    def relay_pubkey(self) -> str:
        return self.guide()["relay"]["pubkey"]

    def whoami(self) -> dict[str, Any]:
        return {
            "handle": self.handle,
            "pubkey": self.pubkey,
            "x25519_pubkey": self.kp.x25519_pub,
            "fingerprint": crypto.fingerprint(self.pubkey),
            "relay_url": self.cfg["relay_url"],
            "runtime": self.cfg["runtime"],
            "registered": self.cfg.get("registered", False),
            "home": str(self.home.path),
        }

    def register(self) -> dict[str, Any]:
        result = self.relay.register(handle=self.handle, runtime=self.cfg["runtime"], card=self.home.card())
        self.cfg["registered"] = True
        self.home.save_config(self.cfg)
        return result["entry"]

    def publish_card(self) -> dict[str, Any]:
        return self.relay.update_card(self.home.card())["entry"]

    # ---- directory -------------------------------------------------------- #

    def lookup(self, target: str, fresh: bool = False) -> dict[str, Any]:
        """Directory lookup with trust-on-first-use pinning.

        The relay controls handle resolution. On first sight of a handle the
        client pins handle -> pubkey and pubkey -> x25519 key in local state; a
        later answer that differs is refused unless the old key published a
        signed rotation to the new one. The human can override with ``trust``.
        """
        key = target.lstrip("@")
        if not fresh and key in self._entry_cache:
            return self._entry_cache[key]
        entry = self.relay.lookup(key)  # verifies the signed registration binding
        self._pin(key, entry)
        self._entry_cache[key] = entry
        self._entry_cache[entry["pubkey"]] = entry
        if entry.get("handle"):
            self._entry_cache[entry["handle"]] = entry
        return entry

    def _pin(self, requested: str, entry: dict[str, Any]) -> None:
        st = self.home.state()
        pins = st.setdefault("pins", {})
        changed = False
        pub = entry["pubkey"]
        if crypto.is_ed25519_pub(requested):
            if pub != requested:
                raise AgentError(f"asked the relay for {requested} and got an entry for {pub}")
        elif entry.get("handle") != requested:
            # Another identity's perfectly valid entry, served under the wrong name.
            raise AgentError(f"asked the relay for handle {requested!r} and got an entry for {entry.get('handle')!r}")
        pinned_x = pins.get(pub)
        if pinned_x is None:
            pins[pub] = entry["x25519_pubkey"]
            changed = True
        elif pinned_x != entry["x25519_pubkey"]:
            raise AgentError(f"x25519 key for {pub} changed since first contact; refusing (the signed registration should make this impossible)")
        handle = entry.get("handle")
        if handle:
            pinned_pub = pins.get("@" + handle)
            if pinned_pub is None:
                pins["@" + handle] = pub
                changed = True
            elif pinned_pub != pub:
                if not self._rotation_verified(pinned_pub, pub):
                    raise AgentError(
                        f"handle {handle!r} now resolves to {crypto.fingerprint(pub)} but was pinned to "
                        f"{crypto.fingerprint(pinned_pub)}; verify out of band and run `switchboard trust {handle} --fingerprint ...`"
                    )
                pins["@" + handle] = pub
                changed = True
        if changed:
            self.home.save_state(st)

    def _rotation_verified(self, old_pub: str, new_pub: str) -> bool:
        try:
            old_entry = self.relay.lookup(old_pub)  # verify_entry checks the signed rotation record
        except (RelayError, DirectoryError, envelope.EnvelopeError):
            return False
        return old_entry.get("rotated_to") == new_pub and old_entry.get("rotation") is not None

    def trust(self, handle: str, fingerprint: str) -> dict[str, Any]:
        """Human-confirmed re-pin of a handle after an out-of-band fingerprint check."""
        entry = self.relay.lookup(handle.lstrip("@"))
        if entry["fingerprint"] != fingerprint:
            raise AgentError(f"fingerprint mismatch: directory says {entry['fingerprint']}, you gave {fingerprint}")
        st = self.home.state()
        pins = st.setdefault("pins", {})
        pins["@" + entry["handle"]] = entry["pubkey"]
        pins[entry["pubkey"]] = entry["x25519_pubkey"]
        self.home.save_state(st)
        self._entry_cache.clear()
        return entry

    def search(self, **filters: Any) -> list[dict[str, Any]]:
        return self.relay.search(**filters)["entries"]

    # ---- sending ---------------------------------------------------------- #

    def _publish(self, type: str, to: str, payload: dict[str, Any], **kw: Any) -> dict[str, Any]:
        env = envelope.build(type=type, from_handle=self.handle, from_pubkey=self.pubkey, to=to, payload=payload, **kw)
        env = envelope.sign(env, self.kp)
        self.relay.publish(env)
        return env

    def _send_sealed(self, type: str, entry: dict[str, Any], inner: dict[str, Any], **kw: Any) -> dict[str, Any]:
        box = crypto.seal(entry["x25519_pubkey"], canonical_bytes(inner))
        return self._publish(type, entry["pubkey"], box, **kw)

    def post(self, channel: str, text: str, type: str = "post") -> dict[str, Any]:
        return self._publish(type, f"channel:{channel}", {"text": text})

    def dm(self, target: str, text: str) -> dict[str, Any]:
        entry = self.lookup(target)
        return self._send_sealed("dm", entry, {"text": text})

    def subscribe(self, channel: str) -> list[str]:
        return self.relay.subscribe(channel)["channels"]

    def unsubscribe(self, channel: str) -> list[str]:
        return self.relay.unsubscribe(channel)["channels"]

    def vouch(self, target: str, statement: str, *, fingerprint: str | None = None, days: int = 365) -> dict[str, Any]:
        entry = self.lookup(target, fresh=True)
        if fingerprint is not None and entry["fingerprint"] != fingerprint:
            raise AgentError(f"fingerprint mismatch: directory says {entry['fingerprint']}, you gave {fingerprint}")
        payload = {
            "subject_pubkey": entry["pubkey"],
            "subject_handle": entry["handle"],
            "statement": statement,
            "expires_at": _iso_in(days=days),
        }
        return self._publish("vouch", self.relay_pubkey, payload)

    def revoke_vouch(self, vouch_id: str) -> dict[str, Any]:
        return self._publish("vouch_revoke", self.relay_pubkey, {"vouch_id": vouch_id})

    def rate(self, target: str, request_id: str, capability: str, score: int, note: str | None = None) -> dict[str, Any]:
        entry = self.lookup(target)
        payload: dict[str, Any] = {"request_id": request_id, "subject_pubkey": entry["pubkey"], "capability": capability, "score": score}
        if note is not None:
            payload["note"] = note
        env = self._publish("task_rate", self.relay_pubkey, payload)
        st = self.home.state()
        if request_id in st["tasks"]:
            st["tasks"][request_id]["rated"] = score
            self.home.save_state(st)
        return env

    def report(self, target: str, reason: str, evidence_ids: list[str] | None = None) -> dict[str, Any]:
        entry = self.lookup(target)
        return self.relay.report(entry["pubkey"], reason, evidence_ids)

    def rotate(self) -> crypto.Keypair:
        """Publish a rotation signed by the old key, then re-register under a new one."""
        new_kp = crypto.Keypair.generate()
        self._publish("rotation", self.relay_pubkey, {"old_pubkey": self.pubkey, "new_pubkey": new_kp.ed25519_pub, "handle": self.handle})
        # The old key is now revoked on the relay. Keep it locally so mail
        # sealed to the old X25519 key before the rotation stays readable.
        self.home.replace_keypair(new_kp, keep_previous=True)
        self.kp = new_kp
        self.relay.keypair = new_kp
        try:
            self.relay.register(handle=self.handle, runtime=self.cfg["runtime"], card=self.home.card())
        except RelayError as exc:
            raise AgentError(f"rotation published but re-registration failed ({exc}); the handle is reserved for your new key, run `switchboard register` to finish") from exc
        return new_kp

    # ---- tasks: requester side ------------------------------------------- #

    def task_request(self, target: str, capability: str, input: dict[str, Any], *, expires_hours: float = 24, force: bool = False) -> dict[str, Any]:
        entry = self.lookup(target, fresh=True)
        cap = find_capability(entry["capability_card"], capability)
        if cap is None:
            raise AgentError(f"{entry['handle']} does not offer {capability!r}")
        problems = validate_value(cap.get("input_schema", {}), input)
        if problems:
            raise AgentError("input does not match the seller's input_schema: " + "; ".join(problems))
        decision = decide_outbound_task(self.home.policy(), entry, capability)
        if not decision.automatic and not force:
            raise NeedsConfirmation(decision.reason)
        # The request id is the task_request envelope's id, so the relay can
        # later check that a rating refers to a request it actually carried.
        request_id = envelope.new_ulid()
        inner = {"request_id": request_id, "capability": capability, "input": input, "expires_at": _iso_in(hours=expires_hours)}
        env = self._send_sealed("task_request", entry, inner, id=request_id)
        st = self.home.state()
        st["tasks"][request_id] = {
            "request_id": request_id,
            "role": "requester",
            "counterparty_pubkey": entry["pubkey"],
            "counterparty_handle": entry["handle"],
            "capability": capability,
            "input": input,
            "state": "proposed",
            "expires_at": inner["expires_at"],
            "history": [env["id"]],
        }
        self.home.save_state(st)
        return st["tasks"][request_id]

    def task_cancel(self, request_id: str, reason: str = "") -> dict[str, Any]:
        return self._task_transition(request_id, "task_cancel", {"reason": reason}, "cancelled")

    def task_question(self, request_id: str, question: str) -> dict[str, Any]:
        return self._task_transition(request_id, "task_question", {"question": question}, "clarifying")

    def task_answer(self, request_id: str, answer: str) -> dict[str, Any]:
        return self._task_transition(request_id, "task_answer", {"answer": answer}, "in_progress")

    # ---- tasks: seller side ---------------------------------------------- #

    def task_accept(self, request_id: str, eta: str | None = None) -> dict[str, Any]:
        eta = eta or _iso_in(hours=24)
        return self._task_transition(request_id, "task_accept", {"eta": eta}, "accepted", must_be="proposed")

    def task_decline(self, request_id: str, reason: str) -> dict[str, Any]:
        return self._task_transition(request_id, "task_decline", {"reason": reason}, "declined", must_be="proposed")

    def task_update(self, request_id: str, note: str) -> dict[str, Any]:
        return self._task_transition(request_id, "task_update", {"progress_note": note}, "in_progress")

    def task_result(self, request_id: str, output: dict[str, Any]) -> dict[str, Any]:
        task = self._task(request_id)
        cap = find_capability(self.home.card(), task["capability"])
        if cap is not None:
            problems = validate_value(cap.get("output_schema", {}), output)
            if problems:
                raise AgentError("output does not match your output_schema: " + "; ".join(problems))
        return self._task_transition(request_id, "task_result", {"output": output}, "completed")

    def task_failed(self, request_id: str, error: str, retryable: bool = False) -> dict[str, Any]:
        return self._task_transition(request_id, "task_failed", {"error": error, "retryable": retryable}, "failed")

    def tasks(self) -> dict[str, Any]:
        return self.home.state()["tasks"]

    def _task(self, request_id: str) -> dict[str, Any]:
        st = self.home.state()
        task = st["tasks"].get(request_id)
        if task is None:
            raise AgentError(f"unknown task {request_id}")
        return task

    def _task_transition(self, request_id: str, type: str, extra: dict[str, Any], new_state: str, must_be: str | None = None) -> dict[str, Any]:
        st = self.home.state()
        task = st["tasks"].get(request_id)
        if task is None:
            raise AgentError(f"unknown task {request_id}")
        if task["state"] not in OPEN_STATES:
            raise AgentError(f"task {request_id} is already {task['state']}")
        role = OUTBOUND_ROLE[type]
        if role is not None and task["role"] != role:
            raise AgentError(f"only the {role} can send {type}; you are the {task['role']} on {request_id}")
        if must_be and task["state"] != must_be:
            raise AgentError(f"task {request_id} is {task['state']}, expected {must_be}")
        if task["state"] not in ALLOWED_FROM[type]:
            raise AgentError(f"cannot send {type} while task {request_id} is {task['state']}")
        if type == "task_accept" and task.get("expires_at"):
            try:
                if envelope.parse_iso(task["expires_at"]) < datetime.now(timezone.utc):
                    raise AgentError(f"task {request_id} expired at {task['expires_at']}")
            except envelope.EnvelopeError:
                pass  # unparseable expiry from a foreign client: do not block the human
        entry = self.lookup(task["counterparty_pubkey"])
        env = self._send_sealed(type, entry, {"request_id": request_id, **extra})
        task["state"] = new_state
        task["history"].append(env["id"])
        task.update({k: v for k, v in extra.items() if k in ("eta", "output", "error", "reason")})
        st["pending"] = [p for p in st["pending"] if p != request_id]
        self.home.save_state(st)
        return task

    def approve(self, request_id: str, eta: str | None = None) -> dict[str, Any]:
        """Human approves a pending inbound task_request."""
        return self.task_accept(request_id, eta)

    # ---- polling ---------------------------------------------------------- #

    def poll(self, *, auto: bool = True, limit: int = 100, ack: bool = True) -> list[DigestItem]:
        # Tiers change (vouches, revocations); look every sender up fresh once per poll.
        self._entry_cache.clear()
        st = self.home.state()
        policy = self.home.policy()
        card = self.home.card()
        seen = set(st["seen"])
        digest: list[DigestItem] = []
        page = self.relay.inbox(cursor=st["cursor"], limit=limit)
        for item in page["items"]:
            env = item.get("envelope") if isinstance(item, dict) else None
            env_id = env.get("id") if isinstance(env, dict) else None
            try:
                envelope.verify(env)
            except Exception as exc:  # noqa: BLE001  (EnvelopeError, CanonicalError, TypeError on junk)
                digest.append(DigestItem("error", f"dropped envelope with invalid signature or shape: {exc}", env_id if isinstance(env_id, str) else None))
                continue
            if env["id"] in seen:
                continue
            seen.add(env["id"])
            try:
                self._handle(env, st, policy, card, auto, digest)
            except Exception as exc:  # noqa: BLE001
                # Anything a sender or the relay can provoke must not stop the
                # cursor from advancing, or one hostile envelope wedges the inbox.
                digest.append(DigestItem("error", f"{env['type']} from {env['from']['handle']}: {type(exc).__name__}: {exc}", env["id"]))
        st["cursor"] = page["next_cursor"]
        st["seen"] = sorted(seen)
        self.home.save_state(st)
        if ack and page["next_cursor"] != page["cursor"]:
            self.relay.ack(page["next_cursor"])
        return digest

    def _sender_info(self, env: dict[str, Any], st: dict[str, Any]) -> tuple[dict[str, Any] | None, str, bool]:
        pub = env["from"]["pubkey"]
        try:
            entry = self.lookup(pub)
        except RelayError:
            entry = None
        tier = entry["tier"] if entry else "T0"
        known = pub in st["contacts"]
        st["contacts"].setdefault(pub, {"handle": env["from"]["handle"], "fingerprint": crypto.fingerprint(pub), "first_seen": env["timestamp"]})
        return entry, tier, known

    def _open_inner(self, env: dict[str, Any]) -> dict[str, Any]:
        raw = None
        for kp in [self.kp, *self.home.previous_keypairs()]:  # mail sealed before a rotation stays readable
            try:
                raw = crypto.open_sealed(kp.x25519_secret, env["payload"])
                break
            except crypto.CryptoError:
                continue
        if raw is None:
            raise AgentError("could not decrypt payload with the current or any previous key")
        try:
            inner = json.loads(raw)
        except ValueError as exc:
            raise AgentError(f"sealed payload is not JSON: {exc}") from exc
        if not isinstance(inner, dict):
            raise AgentError("sealed payload is not an object")
        return inner

    def _handle(self, env: dict[str, Any], st: dict[str, Any], policy: dict[str, Any], card: dict[str, Any], auto: bool, digest: list[DigestItem]) -> None:
        t = env["type"]
        frm = env["from"]
        entry, tier, known = self._sender_info(env, st)
        base = dict(envelope_id=env["id"], from_handle=frm["handle"], from_pubkey=frm["pubkey"], fingerprint=crypto.fingerprint(frm["pubkey"]), tier=tier)

        if t in envelope.CHANNEL_TYPES:
            if t == "shout" and tier == "T0":
                return  # default client drops T0 shouts entirely (spec 6.4)
            digest.append(DigestItem("channel", f"[{env['to']}] {frm['handle']}: {env['payload'].get('text', '')}", data={"type": t}, **base))
            return

        if t in envelope.RELAY_RECORD_TYPES:
            digest.append(DigestItem("notice", f"{t} from {frm['handle']}: {json.dumps(env['payload'])}", data={"type": t, "payload": env["payload"]}, **base))
            return

        if env["to"] != self.pubkey and env["to"] not in {k.ed25519_pub for k in self.home.previous_keypairs()}:
            return
        inner = self._open_inner(env)

        if t == "dm":
            kind = "quarantine" if quarantine_dm(policy, tier) else "dm"
            digest.append(DigestItem(kind, f"{frm['handle']}: {inner.get('text', '')}", data={"text": inner.get("text", "")}, **base))
            return

        if t in ("capability_query", "capability_response"):
            digest.append(DigestItem("dm", f"{t} from {frm['handle']}", data=inner, **base))
            return

        if t == "task_request":
            self._on_task_request(env, inner, entry, tier, known, st, policy, card, auto, digest, base)
            return

        if t in TASK_TYPES:
            self._on_task_message(t, inner, st, digest, base)
            return

    def _on_task_request(self, env, inner, entry, tier, known, st, policy, card, auto, digest, base) -> None:
        request_id = str(inner.get("request_id", ""))
        if not envelope.is_ulid(request_id):
            digest.append(DigestItem("error", f"task_request from {base['from_handle']} has a malformed request_id", **base))
            return
        if request_id != env["id"]:
            digest.append(DigestItem("error", f"task_request from {base['from_handle']}: request_id does not match the envelope id; ignored", **base))
            return
        if request_id in st["tasks"]:
            return  # duplicate request
        open_tasks = sum(1 for x in st["tasks"].values() if x["role"] == "seller" and x["state"] in OPEN_STATES)
        decision = decide_inbound_task(policy, card, tier, known, inner, open_tasks)
        task = {
            "request_id": request_id,
            "role": "seller",
            "counterparty_pubkey": base["from_pubkey"],
            "counterparty_handle": base["from_handle"],
            "capability": inner.get("capability"),
            "input": inner.get("input"),
            "state": "proposed",
            "expires_at": inner.get("expires_at"),
            "history": [env["id"]],
            "decision": decision.action,
            "decision_reason": decision.reason,
        }
        st["tasks"][request_id] = task
        self.home.save_state(st)
        if decision.action in ("decline", "accept") and auto:
            verb = "declined" if decision.action == "decline" else "auto-accepted"
            try:
                if decision.action == "decline":
                    self.task_decline(request_id, decision.reason)
                else:
                    self.task_accept(request_id)
            except Exception as exc:  # noqa: BLE001  (publish failed: rate limit, relay down, ...)
                # Never strand a decided task: hand it to the human instead.
                st.update(self.home.state())
                st["pending"].append(request_id)
                digest.append(DigestItem("task", f"NEEDS ATTENTION: policy said {decision.action} for {request_id} from {base['from_handle']} but sending failed ({exc}). Retry with `switchboard task {decision.action} {request_id}`", data=dict(task), **base))
                return
            st.update(self.home.state())
            digest.append(DigestItem("task", f"{verb} {task['capability']} {request_id} from {base['from_handle']} ({decision.reason})", data=dict(task), **base))
        elif decision.action == "decline":
            st["pending"].append(request_id)
            digest.append(DigestItem("task", f"WOULD DECLINE (auto off): {request_id} from {base['from_handle']}: {decision.reason}. Decline with `switchboard task decline {request_id} --reason ...`", data=dict(task), **base))
        else:
            st["pending"].append(request_id)
            digest.append(DigestItem("task", f"NEEDS APPROVAL: {task['capability']} {request_id} from {base['from_handle']} ({decision.reason}). Approve with `switchboard task accept {request_id}`", data=dict(task), **base))

    def _on_task_message(self, t, inner, st, digest, base) -> None:
        request_id = str(inner.get("request_id", ""))
        task = st["tasks"].get(request_id)
        if task is None:
            digest.append(DigestItem("error", f"{t} for unknown task {request_id} from {base['from_handle']}", **base))
            return
        if task["counterparty_pubkey"] != base["from_pubkey"]:
            digest.append(DigestItem("error", f"{t} for task {request_id} from a non-party ({base['from_handle']}); ignored", **base))
            return
        if task["state"] not in OPEN_STATES:
            digest.append(DigestItem("error", f"{t} for already-{task['state']} task {request_id}; ignored", **base))
            return
        # Only the seller answers, works, and delivers; only a party may cancel or clarify.
        expected_role = INBOUND_ROLE.get(t)
        if expected_role is not None and task["role"] != expected_role:
            digest.append(DigestItem("error", f"{t} for task {request_id} is a {'seller' if expected_role == 'requester' else 'requester'} message but I am the {task['role']}; ignored", **base))
            return
        if task["state"] not in ALLOWED_FROM[t]:
            digest.append(DigestItem("error", f"{t} for task {request_id} while {task['state']}; ignored", **base))
            return
        if t == "task_result" and task["role"] == "requester":
            entry = self.lookup(task["counterparty_pubkey"])
            cap = find_capability(entry["capability_card"], task["capability"])
            problems = validate_value(cap.get("output_schema", {}), inner.get("output")) if cap else []
            if problems:
                task["state"] = "failed"
                task["error"] = "output failed schema validation: " + "; ".join(problems)
                digest.append(DigestItem("task", f"task {request_id} result from {base['from_handle']} FAILED schema validation", data=dict(task), **base))
                return
        task["state"] = TRANSITIONS[t]
        task["history"].append(base["envelope_id"])
        for k in ("eta", "output", "error", "reason", "progress_note", "question", "answer", "retryable"):
            if k in inner:
                task[k] = inner[k]
        digest.append(DigestItem("task", f"task {request_id} ({task['capability']}) is now {task['state']} per {base['from_handle']}", data=dict(task), **base))
