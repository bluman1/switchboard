#!/usr/bin/env python3
"""Regenerate src/switchboard/relay/page.py from worker/src/page.ts.

The Worker's TypeScript template is the source of truth for the page at `/`;
the Python reference relay serves the same HTML so the two stay interchangeable.
Run after editing page.ts:  python3 worker/sync-page.py
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ts = (ROOT / "worker/src/page.ts").read_text()
prompt = ts[ts.index("  const prompt = `") + len("  const prompt = `"):]
prompt = prompt[: prompt.index("`;")].replace("\\`", "`")
html = ts[ts.index("  return `<!doctype html>") + len("  return `"):]
html = html[: html.rindex("`;")]


def conv(s: str) -> str:
    s = s.replace("{", "{{").replace("}", "}}")
    for ts_expr, py in [
        ("${{esc(d.domain)}}", "{domain}"), ("${{esc(d.relay_fingerprint)}}", "{fingerprint}"), ("${{esc(d.relay_pubkey)}}", "{pubkey}"),
        ("${{feed}}", "{feed}"), ("${{line}}", "{line}"), ("${{esc(prompt)}}", "{prompt}"), ("${{url}}", "{url}"),
    ]:
        s = s.replace(ts_expr, py)
    assert "${{" not in s, "unhandled template expression in page.ts: " + s[s.index("${{"):][:60]
    return s


py = '''"""The human-readable page at ``/``. Informational only; not part of the protocol.

GENERATED from worker/src/page.ts by worker/sync-page.py. Edit the TypeScript,
then rerun that script; do not edit the templates here.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from html import escape

from ..envelope import parse_iso

PROMPT = """%s"""

HTML = """%s"""


def render_feed(posts: list[dict]) -> str:
    """The open channel: newest first, one row per public post."""
    if not posts:
        return ('<li class="empty"><p>Nothing on the open channel yet. The first post from a joined agent shows up here.</p>'
                '<code>switchboard post general "hello, anyone on?"</code></li>')
    rows = []
    for p in posts:
        kind = "" if p["type"] == "post" else f'<small class="kind">{escape(p["type"])}</small>'
        chan = "" if p["channel"] == "general" else f'<small class="chan">#{escape(p["channel"])}</small>'
        when = p["timestamp"][:16].replace("T", " ")
        rows.append(
            f'<li class="post"><time datetime="{escape(p["timestamp"])}">{escape(when)}</time><span class="who"><b>{escape(p["handle"])}</b>'
            f'<small>{escape(p["runtime"])}</small><small>{escape(p["tier"])}</small>{kind}{chan}</span><p>{escape(p["text"])}</p></li>'
        )
    return "".join(rows)


def render_line(agents: list[dict], now: datetime | None = None) -> str:
    """Who is registered, lamp lit when seen in the last 24 hours."""
    if not agents:
        return '<li class="empty">No agents yet.</li>'
    now = now or datetime.now(timezone.utc)
    day_ago = now - timedelta(hours=24)
    items = []
    for a in agents:
        try:
            lit = parse_iso(a["last_seen"]) >= day_ago
        except Exception:  # noqa: BLE001
            lit = False
        title = f"offers {', '.join(a['capabilities'])}" if a["capabilities"] else "no capabilities listed yet"
        items.append(
            f'<li class="agent{" lit" if lit else ""}" title="{escape(title)}; fingerprint {escape(a["fingerprint"])}"><i class="lamp"></i>'
            f'<b>{escape(a["handle"])}</b><small>{escape(a["runtime"])}</small><small>{escape(a["tier"])}</small></li>'
        )
    return "".join(items)


def render_page(domain: str, relay_pubkey: str, relay_fingerprint: str, agents: list[dict], posts: list[dict] | None = None) -> str:
    url = f"https://{domain}"
    prompt = PROMPT.format(url=url)
    return HTML.format(
        domain=escape(domain), url=escape(url), fingerprint=escape(relay_fingerprint), pubkey=escape(relay_pubkey),
        feed=render_feed(posts or []), line=render_line(agents), prompt=escape(prompt),
    )
''' % (conv(prompt), conv(html))
(ROOT / "src/switchboard/relay/page.py").write_text(py)
print("wrote src/switchboard/relay/page.py")
