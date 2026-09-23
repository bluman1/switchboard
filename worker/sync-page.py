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
        ("${{esc(d.domain)}}", "{domain}"), ("${{d.agents.length}}", "{n}"), ("${{trusted}}", "{trusted}"),
        ("${{esc(d.relay_fingerprint)}}", "{fingerprint}"), ("${{esc(d.relay_pubkey)}}", "{pubkey}"),
        ("${{jacks}}", "{jacks}"), ("${{esc(prompt)}}", "{prompt}"), ("${{url}}", "{url}"),
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


def render_jacks(agents: list[dict], now: datetime | None = None) -> str:
    """One jack per agent, lamp lit when seen in the last 24 hours, padded to full rows."""
    now = now or datetime.now(timezone.utc)
    day_ago = now - timedelta(hours=24)
    cells = []
    for a in agents:
        try:
            lit = parse_iso(a["last_seen"]) >= day_ago
        except Exception:  # noqa: BLE001
            lit = False
        title = f"offers {', '.join(a['capabilities'])}" if a["capabilities"] else "no capabilities listed yet"
        cells.append(
            f'<li class="jack{" lit" if lit else ""}" title="{escape(title)}; fingerprint {escape(a["fingerprint"])}">'
            f'<span class="ring"><span class="lamp"></span></span><span class="label"><b>{escape(a["handle"])}</b>'
            f'<small>{escape(a["runtime"])}</small><small>{escape(a["tier"])}</small></span></li>'
        )
    total = max(24, -(-len(agents) // 24) * 24)  # 24 divides by every column count the CSS uses
    cells.extend('<li class="jack empty" aria-hidden="true"><span class="ring"></span></li>' for _ in range(len(agents), total))
    return "".join(cells)


def render_page(domain: str, relay_pubkey: str, relay_fingerprint: str, agents: list[dict]) -> str:
    url = f"https://{domain}"
    trusted = sum(1 for a in agents if a["tier"] != "T0")
    prompt = PROMPT.format(url=url)
    return HTML.format(
        domain=escape(domain), n=len(agents), trusted=trusted, fingerprint=escape(relay_fingerprint),
        pubkey=escape(relay_pubkey), jacks=render_jacks(agents), prompt=escape(prompt),
    )
''' % (conv(prompt), conv(html))
(ROOT / "src/switchboard/relay/page.py").write_text(py)
print("wrote src/switchboard/relay/page.py")
