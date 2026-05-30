#!/usr/bin/env python3
"""
evidence-card.py — render a raw HTTP request/response pair into a clean, redacted
HTML "evidence card" that Playwright MCP can screenshot into a real PNG.

Why: Burp MCP returns request/response TEXT, not images. To get a real screenshot
into a bug-bounty report without capturing the Burp GUI, drop that text into a
styled card and screenshot it headless. Reproducible, redactable, and it uses the
already-connected Playwright MCP — no Burp GUI, no OS window capture.

Pipeline (two steps — the script makes the HTML, the agent takes the shot):

    1.  scripts/evidence-card.py \
            --request  req.txt --response resp.txt \
            --title "IDOR — read another user's invoice" \
            --out evidence/01-idor-http.html
        # prints the file:// URL + the exact Playwright MCP call to run next

    2.  (agent, in the Claude Code session, via Playwright MCP)
        browser_navigate(url="file:///abs/.../evidence/01-idor-http.html")
        browser_take_screenshot(filename="<finding>/evidence/01-idor-http.png",
                                fullPage=True)

Redaction (default ON for your-account secrets, per evidence-hygiene):
  - Cookie values (cookie NAMES kept), Set-Cookie values
  - Authorization header values, inline `Bearer <token>`, JWTs (eyJ...)
Pass --redact-pii to also mask emails (off by default — you often need to SHOW
cross-account PII to prove impact; mask faces/names manually when you do).
Pass --no-redact to disable all masking (e.g. when nothing sensitive is present).

Stdlib only.
"""
from __future__ import annotations

import argparse
import datetime
import html
import re
import sys
from pathlib import Path

MASK = "██████"  # ██████


def _redact_secrets(text: str) -> str:
    # Cookie: keep names, mask each value
    def _cookie(m):
        head, val = m.group(1), m.group(2)
        parts = []
        for kv in val.split(";"):
            if "=" in kv:
                name, _, _v = kv.partition("=")
                parts.append(f"{name.strip()}={MASK}")
            else:
                parts.append(kv.strip())
        return head + "; ".join(p for p in parts if p)

    text = re.sub(r"(?im)^(Cookie:\s*)(.+)$", _cookie, text)
    # Set-Cookie: keep "name=", mask value up to first ; or EOL
    text = re.sub(r"(?im)^(Set-Cookie:\s*[^=;\s]+=)([^;\r\n]+)", lambda m: m.group(1) + MASK, text)
    # Authorization header value
    text = re.sub(r"(?im)^(Authorization:\s*).+$", lambda m: m.group(1) + "[REDACTED]", text)
    # Inline bearer tokens
    text = re.sub(r"(?i)\bBearer\s+[A-Za-z0-9._\-]+", "Bearer [REDACTED]", text)
    # JWTs anywhere
    text = re.sub(r"\beyJ[A-Za-z0-9._\-]{10,}", "[REDACTED-JWT]", text)
    # api_key / token / secret = value  (json or form)
    text = re.sub(r'(?i)("?(?:api[_-]?key|token|secret|access[_-]?token|refresh[_-]?token)"?\s*[:=]\s*"?)([A-Za-z0-9._\-]{6,})',
                  lambda m: m.group(1) + "[REDACTED]", text)
    return text


def _redact_pii(text: str) -> str:
    return re.sub(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b", "[email-redacted]", text)


def build_html(title: str, request: str, response: str, captured: str, note: str | None) -> str:
    req_e = html.escape(request.rstrip())
    res_e = html.escape(response.rstrip())
    title_e = html.escape(title)
    note_block = f'<div class="note">{html.escape(note)}</div>' if note else ""
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<style>
  * {{ box-sizing: border-box; }}
  body {{ margin:0; background:#0f1115; color:#e6e6e6;
         font-family: ui-monospace, "SFMono-Regular", Menlo, Consolas, monospace; }}
  .wrap {{ max-width: 1100px; margin: 0 auto; padding: 24px; }}
  .hdr {{ display:flex; align-items:baseline; justify-content:space-between;
          border-bottom:2px solid #da7756; padding-bottom:10px; margin-bottom:16px; }}
  .hdr h1 {{ font-size:18px; margin:0; color:#fff; font-family: system-ui, sans-serif; }}
  .hdr .ts {{ font-size:12px; color:#8a8f98; }}
  .note {{ background:#1b1f27; border-left:3px solid #ff8b14; padding:8px 12px;
           margin-bottom:16px; font-family: system-ui, sans-serif; font-size:13px; color:#ffd9b0; }}
  .grid {{ display:grid; grid-template-columns: 1fr 1fr; gap:16px; }}
  .panel {{ background:#171a21; border:1px solid #2a2f3a; border-radius:8px; overflow:hidden; }}
  .panel .label {{ background:#222732; color:#9fb3c8; font-size:12px; letter-spacing:.08em;
                   text-transform:uppercase; padding:7px 12px; border-bottom:1px solid #2a2f3a;
                   font-family: system-ui, sans-serif; }}
  .panel pre {{ margin:0; padding:12px; font-size:12.5px; line-height:1.5; white-space:pre-wrap;
                word-break:break-word; color:#d7dce5; }}
  .panel.req .label {{ color:#ffb591; }}
  .panel.res .label {{ color:#a6e3a1; }}
  .foot {{ margin-top:14px; font-size:11px; color:#6b7280; font-family: system-ui, sans-serif; }}
  @media (max-width: 820px) {{ .grid {{ grid-template-columns: 1fr; }} }}
</style></head>
<body><div class="wrap">
  <div class="hdr"><h1>{title_e}</h1><span class="ts">captured {html.escape(captured)}</span></div>
  {note_block}
  <div class="grid">
    <div class="panel req"><div class="label">HTTP Request</div><pre>{req_e}</pre></div>
    <div class="panel res"><div class="label">HTTP Response</div><pre>{res_e}</pre></div>
  </div>
  <div class="foot">claude-bughunter · evidence-card · secrets redacted before render</div>
</div></body></html>"""


def _read(src: str | None) -> str:
    if src is None:
        return ""
    if src == "-":
        return sys.stdin.read()
    return Path(src).read_text(encoding="utf-8", errors="replace")


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Render an HTTP request/response into a redacted evidence card HTML.")
    ap.add_argument("--request", "-q", help="file with the raw HTTP request ('-' for stdin)")
    ap.add_argument("--response", "-s", help="file with the raw HTTP response ('-' for stdin)")
    ap.add_argument("--title", "-T", default="HTTP evidence", help="card title")
    ap.add_argument("--note", "-n", help="optional context line shown above the panels")
    ap.add_argument("--out", "-o", required=True, help="output .html path (PNG will be the same stem)")
    ap.add_argument("--captured", help="capture timestamp text (default: now)")
    ap.add_argument("--no-redact", action="store_true", help="disable all redaction")
    ap.add_argument("--redact-pii", action="store_true", help="also mask emails")
    args = ap.parse_args(argv)

    request = _read(args.request)
    response = _read(args.response)
    if not request and not response:
        print("evidence-card: need --request and/or --response", file=sys.stderr)
        return 2

    if not args.no_redact:
        request, response = _redact_secrets(request), _redact_secrets(response)
        if args.redact_pii:
            request, response = _redact_pii(request), _redact_pii(response)

    captured = args.captured or datetime.datetime.now().isoformat(timespec="seconds")
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(build_html(args.title, request, response, captured, args.note), encoding="utf-8")
    png = out.with_suffix(".png")

    print(f"[evidence-card] wrote {out}")
    print(f"[evidence-card] redaction: {'OFF' if args.no_redact else 'secrets' + (' + PII' if args.redact_pii else '')}")
    print("[evidence-card] next — screenshot it via Playwright MCP:")
    print(f"    browser_navigate(url=\"file://{out.resolve()}\")")
    print(f"    browser_take_screenshot(filename=\"{png}\", fullPage=True)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
