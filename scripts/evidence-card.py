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


def _caption(title: str, note: str | None) -> str:
    """A minimal, plain context line — only rendered when the operator passes one.
    Kept deliberately unstyled so the image reads like a real captured artifact, not
    a designed card. Most captions belong in the report text, not baked into the PNG."""
    bits = []
    if title:
        bits.append(f'<div class="cap-t">{html.escape(title)}</div>')
    if note:
        bits.append(f'<div class="cap-n">{html.escape(note)}</div>')
    return f'<div class="cap">{"".join(bits)}</div>' if bits else ""


def build_html(title: str, request: str, response: str, captured: str,
               note: str | None, style: str = "burp") -> str:
    req_e = html.escape(request.rstrip())
    res_e = html.escape(response.rstrip())
    cap = _caption(title, note)

    if style == "terminal":
        # Looks like `curl -i` output in a plain terminal — request, then response.
        return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><style>
  body {{ margin:0; background:#1c1c1c; color:#d0d0d0;
         font-family: "Cascadia Mono","DejaVu Sans Mono",Menlo,Consolas,monospace;
         font-size:13px; line-height:1.5; }}
  .term {{ padding:14px 16px; white-space:pre-wrap; word-break:break-word; }}
  .cap {{ padding:10px 16px 0; color:#8a8a8a; font-size:12px; }}
  .cap-t {{ color:#cfcfcf; }} .cap-n {{ color:#8a8a8a; }}
  .c {{ color:#8a8a8a; }}            /* comments / separators */
</style></head><body>
{cap}<div class="term"><span class="c"># request</span>
{req_e}

<span class="c"># response</span>
{res_e}</div></body></html>"""

    # Default "burp": neutral light HTTP viewer — plain Request | Response split,
    # no accent colors, no branding, no footer. Boring on purpose.
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><style>
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:#d4d0c8; color:#101010;
         font-family: Consolas,Menlo,"DejaVu Sans Mono",monospace; font-size:12.5px; }}
  .cap {{ padding:6px 8px; font-family:Tahoma,"Segoe UI",sans-serif; font-size:11.5px; color:#333; }}
  .cap-t {{ font-weight:600; }} .cap-n {{ color:#555; }}
  .split {{ display:flex; gap:2px; }}
  .pane {{ flex:1; background:#ffffff; border:1px solid #8a8a8a; min-width:0; }}
  .pane .tab {{ background:#ece9d8; border-bottom:1px solid #8a8a8a; padding:3px 9px;
               font-family:Tahoma,"Segoe UI",sans-serif; font-size:11.5px; color:#222; }}
  .pane pre {{ margin:0; padding:8px 10px; white-space:pre-wrap; word-break:break-word;
               line-height:1.45; color:#101010; }}
  @media (max-width:820px) {{ .split {{ flex-direction:column; }} }}
</style></head><body>
{cap}<div class="split">
  <div class="pane"><div class="tab">Request</div><pre>{req_e}</pre></div>
  <div class="pane"><div class="tab">Response</div><pre>{res_e}</pre></div>
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
    ap.add_argument("--title", "-T", default="", help="optional plain caption above the panes (default: none — keep captions in the report text)")
    ap.add_argument("--note", "-n", help="optional context line shown above the panes")
    ap.add_argument("--style", choices=["burp", "terminal"], default="burp",
                    help="burp = neutral light Request|Response split (default); terminal = curl -i look")
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
    out.write_text(build_html(args.title, request, response, captured, args.note, args.style), encoding="utf-8")
    png = out.with_suffix(".png")

    print(f"[evidence-card] wrote {out}")
    print(f"[evidence-card] redaction: {'OFF' if args.no_redact else 'secrets' + (' + PII' if args.redact_pii else '')}")
    print("[evidence-card] next — Playwright MCP blocks file:, so serve on loopback then shoot:")
    print(f"    python3 -m http.server 8731 --bind 127.0.0.1 --directory {out.parent}")
    print(f"    browser_navigate(url=\"http://127.0.0.1:8731/{out.name}\")")
    print(f"    browser_take_screenshot(filename=\"{png}\", fullPage=True)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
