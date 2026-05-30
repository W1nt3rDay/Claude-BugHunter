---
name: nuclei-template-forge
description: Forge custom nuclei templates from a CVE advisory, a disclosed report, or your own manual finding — AI drafts the YAML, you validate it against a known-vulnerable AND a clean instance before it ever joins your private corpus. Use when you want to turn a one-off finding or a fresh CVE into a scan you can run across your whole scope, when repositioning nuclei from "vuln discoverer" to "custom-template engine / CVE monitor", or when someone says "write a nuclei template", "scan my scope for this CVE", or "automate this finding at scale". NOT for spraying default community templates at a mature target — that yields dups and N/A.
---

# nuclei-template-forge

Turn a *known* signature into a scan. The engine (nuclei) is dumb on purpose; the
intelligence is **which request reveals the bug** and **which response feature
distinguishes vulnerable from patched without false positives**. AI drafts that
YAML fast — but a template is only as good as its FP/FN rate, and that number does
not exist until you test it. This skill is the discipline that makes AI-drafted
templates trustworthy instead of noise.

## Running nuclei when scanning is prohibited (zero target impact)

Most programs ban automated scanners. You can still get nuclei's value **without
sending one request to their infrastructure** — run the engine only against data you
already captured or a target you self-host. Enforce that with the guard wrapper
`scripts/nuclei-passive.py`, which **refuses to run nuclei unless every target is
loopback (127.0.0.0/8 / localhost / ::1) or a local file** (strict IP parsing — no
`127.0.0.1.evil.com` rebinding tricks):

```bash
# A) OFFLINE — scan artifacts you already saved while manually browsing (0 network)
scripts/nuclei-passive.py -file -target ./loot/js/ -t exposures/ -t exposures/tokens/

# B) LOCALHOST — self-host the target's OSS (or replay captured responses), scan that
python3 -m http.server 9000 --bind 127.0.0.1 --directory ./loot/responses &
scripts/nuclei-passive.py -u http://127.0.0.1:9000/ -t exposures/
```

Point it at `https://their-site/` and it exits 2 without running anything. The
operator supplies data gathered during normal manual testing; the program's servers
are never touched. This is the *only* nuclei usage that is unconditionally safe on a
no-scanning program — see also the matching lab-validation step below.

## The one rule (read first)

> **No template enters the private corpus until it has fired GREEN on a
> known-vulnerable instance AND stayed SILENT on a clean/patched instance.**

Skip this and you build a corpus of plausible-but-untested matchers → false-positive
flood → triage drowns → you are back to the N/A noise problem that made default
nuclei worthless. The drafting is the easy 20%. The validation is the 80% that earns
the "custom" in custom templates.

## What this is / isn't for

| Use it for | Do NOT use it for |
|---|---|
| Encoding a *fresh CVE* (advisory + PoC + patch diff) into a scope-wide sweep | Spraying `~/nuclei-templates/` default set at a mature target (dups / N/A) |
| Turning *your own manual finding* into a template to scale across N hosts/subdomains | Inventing a template for an unknown bug from "understanding" alone (that's 0-day discovery — engine can't do it) |
| Mining `docs/disclosed-reports/` for repeatable signatures | Trusting any matcher that hasn't seen a real vulnerable + clean instance |
| Building a private CVE-monitor corpus run on a cron over time | Recalling recent-CVE specifics from memory (feed the real advisory) |

This is the operational form of the conclusion that **nuclei belongs in recon /
monitoring, not discovery**: keep the engine, swap the ammunition for your own.

## Template anatomy (what AI is actually writing)

A nuclei template = `request(s)` + `matchers`/`extractors` in YAML. Minimum viable:

```yaml
id: acme-example-cve-2025-xxxx
info:
  name: ACME Widget <2.3 — Unauthenticated Config Disclosure
  author: <you>
  severity: high
  description: /api/config returns the admin token pre-auth on ACME Widget < 2.3.
  reference:
    - https://nvd.nist.gov/vuln/detail/CVE-2025-XXXX
    - <PoC or advisory URL>
  classification:
    cve-id: CVE-2025-XXXX
  tags: cve,cve2025,acme,exposure
http:
  - method: GET
    path:
      - "{{BaseURL}}/api/config"
    matchers-condition: and          # AND, not OR — narrow the match
    matchers:
      - type: word
        part: body
        words:
          - '"admin_token"'
          - '"acme_widget"'          # a SECOND anchor so it can't fire on any JSON
        condition: and
      - type: status
        status:
          - 200
    extractors:
      - type: regex
        part: body
        regex:
          - '"admin_token"\s*:\s*"([a-f0-9]{32})"'
```

The craft is entirely in the matcher. See "Matcher discipline" below.

## The forge workflow

```
1. SOURCE     pick one: a CVE (advisory+PoC), a docs/disclosed-reports entry,
              or your own validated manual finding. Feed the REAL text, not memory.
2. EXTRACT    pull the signature: trigger request (method/path/params/headers/body)
              + the response feature that proves vulnerable (status, word, regex,
              dsl, time-delay, OOB interaction).
3. DRAFT      AI writes the YAML. Add a SECOND independent anchor to the matcher so
              it cannot fire on an unrelated 200. Set tags = cve,<year>,<product>,<class>.
4. VALIDATE   non-negotiable — see "Validation protocol". GREEN on vuln, SILENT on clean.
5. CURATE     dedup vs existing corpus, drop into the private template dir, record
              provenance. Now /recon --scan and the CVE-monitor cron can use it.
```

## Step 1 — Sources (where the signature comes from)

- **Fresh CVE** — read the advisory + public PoC + (best) the patch diff. The diff
  tells you the exact pre/post behavior to match on. `scripts/refresh-cve-index.py`
  surfaces which in-scope CVEs aren't yet covered — that list is your forge queue.
- **`docs/disclosed-reports/`** — 681 disclosed reports. Many describe a repeatable
  request→response signature (a specific path, param, header reflection). Mine them
  for candidates.
- **Your own manual finding** — the highest-value source. You already validated it by
  hand on one host; the template lets you find the same pattern on every other host.
- **Fingerprint** — header / favicon-hash / path signatures to map *what's running
  where* (feeds manual work; severity: info — not a "finding").

## Step 3 — Matcher discipline (where AI hallucinates FPs)

AI will write a matcher that *looks* right and fires on the wrong thing. Force these:

- **`matchers-condition: and`** and `condition: and` — narrow by default; OR matchers
  are how you get false positives.
- **At least two independent anchors** — a status code alone, or a single generic word
  (`"error"`, `"token"`), fires everywhere. Pair the vuln marker with a product marker.
- **Match the EFFECT, not just the request succeeding** — a 200 means the endpoint
  exists, not that it's vulnerable. Match the leaked value / the injected marker / the
  time delay, not merely "the request didn't 404".
- **Prefer `dsl` / `regex` extracting the proof** over a bare `word` when you can pull
  the actual leaked secret — it doubles as evidence.
- **For blind/OOB** (SSRF, RCE-no-echo) use nuclei's interactsh placeholders, not a
  guessed response string.

## Step 4 — Validation protocol (the 80%)

```bash
# a) syntax — free, instant, catches AI YAML errors
nuclei -t forge/CVE-2025-xxxx.yaml -validate

# b) TRUE POSITIVE — must fire on a known-vulnerable instance.
#    Stand up the matching lab; this repo ships several:
#      docs/verification/phase2{e,f,g,h,i}-lab/   (Flask vuln apps)
#      docs/verification/hardened-lab/            (defended variant)
#      docs/verification/phase3-playwright/       (browser-execution targets)
nuclei -t forge/CVE-2025-xxxx.yaml -u http://localhost:<vuln-port> -v
#    Expect: GREEN. If silent → matcher too strict (FN). Fix and re-run.

# c) TRUE NEGATIVE — must stay silent on a clean/patched instance.
nuclei -t forge/CVE-2025-xxxx.yaml -u http://localhost:<clean-port> -v
#    Expect: nothing. If it fires → matcher too loose (FP). Add an anchor. THIS is the
#    step that separates a custom template from community noise.
```

The FP/FN gate, in one table — both columns must pass before curation:

| | Vulnerable instance | Clean / patched instance |
|---|---|---|
| **Fires** | ✅ true positive — keep | ❌ false positive — tighten matcher, re-test |
| **Silent** | ❌ false negative — loosen / fix trigger, re-test | ✅ true negative — keep |

No live vulnerable instance available? Then you have an **unvalidated draft**, not a
template — mark it `# UNVALIDATED` and keep it out of the scan corpus until you can
test it. Never let memory-only confidence stand in for a real test.

## Step 5 — Curate & integrate

- Keep a **private template dir** separate from the community set, e.g.
  `~/.nuclei-forge/` (one subdir per program if scopes differ).
- Record provenance in the template `info.reference` (CVE/report/your-finding URL) and
  who validated it against which lab.
- Wire it into recon as the **repositioned** nuclei — run the engine against YOUR
  corpus instead of the full default set. **Which command depends on whether the
  program permits scanning:**

  ```bash
  # DEFAULT (program bans scanners): passive only — captured artifacts or localhost.
  scripts/nuclei-passive.py -file -target ./loot/ -t ~/.nuclei-forge/

  # ONLY if scope.md EXPLICITLY permits automated scanning on the asset: live sweep
  # with the validated private corpus, at the ≤5 req/s scope-derived cap.
  nuclei -l recon/$TARGET/live-hosts.txt -t ~/.nuclei-forge/ \
    -rl "$RL" -c "$CONC" -o recon/$TARGET/forge-hits.txt
  ```

  (`$RL`/`$CONC` come from `/recon` Step 0 — same ≤5 req/s scope-derived cap.) When
  scope.md says "no automated scanning", use the passive form only and skip the live
  sweep entirely.
- **Cron it.** The corpus' value is over *time* — new assets and new CVEs aren't in
  "already scanned". A weekly sweep of your scope with the growing corpus is the
  monitoring play that mature-target one-shot scanning can't give you.

## What AI does well vs what stays human

| AI drafts (trust) | Human owns (do not delegate) |
|---|---|
| Translate advisory/PoC/curl → valid YAML | Decide the template is correct (FP/FN test) |
| Mine many reports/CVEs → candidate signatures | Stand up / pick the vulnerable + clean instance |
| Boilerplate, tags, severity, metadata, dedup | Sign off provenance before it joins the corpus |
| Generate variants (paths, encodings) | Judge whether a "variant" is still the same bug |

## Anti-patterns (never)

- Shipping an AI-drafted template to a real target without the GREEN/SILENT gate.
- A matcher with a single generic anchor or `matchers-condition: or` "to be safe".
- Recalling a recent CVE's request/response from memory instead of the real advisory.
- Treating template *count* as progress — 200 untested templates is negative value
  (FP triage cost). Ten validated ones beat a hundred plausible ones.
- Using this to brute-discover unknown bugs. It encodes KNOWN signatures; discovery is
  still manual depth (the money bugs — IDOR / logic / auth chains — have no template).

## Relationship to the rest of the bundle

- Loads when repositioning nuclei away from default-template discovery — the private
  corpus built here is what `/recon` Step 5 and the autopilot RECON phase should scan
  with, in place of the full `~/nuclei-templates/` default set.
- Consumes `docs/disclosed-reports/` and `scripts/refresh-cve-index.py` output as the
  candidate-signature feed.
- Validation labs live in `docs/verification/*-lab/` and `docs/verification/phase3-playwright/`.
- Pairs with `triage-validation` — a forge hit is still a *lead*, run it through the
  7-Question Gate before reporting.
