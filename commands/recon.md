---
name: recon
description: Run full recon pipeline on a target — subdomain enum (Chaos API + subfinder), live host discovery (dnsx + httpx), URL crawl (katana + waybackurls + gau), gf pattern classification, nuclei scan. All target-facing tools are hard-capped at 5 req/s (lower if scope.md declares a stricter cap). Outputs to recon/<target>/ directory. Usage: /recon target.com
---

# /recon

Run the full recon pipeline on a target and produce a prioritized attack surface.

## What This Does

1. Enumerates subdomains (Chaos API + subfinder + assetfinder)
2. Resolves DNS and finds live hosts (dnsx + httpx with status/title/tech)
3. Crawls URLs (katana deep crawl + waybackurls + gau historical)
4. Classifies URLs by bug class (gf patterns)
5. Runs nuclei for known CVEs and misconfigs
6. Outputs prioritized attack surface summary

## Usage

```
/recon target.com
```

Or with specific focus:
```
/recon target.com --focus api
/recon target.com --focus auth
/recon target.com --fast      (skip historical URLs)
/recon target.com --rate 2    (force an even lower cap; values >5 are ignored)
```

## Rate-limit policy (NON-NEGOTIABLE)

Every **target-facing** tool (`httpx`, `katana`, `nuclei`) is rate-limited. The
effective cap is the **lower** of:

- a **hard ceiling of 5 req/s** — this is never exceeded, regardless of input, and
- whatever rate cap is declared in `scope.md` (parsed dynamically — see Step 0).

So if the program says "max 2 req/s", recon runs at 2. If the program says nothing
(or says 50), recon runs at 5. There is no way to go above 5 from this command.

> Passive tools (`subfinder`, `assetfinder`, `waybackurls`, `gau`, Chaos API) hit
> third-party data sources, **not the target**, so the cap does not apply to them.

## Egress policy (NON-NEGOTIABLE)

All recon/scan/probe traffic exits the **10888 burner node**, never the **10808
clean node**. The host's global proxy env points everything at 10808 (clean) — which
is correct for claude and normal WSL2 apps, but must NOT carry engagement scanning.
Each recon step therefore re-exports the proxy env to the burner **for that shell
only**, and the HTTP scanners also take an explicit `-proxy` flag:

```
BURNER="${BURNER_PROXY:-socks5://127.0.0.1:10888}"   # override with BURNER_PROXY if your port differs
export HTTP_PROXY=$BURNER HTTPS_PROXY=$BURNER ALL_PROXY=$BURNER (and lowercase)
httpx/katana/nuclei ... -proxy "$BURNER"
```

> Why both env AND `-proxy`: setting `ALL_PROXY` alone is **not enough** — a pre-set
> `HTTPS_PROXY=…10808` wins over `ALL_PROXY` for https URLs, so all the `*_PROXY` vars
> must be overwritten together. The explicit `-proxy` flag is the reliable backstop
> (verified: `httpx -proxy socks5://127.0.0.1:10888` exits via the burner regardless).
> Verify any time with `curl -s https://api.ipify.org` through the same proxy — it must
> show the burner IP, not the clean-node IP.

## Steps

### Step 0: Resolve the rate cap from scope.md

```bash
TARGET="$1"
HARD_MAX=5                       # absolute ceiling — recon NEVER exceeds this

# --rate <n> override (can only LOWER the cap, never raise it above HARD_MAX)
CLI_RATE=""
for a in "$@"; do case "$prev" in --rate) CLI_RATE="$a";; esac; prev="$a"; done

# Parse a declared cap out of scope.md free text, e.g.:
#   "Max 2 requests/second", "rate limit: 3 req/s", "rate-limit: 4/sec"
SCOPE_RL=""
if [ -f scope.md ]; then
  SCOPE_RL=$(grep -ioE '([0-9]+)[[:space:]]*(req|request)s?[[:space:]]*/?[[:space:]]*(s|sec|second)' scope.md | grep -oE '[0-9]+' | head -1)
  [ -z "$SCOPE_RL" ] && SCOPE_RL=$(grep -iE 'rate[-_ ]?limit' scope.md | grep -oE '[0-9]+' | head -1)
fi

# Effective cap = min(everything provided), clamped to [1, HARD_MAX]
RL=$HARD_MAX
[ -n "$SCOPE_RL" ] && [ "$SCOPE_RL" -lt "$RL" ] && RL=$SCOPE_RL
[ -n "$CLI_RATE" ]  && [ "$CLI_RATE"  -lt "$RL" ] && RL=$CLI_RATE
[ "$RL" -gt "$HARD_MAX" ] && RL=$HARD_MAX     # belt-and-suspenders
[ "$RL" -lt 1 ] && RL=1
CONC=$RL                                       # keep concurrency <= rate so bursts can't exceed it
export RL CONC

echo "[+] Rate cap: ${RL} req/s  (hard ceiling ${HARD_MAX}; scope.md declared: ${SCOPE_RL:-none}; --rate: ${CLI_RATE:-none})"
```

> **Re-run Step 0 if you edit `scope.md` mid-engagement.** The cap is read once at the
> top of the run; changing the program's stated limit means re-deriving `$RL`.

### Step 1: Subdomain Enumeration

```bash
TARGET="$1"
mkdir -p recon/$TARGET

# Scan/probe egress → 10888 BURNER node (never the 10808 clean node). Overrides the
# global proxy env for THIS recon shell only; claude & normal WSL2 apps keep 10808.
BURNER="${BURNER_PROXY:-socks5://127.0.0.1:10888}"
export HTTP_PROXY="$BURNER" HTTPS_PROXY="$BURNER" ALL_PROXY="$BURNER" \
       http_proxy="$BURNER" https_proxy="$BURNER" all_proxy="$BURNER"

# Chaos API (ProjectDiscovery — most comprehensive)
curl -s "https://dns.projectdiscovery.io/dns/$TARGET/subdomains" \
  -H "Authorization: $CHAOS_API_KEY" \
  | jq -r '.[]' > recon/$TARGET/subdomains.txt

# subfinder + assetfinder
subfinder -d $TARGET -silent | anew recon/$TARGET/subdomains.txt
assetfinder --subs-only $TARGET | anew recon/$TARGET/subdomains.txt

echo "[+] Subdomains: $(wc -l < recon/$TARGET/subdomains.txt)"
```

### Step 2: Live Host Discovery

```bash
# DNS resolve + HTTP probe with tech detection
: "${RL:=5}"; : "${CONC:=5}"     # fallback to hard cap if Step 0 ran in a separate shell
BURNER="${BURNER_PROXY:-socks5://127.0.0.1:10888}"
export HTTP_PROXY="$BURNER" HTTPS_PROXY="$BURNER" ALL_PROXY="$BURNER" \
       http_proxy="$BURNER" https_proxy="$BURNER" all_proxy="$BURNER"
# -rl caps probe rate; -t holds threads to it; -proxy forces the probe out the 10888
# burner (explicit flag — most reliable; env alone loses to a pre-set HTTPS_PROXY).
cat recon/$TARGET/subdomains.txt \
  | dnsx -silent \
  | httpx -silent -status-code -title -tech-detect -rl "$RL" -t "$CONC" -proxy "$BURNER" \
  | tee recon/$TARGET/live-hosts.txt

echo "[+] Live hosts: $(wc -l < recon/$TARGET/live-hosts.txt)"
```

### Step 3: URL Crawl

```bash
# Active crawl — -rl/-c hold katana to the scope cap (it hits the live target)
: "${RL:=5}"; : "${CONC:=5}"     # fallback to hard cap if Step 0 ran in a separate shell
BURNER="${BURNER_PROXY:-socks5://127.0.0.1:10888}"
export HTTP_PROXY="$BURNER" HTTPS_PROXY="$BURNER" ALL_PROXY="$BURNER" \
       http_proxy="$BURNER" https_proxy="$BURNER" all_proxy="$BURNER"
cat recon/$TARGET/live-hosts.txt | awk '{print $1}' \
  | katana -d 3 -jc -kf all -silent -rl "$RL" -c "$CONC" -proxy "$BURNER" \
  | anew recon/$TARGET/urls.txt

# Historical URLs
echo $TARGET | waybackurls | anew recon/$TARGET/urls.txt
gau $TARGET --subs | anew recon/$TARGET/urls.txt

echo "[+] Total URLs: $(wc -l < recon/$TARGET/urls.txt)"
```

### Step 4: Classify URLs

```bash
# Bug class classification
cat recon/$TARGET/urls.txt | gf xss       > recon/$TARGET/xss-candidates.txt
cat recon/$TARGET/urls.txt | gf ssrf      > recon/$TARGET/ssrf-candidates.txt
cat recon/$TARGET/urls.txt | gf idor      > recon/$TARGET/idor-candidates.txt
cat recon/$TARGET/urls.txt | gf sqli      > recon/$TARGET/sqli-candidates.txt
cat recon/$TARGET/urls.txt | gf redirect  > recon/$TARGET/redirect-candidates.txt
cat recon/$TARGET/urls.txt | gf lfi       > recon/$TARGET/lfi-candidates.txt

# API endpoints
cat recon/$TARGET/urls.txt | grep -E "/api/|/v1/|/v2/|/graphql|/rest/" \
  > recon/$TARGET/api-endpoints.txt

echo "[+] IDOR candidates: $(wc -l < recon/$TARGET/idor-candidates.txt)"
echo "[+] SSRF candidates: $(wc -l < recon/$TARGET/ssrf-candidates.txt)"
echo "[+] API endpoints:   $(wc -l < recon/$TARGET/api-endpoints.txt)"
```

### Step 5: Nuclei Scan

```bash
: "${RL:=5}"; : "${CONC:=5}"     # fallback to hard cap if Step 0 ran in a separate shell
BURNER="${BURNER_PROXY:-socks5://127.0.0.1:10888}"
export HTTP_PROXY="$BURNER" HTTPS_PROXY="$BURNER" ALL_PROXY="$BURNER" \
       http_proxy="$BURNER" https_proxy="$BURNER" all_proxy="$BURNER"
# -rl = global requests/sec cap, -c = template concurrency (both pinned to the
# scope-derived cap, ≤5 req/s). -proxy forces nuclei out the 10888 burner node.
nuclei -l recon/$TARGET/live-hosts.txt \
  -t ~/nuclei-templates/ \
  -severity critical,high,medium \
  -rl "$RL" -c "$CONC" -proxy "$BURNER" \
  -o recon/$TARGET/nuclei.txt

echo "[+] Nuclei findings: $(wc -l < recon/$TARGET/nuclei.txt)  (rate-capped at ${RL} req/s)"
```

## Output

After running, you will have in `recon/<target>/`:
```
subdomains.txt          # All discovered subdomains
live-hosts.txt          # Live hosts with status/title/tech
urls.txt                # All crawled URLs
api-endpoints.txt       # API-specific paths
idor-candidates.txt     # URLs with ID parameters
ssrf-candidates.txt     # URLs with URL parameters
xss-candidates.txt      # URLs with reflection candidates
nuclei.txt              # Known CVE/misconfig findings
```

## What to Do Next

1. Review `live-hosts.txt` — open interesting ones in browser
2. Check `nuclei.txt` — any high/critical findings?
3. Review `api-endpoints.txt` — start IDOR testing
4. Check for admin panels: grep live-hosts for `/admin`, `/jenkins`, `/grafana`
5. Run `/hunt target.com` to start active vulnerability testing

## 5-Minute Rule

If after running this pipeline:
- All hosts return 403 or static pages
- No API endpoints visible
- No interesting parameters in URLs
- nuclei returns 0 medium/high findings

**→ Move on to a different target.**
