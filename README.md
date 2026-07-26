# AutoFuzz

Recon + `ffuf` automation for authorized bug bounty work. Give it one or
more domains and it checks liveness, pulls JS files and historical URLs
(`katana`, `gau`, `wayback`), extracts endpoints and possible secrets,
builds a wordlist, and fuzzes each target with `ffuf`.

AutoFuzz only orchestrates existing, well-known tools — it doesn't
implement any exploit or attack logic itself.

## ⚠️ Authorized use only

Only run this against assets you own or have explicit written permission
to test (e.g. an in-scope bug bounty program). You're responsible for
scope, rate-limiting, and following the rules of engagement of any
program you participate in.

## How it works

| Step | What happens | Tool |
|---|---|---|
| 1 | Check the target is alive | `httpx` |
| 2 | Collect JS files + historical URLs | `katana`, `gau`, `wayback` |
| 3 | Extract endpoints from JS | `linkfinder` |
| 4 | Extract more endpoints (fetch/axios/ajax calls) | built-in |
| 5 | Scan JS for possible secrets | built-in |
| 6 | Build a deduplicated wordlist | built-in |
| 7 | Fuzz the target | `ffuf` |
| 8 | Probe for API schemas (swagger/openapi/graphql) | built-in |
| 9 | Highlight interesting responses | built-in |
| 10 | Fingerprint server/framework | built-in |

Each step is skipped gracefully (with a warning) if its tool isn't
installed — you don't need every tool to get useful output.

## Requirements

- Python 3.10+
- External tools (see below), or use the Docker image which bundles them

## Install

```bash
git clone https://github.com/Assili-yassine/autofuzz.git
cd autofuzz
pip install --user .
```

That's it — `autofuzz` is now a command on your `PATH`, usable from any
directory.

Prerequisites (install separately, or use Docker instead — see below):
`httpx`, `katana`, `gau`, `ffuf`, [LinkFinder](https://github.com/GerbenJavado/LinkFinder),
and `waybackurls` renamed to `wayback`:
```bash
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/ffuf/ffuf/v2@latest
mv "$(go env GOPATH)/bin/waybackurls" "$(go env GOPATH)/bin/wayback"
```
Missing tools are auto-detected — AutoFuzz warns and skips that stage
instead of failing.

### Docker (bundles everything, no local tool install needed)

```bash
docker build -t autofuzz .
docker run --rm -v "$(pwd):/work" autofuzz -d https://example.com --json
```

## Usage

```bash
autofuzz -d https://example.com                     # single target
autofuzz -i domains.txt --html --json                # domain list
autofuzz -i domains.txt -w mywordlist.txt -s          # merge + keep wordlist
autofuzz -i domains.txt -p                             # route through Tor
autofuzz -i domains.txt -p socks5://1.2.3.4:9050        # route through a specific proxy
autofuzz -i domains.txt --resume                          # resume an interrupted run
autofuzz -d https://example.com --threads 80 --debug        # more threads, verbose logs
```

Results are always written to `./results` in whatever directory you run
the command from — not next to wherever AutoFuzz itself is installed.

## Output

```
results/
  <target>/
    ffuf.txt          # status, words, lines, length, url per hit
    interesting.txt   # highlighted subset (status codes + keywords)
    secret.txt        # confidence, type, match (truncated), source
    custom_wordlist.txt   # only if -s / --save-wordlist was passed
  global_fuzzing_results.txt   # summary, only for -i (multi-domain) runs
  results.json                  # only with --json
  report.html                    # only with --html
```

## Secret scanning

JS files are scanned for credential-shaped strings: AWS/GCP/Azure keys,
Stripe/Square/PayPal tokens, Slack/Discord tokens & webhooks, GitHub/GitLab/
NPM/PyPI tokens, SendGrid/Mailgun/Twilio/Mailchimp keys, private key blocks,
database connection strings with embedded credentials, JWTs, and generic
bearer/API-key/password assignments.

Every hit gets a **confidence** level, not just a match:
- `high` — a distinctive, format-specific pattern (e.g. `AKIA...`, `sk_live_...`, `ghp_...`)
- `medium`/`low` — a generic keyword+value pattern, downgraded automatically
  when the captured value looks like a placeholder (`your_api_key_here`,
  `changeme`, repeated/sequential characters) or has low randomness for its
  length — so `password: "changeme"` doesn't get the same weight as an
  actually random-looking secret.

Only truncated matches are ever written to disk (`secret.txt` /
`results.json`) — full values aren't persisted. This flags candidates for a
human to confirm and get rotated; it never verifies or uses a matched
secret.

## Config

No config needed to get started — sensible defaults are built in. To
customize (threads, timeouts, match codes, skip-extensions, etc.), copy
`config.yaml` to `~/.config/autofuzz/config.yaml`, or pass
`--config path/to/file.yaml`. A local `./config.yaml` in the directory
you run `autofuzz` from also works and takes priority over the
`~/.config` copy.

## Common flags

```
-i FILE        domain list, one per line
-d URL         single domain
-w FILE        extra wordlist to merge in
-p [URL]       proxy for gau + ffuf only (bare -p = local Tor, or give a URL)
-s             keep the generated wordlist instead of deleting it
--resume       skip targets already completed in a prior run
--json/--html  extra report formats
--threads N    worker/ffuf thread count
--rate N       request rate limit
--cookies STR  cookie header for ffuf requests
--headers STR  extra header, repeatable
--silent       quiet console output
--debug        verbose logging
```

## Troubleshooting

- **`pip install .` builds a package called `UNKNOWN-0.0.0` and `autofuzz`
  isn't found after install:** this means your `pip`/`setuptools` didn't
  read `pyproject.toml`'s metadata (seen on some Debian/Kali-provided pip
  versions, even when `[build-system]` asks for a newer setuptools). Fixed
  as of this version — a `setup.py` is now included alongside
  `pyproject.toml` specifically so the package name, version, and the
  `autofuzz` command still get registered correctly regardless of which
  metadata format your toolchain actually reads (verified against both a
  normal install and one where `pyproject.toml`'s `[project]` table is
  stripped out entirely). If you hit this with an older copy of the repo,
  `git pull` for the fix, then clean up the broken previous attempt first:
  ```bash
  pip uninstall -y UNKNOWN autofuzz
  rm -rf build dist ./*.egg-info UNKNOWN.egg-info
  pip install --user .
  ```
- **0 results despite known endpoints:** try setting
  `ffuf.auto_calibrate: false` in your config — auto-calibration can filter
  out real hits on apps that return the same catch-all page for every
  unknown path (common on single-page apps).
- **A stage says a binary wasn't found:** install that tool, or ignore it —
  AutoFuzz keeps going with whatever's available.
- **Wordlist looks huge:** `-w` merges in your own file plus everything
  scraped from JS/`gau`/`wayback`/`katana`; static assets (images, fonts,
  etc.) are filtered out automatically, and duplicate query-parameter
  values collapse to one example per parameter set.

## What this does **not** do

- No exploitation, payload delivery, or credential verification
- No wordlists of real-world secrets/keys bundled
- No bypass of authentication, WAFs, or rate limits
- No screenshots, no parameter-value fuzzing

---

by assili_yassine — https://github.com/Assili-yassine
