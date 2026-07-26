# AutoFuzz

AutoFuzz is an orchestration framework for authorized reconnaissance and
content-discovery workflows. It does **not** implement any exploit,
vulnerability, or attack logic itself — it coordinates well-known, publicly
maintained external tools (`httpx`, `katana`, `gau`, `wayback`,
`linkfinder`, `ffuf`) and organizes their output.

## ⚠️ Authorized use only

Only run AutoFuzz against assets you own or have **explicit written
permission** to test (e.g. an in-scope bug bounty program). Running active
scanning or fuzzing tools against systems without authorization is illegal in
most jurisdictions and against the terms of virtually every bug bounty
program. You are responsible for scoping, rate-limiting, and complying with
the rules of engagement of any program you participate in.

## Pipeline overview

<table style="width: 100%;">
  <thead>
    <tr>
      <th>Stage</th>
      <th>What it does</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>1</td>
      <td>Liveness check</td>
    </tr>
    <tr>
      <td>2</td>
      <td>Collect JS files</td>
    </tr>
    <tr>
      <td>3</td>
      <td>Endpoint extraction from JS</td>
    </tr>
    <tr>
      <td>4</td>
      <td>Endpoint extraction (fetch/axios/ajax/location)</td>
    </tr>
    <tr>
      <td>5</td>
      <td>Secret-pattern scanning</td>
    </tr>
    <tr>
      <td>6</td>
      <td>Wordlist build</td>
    </tr>
    <tr>
      <td>7, 9, 10</td>
      <td>Directory / recursive / extension fuzzing</td>
    </tr>
    <tr>
      <td>11</td>
      <td>API/schema discovery (swagger/openapi/graphql)</td>
    </tr>
    <tr>
      <td>12, 13</td>
      <td>Interesting-response / keyword classification</td>
    </tr>
    <tr>
      <td>14</td>
      <td>Technology fingerprinting</td>
    </tr>
  </tbody>
</table>




## Prerequisites

External tools must be installed separately and are **not** bundled by the
pip package — they're either on your system already or you use the Docker
image below, which bundles all of them:

```bash
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest   # rename the binary to `wayback` — see below
go install github.com/ffuf/ffuf/v2@latest
# LinkFinder: https://github.com/GerbenJavado/LinkFinder (install as an executable named `linkfinder` on PATH)
```

`waybackurls` needs renaming, since AutoFuzz looks for a binary literally
named `wayback`:
```bash
mv "$(go env GOPATH)/bin/waybackurls" "$(go env GOPATH)/bin/wayback"
```

AutoFuzz detects missing binaries at runtime, prints a clear warning, and
skips the corresponding stage instead of failing the whole run — so it's
still useful even if you only have some of these installed.

## Install

Three ways to get the `autofuzz` command, in order of convenience.

### Option 1 — pip install (recommended)

This is what actually creates a real `autofuzz` command on your `PATH` —
no manual `chmod`/`mv`/`PATH` editing needed; `pip` generates the wrapper
executable for you from the `[project.scripts]` entry in `pyproject.toml`.

```bash
git clone https://github.com/Assili-yassine/autofuzz.git
cd autofuzz

# Per-user install (recommended — no sudo, installs to ~/.local/bin)
pip install --user .

# — or system-wide (needs sudo, installs to e.g. /usr/local/bin) —
sudo pip install .
```

Or just run the included script, which does the same thing and tells you
if `~/.local/bin` needs adding to your `PATH`:
```bash
./install.sh
```

Then, from **any** directory:
```bash
autofuzz --help
autofuzz -d https://example.com
```

To update later, just `git pull` and re-run `pip install --user .` (or
`./install.sh`) — pip overwrites the old installed version.

To uninstall:
```bash
pip uninstall autofuzz
```

### Option 2 — Docker (bundles every external tool too)

If you don't want to install `httpx`/`katana`/`gau`/`ffuf`/`linkfinder`
yourself, the Docker image builds all of them alongside AutoFuzz:

```bash
git clone https://github.com/Assili-yassine/autofuzz.git
cd autofuzz
docker build -t autofuzz .
```

Run it against the directory you're standing in — results land in
`./results` on your **host** machine, via the bind mount:
```bash
docker run --rm -v "$(pwd):/work" autofuzz -d https://example.com --json
docker run --rm -v "$(pwd):/work" autofuzz -i domains.txt --html
```

Or with `make`:
```bash
make docker-build
make docker-run ARGS="-d https://example.com --json"
```

### Option 3 — run without installing (development mode)

Useful if you're editing AutoFuzz itself:
```bash
git clone https://github.com/Assili-yassine/autofuzz.git
cd autofuzz
pip install -r requirements.txt
python3 autofuzz.py -d https://example.com
```

## Usage

Once installed (Option 1 or 2), just use `autofuzz` directly, from
anywhere — results are always created in **whatever directory you run the
command from** (a `results/` folder there, not next to wherever AutoFuzz
itself is installed):

```bash
# Single target
autofuzz -d https://api.example.com --threads 50

# Domain list, extra wordlist merged in, keep the generated wordlist
autofuzz -i domains.txt -w fuzzingworld/wordlist.txt -s --html --json

# Route gau + ffuf through local Tor
autofuzz -i domains.txt -p

# Route gau + ffuf through a specific proxy
autofuzz -i domains.txt -p socks5://8.16.42.30:8060

# Resume an interrupted run
autofuzz -i domains.txt --resume
```

(If you're running in development mode via Option 3 instead, replace
`autofuzz` with `python3 autofuzz.py` in all of the above.)

### Configuration

You don't need a `config.yaml` at all — AutoFuzz has sensible built-in
defaults. If you want to customize thread counts, timeouts, match codes,
skip-extensions, etc., AutoFuzz looks in this order:

1. `--config /path/to/config.yaml`, if you pass one explicitly.
2. `./config.yaml` in whatever directory you run `autofuzz` from
   (project-local config — copy the one from this repo as a starting point).
3. `~/.config/autofuzz/config.yaml` — a **persistent global config** so you
   don't need a `config.yaml` in every directory. Handy once `autofuzz` is
   installed as a system command:
   ```bash
   mkdir -p ~/.config/autofuzz
   cp config.yaml ~/.config/autofuzz/config.yaml
   ```
4. Built-in defaults, if none of the above exist.

## CLI reference

```
-i, --input FILE        File with one target per line
-d, --domain URL        Single target URL/domain
--config PATH           Path to config.yaml (default: config.yaml)
--threads N             Worker/ffuf thread count
-p, --proxy [URL]       Proxy for gau + ffuf only. Bare -p = socks5://127.0.0.1:9050 (Tor).
                         -p URL = that proxy. Omitted = no proxy.
--rate N                Request rate limit (req/s)
--timeout N             Per-request timeout (seconds)
--cookies STR           Cookie header value for ffuf requests
--headers "Name: Val"   Extra header (repeatable)
--extensions .a,.b      Comma-separated extension list, overrides config.yaml
-w, --wordlist FILE     Extra wordlist file merged into the generated wordlist
-s, --save-wordlist     Keep custom_wordlist.txt after fuzzing instead of deleting it
--resume                Skip targets already completed in a prior run
--json                  Write results/results.json
--html                  Write results/report.html
--silent                Suppress non-essential console output
--debug                 Verbose debug logging
--max-workers N         Targets processed concurrently (default: 4)
```

## Output layout

```
results/
  <target-slug>/
    ffuf.txt              # status \t length \t url, per fuzzed result
    interesting.txt        # filtered/highlighted subset (status codes + keywords)
    secret.txt              # secret-pattern hits (truncated matches only)
    custom_wordlist.txt      # only present if -s / --save-wordlist was passed
  global_fuzzing_results.txt # only for -i (multi-domain) runs
  results.json                # only with --json
  report.html                  # only with --html
  .autofuzz_state.json          # resume checkpoint
```

## What this repository does **not** do

- No exploitation, payload delivery, or credential verification.
- No wordlists of real-world secrets/keys are bundled.
- No bypass of authentication, WAFs, or rate limits.
- No screenshots, no parameter fuzzing (both removed in this revision).

---
by assili_yassine — https://github.com/Assili-yassine
 