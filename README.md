<div align="center">
  <img src="./banner.svg" alt="ReconPal" width="800">
</div>

<div align="center">

```
  ___                    ___      _
 | _ \___ __ ___ _ _    | _ \__ _| |
 |   / -_) _/ _ \ ' \   |  _/ _` | |
 |_|_\___\__\___/_||_|  |_| \__,_|_|
```

# ReconPal

**Your friendly recon companion for authorised security testing.**

[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

[Quick start](#quick-start) · [Modules](#modules) · [MCP discovery](#mcp-discovery) · [Staying in scope](#staying-in-scope) · [Reports](#reports)

</div>

---

## What it is

ReconPal maps the attack surface of a web target and audits its configuration, then hands you a report you can actually read. It is built for bug bounty hunters and penetration testers who want a fast first pass before the manual work starts.

It is deliberately **quiet and read-only by default**. There are no injection payloads, no bruteforce wordlists, and no bulk target lists. It observes how a server answers ordinary requests and tells you what stood out. That is the part of recon worth automating; the part that follows is yours.

Three things make it a little different:

- **A guided wizard.** `reconpal wizard` walks you through the options and explains each one. No flag archaeology on your first run.
- **A scope guard that actually refuses.** Every request is checked against an allow-list before it leaves. Out-of-scope hosts are blocked, not warned about.
- **MCP deployment discovery.** ReconPal understands Model Context Protocol servers — the OAuth surface in front of an AI agent's tool endpoint. As far as I know nothing else does this.

## Quick start

```bash
git clone https://github.com/amooryx/ReconPal.git
cd ReconPal
pip install -r requirements.txt

# guided, recommended for a first run
python -m reconpal wizard

# or go straight at it
python -m reconpal scan example.com
```

You will be asked to confirm you have authorisation before anything is sent. That prompt is there because a mistyped hostname is a real way to end a good week.

## Usage

```bash
# default checks: fingerprint, endpoints, headers, cors, cookies, disclosure
python -m reconpal scan target.com

# pick your own modules
python -m reconpal scan target.com -m headers cors cookies

# everything, including subdomains and MCP discovery
python -m reconpal scan target.com -m subdomains fingerprint endpoints headers cors cookies disclosure mcp

# most programs want an identifying header on your traffic
python -m reconpal scan target.com -H "X-Bug-Bounty: yourhandle"

# slow right down (default is a deliberately gentle 4/sec)
python -m reconpal scan target.com --rps 1

# see what is available
python -m reconpal modules
```

| Flag | What it does |
|---|---|
| `-m, --modules` | Which checks to run |
| `--rps` | Requests per second, default `4` |
| `-H, --header` | Extra header, repeatable |
| `-o, --out` | Report directory, default `reports/` |
| `--allow-private` | Permit targets resolving to private ranges |
| `--mcp-register` | Attempt MCP dynamic client registration |
| `-y, --yes` | Skip the authorisation prompt |
| `--no-html` | JSON only |

## Modules

| Module | What it looks at | On by default |
|---|---|:--:|
| `fingerprint` | Server software and frameworks, from headers and body markers | ✅ |
| `endpoints` | A short list of interesting paths — `.env`, `.git/HEAD`, `/actuator`, API docs | ✅ |
| `headers` | HSTS, CSP, X-Frame-Options, and the rest of the security header set | ✅ |
| `cors` | Whether an arbitrary `Origin` is reflected, and what that means with credentials | ✅ |
| `cookies` | `HttpOnly`, `Secure`, `SameSite` | ✅ |
| `disclosure` | Credential-shaped patterns in response bodies | ✅ |
| `subdomains` | Certificate Transparency lookup via crt.sh (passive — never touches the target) | — |
| `mcp` | Model Context Protocol deployment discovery | — |

Every finding carries a **severity** *and* a separate **confidence**. Those are different questions: a leaked private key is severe if real but only tentative if all we did was match a regex. Collapsing them into one number is how scanners end up crying wolf, so ReconPal keeps them apart and shows both.

## MCP discovery

Model Context Protocol servers are becoming standard infrastructure for connecting language models to real tools and data. Published MCP security work is almost all about the agent layer — tool poisoning, prompt injection. But a remote MCP server is also an ordinary HTTP deployment with an OAuth 2.1 stack in front of its JSON-RPC endpoint, and that stack is reachable by anyone with a network route.

The `mcp` module maps that surface:

- Probes common MCP endpoint paths and identifies a JSON-RPC responder
- Checks whether the `401` carries `resource_metadata` in `WWW-Authenticate` (the spec requires it; many deployments skip it)
- Retrieves all three OAuth discovery documents and **cross-compares them** — divergent `issuer` values or field sets mean they are maintained separately, which predicts inconsistency elsewhere
- Reviews advertised client authentication methods and PKCE support
- With `--mcp-register`, registers twice and compares whether `client_secret` is a per-client value or a shared constant

It deliberately does **not** report open Dynamic Client Registration as a weakness. Open DCR is what the specification asks for. What matters is what a registration *yields*, and the module reasons about that instead — a shared secret is only material if something downstream actually authenticates with it.

## Staying in scope

The scope guard is not advisory. `Scope.check()` runs before every request and raises rather than sends.

```python
Scope.from_target("https://example.com")
# allows: example.com, *.example.com
# blocks: evil.com, example.com.evil.com, notexample.com
```

Suffix confusion (`example.com.evil.com`) is handled correctly, which matters when following redirects. Targets resolving to private, loopback, or link-local ranges are refused unless you pass `--allow-private`.

Pacing is conservative by default: a 4 rps token bucket with jitter, halving on any `429` or `503` and recovering slowly. This is partly courtesy and partly self-interest — once bot mitigation starts throttling you, timing-based inference is worthless anyway.

## Reports

Every scan writes two files to `reports/`:

- **JSON** — the full result, for diffing between runs or feeding into other tooling
- **HTML** — a self-contained page, no external assets, light and dark themes, with each finding's evidence inline so you can verify without re-running

## Responsible use

ReconPal sends live traffic. Only point it at systems you have written permission to test: a bug bounty program whose scope covers the target, a signed engagement, or infrastructure you own.

Findings are **automated observations, not confirmed vulnerabilities**. Every one needs manual verification before it goes in a report. The confidence field tells you how much work that will be.

## Roadmap

- TLS certificate and cipher review
- Optional `nuclei` handoff for template-based checks
- Per-run scope files for multi-host engagements
- Post-authentication MCP `tools/list` schema classification

## Licence

MIT — see [LICENSE](LICENSE).

Inspired by [BugScanner](https://github.com/eldarshiraliyev/BugScanner), which is worth a look if you want a heavier scanner with an active vulnerability engine.
