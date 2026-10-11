# leakhunter

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![C++20](https://img.shields.io/badge/C%2B%2B-20-blue.svg)](https://en.cppreference.com/w/cpp/20)
[![.NET 8](https://img.shields.io/badge/.NET-8-purple.svg)](https://dotnet.microsoft.com/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Platform: Windows](https://img.shields.io/badge/platform-Windows-lightgrey.svg)]()

Recon-grade HTTP prober, endpoint harvester, and IDOR fuzzer for authorized
security testing. C++ engine for the sweep, Python for recon and IDOR diffing,
C# for parallel authed-vs-unauthed probing.

**Use only on infrastructure you own or are explicitly authorized to test.**
See [Target selection](#target-selection).

---

## Features

- **Recon** — scrape JS bundles for endpoints, absolute URLs, and API paths.
- **Sweep** — hit every path, capture full headers, follow redirects, time each
  response, and score every reply for leak risk.
- **IDOR** — rotate an ID slot in a URL, diff normalized bodies, flag
  candidates that shift enough to look like data exposure.
- **TLS or plaintext** — WinHTTP (SChannel) for HTTPS, raw Winsock for HTTP.
  Auto-flips on port 443.
- **Zero third-party deps** for the C++ engine — `ws2_32` + `winhttp` ship
  with the Windows SDK.
- **Three languages, one pipeline** — recon finds the surface, the C++ engine
  sweeps it, Python and C# confirm the interesting hits.

## Install

### C++ engine (Windows)

Requires **Visual Studio 2022** (Community or BuildTools) with the
*Desktop development with C++* workload and the *Windows 11 SDK*.

    winget install Kitware.CMake
    winget install Ninja-build.Ninja

    git clone https://github.com/<your-user>/leakhunter.git
    cd leakhunter\cpp
    build.bat

Output: `cpp\build\leakhunter.exe` (Ninja) or `cpp\build\Release\leakhunter.exe`
(VS generator). `build.bat` auto-detects Visual Studio via `vswhere`, loads
`vcvars64`, picks Ninja if available, and prints the resulting binary path.

### C# (cross-platform)

Requires **.NET 8 SDK**.

    winget install Microsoft.DotNet.SDK.8

    cd leakhunter\cs
    dotnet build -c Release

### Python (cross-platform)

Requires **Python 3.10+**.

    cd leakhunter\py
    python -m pip install -r requirements.txt

---

## Usage

### 1. Recon — find the surface

    python py\recon.py https://target.tld

Emits JSON: `bundles`, `endpoints`, `absolute`, `api`. Feed `api[]` into the
sweeper.

### 2. Sweep — hit every path, read the reply

    leakhunter.exe HOST PORT [paths...] [https] [--headers]

    leakhunter.exe example.com 80 / /robots.txt /sitemap.xml
    leakhunter.exe target.tld 443 / /api /robots.txt --headers
    leakhunter.exe target.tld 8443 / /api https

Flags:

    https | tls | --https   force TLS (auto on port 443)
    --headers | -h          dump response headers with lowercase keys

Per-path output:

    /robots.txt -> [200 OK] 2181B 498ms  RISK=30  -> https://www.roblox.com/robots.txt
        cache-control: no-store
        server: public-gateway
        strict-transport-security: max-age=3600
        ...
        | user-agent: *  disallow: *.ashx ...

### 3. IDOR — rotate an ID, diff the responses

    python py\idor.py URL_WITH_{id} TOKEN START_ID END_ID

    python py\idor.py "https://target.tld/api/users/{id}" eyJhbGc... 1 5000

Every 200 outside the first is a candidate. **Manual confirmation required** —
automated diffs produce false positives.

### 4. Authed-vs-unauthed cross-check (C#)

    set LH_TOKEN=eyJhbGc...
    dotnet run --project cs -- https://target.tld/api/me https://target.tld/api/users/1

Sends each endpoint twice — with and without the bearer token — and reports
URLs that return the same content both ways. Classic missing-auth-check shape.

---

## Reading the output

### `HttpResponse`

| Field | Meaning |
|-------|---------|
| `status` | HTTP status code, negative on transport error |
| `status_text` | `OK`, `Not Found`, ... |
| `size` | body bytes captured (capped at 64 KB) |
| `body_truncated` | true if the real body exceeded the cap |
| `headers` | lowercased key → value |
| `redirect_chain` | final URL if it differed from the request |
| `final_url` | URL after redirects |
| `content_type` | pulled from headers for convenience |
| `elapsed_ms` | wall time for the request |
| `error_code`, `error_text` | set only on transport failure |

### Transport error codes

| Code | Meaning |
|------|---------|
| -1 | DNS or connect failed (Winsock path) |
| -2 | `WSAStartup` failed |
| -3 | `WinHttpOpen` failed |
| -4 | `WinHttpConnect` failed |
| -5 | `WinHttpOpenRequest` failed — usually malformed path |
| -6 | `WinHttpSendRequest` failed — often TLS handshake blocked |
| -7 | `WinHttpReceiveResponse` failed |

### Leak-risk score (0–100)

A heuristic, not a verdict. `RISK >= 60` prints with `HIGH`.

| Signal | Points |
|--------|--------|
| 200 with a non-empty body | +5 |
| 500 or 502 | +25 |
| 403 with a body over 500 bytes | +15 |
| Truncated body | +3 |
| Tech-disclosure headers (`server`, `x-powered-by`, `via`, ...) | +8 each |
| `Set-Cookie` present | +5 |
| Cookie missing `HttpOnly` | +5 |
| Cookie missing `Secure` | +5 |
| `Content-Type: json` | +10 |
| Body contains `password`, `api_key`, `secret`, `token`, `private_key`, `aws_access_key`, `BEGIN RSA PRIVATE`, `SQLSTATE`, `at line` | +20 |
| `Access-Control-Allow-Origin: *` or `null` | +10 |
| Each missing security header (HSTS, CSP, XFO, XCTO) | +2 |

Tune in `http.cpp` → `score_leak_risk()`. It's a single function.

---

## Target selection

Point this at one of three things:

1. **Your own infrastructure.** A VPS, a lab, an app you wrote.
2. **A target you have written permission for.** Contract or engagement letter.
3. **A host explicitly in scope for a program you're enrolled in.** Read the
   scope page — most programs self-exclude missing headers, version
   disclosure, TLS config, and raw scanner output.

**Do not run this against third-party sites without authorization.** That is
live-fire targeting, it violates the CFAA and its equivalents in most
jurisdictions, and intent does not enter into it. The authors of this project
take no responsibility for misuse. See LICENSE.

---

## Hardening notes

- The C++ build compiles with `/W4 /utf-8`. Fix warnings — they're real.
- `http.cpp` sets `SECURITY_FLAG_IGNORE_*` on the WinHTTP request to accept
  self-signed certs, which is convenient for a lab box. **Remove that block
  for any build aimed at a real production target** — you want cert validation
  on when talking to someone else's infrastructure, or you'll miss MITM.
- The 64 KB body cap (`kBodyCap` in `http.cpp`) keeps memory bounded when a
  target streams gigabytes.
- **Rate limiting is not built in.** Many production targets cap at 100
  req/min per IP (roblox does — see `x-ratelimit-limit`). A wide sweep will
  hit 429s. Add a `--rate N` flag in `main.cpp` when you need it.
- The IDOR normalizer (`norm()` in `idor.py`) strips timestamps and long hex
  strings before hashing. Extend it if your target emits IDs or nonces that
  make every response unique.

---

## Contributing

PRs and issues welcome.

- **Bug reports** — include the exact command, expected output, observed
  output, and the target class (lab / own / bounty-in-scope). Do not paste
  sensitive data from a live target.
- **New leak signals** — one block in `score_leak_risk()`. Keep the points
  meaningful; don't drown the score in noise.
- **New languages** — the pipeline is modular. A Go or Rust port of the C++
  engine is welcome as `go/` or `rust/` alongside the existing tree.
- **Style** — C++: C++20, `snake_case` for functions and variables,
  `PascalCase` for types. Python: PEP 8, type hints where useful. C#: default
  Microsoft style.

Open an issue before a large PR so we can agree on the shape.

---

## Roadmap

- [ ] `--from-json FILE` — chain `recon.py` output directly into the sweeper.
- [ ] `--rate N` — per-second request cap with backoff on 429.
- [ ] POST / custom method + body support.
- [ ] Go port of the C++ engine.
- [ ] SARIF output for CI integration.

---

## License

MIT — see [LICENSE](LICENSE).

---
## The Tool Process
<img width="1920" height="1080" alt="prove 1" src="https://github.com/user-attachments/assets/bf91e272-552c-4e0b-ac8c-ccee48814dc7" />
<img width="1912" height="1072" alt="prove 2" src="https://github.com/user-attachments/assets/8423a6a2-fe7a-4d7e-98ee-3b2c27c8375b" />


## Acknowledgments

Built for authorized security research. Respect scope. Don't be the reason
someone's weekend gets worse.
