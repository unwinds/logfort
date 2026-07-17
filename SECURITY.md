# Security Policy

LogFort is a defensive security tool: it parses attacker-controlled log lines,
can modify the host firewall, and exposes a dashboard with sensitive data
(attacker IPs, login usernames, timing). We take security reports seriously and
appreciate responsible disclosure.

## Supported Versions

Security fixes are applied to the latest released version and the `main` branch.
Older tagged releases do not receive backported fixes — please upgrade to the
latest release before reporting.

| Version | Supported |
|---|---|
| Latest release / `main` | ✅ |
| Any older tag | ❌ |

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Report privately via GitHub's **[Private vulnerability reporting](https://github.com/unwinds/logfort/security/advisories/new)**
(the *Security* tab → *Report a vulnerability*). This keeps the details private
until a fix is available and lets us coordinate a disclosure.

Please include, where possible:

- A description of the issue and its impact
- The affected version or commit (`logfort version`)
- Steps to reproduce, a proof of concept, or a crafted log line / request
- Your assessment of severity and any suggested remediation

### What to expect

This is a small project maintained on a best-effort basis. We aim to:

- Acknowledge your report within **7 days**
- Provide an initial assessment and a remediation plan within **30 days**
- Credit reporters in the release notes unless you prefer to remain anonymous

Please give us a reasonable window to ship a fix before any public disclosure.

## Scope

LogFort is intended to run **bound to `127.0.0.1`** (the default) and be reached
over an SSH tunnel, Tailscale, or WireGuard — it is **not** designed to be
exposed directly to the internet. See the *Security Notes* section of the
[README](README.md#security-notes).

### In scope

- Memory-safety or panic conditions triggered by crafted log lines reaching the
  parsers (`internal/parse`), the journald decoder, or the fail2ban pickle codec
  (`internal/f2b`)
- Authentication bypass of HTTP Basic Auth, or unauthenticated access to
  protected endpoints
- Server-side request forgery, path traversal, or arbitrary file read/write via
  API parameters (e.g. backup, blocklist, allowlist, notification config)
- Ban / allowlist logic flaws that let an attacker bypass the anti-self-lockout
  guard or induce LogFort to ban an operator-controlled (allowlisted) address
- Injection into outbound notifications, CSV export (formula injection), or the
  firewall backends
- Secrets (SMTP/Telegram/Gotify tokens, basic-auth credentials) leaking through
  the API, logs, or metrics

### Out of scope

- Running LogFort exposed directly to the public internet without a tunnel or
  reverse proxy — this is explicitly unsupported
- Demo mode (`LOGFORT_DEMO=true`), which serves synthetic data and is not for
  production
- Denial of service from an attacker who already controls the contents of the
  monitored log files at an unbounded rate (LogFort ingests whatever the log
  producer writes)
- Vulnerabilities in third-party dependencies without a demonstrated impact on
  LogFort — report those upstream, though we're happy to bump the dependency

## Hardening Checklist for Operators

- Keep LogFort bound to `127.0.0.1` and reach it over an SSH tunnel / VPN.
- Enable HTTP Basic Auth (`LOGFORT_AUTH_ENABLED=true`) as an extra layer.
- Review `LOGFORT_IGNORE_IPS` so active banning can never lock out your own
  networks.
- Treat the SQLite database and any downloaded `.mmdb` files as sensitive — they
  contain attacker IPs and login attempts.
