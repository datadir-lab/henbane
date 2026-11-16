# Security Policy

Henbane is a security tool, so we take its own security seriously.

## Supported versions

The project is pre-1.0 and under active development. Only the latest `main`
is supported; please verify a report against the current `main` before filing.

## Reporting a vulnerability

**Do not open a public issue for security vulnerabilities.**

Please report privately using GitHub's **"Report a vulnerability"** flow
(repository → *Security* → *Advisories* → *Report a vulnerability*), which opens
a private advisory. If you cannot use that flow, email
**security@datadir.co** with:

- a description of the issue and its impact,
- steps to reproduce (a minimal config / request is ideal),
- the affected commit or version.

We aim to acknowledge reports within **7 days** and to provide a remediation
plan or fix timeline within **30 days**. Please give us a reasonable window to
address the issue before any public disclosure.

## Scope

In scope: the gateway engine, detectors, client-IP resolution, the proxy
adapter, token/PoW handling, and configuration parsing: anywhere untrusted
input reaches a decision, log, or response.

Out of scope: operator misconfiguration explicitly documented as the operator's
responsibility (e.g. over-broad `trusted_proxies` unions), and vulnerabilities
in third-party reverse proxies placed in front of Henbane.
