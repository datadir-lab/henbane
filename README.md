<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo/henbane-flower-dark.png">
    <img src="assets/logo/henbane-flower.png" alt="Henbane" width="150">
  </picture>
</p>

<h1 align="center">henbane</h1>

<p align="center">Self-hosted gateway that keeps abusive AI scrapers off your site without taxing real visitors</p>

<p align="center">
  <img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-2f5233">
  <img alt="Go 1.23+" src="https://img.shields.io/badge/go-1.23%2B-2f5233">
  <img alt="Dependencies: stdlib + yaml" src="https://img.shields.io/badge/deps-stdlib%20%2B%20yaml-2f5233">
  <img alt="Status: early development" src="https://img.shields.io/badge/status-early%20development-8fae63">
</p>

---

Scrapers that train AI models now hit small sites thousands of times an hour. They ignore `robots.txt`, run up the hosting bill, and copy content wholesale. Henbane sits in front of your site as a reverse proxy and decides, per request, who passes untouched and who gets turned away.

The design point is restraint. Tools like Anubis make every visitor solve a proof-of-work puzzle, which also punishes people on no-JS browsers, screen readers, and old devices. Henbane keeps that challenge as one tier, reserved for clients that look suspicious, so a real reader gets through without ever seeing it.

> **Status: early development.** The proxy, the operator denylist, structured logging, and the fail2ban sink are built and tested. The classifier currently has one signal (the denylist). Proof-of-work, the link labyrinth, and dataset poisoning are designed but not yet implemented. See the [roadmap](#roadmap). Not production ready.

## What works today

- **Reverse proxy** in front of any HTTP upstream, with graceful drain on `SIGINT`/`SIGTERM`.
- **Operator denylist** by IP range (CIDR) and by User-Agent substring, returning `403` on a match.
- **Correct client IP** behind a load balancer: `X-Forwarded-For` is honored only from trusted proxy ranges you configure, so the denylist cannot be spoofed by a forged header.
- **Structured JSON log** of every decision, one event per request.
- **fail2ban sink** that writes a stable ban line and ships a matching filter, so repeat offenders can be dropped at the firewall.

## Quick start

Build from source (static binary, no CGO):

```bash
git clone https://github.com/datadir-lab/henbane
cd henbane
go build -o henbane ./cmd/henbane

# proxy a local app on :3000, listening on :8080
./henbane --upstream http://localhost:3000
```

Flags: `--upstream` (required), `--listen` (default `:8080`), `--config`. Flag values override the config file.

Or with Docker:

```bash
docker build -t henbane .
docker run -p 8080:8080 henbane --upstream http://host.docker.internal:3000
```

## How it tiers traffic

Every request is sorted into a tier, and each tier maps to an action. The mapping is the lever: an operator under heavy load can slide the baseline up so unknown clients start as Suspect, which gives you a challenge-everyone mode when you want it.

| Tier | Who lands here | Action | Status |
|---|---|---|---|
| **Pass** | Looks human, or an allowed good bot | Serve real content, untouched | Live |
| **Suspect** | Weak bot signals (unknown UA, bursty rate) | Proof-of-work challenge | Planned |
| **Confirmed** | Known AI crawler, or tripped a honeypot link | Labyrinth and poison | Planned |
| **Blocked** | On the operator denylist | `403`, plus a fail2ban line | Live |

Today only **Pass** and **Blocked** are wired, driven by the denylist. The remaining tiers arrive with the slices on the roadmap.

## Configuration

Zero-config works: a single `--upstream` flag passes all traffic through. For anything more, point `--config` at a YAML file. Every key below is one that henbane reads right now.

```yaml
listen: ":8080"
upstream: "http://localhost:3000"

# When henbane runs behind a proxy or load balancer, trust X-Forwarded-For
# only from these source ranges. Leave empty if henbane faces the internet directly.
trusted_proxies:
  - "10.0.0.0/8"

deny:
  # 403 any client whose resolved IP falls in these ranges...
  cidrs:
    - "203.0.113.0/24"
  # ...or whose User-Agent contains any of these (case-insensitive substring)
  user_agents:
    - "GPTBot"
    - "CCBot"
    - "ClaudeBot"

sinks:
  fail2ban:
    enabled: true
    path: /var/log/henbane/ban.log
```

## fail2ban

When the fail2ban sink is enabled, a blocked request appends one greppable line:

```
henbane: action=ban ip=203.0.113.9 tier=blocked reason=denylist_ua ua="GPTBot/1.1"
```

The shipped filter (`deploy/fail2ban/henbane.conf`) and jail snippet (`deploy/fail2ban/jail.local`) match this line, so you can ban at the firewall without writing a regex. The User-Agent is quoted, so a crawler cannot inject a fake ban line through its header.

## Why henbane

- **`robots.txt` is a request, not a fence.** Abusive crawlers ignore it. Henbane acts on the traffic instead of asking it to behave.
- **Challenge-everyone tools stop the load but tax humans.** Keeping proof-of-work as one tier means the cost lands on clients that look hostile, not on every reader.
- **Tarpits and poison already work.** Nepenthes, Iocaine, and Cloudflare's AI Labyrinth proved the approach. Henbane makes it self-hostable, configurable, and aimed only at confirmed crawlers.

## Dependencies

Henbane is Go, stdlib-first by policy. The only third-party import in the core is `gopkg.in/yaml.v3` for config, with `golang.org/x/crypto/acme/autocert` reserved for optional auto-HTTPS later. A CI guard fails the build if anything outside that allowlist appears in `go.mod`. A tool that fights surveillance should not become a supply-chain risk of its own.

## Roadmap

Each item is an end-to-end, tested slice. Checked items ship in the current build.

- [x] Reverse-proxy skeleton with a JSON event log
- [x] Operator denylist (IP and UA) to `403`, with a fail2ban line
- [ ] Honeypot tripwire that marks a client Confirmed
- [ ] Labyrinth: an endless tree of generated links that wastes crawl budget
- [ ] Poison: Markov-generated text that fills the maze and corrupts scraped datasets
- [ ] Proof-of-work challenge: themeable page, WASM solver, signed session token, no-JS fallback
- [ ] Bundled AI-crawler IP ranges, plus a verified-good-bot check
- [ ] Rate-based suspicion
- [ ] Prometheus `/metrics` sink
- [ ] `net/http` middleware form factor
- [ ] Caddy module, with nginx and Traefik via a ForwardAuth sidecar
- [ ] Federated reporter seam for a shared crawler denylist

## Design

The full design, including the ports-and-adapters layout, the decision contract, and the event schema, lives in [`docs/design/2026-11-13-henbane-design.md`](docs/design/2026-11-13-henbane-design.md). Brand and logo assets, with the WCAG-audited palette, are in [`assets/logo/`](assets/logo/README.md).

## Scope and ethics

Henbane is defensive. It acts only on traffic to the operator's own site and never reaches out to third-party systems. Humans pass by default, the proof-of-work tier is built with a no-JS fallback, and the labyrinth and poison apply only to confirmed crawlers. You serve your own content and your own traps on your own infrastructure.

## License

[MIT](LICENSE)
