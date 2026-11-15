# Federation: shared bad-bot intelligence

## Goal

A bot caught at one Henbane deployment should be known at the next — the
network-effect moat, federated and open. Two independent, opt-in halves:

- **Consumer** — pull a shared bad-IP blocklist and block listed clients.
- **Reporter** — contribute your own confirmed detections back to the feed.

The Poison Garden control plane (curation, consensus, distribution) is a separate
build; this is the deployment-side seam.

## Research basis

- **Legal (GDPR).** Sharing malicious IPs as threat intelligence rests on
  **Article 6(1)(f) legitimate interest**, with **Recital 49** naming network and
  information security — preventing unauthorised access, malicious code, DoS — as
  a legitimate interest explicitly. Requirements: both sender and receiver need a
  basis, process only what is *strictly necessary and proportionate*, and document
  a **Legitimate Interests Assessment (LIA)**. (Osborne Clarke; MISP GDPR
  compliance note.)
- **The analog: CrowdSec** (EU/open-source, 300k+ engines, 60M signals/day) shares
  exactly three fields — **the aggressive IP, the scenario that fired, and a
  timestamp** — metadata only, logs stay local. Its anti-poisoning defence is the
  key lesson: **an IP only enters the shared blocklist after consensus across many
  independent reporters**, plus per-reporter trust ranking and canary
  whitelisting. IPs auto-expire (unseen 72h → cleared). Sharing earns access
  (reciprocity).
- **Hashing is not a privacy shortcut.** Per the 2025 EDPB pseudonymisation
  guidance and Recital 26, hashed/truncated IPs remain personal data, and plain
  IPv4 hashing is trivially reversible. Keyed HMAC is irreversible but then IPs
  cannot be matched across reporters, which breaks consensus. So: share the raw IP
  under legitimate interest + minimisation, like CrowdSec — do not hash.
- **Format.** STIX/TAXII is the standard but heavyweight and retrospective; a
  zero-dependency tool uses **line-based blocklists (consume)** and **compact JSON
  (report)**. A STIX export is a later nicety.

## Consumer (built)

`internal/detect/remotedeny`: a denylist detector whose prefix set is fetched from
`federation.feed_url` and hot-swapped by a background `Refresher`.

- **Detector** holds an `atomic.Pointer` to an immutable prefix set; `Inspect`
  fires `Blocked` for a listed client IP (`.Unmap()`ed). Read-only and lock-free.
- **Refresher** fetches immediately, then every `refresh` interval, until its
  context is cancelled.
- **Trust model** (feed is operator-chosen but untrusted input): strict line
  parsing (CIDR or bare IP → host prefix; `#` comments), **reject `/0`** (no
  block-everyone injection), **hard entry cap** (`max_entries`), **bounded body**
  (32 MiB read limit), and **fail-safe** — any fetch/parse error keeps the last
  good set, never block-all or allow-all.
- **Lifecycle.** The refresher is a background task returned from `newHandler` and
  run by `serve` under the shutdown context. v1 is CLI-wired; the library/Caddy
  get the detector but not the refresher (a lifecycle hook is follow-up).

## Reporter (next PR)

An asynchronous sink that contributes confirmed detections to `federation.report_url`.

- **What is sent** (minimisation): `{ip, signal, tier, timestamp}` — nothing else
  (no logs, UA, path, or payload). **Only `Confirmed`/`Blocked` tiers** are
  reported, never `Pass`/`Suspect`, so a human's IP is never shared.
- **How**: events buffer in a bounded channel; a background flusher POSTs compact
  JSON batches off the request path. On overflow it **drops** (never blocks the
  request); on POST error it drops the batch (no unbounded retry). An optional
  bearer token authenticates; a stable `deployment_id` lets the feed count
  distinct reporters for consensus.
- **Trust/anti-poisoning is server-side** (consensus across many reporters +
  per-reporter trust rank), mirroring CrowdSec — a single reporter cannot
  blocklist an arbitrary IP, which defends both the network and against an
  operator trying to get a competitor or victim listed.
- **Compliance**: opt-in, minimised, legitimate-interest basis; ship the LIA as a
  document alongside the feature.

## Non-goals (v1)

- No STIX/TAXII (line-based + JSON only); no client-side curation (the control
  plane curates); no library/Caddy background-task lifecycle yet.
