# Cloud/hosting-IP signal: a browser that runs in a datacenter

**Status:** shipped. A soft, compounding scoring signal, off by default.

## Problem

A real person browses from a residential or mobile ISP. A scraper fleet runs on cloud
compute. Anti-bot stacks check the originating network before almost anything else,
because the mismatch, a client that claims to be a browser yet arrives from a cloud
provider's address space, is cheap to read and hard to fake without paying for
residential IPs. Henbane had no network-reputation signal; this adds one.

## Approach

A new scorer, `internal/detect/hostingip`, adds a point when a request **claims a
mainstream browser** and its resolved client IP falls inside a published cloud-provider
range. It only judges browser-claimers: an honest non-browser client (which is *expected*
to run in a datacenter) is never penalized, consistent with the project's stance of
targeting deception, not automation.

The signal is weak and compounding by design:

- **Weight 1 by default** (tunable). On its own it stays below the Suspect threshold, so a
  legitimate client from a cloud range is not challenged. It tips a browser-claimer that
  *also* trips a header or HTTP/2-fingerprint signal from Suspect toward Confirmed.
- **Off by default.** A thin legitimate population browses from these ranges: corporate
  secure-web-gateways (Zscaler, Netskope), cloud VPNs, privacy relays. Enable it where
  that population is small. `hosting_ip.enabled` requires `scoring.enabled`, and the
  config fails loud otherwise rather than leaving an inert toggle.
- **Verified good bots are exempt.** The verifiers (FCrDNS, Web Bot Auth, AI-crawler IP
  ranges) run before scoring and allowlist a confirmed crawler, so Googlebot from
  Google's own datacenter is never scored here.

## Data

The bundled ranges come from the cloud providers' **own** published feeds, never a
third-party aggregator:

- AWS: `https://ip-ranges.amazonaws.com/ip-ranges.json`
- GCP: `https://www.gstatic.com/ipranges/cloud.json`

The `gen` tool (run with `go generate ./internal/detect/hostingip/...`) fetches both,
deduplicates, drops any prefix contained in another, and sorts the result, leaving a
non-overlapping, sorted set per address family. The snapshot in `data_gen.go` is 6,381
IPv4 and 3,166 IPv6 prefixes. A non-overlapping sorted set means membership is a binary
search (the only possible container of an address is the rightmost prefix whose network
address is <= it), so the per-request cost is about a dozen comparisons regardless of
the set size, with no third-party dependency. AWS and GCP cover a large share of
cloud-hosted scraping; Azure (a weekly-rotating feed) and ASN-based hosters are a natural
later addition to the same `gen` tool.

## Honest limitations

- **Residential proxies defeat it.** This is the signal's known ceiling: Imperva's 2025
  data attributes 21% of bot attacks to residential proxies used specifically to beat
  network reputation, and a large study found 78% of residential-IP bot sessions evaded
  conventional IP feeds. The signal catches the cheap, datacenter-hosted majority, not the
  determined adversary who pays for residential egress. It is the same honest shape as the
  headless-UA signal: a real win against the common case, documented scope for the rest.
- **The snapshot ages.** Cloud ranges change; `gen` is the refresh path. A stale snapshot
  only *misses* ranges (a false negative), never invents one.
- **The legitimate cloud-browser population is real.** Hence weight 1, off by default,
  tunable, and never a block on its own.

## Config

```yaml
pow: { mode: suspect }
scoring:
  enabled: true
hosting_ip:
  enabled: true
  weight: 1        # 0 => default 1
```

## Testing

- `hostingip`: a browser from a hosting range is flagged, an honest bot from the same IP
  is not, a browser from a non-hosting IP is not, IPv6 is handled, and the weight default
  applies. `TestBundledDataSortedNonOverlapping` verifies, directly on the generated data,
  the sorted non-overlapping invariant the binary search relies on, plus a self-consistent
  match from the first bundled range.
- `config`: `hosting_ip.enabled` without `scoring.enabled` is rejected; a negative weight
  is rejected.

## References

- Imperva, 2025 Bad Bot Report (residential-proxy share of bot attacks).
- AWS and GCP published IP-range feeds (first-party, linked above).
