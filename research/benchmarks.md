# Performance & resource-cost benchmarks

*The two cost dimensions that are honestly quantifiable: what Henbane costs the
operator per request, and what it costs a crawler it decides to trap.*

Reproducible: `go test -bench=. -benchmem -count=6 ./research/benchmark` and
`go test -run TestBombAmplification -v ./research/benchmark`.

## Read this before any number below

Absolute times here are **single-host point estimates and they are not stable**.
We measured **2–3× variation** for the same benchmark across machines, core counts,
and load — e.g. the full decision measured ~**2.9 µs** on a 16-thread amd64 laptop
at default parallelism but ~**5–9 µs** single-core / cold on the same class of host.
**Only two things in this document are hardware-independent: the allocation counts
and the decompression-bomb amplification ratio.** Everything expressed in
nanoseconds or MB/s should be read as an order of magnitude with a ±2–3× band, and
the *ratios between strategies* (splice is ~10× faster per byte than babble) are far
more stable than the absolutes. Figures below are from one commodity 16-thread amd64
laptop (Go 1.27.4), 6 runs each.

## Operator cost: per-request decision latency

The full classifier — IP + UA denylists, honeypot, velocity, both good-bot
verifiers, and the scoring layer — deciding a well-formed browser request:

| benchmark | time/op (this host) | allocations (stable) |
|---|---|---|
| `EngineDecide` (full stack) | ~3 µs (≈5–9 µs single-core) | **520 B, 5 allocs** |

The honest reading is the order of magnitude: **a decision is microsecond-scale and
a handful of allocations** — not a meaningful part of a request's latency budget on
any hardware. (Caveat: for a browser request both good-bot verifiers short-circuit
at the User-Agent match, so this measures the denylist + honeypot + velocity +
scoring traversal, *not* the reverse-DNS or IP-range lookups — reverse DNS is never
on the request path by design. It is the cost to wave a browser through, which is
the common case.)

## Crawler cost: poison generation throughput

Throughput is computed from the **actual bytes emitted across all (varying-seed)
iterations** (an earlier version extrapolated one seed's page size and biased this
column). Per-page byte counts are deterministic; the MB/s is the ±2–3× quantity.

| strategy | time/page (this host) | throughput (this host) |
|---|---|---|
| `splice` | ~14 µs | **~200 MB/s** |
| `babble` | ~40 µs | ~25 MB/s |
| `article` | ~85 µs | ~20 MB/s |
| `canary` | ~110 µs | ~16 MB/s |
| full maze page (32 links + 4 paragraphs) | ~210 µs | ~17 MB/s (~5,000 pages/s) |

What's robust across hardware is the **relative** picture: `splice` is roughly an
order of magnitude cheaper per byte (it recombines whole corpus sentences), while
`article`/`canary` spend more CPU on fluent, lexically-distinct prose. Even the
slowest strategy generates garbage far faster than a crawler can fetch, parse, and
(for a training pipeline) tokenise and filter it. (The maze figure regenerates
distinct pages per iteration; it is CPU-bound single-goroutine — real aggregate
throughput is higher and network-bound.)

## Crawler cost: decompression-bomb amplification

The one figure that **is** hardware-independent. Measured end to end (generate →
gzip → verify the inflated size):

| sent on the wire | crawler must decompress | amplification |
|---|---|---|
| 74 KB | 10 MB | **~141×** |
| 745 KB | 100 MB | ~141× |
| 7.6 MB | 1 GB | ~141× |

**Honest caveat on what the amplification means.** The payload is ~97% compressible
newline filler and ~3% incompressible poison, so "141×" is dominated by how well
whitespace compresses, and it is **tunable** (raise the filler block and the ratio
rises arbitrarily — it is not an intrinsic property of the system). The real cost
it imposes is in two layers: the crawler must **download and decompress** the full
inflated size (bandwidth + a classic gzip-bomb memory/CPU hit, which is real and
whitespace-independent), and only then strips the filler — leaving the ~3% poison to
parse. So the honest claim is "a gzip-bomb-grade download+decompress cost," not
"141× of useful adversary work."

## What these numbers do and don't claim

- They **do** show the shape: operator cost is microsecond-scale; crawler cost is
  asymmetric (cheap to generate, expensive to download/decompress/parse).
- They **do not** claim a precise throughput spec (±2–3× by hardware) and they say
  nothing about model-training impact (unobservable — see the README's
  "Does this actually work?").
- Benchmarks are single-goroutine and CPU-bound; real aggregate throughput is
  network- and concurrency-bound and higher. Treat these as per-core order of
  magnitude, not a capacity plan.
