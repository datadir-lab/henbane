# Performance & resource-cost benchmarks

*The two cost dimensions that are honestly quantifiable: what Henbane costs the
operator per request, and what it costs a crawler it decides to trap.*

Reproducible: `go test -bench=. -benchmem ./research/benchmark` and
`go test -run TestBombAmplification -v ./research/benchmark`. Absolute numbers
below are from one commodity amd64 host (Go 1.27.4, single goroutine); they will
vary by hardware, but the **ratios** — microseconds per decision, the bomb
amplification factor — are what matter and are hardware-independent.

## Operator cost: per-request decision latency

The full classifier — IP + UA denylists, honeypot, velocity, **both** good-bot
verifiers (reverse-DNS + IP-range), and the scoring layer — deciding a
well-formed browser request (the common case, which must traverse everything
before being allowed):

| benchmark | time/op | allocations |
|---|---|---|
| `EngineDecide` (full stack) | **~3.2 µs** | 535 B, 5 allocs |

That is **~310,000 decisions per second per core**, with five allocations. The
classifier is not a meaningful part of a request's latency budget; you can turn
every layer on and not measure it. (This is the decision only — a PoW *challenge*
or maze *render* is a separate cost paid only for suspect/confirmed clients, below.)

## Crawler cost: poison generation throughput

How fast Henbane manufactures the garbage a trapped crawler must download and
parse (one page = 4 paragraphs):

| strategy | time/page | throughput |
|---|---|---|
| `splice` | 18 µs | **162 MB/s** |
| `article` | 130 µs | 15 MB/s |
| `canary` | 152 µs | 14 MB/s |
| `babble` | 59 µs | 13 MB/s |
| full maze page (32 links + 4 paragraphs) | **336 µs** | 11 MB/s (~3,000 pages/s/core) |

Generation is far cheaper than what it costs the crawler to fetch, parse, and
(for a training pipeline) tokenise and filter the result. `splice` is the
cheapest-per-byte — it recombines whole corpus sentences — while `article` and
`canary` spend more CPU to produce grammatically fluent, lexically distinct prose.

## Crawler cost: decompression-bomb amplification

The optional gzip bomb is the sharpest asymmetry. Measured end to end (generate →
gzip → verify the inflated size):

| sent on the wire | crawler must decompress | amplification |
|---|---|---|
| 74 KB | 10 MB | **142×** |
| 745 KB | 100 MB | 141× |
| 7.6 MB | 1 GB | 141× |

A crawler that advertised `Accept-Encoding: gzip` pays ~**141× the bytes** Henbane
spends — before the CPU it burns decompressing and parsing the result, and the
poison studded through it. (The filler alone compresses ~1000×; the real ~141×
is the honest figure *after* the incompressible poison text is interleaved.)

## What these numbers do and don't claim

- They **do** quantify the honest core value: Henbane imposes an asymmetric
  resource cost on crawlers at negligible cost to the operator.
- They **do not** claim anything about model training impact — that remains
  unobservable from outside (see the README's "Does this actually work?").
- Benchmarks are single-goroutine and CPU-bound; real throughput is network- and
  concurrency-bound and higher in aggregate. Treat these as a floor on per-core
  capability, not a deployment capacity plan.
