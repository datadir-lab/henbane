# HTTP/2 (Akamai) fingerprint signal

**Status:** shipped · **Date:** 2026-11-16 · **Issue:** #55

## Problem

The classifier study established the ceiling (`research/classifier-benchmark.md` §2.6):
**a careful scraper that omits only `Sec-Fetch` is header-identical to an old real
browser.** No HTTP *header* signal separates them. The one signal that does is the
**HTTP/2 fingerprint**: the SETTINGS values and order, the connection
`WINDOW_UPDATE` increment, any `PRIORITY` frames, and the request pseudo-header
order a client emits when it opens an h2 connection. These come from deep in a
client's HTTP/2 engine and are not request-level options, so a scraper cannot match
a browser's h2 fingerprint without replacing its whole transport. It is exactly the
signal modern anti-bot stacks (Akamai Bot Manager) use as the layer below JA4: *"JA4
says Chrome but the SETTINGS frame has `HEADER_TABLE_SIZE 4096` (a library default)
→ max bot score."*

## Why it cannot live in the zero-dependency core

To read the fingerprint, something must see the raw HTTP/2 byte stream before it is
served. Go's standard library makes that impossible without a third-party dependency:
`http.Server` couples HTTP/2 to the concrete `*tls.Conn` (wrap the conn and Go
silently drops to HTTP/1.1), and the only override hook, `TLSNextProto["h2"]`, hands
you the connection but expects *you* to be the HTTP/2 server. Driving the connection
needs `golang.org/x/net/http2`'s `Framer`/`Server`, forbidden in the core by the
zero-dependency rule.

**Decision:** split the feature so the dependency never touches the core.

## Architecture

Two pieces, mirroring the existing `tlsfp` (in-core, stdlib) + `caddy/` (separate
module, heavy deps) split:

### Core `h2fp` package (stdlib only, exported)

`github.com/datadir-lab/henbane/h2fp` holds the decoded pieces (`Setting`,
`Priority`, `Fingerprint`), renders the canonical Akamai string, and carries a
captured fingerprint from a connection to the request on it (`WithFingerprint` /
`FromContext`, the same context-handoff pattern as `tlsfp`). It is pure and fully
unit-testable: no HTTP/2 machinery, no network. The classifier that scores a
fingerprint also lives here so both the engine and the capture module share it.

The exact format (triangulated from the Akamai 2017 whitepaper and the byte-exact
reference implementation, [wi1dcard/fingerproxy](https://github.com/wi1dcard/fingerproxy)):

```
SETTINGS | WINDOW_UPDATE | PRIORITY | PSEUDO_HEADER_ORDER
```

| Field | Rule | Empty case |
|---|---|---|
| SETTINGS | `id:value` joined by `;`, **wire order**, no sort, no dedup | `""` (string starts with `|`) |
| WINDOW_UPDATE | stream-0 increment, first frame only, zero-padded to 2 digits | `00` (a real increment is never 0, RFC 7540 §6.9) |
| PRIORITY | `stream:excl:dep:weight` joined by `,`; weight = wire octet **+ 1** (RFC 7540 §6.3) | `0` |
| PSEUDO_HEADER_ORDER | `m`/`a`/`s`/`p` for `:method`/`:authority`/`:scheme`/`:path`, HPACK-decode order, joined by `,` | `` |

Worked, test-pinned examples: Chrome `1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p`,
Firefox `1:65536;4:131072;5:16384|12517377|3:0:0:201|m,p,a,s`, Go/x-net client
`2:0;4:4194304;5:1048576;6:10485760|1073741824|0|a,m,p,s` (the last captured live by
the module's e2e test, proof the pipeline parses real frames correctly).

### Optional `h2capture` module (separate `go.mod`, requires `x/net/http2`)

`github.com/datadir-lab/henbane/h2capture` performs the capture. `Enable(srv)`
installs a `TLSNextProto["h2"]` hook on a caller's `*http.Server`, so **HTTP/1.1 is
served by the standard server untouched and only the h2 path is intercepted.** For
each new h2 connection the hook:

1. `io.TeeReader`s the connection, consumes and verifies the 24-byte client preface.
2. Drives an `http2.Framer` (with `ReadMetaHeaders` set so HEADERS+CONTINUATION are
   HPACK-decoded into a `MetaHeadersFrame`) until the first HEADERS frame, collecting
   SETTINGS (in wire order via `ForeachSetting`), the stream-0 WINDOW_UPDATE, any
   PRIORITY frames, and the pseudo-header order.
3. Builds a **replay connection** (`io.MultiReader(buffered bytes, live conn)`) and
   hands it to `http2.Server.ServeConn`. Because the tee buffered the exact bytes
   consumed, the replay reconstructs the original stream byte-for-byte *regardless of
   where sniffing stopped*, so a sniff timeout mid-frame still serves correctly (it
   just yields a partial/empty fingerprint). The fingerprint is attached to every
   request's context.

A read deadline (`defaultSniffTimeout`, 5s) bounds sniffing so a stalled client can
never hang the capture goroutine; the deadline is cleared before `ServeConn` runs.

The dependency allowlist test (`internal/arch`) is unaffected: it lists the main
module's packages, and nested modules (like `caddy/`) are excluded, so `h2capture`
with `x/net` sits outside it exactly as intended. It uses `x/net/http2`'s low-level
`Framer` and `Server.ServeConn`, which that package marks **deprecated** in favour of
the stdlib, but the stdlib is precisely what cannot read raw frames, so the
deprecated API is the only option; the module is therefore vet/test-gated in CI, not
staticcheck'd (the same posture as `caddy/`), with its own `h2capture.yml` workflow.

### Standalone `henbane-h2` binary (both fingerprints)

`h2capture/cmd/henbane-h2` is a drop-in reverse proxy for operators who want the HTTP/2
signal without embedding Henbane in Go code. It reads the same `henbane.yaml` and runs
the same engine as the shipped binary, terminates TLS, and calls `Enable`, so it
captures the HTTP/2 fingerprint **and** the TLS fingerprint. It requires `tls.cert` and
`tls.key` (HTTP/2 fingerprinting needs direct TLS termination) and lives in the
`h2capture` module so the `x/net/http2` dependency never reaches the zero-dep core. The
shipped core binary still captures only the TLS fingerprint; this binary is the way to
get both from a prebuilt artifact.

For the TLS fingerprint to reach h2 requests, `tlsfp` is now an exported package
(parallel to `h2fp`). An HTTP/2 connection is served by `x/net/http2`, which builds its
own request contexts and never runs net/http's `ConnContext`, the path that normally
carries the TLS fingerprint. The module closes that gap: the handshake has completed by
the time ALPN dispatch runs, so it reads the already-computed fingerprint off the
connection with `tlsfp.FromConn` and re-attaches it with `tlsfp.WithFingerprint`. Both
`tls_fp` and the h2 fingerprint are therefore present on every captured h2 request.

## Consuming the signal

The engine reads the fingerprint through a new optional capability,
`ports.H2Fingerprinter` (`H2Fingerprint() string`), implemented by the proxy's
`requestView` via `h2fp.FromContext`. It is "" whenever capture is not wired (plain
HTTP/1.1, behind a proxy, or the core alone), so every consumer treats absent as
unknown, the same safety model as `TLSFingerprinter`.

The consumer is the **browser-consistency scorer**: when a request wears a browser
User-Agent and carries an h2 fingerprint no real browser would produce, that is
strong evidence of spoofing and adds score. `h2fp.ContradictsBrowser` uses two
independent tells, either sufficient:

1. **Pseudo-header order not in the browser set.** This is the primary discriminator
   because it is the most **stable** field: a browser engine has one canonical order
   that rarely changes between versions, unlike the SETTINGS values, which drift. The
   browser orders form a tiny, closed allowlist:

   | Family | Pseudo-order |
   |---|---|
   | Chrome / Chromium / Edge / Opera | `m,a,s,p` |
   | Firefox | `m,p,a,s` |
   | Safari / WebKit (macOS, iOS) | `m,s,p,a` |

   Anything else is flagged: Go's `a,m,p,s` (leads with `:authority`, no browser
   does), curl and Java's `m,s,a,p`, etc.

2. **HPACK table size (SETTINGS id 1) equal to 4096.** Pseudo-order alone has one
   blind spot: the Python `h2` library (httpx, Scrapy) copies Chrome's `m,a,s,p`
   exactly. But those clients send the bare RFC 7540 default `HEADER_TABLE_SIZE`
   (4096), which no current browser does. Chrome/Edge/Firefox send 65536 and Safari
   omits id 1. Flagging only that specific value (not "anything but 65536") keeps the
   false-positive surface minimal while still catching the h2-library scraper family.

The signal only *raises* score and, like every scorer signal, costs at most a
challenge on its own; it compounds with the header signals toward a confident
classification, and stays inert with no capture wired, so turning it on is purely
additive. The allowlist is seeded from **measured** fingerprints (live self-measured
Chromium 157, Go 1.27.4, httpx; browser values cross-corroborated across lwthiker and
Scrapfly; curl and Java derived from their current source), deliberately *not* from
unvetted public fingerprint dumps, one of which was found to be self-contradictory.

## Honest limitations

- **RFC 9218 / modern Chrome** no longer sends legacy `PRIORITY` frames, so its
  PRIORITY field is `0`, indistinguishable from any other client that omits them.
  The replacement signal (the `priority` request header, SETTINGS id `9`
  `NO_RFC7540_PRIORITIES`) lives outside the classic 4-field string; the SETTINGS and
  pseudo-order fields still separate Chrome cleanly.
- **Allowlists drift.** Browser h2 fingerprints change over major versions. The
  pseudo-order allowlist is deliberately the slowest-drifting field, but it is still a
  maintained dataset, not a law. A wrong entry risks flagging a real browser, so the
  scorer weights the h2 signal like the other soft signals (a single point or two),
  never an outright block.
- **Capture requires direct h2 termination.** Behind a CDN or TLS-terminating proxy
  the h2 hop Henbane sees is the proxy's, not the client's, so the fingerprint is
  absent and the signal correctly goes silent.

## Testing

- `h2fp` (core, zero-dep): the formatter against the three pinned real-client vectors
  and the empty-section conventions; context round-trip; the pseudo-order classifier.
- `h2capture` (module): an **end-to-end** test, a real `x/net/http2` client against an
  `Enable`'d server asserts the handler observes a well-formed fingerprint with the
  Go client's canonical `a,m,p,s` order, and that an HTTP/1.1 request carries none.
  A second e2e test wires `tlsfp.WrapListener` + `Enable` and asserts an HTTP/2 request
  carries both the h2 fingerprint and the TLS fingerprint, pinning the cross-protocol
  propagation. Run under `-race`.
- Consistency scorer: browser-UA + non-browser h2 order adds the h2 point; a real
  browser order does not; absent fingerprint is inert.

## Scope / non-goals

- No change to the zero-dep core's dependency surface; the signal is dormant until an
  operator runs `h2capture.Enable`.
- The capture module targets direct TLS+h2 termination. Co-propagating the TLS
  fingerprint onto captured h2 connections (so both signals are present together) is
  now implemented, and shipped as the standalone `henbane-h2` binary (see above).
- A full per-UA-family fingerprint allowlist (contradiction detection across every
  field, not just pseudo-order) is a richer future dataset; this slice ships the
  highest-signal, lowest-drift field first.
