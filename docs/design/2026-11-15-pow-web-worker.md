# Proof-of-work solver: Web Worker, not WASM

## Decision

Run the SHA-256 proof-of-work solver in a **Web Worker** using optimized
JavaScript, with a main-thread fallback and an informative no-JS page. **Do not
ship a WebAssembly solver.**

## Why not WASM

The solver was briefly built in Go/WASM and measured, and the ecosystem was
researched:

- **Go's WASM is heavy.** The Go-compiled solver is 2.4 MB raw / **~700 KB
  gzipped**; the Go runtime dominates. At the default difficulty (20 bits) the
  JS solver finishes in ~1 to 2 s, *faster than downloading 700 KB on many
  connections*, so the WASM would usually arrive after the puzzle is already
  solved. TinyGo would cut it to ~290 KB gzipped but adds a build-tool dependency
  for a modest gain.
- **The speedup is modest for optimized JS.** mCaptcha's own benchmark concludes
  native/WASM is "only slightly faster than the WASM library and for all intents
  and purposes, this shouldn't matter much"; the dramatic "30 to 50×" figures are
  WASM vs *naïve* JS, not the tuned SHA-256 we already have (~25% range).
- **The closest analog doesn't use WASM.** Anubis (a Go anti-AI-scraper PoW
  gateway, Henbane's peer) delivers its challenge in plain JavaScript.

## What the Web Worker actually buys

The real limitation of the previous solver was not hash speed. It ran on the
**main thread**, yielding every ~120 ms to stay responsive (which also
*throttled* it). Moving it into a Worker:

- runs **flat-out** (no yield throttling → genuinely faster), and
- runs **off the main thread** (zero UI jank), at **zero download cost** and with
  universal browser support.

## Implementation

- One SHA-256 implementation, defined on the page and **stringified into the
  Worker's source** (via `Function.prototype.toString()` plus a serialized round
  constant table), so there is no duplicated hash code.
- The Worker solves in a tight loop, posting progress every 8192 hashes and the
  solution when found. A `sha256("abc")` self-test (checked in the Worker and the
  fallback) fails the challenge closed if the hash is ever broken.
- **Fallbacks:** if `Worker`/`Blob`/`URL` are unavailable or the Worker errors,
  the page solves on the main thread in ~120 ms slices (the previous, proven
  behavior). If JavaScript is disabled entirely, a `<noscript>` block explains
  that JS is required.

## Verification

The browser solver can't run in Go CI, so it is checked headlessly: a Node
harness extracts the template's `<script>`, builds the Worker source exactly as
the browser does, simulates the Worker/DOM/fetch, and asserts the emitted
solution satisfies the difficulty under Node's **standard** SHA-256 (matching
Go's `crypto/sha256`). The server-side rendering and verification keep their Go
tests.

## Future

If a high-difficulty deployment ever wants WASM speed, the small-binary path is
**TinyGo** (~290 KB gzipped), run inside the same Worker, a documented option,
not a default.
