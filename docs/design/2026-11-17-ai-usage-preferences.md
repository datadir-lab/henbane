# Machine-readable AI-usage preferences (AIPREF + Content-Signals)

**Status:** shipped (robots.txt directives). The HTTP `Content-Usage` header is a noted
follow-up.

## Problem

An operator can already `Disallow` a path, but robots.txt `Disallow` is a coarse
crawl-access control: it does not say what content may be used *for* once fetched.
Two standards now fill that gap, and both are gaining real adoption, so Henbane should
speak them. Declaring intent this way is also the honest precondition for the deterrent:
a confirmed AI crawler that ignores a machine-readable "do not train on this" is a
*provable* violator, which is a far stronger justification for tarpitting and poisoning
it than "it fetched a page."

## The two ecosystems

They express the same intent in different syntaxes, from different bodies, and a given
crawler may honour one and not the other, so Henbane emits both from one config.

- **IETF AIPREF** (`draft-ietf-aipref-attach`, `draft-ietf-aipref-vocab`): a
  `Content-Usage` directive, in robots.txt or as an HTTP header. Vocabulary tokens
  `train-ai` (foundation-model training), `search`, `ai-output`, `bots`, each `y`/`n`,
  with a most-restrictive-wins hierarchy. Chartered IETF working group (Oct 2025).
- **Cloudflare Content-Signals**: a `Content-signal` line in the robots.txt group, with
  `search`, `ai-input` (live AI answers / RAG), and `ai-train`, each `yes`/`no`.
  Deployed across Cloudflare's network.

## Approach

A new optional config block maps one operator intent to both syntaxes:

```yaml
robots:
  serve: true
  ai_usage:
    train: false      # no foundation-model training    -> ai-train=no,  train-ai=n
    ai_input: false   # no live AI input (RAG/answers)   -> ai-input=no
    search: true      # search indexing is fine          -> search=yes,   search=y
```

Each field is optional (a nil pointer); an unset preference is omitted from both
syntaxes rather than guessed. `buildRobots` then renders, inside the `User-agent: *`
group:

```
Content-signal: search=yes, ai-input=no, ai-train=no
Content-Usage: train-ai=n
Content-Usage: search=y
```

(`ai-input` has no AIPREF vocabulary token, so it appears only in the Cloudflare line.)
`ai_usage` is emitted in robots.txt, so it requires `robots.serve`; the config fails
loud otherwise, consistent with the strict-config posture.

## Honest framing

These are **preferences, not enforcement.** A crawler is free to ignore them, exactly as
it is free to ignore `Disallow`. Their value is twofold: they are the standard,
machine-readable way to state intent (so a cooperative crawler and an auditor can read
it), and they convert "this crawler fetched my page" into "this confirmed AI crawler
fetched content I marked `ai-train=no`", a provable violation. Enforcement remains what
it always was in Henbane: the honeypot confirmation, the tarpit, and the poison. Gating
the poison explicitly on that provable violation is a natural follow-up.

## HTTP response header

AIPREF's primary mechanism is a `Content-Usage` HTTP response header that attaches the
preference to the actual content response, not just the site-wide robots.txt. The
standalone binary emits it too, from the same `ai_usage` config, on every response:

```
Content-Usage: train-ai=n, search=y
```

AIPREF's vocabulary covers training and search, so the Cloudflare-only `ai-input` token
appears only in the robots.txt `Content-signal` line, not the header.

## Scope / non-goals

- No change to enforcement. The signals describe intent; the deterrent enforces.

## Testing

- `cmd/henbane`: a served robots.txt carries the Cloudflare `Content-signal` line and
  the AIPREF `Content-Usage` lines with the right values.
- `config`: `ai_usage` without `serve` is rejected.

## References

- IETF AIPREF: `draft-ietf-aipref-attach-04` (attachment), `draft-ietf-aipref-vocab-04`
  (vocabulary).
- Cloudflare Content Signals (managed robots.txt).
