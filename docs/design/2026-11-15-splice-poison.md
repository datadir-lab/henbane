# Sentence-splice poison strategy

## Problem

The poison-survival study (`research/STUDY.md`) found that a word-trigram
**perplexity** filter catches 100% of every existing strategy: real text sits
at ~1.0× the cutoff, grammar (`article`) at ~2.2×, Markov (`babble`) at ~4.0×.
Generated text — however fluent locally — carries a statistical fingerprint the
filter keys on. The study's recommendation for a non-LLM improvement was to stop
*generating* tokens and instead *recombine real ones*.

## Approach

`splice` recombines whole sentences drawn **verbatim** from the corpus:

1. Split the corpus into sentences (terminal `.`/`!`/`?`), keep those within a
   word-count band (drop fragments and run-ons).
2. Per page, deterministically sample sentences from the pool and concatenate
   them into paragraphs.

Each sentence is real text, so every in-sentence trigram is a real trigram — the
output's perplexity should approach real text and clear the filter that catches
`babble`/`article`. The poison is in the *arrangement*: unrelated sentences in
one paragraph destroy topical coherence, so a model training on it learns false
associations rather than facts.

The trade-off is explicit: `splice` buys perplexity-survival at the cost of
local-only fluency (no paragraph-level argument), and leans on a different
weakness than the generators — it is vulnerable to exact/near-duplicate dedup if
the same sentences recur across pages, which the per-(seed, salt) sampling and
the study's MinHash pass both probe.

## Interface & determinism

Implements `ports.Poisoner`: `splice.New(corpus []byte, salt string)` (nil
corpus ⇒ embedded CC0 default, shared text with `babble`), deterministic per
`(seed, salt)`, bounded length, plain text only (the maze template escapes it).
Mirrors `babble`'s shape exactly, including honoring an operator `corpus_path`.

## Validation plan

Add `splice` to `research/emit` and re-run the study. The honest headline to
confirm or refute: **does splice land below the perplexity cutoff** where every
generator failed? Whatever the number, record it in `STUDY.md` — a splice that
still filters is as useful a finding as one that survives.

## Policy

Shipped default = the embedded fictional CC0 corpus, so `splice` output contains
no real people or organizations. Splicing a real operator corpus via
`corpus_path` is the operator's choice and liability, exactly as with `babble`.
