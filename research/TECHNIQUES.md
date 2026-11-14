# Improving poison survival — techniques besides an LLM

The [study](STUDY.md) showed every current generator is caught by perplexity
filtering (babble ~4.0×, article ~2.2× real-text perplexity). This note surveys
text-generation / mutation techniques that could lower perplexity and carry a
semantic payload **without** an LLM rewrite, and assesses each against Henbane's
hard constraint: the gateway is **zero-dependency Go stdlib**, generation must be
cheap, deterministic-per-URL, and bounded.

> **Provenance note.** This session's live web-search budget was exhausted, so this
> is a knowledge-based synthesis of well-established NLP / text-generation methods,
> not fresh citations. Treat it as a design menu to validate with a literature pass
> next session.

## The core tension

Perplexity rewards text that *looks like real prose*; "poison" needs *plausible
but false content*. The two pull apart:

- **Pure fluency** (e.g. Markov over real text) → low perplexity but it is
  meaningless noise, not false *claims* — nothing for a model to mislearn.
- **Pure falsehood** (coined entities, invented facts) → a real payload, but the
  unusual surface form spikes perplexity and it gets filtered.

**The winning region is real, fluent surface form carrying false semantic
content.** Every technique below is judged on how well it occupies that region.

## Technique survey

| # | Technique | Perplexity | Semantic payload | Zero-dep? | Henbane fit |
|---|---|---|---|---|---|
| 1 | **Real-lexicon grammar** — the `article` CFG but slots filled from bundled lists of *real* high-frequency words/names instead of coined tokens | ↓↓ (kills the `<unk>` spike) | yes (false facts) | **yes** | **highest ROI** |
| 2 | **Sentence splicing + false-fact injection** — recombine real public-domain sentences, interleaved with templated false claims | ↓↓↓ (real sentences score near-real) | yes (injected) | yes (needs a bundled real corpus) | **strong** |
| 3 | **Higher-order Markov on a large real corpus** (order 3–4) | ↓↓ (reproduces real n-grams) | **no** (fluent noise) | yes (bundled corpus) | partial — fluency only |
| 4 | **Corrupt-in-place** — swap entities/numbers/facts in a *real* article (Quixotic-style) | ↓↓↓ | yes | yes | only when poisoning the operator's own content |
| 5 | **Synonym / WordNet substitution** on seed text | ↓ (modest, can read oddly) | weak | needs a bundled lexicon | minor |
| 6 | **Tiny bundled neural LM** (char-RNN / small n-gram NN) | ↓↓↓ | depends | **no** (model + inference) | optional adapter, like the LLM path |
| 7 | **Adversarial surface tricks** — homoglyphs, zero-width chars, confusables | ↑ (hurts it) + stripped by normalization | no | yes | **avoid** — counterproductive |
| 8 | **Retrieval + recombination** of real web snippets | ↓↓↓ | weak | no (corpus/index + copyright) | avoid |

## Recommendations for Henbane (ranked)

1. **Real-lexicon grammar (do this first).** The study's single biggest finding is
   that coined proper nouns go straight to `<unk>` and spike perplexity. Keep the
   `article` context-free grammar but fill entity/place/noun slots from embedded
   lists of *real, common* English words and plausible names. Zero-dep, small, and
   it directly attacks the measured failure mode. Expected: article's ~2.2× gap
   shrinks materially. This should be the next generator slice.

2. **A `splice` strategy.** Bundle a large public-domain corpus; emit documents by
   concatenating real sentences (near-real perplexity) with a minority of
   templated false-fact sentences (the payload). Deterministic per URL via the
   existing seed+salt. Zero-dep (`bufio`/`strings`). This likely clears perplexity
   where grammars cannot, at the cost of global coherence — which matters only for
   the (stretch) LLM-judge stage, not the perplexity/Gopher/C4/dedup stages.

3. **Higher-order Markov as a fluency upgrade to `babble`**, not a poison upgrade.
   Order-3 over a larger corpus lowers perplexity but adds no false *claims*; keep
   it as the cheap tarpit tier.

4. **Optional LLM / tiny-model adapter** (breaks zero-dep, so it lives behind a
   port like the operator-supplied corpus): the only path to genuinely closing the
   gap, matching the Nemotron-CC laundering observation from the Slice-4 research.

## The honest conclusion

Non-LLM methods **can** move the needle — real-lexicon grammar and sentence
splicing are concrete, zero-dep, and target the measured failure directly — but
there is a ceiling: text that both reads as real prose *and* asserts false,
model-relevant content, cheaply and deterministically, is hard without a learned
model. So Henbane's honest posture stands: pursue (1) and (2) to make the poison
*filter-resistant-er*, keep the tarpit + per-deployment-salt federation as the
load-bearing story (see [STUDY.md](STUDY.md) and [../docs/STRATEGY.md](../docs/STRATEGY.md)),
and never claim single-site model impact — which remains unobservable from outside.
