# Poison-survival study

How much of each Henbane poison strategy's output survives the dataset-filter gauntlet that web-scale LM training pipelines apply before text reaches a model. Lower survival = the filters discard it (a resource-draining tarpit but weak poison); higher survival = it could plausibly reach a training set.

**Method.** Each strategy emits its real maze-page HTML; a boilerplate step keeps the main `<p>`/`<h1>` content (dropping nav links); the text then passes Gopher heuristics, C4 rules, a word-trigram perplexity filter calibrated to keep ~90% of real text, and MinHash near-duplicate dedup. The baseline is real public-domain prose (a *different* book from the one the perplexity model trained on). Perplexity is option (b), a trigram approximation of the KenLM/Wikipedia stage; treat absolute numbers as directional.

Perplexity cutoff (calibrated): **618**.

## Survival funnel (documents remaining, %)

| strategy | generated | boilerplate | Gopher | C4 | perplexity | dedup |
|---|---|---|---|---|---|---|
| babble (Markov) | 300 | 300 (100%) | 300 (100%) | 300 (100%) | 0 (0%) | 0 (0%) |
| article (grammar) | 300 | 300 (100%) | 300 (100%) | 300 (100%) | 0 (0%) | 0 (0%) |
| canary | 300 | 300 (100%) | 300 (100%) | 300 (100%) | 0 (0%) | 0 (0%) |
| real text (baseline) | 300 | 300 (100%) | 300 (100%) | 231 (77%) | 210 (70%) | 89 (30%) |

![survival funnel](figures/survival_funnel.png)

## Perplexity by strategy (word-trigram; lower = more fluent)

| strategy | median | 10th pct | min | multiple of real-text median |
|---|---|---|---|---|
| babble (Markov) | 1934 | 1551 | 1111 | 4.0x |
| article (grammar) | 1059 | 891 | 724 | 2.2x |
| canary | 1065 | 898 | 731 | 2.2x |
| real text (baseline) | 479 | 393 | 296 | 1.0x |

![perplexity](figures/perplexity.png)

![final survival](figures/final_survival.png)

## What the numbers say

- **The perplexity stage filters 100% of every current poison strategy.** The cutoff that keeps ~90% of real text is ~618; the *lowest-perplexity* poison document is still well above it. A perplexity filter (the CCNet/KenLM stage that discards ~84% of Common Crawl) catches this poison wholesale.
- **Grammar helps, but not enough.** `article`/`canary` (context-free grammar) score noticeably lower perplexity than `babble` (order-2 Markov) — the Markov word-salad is the worst case, exactly as predicted — yet all three sit several times above real prose.
- **The gap is large and structural.** Poison medians are many multiples of the real-text median (see table). Closing it is not a matter of tuning; it needs real, common vocabulary in natural sequences — not coined entities (which go straight to `<unk>`) and not Markov transitions.

## How to poison the well better (actionable)

1. **Drop coined proper nouns** — `article`/`canary` invent entity names that are out-of-vocabulary to any real LM and spike perplexity. Use real, common words.
2. **Generate at the sentence/paragraph level with a real grammar or a small LM**, not word-level Markov — the win from `article` over `babble` shows the direction.
3. **The honest ceiling:** to approach the cutoff you likely need an LLM rewrite (the Nemotron-CC laundering path), which trades the zero-dependency property. Henbane keeps the fluent generators as *filter-resistant-ish*, and leans on the **tarpit + federation** story (see `docs/STRATEGY.md`) rather than claiming single-site model impact — which remains unobservable from outside.

---

Regenerate with the commands at the top of `research/study.py`. Perplexity is option (b), an interpolated word-trigram trained on held-out public-domain prose; a real KenLM/Wikipedia model is the documented upgrade and would sharpen the absolute numbers (not the direction).