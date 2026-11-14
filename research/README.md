# research/ — poison-survival study

A reproducible study of **how much of Henbane's poison survives the dataset-filter
gauntlet** that web-scale LM training pipelines (C4, Gopher, Dolma, FineWeb, CCNet)
apply before text reaches a model — the honest, evidence-based answer to "does the
poison work, and how do we poison the well better?"

This directory is **research tooling, deliberately separate from the shipped
gateway.** The gateway is zero-dependency Go; the study uses Python and third-party
libraries, because a credible study must run the *actual* filters, not a pure-Go
approximation. Nothing here is imported by or shipped with the gateway.

## What it does

1. `emit/` (Go) generates each poison strategy's **real maze-page HTML** plus a
   real-text baseline, as JSON Lines.
2. `study.py` (Python) runs every document through a faithful reimplementation of
   the filter stages and measures survival at each:
   - **boilerplate extraction** — keep `<h1>`/`<p>` main content, drop nav links
   - **Gopher heuristics** — word count, mean word length, symbol ratio, stopwords, repetition
   - **C4 rules** — terminal punctuation, ≥5 sentences, badword/LDNOOBW list, "lorem ipsum"
   - **perplexity** — interpolated word-trigram trained on held-out public-domain prose
     (option b; a real KenLM/Wikipedia model is the documented upgrade)
   - **MinHash/LSH dedup** — near-duplicate collapse ("variety beats volume")
3. It writes publication-quality figures to `figures/` and a written report to
   [`STUDY.md`](STUDY.md).

## Run it

```sh
# from the repo root
python -m venv research/.venv
research/.venv/Scripts/pip install -r research/requirements.txt   # (Scripts\ on Windows, bin/ on POSIX)
go run ./research/emit -n 300 -out research/data/samples.jsonl
research/.venv/Scripts/python research/study.py
```

Reference corpora in `data/` are public-domain Project Gutenberg texts (the
perplexity model trains on a *different* set of books than the baseline, so the
real-text comparison is not memorized). `data/samples.jsonl` and `.venv/` are
regenerable and git-ignored; `STUDY.md` and `figures/` are committed.

## Honest limits

This is a **single-site, single-run approximation**. It measures *filter
survival*, not model impact — which is unobservable from outside (see the README's
"Does this actually work?" and `docs/STRATEGY.md`). The headline result is
deliberately unflattering: current poison is an excellent crawler-cost tarpit but
is caught wholesale by perplexity filtering. The value is the *actionable* part —
which strategies are closer, and what it would take to close the gap.
