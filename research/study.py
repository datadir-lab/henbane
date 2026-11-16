#!/usr/bin/env python3
"""Poison-survival study.

Runs each Henbane poison strategy's real maze-page output through faithful
reimplementations of the dataset-filter gauntlet that web-scale LM pipelines
(C4, Gopher, Dolma, FineWeb, CCNet) apply before text reaches a model, and
measures how much survives at each stage versus a real-text baseline.

This is research tooling: it uses third-party libraries and is intentionally
separate from the zero-dependency gateway. Perplexity uses a word trigram
(option b) trained on a held-out public-domain text; a real KenLM/Wikipedia
model is a documented upgrade. Run from the repo root after generating samples:

    go run ./research/emit -n 300 -out research/data/samples.jsonl
    research/.venv/Scripts/python research/study.py
"""
from __future__ import annotations
import collections
import html
import json
import math
import random
import re
import pathlib

import numpy as np
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

# A consistent, readable style for every figure: bold titles, a recessive grid,
# and no top/right spines (the dataviz "render it and look at it" pass: legible
# labels, no clutter).
plt.rcParams.update({
    "figure.dpi": 150,
    "font.size": 11,
    "axes.titlesize": 14,
    "axes.titleweight": "bold",
    "axes.labelsize": 11,
    "axes.grid": True,
    "grid.alpha": 0.3,
    "axes.axisbelow": True,
    "axes.spines.top": False,
    "axes.spines.right": False,
    "legend.framealpha": 0.9,
})

ROOT = pathlib.Path(__file__).resolve().parent
DATA = ROOT / "data"
FIGS = ROOT / "figures"
FIGS.mkdir(exist_ok=True)

STRATEGIES = ["babble", "splice", "splice_ref", "markov_ref", "article", "canary", "baseline_real"]
LABELS = {"babble": "babble (Markov)", "splice": "splice (embedded corpus)",
          "splice_ref": "splice_ref (matched corpus)",
          "markov_ref": "markov_ref (matched corpus)",
          "article": "article (grammar)",
          "canary": "canary", "baseline_real": "real text (baseline)"}
# Categorical palette validated colorblind-safe (CVD ΔE 9.1, normal-vision floor
# 19.6) against a light surface; see the dataviz skill's validator. Hues are
# assigned per entity, in fixed order: splice_ref (the one survivor) takes the
# salient blue, babble/splice the warm/aqua pair so the two high-perplexity
# look-alikes stay distinct, and the real-text baseline a magenta that reads as
# "not a strategy". The low-contrast WARN colors are fine here: every figure ships
# with markers, a legend, and a data table (the relief rule).
COLORS = {"babble": "#eb6834", "splice": "#1baf7a", "splice_ref": "#2a78d6",
          "markov_ref": "#4a3aa7",
          "article": "#008300", "canary": "#eda100",
          "baseline_real": "#e87ba4"}
# Distinct marker shapes so lines that trace the same path (several strategies all
# cliff to 0% together) stay tellable apart by shape, not colour alone.
MARKERS = {"babble": "o", "splice": "s", "splice_ref": "D", "markov_ref": "X",
           "article": "^", "canary": "v", "baseline_real": "P"}


# --- Markov text generation (research probe for the perplexity-bypass experiment) ---
def build_markov(toks, order):
    """An order-`order` Markov model: each context of `order` tokens maps to the
    tokens that followed it in the corpus."""
    m = collections.defaultdict(list)
    for i in range(len(toks) - order):
        m[tuple(toks[i:i + order])].append(toks[i + order])
    return m


def markov_gen(m, order, n, rng):
    """Generate n tokens from a Markov model, restarting from a random context on a
    dead end. Deterministic given rng."""
    keys = list(m.keys())
    out = list(rng.choice(keys))
    while len(out) < n:
        nxt = m.get(tuple(out[-order:]))
        out.extend([rng.choice(nxt)] if nxt else rng.choice(keys))
    return " ".join(out[:n])


_PUNCT_WORD = re.compile(r"[a-z]+|[.!?]")


def markov_tokens(text):
    """Words plus sentence-ending punctuation, so a Markov chain over these emits
    sentence boundaries (the markov_ref strategy needs them to clear the C4 checks)."""
    return _PUNCT_WORD.findall(text.lower())

STOPWORDS = set("the be to of and a in that have i it for not on with he as you "
                "do at this but his by from they we say her she or an will my one "
                "all would there their what so up out if about who get which go me".split())
# A small LDNOOBW-style sample (the real C4 filter uses a ~400-word list).
BADWORDS = set("anal anus arse ass bastard bitch bollock boner boob bugger cock "
               "crap cunt damn dick dildo dyke fuck goddamn hell homo jerk jizz "
               "nigger nigga piss poop porn prick pube pussy queer scrotum sex shit "
               "slut smegma spunk tit turd twat wank whore".split())

WORD_RE = re.compile(r"[a-z]+")


# ------------------------- text extraction (boilerplate removal) -------------
def extract_text(doc_html: str) -> str:
    """Approximate a boilerplate extractor: keep <h1>/<p> main content, drop the
    <a>/<li> navigation (links are what a maze page pads with)."""
    parts = re.findall(r"<(?:h1|p)>(.*?)</(?:h1|p)>", doc_html, flags=re.S | re.I)
    text = " ".join(html.unescape(re.sub(r"<[^>]+>", "", p)).strip() for p in parts)
    return re.sub(r"\s+", " ", text).strip()


def tokens(text: str) -> list[str]:
    return WORD_RE.findall(text.lower())


# ------------------------- Gopher quality heuristics -------------------------
def passes_gopher(text: str) -> bool:
    words = text.split()
    n = len(words)
    if n < 50 or n > 100_000:
        return False
    mean_len = sum(len(w) for w in words) / n
    if mean_len < 3 or mean_len > 10:
        return False
    alpha = sum(1 for w in words if any(c.isalpha() for c in w)) / n
    if alpha < 0.8:
        return False
    symbols = sum(text.count(c) for c in "#…")
    if symbols / max(n, 1) > 0.1:
        return False
    low = set(w.lower().strip(".,!?;:") for w in words)
    if len(STOPWORDS & low) < 2:
        return False
    # Repetition: duplicate-line fraction (we treat sentences as lines).
    sents = [s.strip() for s in re.split(r"[.!?]", text) if s.strip()]
    if sents:
        dup = 1 - len(set(sents)) / len(sents)
        if dup > 0.30:
            return False
    return True


# ------------------------- C4 rules -----------------------------------------
def passes_c4(text: str) -> bool:
    if "lorem ipsum" in text.lower():
        return False
    sents = [s.strip() for s in re.split(r"(?<=[.!?])\s+", text) if s.strip()]
    if len(sents) < 5:
        return False
    # Fraction of sentences ending in terminal punctuation.
    term = sum(1 for s in sents if s.endswith((".", "!", "?", '"'))) / len(sents)
    if term < 0.5:
        return False
    toks = set(tokens(text))
    if toks & BADWORDS:
        return False
    return True


# ------------------------- perplexity (word trigram, option b) --------------
class Trigram:
    """Interpolated word trigram (tri/bi/unigram backoff) with <unk> for OOV, so
    unseen word sequences back off gracefully and perplexity reflects fluency
    rather than raw unseen-ngram rate. Still an approximation of KenLM/Wikipedia."""
    UNK = "<unk>"
    L1, L2, L3 = 0.1, 0.3, 0.6  # unigram / bigram / trigram interpolation weights

    def __init__(self, train_text: str):
        raw = tokens(train_text)
        counts = collections.Counter(raw)
        self.vocab = {w for w, c in counts.items() if c >= 2}
        self.vocab.add(self.UNK)
        t = ["<s>", "<s>"] + [w if w in self.vocab else self.UNK for w in raw] + ["</s>"]
        self.uni = collections.Counter(t)
        self.bi = collections.Counter(zip(t, t[1:]))
        self.tri = collections.Counter(zip(t, t[1:], t[2:]))
        self.N = sum(self.uni.values())
        self.V = len(self.uni)

    def _p(self, w1, w2, w3) -> float:
        p_uni = (self.uni[w3] + 1) / (self.N + self.V)
        p_bi = self.bi[(w2, w3)] / self.uni[w2] if self.uni.get(w2) else 0.0
        p_tri = self.tri[(w1, w2, w3)] / self.bi[(w1, w2)] if self.bi.get((w1, w2)) else 0.0
        return self.L1 * p_uni + self.L2 * p_bi + self.L3 * p_tri

    def perplexity(self, text: str) -> float:
        t = ["<s>", "<s>"] + [w if w in self.vocab else self.UNK for w in tokens(text)] + ["</s>"]
        if len(t) <= 3:
            return float("inf")
        lp = 0.0
        for i in range(len(t) - 2):
            p = self._p(t[i], t[i + 1], t[i + 2])
            lp += math.log(p if p > 0 else 1e-10)
        return math.exp(-lp / (len(t) - 2))


# ------------------------- MinHash near-duplicate dedup ---------------------
def dedup_survivors(texts: list[str]) -> int:
    try:
        from datasketch import MinHash, MinHashLSH
    except Exception:
        return len(texts)  # dedup skipped if datasketch unavailable
    lsh = MinHashLSH(threshold=0.7, num_perm=96)
    kept = 0
    for i, t in enumerate(texts):
        shingles = set()
        toks = tokens(t)
        for j in range(len(toks) - 4):
            shingles.add(" ".join(toks[j:j + 5]))
        m = MinHash(num_perm=96)
        for sh in shingles:
            m.update(sh.encode())
        if not lsh.query(m):
            lsh.insert(str(i), m)
            kept += 1
    return kept


# ------------------------- pipeline -----------------------------------------
def main():
    docs = collections.defaultdict(list)
    for line in open(DATA / "samples.jsonl", encoding="utf-8"):
        d = json.loads(line)
        docs[d["strategy"]].append(extract_text(d["html"]))

    # markov_ref: a research-probe generator. An order-2 Markov chain over the MATCHED
    # reference corpus (the register the perplexity model expects), not the embedded
    # one the shipped generators use. It tests whether a *generator* (not sentence
    # splicing) survives the gauntlet once the corpus matches the filter's distribution.
    ref_text = (DATA / "reference.txt").read_text(encoding="utf-8")
    matched = tokens(ref_text)                       # words only, for the order-sweep experiment
    mk = build_markov(markov_tokens(ref_text), 2)    # words + punctuation, for a C4-passing document
    n_ref = len(docs["splice_ref"]) or 300
    for i in range(n_ref):
        raw = markov_gen(mk, 2, 170, random.Random(1000 + i))
        docs["markov_ref"].append(re.sub(r"\s+([.!?])", r"\1", raw))  # attach " ." -> "."

    train = (DATA / "reference_train.txt").read_text(encoding="utf-8")
    lm = Trigram(train)

    # Calibrate the perplexity threshold to the real baseline: a cutoff that keeps
    # ~90% of real text (so it is "normal English", not an arbitrary number).
    base_ppl = sorted(lm.perplexity(t) for t in docs["baseline_real"])
    ppl_cut = base_ppl[int(0.90 * len(base_ppl))] if base_ppl else float("inf")

    rows = {}
    ppls = {}
    for s in STRATEGIES:
        texts = docs.get(s, [])
        n = len(texts)
        after_extract = [t for t in texts if len(t.split()) >= 50]
        after_gopher = [t for t in after_extract if passes_gopher(t)]
        after_c4 = [t for t in after_gopher if passes_c4(t)]
        p = [lm.perplexity(t) for t in after_c4]
        after_ppl = [t for t, pp in zip(after_c4, p) if pp <= ppl_cut]
        survivors = dedup_survivors(after_ppl)
        rows[s] = {
            "n": n,
            "extraction": len(after_extract),
            "gopher": len(after_gopher),
            "c4": len(after_c4),
            "perplexity": len(after_ppl),
            "dedup": survivors,
        }
        ppls[s] = [lm.perplexity(t) for t in texts if len(t.split()) >= 50]

    write_report(rows, ppls, ppl_cut)
    plot_funnel(rows)
    plot_perplexity(ppls, ppl_cut)
    plot_final_survival(rows)
    plot_perplexity_vs_order(lm, ppl_cut, matched)
    multisite()
    append_footer()
    print("study complete; figures in research/figures/, report in research/STUDY.md")


def multisite():
    """Federation analysis: does poison from many Henbane sites add up, or does
    cross-site near-duplicate dedup collapse it? Compares salted deployments (each
    a distinct per-site salt, as Henbane ships) against identical un-salted sites.
    Requires research/data/multisite.jsonl (see research/README.md)."""
    path = DATA / "multisite.jsonl"
    if not path.exists():
        return
    by = collections.defaultdict(lambda: collections.defaultdict(list))
    for line in open(path, encoding="utf-8"):
        d = json.loads(line)
        by[d["strategy"]][d["site"]].append(extract_text(d["html"]))
    try:
        from datasketch import MinHash, MinHashLSH
    except Exception:
        return
    strategies = ["babble", "splice", "article", "canary"]
    sites = sorted({s for st in by.values() for s in st}, key=lambda x: int(x[1:]))
    M = len(sites)
    ks = list(range(1, M + 1))

    def mh(text):
        m = MinHash(num_perm=64)
        toks = tokens(text)
        for j in range(len(toks) - 4):
            m.update(" ".join(toks[j:j + 5]).encode())
        return m

    def survivors_in(texts):  # dedup a single list
        lsh = MinHashLSH(threshold=0.7, num_perm=64)
        k = 0
        for i, t in enumerate(texts):
            m = mh(t)
            if not lsh.query(m):
                lsh.insert(str(i), m)
                k += 1
        return k

    plt.figure(figsize=(10, 5.6))
    salted_final = {}
    for s in strategies:
        lsh = MinHashLSH(threshold=0.7, num_perm=64)  # add sites incrementally
        y, kept, idx = [], 0, 0
        for site in sites:
            for t in by[s][site]:
                m = mh(t)
                if not lsh.query(m):
                    lsh.insert(str(idx), m)
                    kept += 1
                idx += 1
            y.append(kept)
        salted_final[s] = y[-1]
        plt.plot(ks, y, marker=MARKERS[s], markersize=6, color=COLORS[s],
                 linewidth=2, alpha=0.8, label=f"{LABELS[s]}, salted")
    # Un-salted reference: identical sites collapse to one site's worth; adding more
    # sites adds zero new uniques.
    base = survivors_in(by["article"][sites[0]])
    same = [base] * M
    plt.plot(ks, same, "--", color="#555", linewidth=2.2, label="no per-site salt (identical sites)")
    # The salted lines lie on top of each other (each site's salt makes its docs
    # unique regardless of strategy), so say so rather than leave a viewer puzzling
    # over four legend entries on one visible line.
    plt.annotate("the four salted lines coincide:\nevery strategy accumulates identically",
                 xy=(ks[-1], salted_final["article"]), xytext=(0.30, 0.62),
                 textcoords="axes fraction", fontsize=10, color="#333333",
                 arrowprops=dict(arrowstyle="->", color="#888", lw=1.2))
    plt.xlabel("participating sites")
    plt.ylabel("unique poison docs surviving cross-site dedup")
    plt.title("Federation: per-deployment salt makes sites add up")
    plt.legend(loc="upper left")
    plt.tight_layout()
    plt.savefig(FIGS / "multisite_federation.png", dpi=150)
    plt.close()

    per_site = len(by["article"][sites[0]])
    with open(ROOT / "STUDY.md", "a", encoding="utf-8", newline="\n") as f:
        f.write(
            "\n## Federation: does multi-site poison add up?\n\n"
            f"Simulating **{M} Henbane deployments** ({per_site} docs each), pooled and "
            "run through cross-site MinHash dedup. The question the "
            "[strategy](../docs/STRATEGY.md) hinges on: when many sites poison together, "
            "does the volume accumulate, or does dedup collapse it?\n\n"
            "![federation](figures/multisite_federation.png)\n\n"
            "- **With Henbane's per-deployment salt, it accumulates.** Each site's output "
            "is distinct, so the surviving-after-dedup count grows roughly linearly with "
            f"the number of sites (article: {salted_final['article']} unique docs across "
            f"{M} sites).\n"
            "- **Without a per-site salt, it collapses.** Identical sites dedup down to one "
            f"site's worth (flat dashed line, ~{same[-1]} docs no matter how many sites). "
            "This is *why* the generators mix a per-deployment salt into their seed.\n"
            "- **Honest caveat.** Poison from the *generators* is filtered by perplexity "
            "(above), so their cross-site volume is symbolic. The federation benefit that is "
            "**real today for every strategy** is cumulative *tarpit cost*: each site "
            "independently burns the crawler's bandwidth and compute, scaling linearly with "
            "sites, and no dedup can collapse wasted fetch work. And for the one strategy that "
            "clears the gauntlet (matched-corpus splice), this salted accumulation is exactly "
            "the mechanism by which many sites' *surviving* poison adds up instead of "
            "collapsing.\n"
        )


STAGES = ["n", "extraction", "gopher", "c4", "perplexity", "dedup"]
STAGE_LABELS = ["generated", "boilerplate", "Gopher", "C4", "perplexity", "dedup"]


def plot_funnel(rows):
    plt.figure(figsize=(10, 5.4))
    x = range(len(STAGES))
    for s in STRATEGIES:
        n0 = rows[s]["n"] or 1
        y = [100 * rows[s][k] / n0 for k in STAGES]
        plt.plot(x, y, marker=MARKERS[s], markersize=7, color=COLORS[s],
                 label=LABELS[s], linewidth=2, alpha=0.9)
    plt.xticks(list(x), STAGE_LABELS)
    plt.ylabel("% of documents surviving")
    plt.ylim(-3, 104)
    plt.title("Survival through the dataset-filter gauntlet")
    plt.legend(loc="lower left")
    plt.tight_layout()
    plt.savefig(FIGS / "survival_funnel.png", dpi=150)
    plt.close()


def plot_perplexity(ppls, cut):
    plt.figure(figsize=(10, 5.8))
    data = [np.clip(ppls[s], 0, np.percentile(sum(ppls.values(), []), 99)) for s in STRATEGIES]
    bp = plt.boxplot(data, patch_artist=True, tick_labels=[LABELS[s] for s in STRATEGIES], showfliers=False)
    for patch, s in zip(bp["boxes"], STRATEGIES):
        patch.set_facecolor(COLORS[s])
        patch.set_alpha(0.85)
    for median in bp["medians"]:
        median.set_color("#111111")
        median.set_linewidth(1.6)
    plt.axhline(cut, color="#aa3333", linestyle="--", linewidth=2,
                label=f"filter cutoff (~90% real text kept) = {cut:.0f}")
    # Rotate the long strategy labels so they never collide.
    plt.xticks(rotation=18, ha="right")
    plt.ylabel("word-trigram perplexity (lower = more fluent)")
    plt.title("Perplexity by strategy vs. real text")
    plt.legend(loc="upper right")
    plt.grid(True, axis="y", alpha=0.3)
    plt.gca().set_axisbelow(True)
    plt.tight_layout()
    plt.savefig(FIGS / "perplexity.png", dpi=150)
    plt.close()


def plot_final_survival(rows):
    plt.figure(figsize=(10, 5.2))
    vals = [100 * rows[s]["dedup"] / (rows[s]["n"] or 1) for s in STRATEGIES]
    plt.bar([LABELS[s] for s in STRATEGIES], vals, color=[COLORS[s] for s in STRATEGIES],
            edgecolor="#333333", linewidth=0.6)
    for i, v in enumerate(vals):
        plt.text(i, v + 1, f"{v:.0f}%", ha="center", fontweight="bold")
    plt.xticks(rotation=18, ha="right")
    plt.ylabel("% surviving the full gauntlet")
    plt.title("End-to-end survival rate")
    plt.ylim(0, max(vals) * 1.25 + 5)
    plt.grid(True, axis="y", alpha=0.3)
    plt.gca().set_axisbelow(True)
    plt.tight_layout()
    plt.savefig(FIGS / "final_survival.png", dpi=150)
    plt.close()


def plot_perplexity_vs_order(lm, cut, matched):
    """Isolate what it takes to bypass the perplexity filter. Generate Markov text at
    increasing order (order 1 is a bag of words; higher orders keep longer real spans)
    over the MATCHED reference corpus and over Henbane's UNMATCHED embedded corpus, and
    score each against the perplexity model. The answer is the corpus, not the
    generator: matching the corpus passes at low order, mismatching it fails at every
    order."""
    unmatched = tokens((ROOT.parent / "internal/generate/poison/babble/corpus.txt").read_text(encoding="utf-8"))
    orders = list(range(1, 7))

    def curve(corpus_toks):
        ys = []
        for o in orders:
            m = build_markov(corpus_toks, o)
            ps = [lm.perplexity(markov_gen(m, o, 120, random.Random(s))) for s in range(40)]
            ys.append(float(np.median(ps)))
        return ys

    y_match, y_unmatch = curve(matched), curve(unmatched)

    plt.figure(figsize=(10, 5.6))
    plt.axhspan(0, cut, color="#008300", alpha=0.06)  # the "passes the filter" band
    plt.plot(orders, y_match, marker="o", markersize=8, linewidth=2.2,
             color=COLORS["splice_ref"], label="matched reference corpus")
    plt.plot(orders, y_unmatch, marker="s", markersize=8, linewidth=2.2,
             color=COLORS["babble"], label="unmatched embedded corpus")
    plt.axhline(cut, color="#aa3333", linestyle="--", linewidth=2, label=f"filter cutoff = {cut:.0f}")
    plt.text(6.0, cut * 0.45, "passes the filter", ha="right", color="#4d7a2f", fontsize=10)
    plt.xlabel("Markov order (local coherence of the generator)")
    plt.ylabel("median word-trigram perplexity (lower = more fluent)")
    plt.title("Bypassing the perplexity filter: the corpus, not the generator")
    plt.ylim(0, max(y_unmatch) * 1.12)
    plt.xticks(orders)
    plt.legend(loc="center right")
    plt.tight_layout()
    plt.savefig(FIGS / "perplexity_vs_order.png", dpi=150)
    plt.close()

    passes_at = next((o for o, y in zip(orders, y_match) if y <= cut), None)
    with open(ROOT / "STUDY.md", "a", encoding="utf-8", newline="\n") as f:
        f.write(
            "\n## Bypassing the perplexity filter: the corpus, not the generator\n\n"
            "The perplexity stage discards most generated poison (see the funnel). What "
            "does it actually take to get past it? We generate Markov text at increasing "
            "order (order 1 is a bag of words with no coherence; higher orders keep longer "
            "real spans) over two corpora: the matched reference corpus the filter's model "
            "expects, and Henbane's unmatched embedded corpus.\n\n"
            "![perplexity vs order](figures/perplexity_vs_order.png)\n\n"
            f"- **Over the matched corpus, a plain Markov generator bypasses the filter "
            f"from order {passes_at}.** Even order 1 (random words from the matched "
            f"vocabulary, no word order at all) lands at {y_match[0]:.0f}, near the "
            f"{cut:.0f} cutoff; an order-2 chain sits at {y_match[1]:.0f}, comfortably "
            f"under it.\n"
            f"- **Over the unmatched corpus, no order helps.** Perplexity stays around "
            f"{np.median(y_unmatch):.0f} at every order, far above the cutoff.\n\n"
            "So the perplexity filter scores vocabulary and local distribution, not "
            "coherence or generator sophistication. Match the corpus and even crude "
            "generation passes; mismatch it and nothing does. This is why the shipped "
            "generators (over the embedded corpus) are filtered, why `splice_ref` and "
            "`markov_ref` (both over the matched corpus) survive the full gauntlet, and "
            "why the one real lever is `poison.corpus_path` pointed at distribution-matched "
            "text.\n\n"
            "**Honest limit.** Passing perplexity is not the same as being coherent. An "
            "order-2 Markov over the matched corpus clears the filter but reads as word "
            "salad; a semantic-coherence filter or an LLM judge would still catch it. The "
            "matched-corpus requirement is the real cost, and semantic coherence is the "
            "real remaining defense, neither of which a perplexity filter captures.\n"
        )


def write_report(rows, ppls, cut):
    lines = ["# Poison-survival study", "",
             "How much of each Henbane poison strategy's output survives the "
             "dataset-filter gauntlet that web-scale LM training pipelines apply "
             "before text reaches a model. Lower survival = the filters discard it "
             "(a resource-draining tarpit but weak poison); higher survival = it "
             "could plausibly reach a training set.", "",
             "**Method.** Each strategy emits its real maze-page HTML; a boilerplate "
             "step keeps the main `<p>`/`<h1>` content (dropping nav links); the text "
             "then passes Gopher heuristics, C4 rules, a word-trigram perplexity "
             "filter calibrated to keep ~90% of real text, and MinHash near-duplicate "
             "dedup. The baseline is real public-domain prose (a *different* book from "
             "the one the perplexity model trained on). Perplexity is option (b), a "
             "trigram approximation of the KenLM/Wikipedia stage; treat absolute "
             "numbers as directional.", "",
             f"Perplexity cutoff (calibrated): **{cut:.0f}**.", "",
             "## Survival funnel (documents remaining, %)", "",
             "| strategy | generated | boilerplate | Gopher | C4 | perplexity | dedup |",
             "|---|---|---|---|---|---|---|"]
    for s in STRATEGIES:
        r = rows[s]
        n0 = r["n"] or 1
        lines.append("| {} | {} | {} | {} | {} | {} | {} |".format(
            LABELS[s], r["n"],
            *[f"{r[k]} ({100*r[k]/n0:.0f}%)" for k in STAGES[1:]]))
    lines += ["", "![survival funnel](figures/survival_funnel.png)", "",
              "## Perplexity by strategy (word-trigram; lower = more fluent)", "",
              "| strategy | median | 10th pct | min | multiple of real-text median |",
              "|---|---|---|---|---|"]
    real_med = float(np.median(ppls["baseline_real"])) if ppls["baseline_real"] else 1.0
    for s in STRATEGIES:
        p = ppls[s]
        med = float(np.median(p)) if p else float("nan")
        p10 = float(np.percentile(p, 10)) if p else float("nan")
        lines.append(f"| {LABELS[s]} | {med:.0f} | {p10:.0f} | {min(p):.0f} | {med/real_med:.1f}x |")
    # Data-driven headline so the prose can never drift from the measured result.
    def med(s):
        return float(np.median(ppls[s])) if ppls[s] else float("nan")

    def finalpct(s):
        r = rows[s]
        return 100 * r["dedup"] / (r["n"] or 1)

    sr_ppl, sp_ppl, mr_ppl = med("splice_ref"), med("splice"), med("markov_ref")
    sr_final, real_final, mr_final = finalpct("splice_ref"), finalpct("baseline_real"), finalpct("markov_ref")
    filtered = [LABELS[s] for s in STRATEGIES
                if s != "baseline_real" and rows[s]["dedup"] == 0]

    lines += ["", "![perplexity](figures/perplexity.png)", "",
              "![final survival](figures/final_survival.png)", "",
              "## What the numbers say", "",
              f"- **Only the distribution-matched strategies clear the full gauntlet, and it "
              f"does not matter whether you splice or generate.** `splice_ref` (whole sentences "
              f"recombined from the reference corpus) and `markov_ref` (a plain order-2 Markov "
              f"generator over that same corpus) both land near real-text perplexity "
              f"({sr_ppl:.0f} and {mr_ppl:.0f} vs the ~{cut:.0f} cutoff) and survive through "
              f"dedup ({sr_final:.0f}% and {mr_final:.0f}%). Everything over the *embedded* "
              f"corpus ({', '.join(filtered)}) is filtered ~100% at the perplexity stage. The "
              f"lever is the corpus, not the generator (quantified below).",
              f"- **The lever is the corpus, not the generator.** `splice` over the *embedded* "
              f"corpus scores {sp_ppl:.0f}, indistinguishable from `babble`'s Markov word-salad, "
              f"even though it emits whole real sentences. Keeping sentences intact buys "
              f"nothing when the corpus is out-of-distribution to the filter; matching the "
              f"corpus buys everything. (The generators invent coined entities that hit `<unk>`, "
              f"which is why they sit 2-4x above real text.)",
              f"- **Random recombination dodges dedup better than real text.** `splice_ref` "
              f"finishes at {sr_final:.0f}% versus the real baseline's {real_final:.0f}%: "
              f"sequential real chunks overlap and dedup against each other, while randomly "
              f"recombined sentences keep pages mutually distinct. Here recombination is a "
              f"feature, not a bug.", "",
              "## How to poison the well better (actionable)", "",
              f"1. **Point `splice` at a large, distribution-matched corpus** via "
              f"`poison.corpus_path`. That single change moves poison from 0% to ~{sr_final:.0f}% "
              f"survival; the shipped embedded corpus is deliberately idiosyncratic and matches "
              f"no real LM's distribution.",
              "2. **Match the crawler's own training distribution.** `splice_ref` works because "
              "the reference corpus shares register with the perplexity model's training text; "
              "source prose resembling the encyclopedic/web text the target actually trains on.",
              "3. **Keep the pool large.** A small corpus recombines into near-duplicates and "
              "dies at dedup; a large one keeps pages distinct (splice_ref lost nothing to "
              "dedup here).", "",
              "## Honest caveats", "",
              "- **Perplexity is a trigram approximation** (option b) trained on held-out "
              "public-domain prose; a real KenLM/Wikipedia model would sharpen the absolute "
              "numbers, not the direction.",
              "- **These filters do not check discourse coherence.** `splice_ref`'s sentences "
              "are real but their *order* is scrambled; the Gopher/C4/perplexity/dedup gauntlet "
              "scores fluency and duplication, not whether a paragraph makes sense. A "
              "semantic-coherence filter or an LLM judge could still catch it, so treat splice "
              "as *beats the CCNet-style gauntlet*, not *undetectable*.",
              "- **Policy / liability.** Henbane ships only the fictional embedded corpus, which "
              "(as shown) does not survive. Pointing `splice` at a real, distribution-matched "
              "corpus is the operator's choice and liability, the same boundary as `babble`'s "
              "`corpus_path`.", ""]
    # No footer here: multisite() appends the Federation section after this, and the
    # footer is written last (append_footer) so it stays at the bottom of the page.
    (ROOT / "STUDY.md").write_text("\n".join(lines), encoding="utf-8", newline="\n")


def append_footer():
    with open(ROOT / "STUDY.md", "a", encoding="utf-8", newline="\n") as f:
        f.write("\n---\n\nRegenerate with the commands at the top of `research/study.py`.\n")


if __name__ == "__main__":
    main()
