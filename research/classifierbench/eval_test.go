package classifierbench

import (
	"math"
	"strconv"
	"strings"
	"testing"

	"github.com/datadir-lab/henbane/internal/detect/consistency"
	"github.com/datadir-lab/henbane/internal/ports"
)

// This file holds the rigorous-evaluation machinery added in the study-v2 pass:
// base-rate-adjusted precision, baseline comparators, and per-class accounting.
// It is deliberately separate from the headline benchmark so the methodology is
// easy to audit.

// precisionAtBaseRate returns the precision a detector achieves when bots are a
// `baseRate` fraction of traffic, given its true-positive rate (recall on bots)
// and false-positive rate (on legitimate clients). This is the base-rate
// correction a balanced corpus hides: even a small FPR wrecks precision when
// bots are rare, because the false positives are drawn from the (large)
// legitimate majority. See the base-rate fallacy; Imperva puts bad bots near a
// third of all traffic, but on any one protected site the local rate varies.
func precisionAtBaseRate(tpr, fpr, baseRate float64) float64 {
	tp := baseRate * tpr
	fp := (1 - baseRate) * fpr
	if tp+fp == 0 {
		return 0
	}
	return tp / (tp + fp)
}

func TestPrecisionAtBaseRate_math(t *testing.T) {
	cases := []struct {
		tpr, fpr, rate, want float64
	}{
		{1, 0, 0.01, 1.0},     // a true-zero-FPR detector keeps precision 1 at any base rate
		{1, 0.01, 0.01, 0.50}, // 1% FPR at a 1% bot rate halves precision — the fallacy in action
		{1, 0.10, 0.01, 0.09}, // a 10% FPR at a 1% bot rate is almost all false positives
		{1, 0, 0.30, 1.0},
	}
	for _, c := range cases {
		got := precisionAtBaseRate(c.tpr, c.fpr, c.rate)
		if math.Abs(got-c.want) > 0.01 {
			t.Errorf("precisionAtBaseRate(tpr=%.2f fpr=%.2f rate=%.2f) = %.3f, want ~%.2f", c.tpr, c.fpr, c.rate, got, c.want)
		}
	}
}

// --- baseline comparators: the cheap detectors Henbane's scorer is measured against ---

// baseline is a named yes/no detector over a profile, so the scoring classifier
// can be compared against the simple rules real deployments actually use.
type baseline struct {
	name  string
	catch func(profile) bool
}

func baselines() []baseline {
	botUATerms := []string{"bot", "crawl", "spider", "scrapy", "curl", "wget", "python", "go-http", "java", "okhttp", "libwww", "httpclient"}
	return []baseline{
		// fail2ban-style: nothing to go on unless the UA is empty.
		{"empty-UA block", func(p profile) bool { return p.ua == "" }},
		// Anubis/OWASP-CRS-style: block User-Agents containing known bot tokens.
		{"UA-token blocklist", func(p profile) bool {
			ua := strings.ToLower(p.ua)
			for _, term := range botUATerms {
				if strings.Contains(ua, term) {
					return true
				}
			}
			return false
		}},
		// A single-signal classifier: no Accept header at all.
		{"no-Accept rule", func(p profile) bool { return p.headers["Accept"] == "" }},
	}
}

// isLegitHuman reports whether a profile is a real human browser (modern or a
// pre-Fetch-Metadata one) — the population false positives are drawn from.
func isLegitHuman(c class) bool { return c == human || c == humanEdge }

// baselineRate computes (caught-of-positives, positives, caught-of-humans,
// humans) for a yes/no detector, treating the given classes as the positive set
// and all legitimate human browsers (modern + edge) as the negatives.
func baselineRate(catch func(profile) bool, positives ...class) (tp, posTotal, fp, humanTotal int) {
	posSet := map[class]bool{}
	for _, c := range positives {
		posSet[c] = true
	}
	for _, p := range corpus() {
		hit := catch(p)
		switch {
		case isLegitHuman(p.class):
			humanTotal++
			if hit {
				fp++
			}
		case posSet[p.class]:
			posTotal++
			if hit {
				tp++
			}
		}
	}
	return
}

// TestBaselineComparison shows WHY the scoring classifier exists: the cheap rules
// catch a different population (honest-UA bots) and systematically miss the
// UA-spoofers the scorer is built for. It is a relative comparison on one corpus,
// not an absolute claim.
func TestBaselineComparison(t *testing.T) {
	sm := score(decide(t, consistency.DefaultWeights(), 2, 4), []class{spoofer}, []class{human, humanEdge})

	t.Logf("%-22s %-16s %s", "detector", "spoofers caught", "false positives")
	t.Logf("%s", "-----------------------------------------------------------")
	t.Logf("%-22s %-16s %s", "Henbane scoring", frac(sm.tp, sm.tp+sm.fn), frac(sm.fp, sm.fp+sm.tn))
	for _, b := range baselines() {
		tp, pt, fp, ht := baselineRate(b.catch, spoofer)
		t.Logf("%-22s %-16s %s", b.name, frac(tp, pt), frac(fp, ht))
	}
	t.Logf("")
	t.Logf("Reading: a UA-token blocklist catches honest-UA bots the scorer ignores,")
	t.Logf("but MISSES the browser-UA spoofers (they wear a clean Chrome UA) the scorer")
	t.Logf("is built to catch. The two are complementary layers, not rivals.")
}

func frac(a, b int) string {
	if b == 0 {
		return "0/0"
	}
	return strconv.Itoa(a) + "/" + strconv.Itoa(b)
}

// scorerRates returns the scoring classifier's recall (TPR) on spoofers and its
// false-positive rate (FPR) on all legitimate clients in the corpus.
func scorerRates(t *testing.T) (tpr, fpr float64) {
	t.Helper()
	tiers := decide(t, consistency.DefaultWeights(), 2, 4)
	var tp, fn, fp, tn int
	for _, p := range corpus() {
		caught := tiers[p.name] >= ports.TierSuspect
		switch {
		case isLegitHuman(p.class) && caught:
			fp++
		case isLegitHuman(p.class):
			tn++
		case p.class == spoofer && caught:
			tp++
		case p.class == spoofer:
			fn++
		}
	}
	if tp+fn > 0 {
		tpr = float64(tp) / float64(tp+fn)
	}
	if fp+tn > 0 {
		fpr = float64(fp) / float64(fp+tn)
	}
	return
}

// TestWeightTuningTradeoff quantifies the central dilemma the FP surface exposes:
// the Sec-Fetch signal that catches careful scrapers is the SAME signal that
// flags old browsers, because they are header-identical. Lowering its weight so
// it needs corroboration spares the old browsers but drops the careful scrapers.
// There is no free lunch at the header layer.
func TestWeightTuningTradeoff(t *testing.T) {
	report := func(label string, w consistency.Weights) {
		tiers := decide(t, w, 2, 4)
		naive := score(tiers, []class{spoofer}, []class{human, humanEdge})
		edgeFP := score(tiers, nil, []class{humanEdge})
		scrapy := tiers["scrapy"] >= ports.TierSuspect
		stealth := tiers["stealth-scraper"] >= ports.TierSuspect
		t.Logf("  %-36s naive %d/%d  edge-FP %d/%d  scrapy=%v  careful-scraper=%v",
			label, naive.tp, naive.tp+naive.fn, edgeFP.fp, edgeFP.fp+edgeFP.tn, caught(scrapy), caught(stealth))
	}
	hdr := func(fetch int) consistency.Weights { // header layer only
		w := consistency.DefaultWeights()
		w.H2Mismatch = 0
		w.NoFetchMetadata = fetch
		return w
	}
	h2 := func(fetch int) consistency.Weights { // header layer + the HTTP/2 fingerprint
		w := consistency.DefaultWeights()
		w.NoFetchMetadata = fetch
		return w
	}
	t.Logf("weight-tuning tradeoff (suspect threshold 2):")
	report("header only, Sec-Fetch weight 2", hdr(2))
	report("header only, Sec-Fetch weight 1", hdr(1))
	report("+ HTTP/2 signal, Sec-Fetch weight 1", h2(1))
	t.Logf("  => At the header layer there is no free lunch: weight 2 catches the careful scraper")
	t.Logf("     but challenges every old browser (edge-FP 3/3); weight 1 spares the old browsers")
	t.Logf("     (edge-FP 0/3) but misses the careful scraper. The HTTP/2 fingerprint resolves it:")
	t.Logf("     at weight 1 it still catches the careful scraper while the old browsers stay spared,")
	t.Logf("     because the scraper's h2 fingerprint is not a browser's.")
}

func caught(b bool) string {
	if b {
		return "caught"
	}
	return "MISSED"
}

func TestBaseRatePrecision(t *testing.T) {
	tpr, fpr := scorerRates(t)
	t.Logf("measured on corpus: recall(TPR)=%.2f  false-positive-rate(FPR)=%.2f", tpr, fpr)
	t.Logf("precision at realistic bot base rates:")
	for _, rate := range []float64{0.01, 0.05, 0.10, 0.30, 0.50} {
		t.Logf("  base rate %4.0f%%:  precision %.3f", rate*100, precisionAtBaseRate(tpr, fpr, rate))
	}
	t.Logf("The measured FPR of %.2f (driven by the flagged pre-Fetch-Metadata browsers) is why", fpr)
	t.Logf("precision COLLAPSES at low base rates: at a 1%% bot rate most 'catches' are legitimate")
	t.Logf("old browsers. This is the base-rate fallacy the balanced F1 hides — and why the raw")
	t.Logf("consistency score drives a challenge, not a block.")
}
