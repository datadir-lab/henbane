package browserhint

import (
	"net/netip"
	"testing"

	"github.com/datadir-lab/henbane/internal/ports"
)

type view struct {
	ua      string
	headers map[string]string
}

func (v view) IP() netip.Addr         { return netip.Addr{} }
func (v view) UserAgent() string      { return v.ua }
func (v view) Method() string         { return "GET" }
func (v view) Path() string           { return "/" }
func (v view) Header(n string) string { return v.headers[n] }

const chromeUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

func TestFiresOnBrowserUAWithoutFetchMetadata(t *testing.T) {
	res, fired := New().Inspect(view{ua: chromeUA})
	if !fired || res.Tier != ports.TierSuspect || res.Signal != "browser_hint" {
		t.Errorf("expected Suspect/browser_hint for spoofed browser UA, got fired=%v res=%+v", fired, res)
	}
}

func TestSilentWhenFetchMetadataPresent(t *testing.T) {
	if _, fired := New().Inspect(view{ua: chromeUA, headers: map[string]string{"Sec-Fetch-Site": "none"}}); fired {
		t.Error("a real browser (sends Sec-Fetch-Site) must not be flagged")
	}
}

func TestSilentForNonBrowserUA(t *testing.T) {
	for _, ua := range []string{"curl/8.4.0", "python-requests/2.31.0", "Go-http-client/1.1", "", "GPTBot"} {
		if _, fired := New().Inspect(view{ua: ua}); fired {
			t.Errorf("non-browser UA %q must not be flagged (it isn't claiming to be a browser)", ua)
		}
	}
}

func TestFiresForMainstreamBrowserFamilies(t *testing.T) {
	uas := []string{
		"Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
		"Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36 Edg/120",
	}
	for _, ua := range uas {
		if _, fired := New().Inspect(view{ua: ua}); !fired {
			t.Errorf("browser UA %q lacking Sec-Fetch-Site should fire Suspect", ua)
		}
	}
}

func TestName(t *testing.T) {
	if New().Name() != "browser_hint" {
		t.Errorf("Name() = %q, want browser_hint", New().Name())
	}
}
