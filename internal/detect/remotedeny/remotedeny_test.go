package remotedeny

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/datadir-lab/henbane/internal/ports"
)

var _ ports.Detector = (*Detector)(nil)

type view struct{ ip netip.Addr }

func (v view) IP() netip.Addr       { return v.ip }
func (v view) UserAgent() string    { return "" }
func (v view) Method() string       { return "GET" }
func (v view) Path() string         { return "/" }
func (v view) Header(string) string { return "" }

func mustPfx(s string) netip.Prefix { return netip.MustParsePrefix(s) }

func TestDetectorFiresForListedIP(t *testing.T) {
	d := New()
	d.replace([]netip.Prefix{mustPfx("203.0.113.0/24")})
	res, ok := d.Inspect(view{ip: netip.MustParseAddr("203.0.113.9")})
	if !ok || res.Signal != "remote_denylist" || res.Tier != ports.TierBlocked {
		t.Errorf("listed IP = %+v, %v; want blocked", res, ok)
	}
	if _, ok := d.Inspect(view{ip: netip.MustParseAddr("198.51.100.1")}); ok {
		t.Error("unlisted IP must not fire")
	}
}

func TestDetectorEmptyAndInvalid(t *testing.T) {
	d := New() // empty set
	if _, ok := d.Inspect(view{ip: netip.MustParseAddr("203.0.113.9")}); ok {
		t.Error("empty set must never fire")
	}
	d.replace([]netip.Prefix{mustPfx("0.0.0.0/0")}) // (shouldn't happen via parse, but belt test)
	if _, ok := d.Inspect(view{ip: netip.Addr{}}); ok {
		t.Error("invalid IP must never fire")
	}
}

func TestDetectorUnmaps(t *testing.T) {
	d := New()
	d.replace([]netip.Prefix{mustPfx("1.2.3.0/24")})
	if _, ok := d.Inspect(view{ip: netip.MustParseAddr("::ffff:1.2.3.4")}); !ok {
		t.Error("IPv4-in-IPv6 must match an IPv4 prefix after unmap")
	}
}

func TestParseList(t *testing.T) {
	body := []byte(`
# a comment
203.0.113.0/24
198.51.100.7
not-an-ip
2001:db8::/32
0.0.0.0/0
`)
	got := parseList(body, 1000)
	// Expect: 203.0.113.0/24, 198.51.100.7/32, 2001:db8::/32. Reject comment,
	// garbage, and the /0 default route.
	if len(got) != 3 {
		t.Fatalf("parsed %d prefixes, want 3: %v", len(got), got)
	}
	var sawHost bool
	for _, p := range got {
		if p.Bits() == 0 {
			t.Error("parseList must reject a /0 prefix")
		}
		if p.Addr().Is4() && p.String() == "198.51.100.7/32" {
			sawHost = true
		}
	}
	if !sawHost {
		t.Error("a bare IP should become a /32 host prefix")
	}
}

func TestParseListCapsEntries(t *testing.T) {
	var b []byte
	for i := 0; i < 50; i++ {
		b = append(b, []byte("10.0.0."+string(rune('0'+i%10))+"/32\n")...)
	}
	got := parseList(b, 5)
	if len(got) > 5 {
		t.Errorf("parseList ignored the cap: %d > 5", len(got))
	}
}

func TestRefresherPopulatesFromServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "203.0.113.0/24\n198.51.100.0/24\n")
	}))
	defer srv.Close()
	d := New()
	r := NewRefresher(d, srv.URL, time.Hour, 1000, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := r.refreshOnce(context.Background()); err != nil {
		t.Fatalf("refreshOnce: %v", err)
	}
	if d.count() != 2 {
		t.Errorf("detector has %d prefixes, want 2", d.count())
	}
	if _, ok := d.Inspect(view{ip: netip.MustParseAddr("203.0.113.5")}); !ok {
		t.Error("refreshed IP should fire")
	}
}

func TestRefresherFailsSafeOnError(t *testing.T) {
	// First populate from a good server.
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "203.0.113.0/24\n")
	}))
	d := New()
	r := NewRefresher(d, good.URL, time.Hour, 1000, slog.New(slog.NewTextHandler(io.Discard, nil)))
	_ = r.refreshOnce(context.Background())
	good.Close()
	// Now the server errors; the detector must KEEP the last good set.
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer bad.Close()
	r.url = bad.URL
	if err := r.refreshOnce(context.Background()); err == nil {
		t.Error("a 500 response should be reported as an error")
	}
	if d.count() != 1 {
		t.Errorf("fail-safe violated: set changed to %d entries on error", d.count())
	}
}

func TestConcurrentInspectAndReplace(t *testing.T) {
	d := New()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			d.replace([]netip.Prefix{mustPfx("203.0.113.0/24")})
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			d.Inspect(view{ip: netip.MustParseAddr("203.0.113.9")})
		}
	}()
	wg.Wait()
}
