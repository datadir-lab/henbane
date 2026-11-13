package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/henbane-sh/henbane/internal/core"
	"github.com/henbane-sh/henbane/internal/ports"
)

type recordingSink struct{ events []ports.Event }

func (s *recordingSink) Emit(e ports.Event) { s.events = append(s.events, e) }

func TestProxyForwardsAndEmits(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "hello upstream")
	}))
	defer upstream.Close()

	u, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	rs := &recordingSink{}
	h := New(u, core.NewEngine(), []ports.Sink{rs})

	req := httptest.NewRequest(http.MethodGet, "http://example.com/page", nil)
	req.Header.Set("User-Agent", "curl/8")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if body := rec.Body.String(); body != "hello upstream" {
		t.Errorf("body = %q, want %q", body, "hello upstream")
	}
	if len(rs.events) != 1 {
		t.Fatalf("len(events) = %d, want 1", len(rs.events))
	}
	if rs.events[0].Action != ports.ActionAllow || rs.events[0].Path != "/page" {
		t.Errorf("event = %+v, want allow /page", rs.events[0])
	}
}
