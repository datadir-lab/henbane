package webbotauth

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/datadir-lab/henbane/internal/ports"
)

// DirectoryPath is the well-known location of an agent's key directory.
const DirectoryPath = "/.well-known/http-message-signatures-directory"

const maxDirectoryBytes = 1 << 20

// FetchDirectory fetches and parses the key directory published at origin.
func FetchDirectory(ctx context.Context, client *http.Client, origin string) ([]Key, error) {
	u := strings.TrimRight(origin, "/") + DirectoryPath
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("directory %s: status %d", u, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDirectoryBytes))
	if err != nil {
		return nil, err
	}
	return ParseDirectory(origin, body)
}

// hoster is an optional RequestView capability exposing the request authority,
// which RFC 9421 covers as @authority. proxy.requestView implements it.
type hoster interface {
	Host() string
}

// Detector fires at a configured tier when a request carries a valid Web Bot
// Auth signature from a known agent directory key. It reads the signed authority
// from the optional hoster capability; a RequestView without it never fires.
type Detector struct {
	v    *Verifier
	tier ports.Tier
	now  func() time.Time
}

// NewDetector returns a Detector that fires tier for verified signed agents.
func NewDetector(v *Verifier, tier ports.Tier) *Detector {
	return &Detector{v: v, tier: tier, now: time.Now}
}

// Name identifies the detector.
func (d *Detector) Name() string { return "webbotauth" }

// Inspect fires for a request with a valid Web Bot Auth signature. The signal
// carries the verified agent directory origin (e.g. "webbotauth:https://…").
func (d *Detector) Inspect(r ports.RequestView) (ports.Result, bool) {
	sigInput := r.Header("Signature-Input")
	if sigInput == "" {
		return ports.Result{}, false
	}
	h, ok := r.(hoster)
	if !ok {
		return ports.Result{}, false
	}
	origin, verified := d.v.Verify(d.now(), Request{
		Method:         r.Method(),
		Authority:      canonicalAuthority(h.Host()),
		Path:           r.Path(),
		SignatureInput: sigInput,
		Signature:      r.Header("Signature"),
		SignatureAgent: r.Header("Signature-Agent"),
	})
	if !verified {
		return ports.Result{}, false
	}
	return ports.Result{Signal: ports.Signal("webbotauth:" + origin), Tier: d.tier}, true
}

// canonicalAuthority lowercases the host and strips a default port, matching the
// @authority canonicalization an agent signs (RFC 9421 §2.2.3).
func canonicalAuthority(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	host = strings.TrimSuffix(host, ":443")
	host = strings.TrimSuffix(host, ":80")
	return host
}
