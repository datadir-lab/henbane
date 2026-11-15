// Package henbanecaddy is a Caddy v2 HTTP middleware that runs the Henbane
// anti-AI-scraper gateway in front of your site. Build it into Caddy with
// xcaddy:
//
//	xcaddy build --with github.com/datadir-lab/henbane/caddy
//
// Then use it as an HTTP handler directive:
//
//	example.com {
//	    henbane /etc/henbane.yaml   # or: henbane { config_file /etc/henbane.yaml }
//	    reverse_proxy localhost:8081
//	}
//
// Requests Henbane allows continue down the Caddy handler chain; suspect,
// confirmed, and blocked requests are challenged, tarpitted, or blocked here.
// With no config file the middleware is passive (every posture is off).
package henbanecaddy

import (
	"fmt"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/datadir-lab/henbane"
)

func init() {
	caddy.RegisterModule(Middleware{})
	httpcaddyfile.RegisterHandlerDirective("henbane", parseCaddyfile)
}

// Middleware is the Caddy HTTP handler module for Henbane.
type Middleware struct {
	// ConfigFile is the path to a Henbane YAML config file — the same file the
	// standalone binary reads. Empty means the default, passive configuration.
	ConfigFile string `json:"config_file,omitempty"`

	hb *henbane.Henbane
}

// CaddyModule returns the Caddy module information.
func (Middleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.henbane",
		New: func() caddy.Module { return new(Middleware) },
	}
}

// Provision loads the configuration and builds the Henbane instance once.
func (m *Middleware) Provision(caddy.Context) error {
	cfg := henbane.Config{}
	if m.ConfigFile != "" {
		loaded, err := henbane.LoadConfig(m.ConfigFile)
		if err != nil {
			return fmt.Errorf("henbane: load config: %w", err)
		}
		cfg = loaded
	}
	hb, err := henbane.New(cfg)
	if err != nil {
		return fmt.Errorf("henbane: %w", err)
	}
	m.hb = hb
	return nil
}

// ServeHTTP runs the Henbane pipeline. An allowed request is passed to next
// (the rest of the Caddy handler chain); any error next returns is propagated.
func (m *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	var nextErr error
	wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextErr = next.ServeHTTP(w, r)
	})
	m.hb.Handler(wrapped).ServeHTTP(w, r)
	return nextErr
}

// UnmarshalCaddyfile parses the henbane directive. Both forms are accepted:
//
//	henbane /etc/henbane.yaml
//	henbane { config_file /etc/henbane.yaml }
func (m *Middleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if d.NextArg() {
			m.ConfigFile = d.Val()
		}
		if d.NextArg() {
			return d.ArgErr()
		}
		for d.NextBlock(0) {
			switch d.Val() {
			case "config_file":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.ConfigFile = d.Val()
			default:
				return d.Errf("unknown henbane subdirective %q", d.Val())
			}
		}
	}
	return nil
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m Middleware
	if err := m.UnmarshalCaddyfile(h.Dispenser); err != nil {
		return nil, err
	}
	return &m, nil
}

// Interface guards.
var (
	_ caddy.Provisioner           = (*Middleware)(nil)
	_ caddyhttp.MiddlewareHandler = (*Middleware)(nil)
	_ caddyfile.Unmarshaler       = (*Middleware)(nil)
)
