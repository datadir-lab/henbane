// Package webbotauth verifies Web Bot Auth signed requests: AI agents that
// cryptographically prove their identity via HTTP Message Signatures (RFC 9421,
// Ed25519) and a published key directory (draft-meunier-web-bot-auth). OpenAI's
// ChatGPT agent, DuckDuckGo, and others sign their traffic this way. Henbane
// verifies the signature against the agent's directory keys (fetched from
// operator-configured directories at startup) and, on a valid signature, fires
// a configured tier — letting an operator act on a *proven* agent identity
// instead of a spoofable User-Agent.
//
// Scope: Ed25519 only (the profile Cloudflare's verifier and the signer
// reference implementation use). The verifier is interoperability-tested against
// the reference signer's output (see webbotauth_test.go).
package webbotauth

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

// Key is one agent directory public key, indexed by its RFC 7638 JWK thumbprint
// (which is the keyid carried in signatures).
type Key struct {
	Origin     string // the directory origin this key was published at
	Thumbprint string
	Public     ed25519.PublicKey
}

// Verifier checks Web Bot Auth signatures against a fixed set of directory keys.
type Verifier struct {
	byThumb map[string]Key
}

// NewVerifier indexes keys by thumbprint.
func NewVerifier(keys []Key) *Verifier {
	m := make(map[string]Key, len(keys))
	for _, k := range keys {
		m[k.Thumbprint] = k
	}
	return &Verifier{byThumb: m}
}

// Request is the minimal view a verifier needs of the signed request.
type Request struct {
	Method, Authority, Path string
	SignatureInput          string // the Signature-Input header
	Signature               string // the Signature header
	SignatureAgent          string // the Signature-Agent header
}

// Verify reports the agent directory origin and true if req carries a valid,
// unexpired Web Bot Auth Ed25519 signature from a known directory key. It never
// errors: any failure (missing/garbled headers, unknown key, expired, bad
// signature) returns ok=false, so a verification failure is handled as "not a
// verified agent", never as a trusted one.
func (v *Verifier) Verify(now time.Time, req Request) (origin string, ok bool) {
	if req.SignatureInput == "" || req.Signature == "" {
		return "", false
	}
	label, comps, params, rawParams, parsed := parseSignatureInput(req.SignatureInput)
	if !parsed {
		return "", false
	}
	if params["tag"] != "web-bot-auth" {
		return "", false
	}
	if alg, has := params["alg"]; has && alg != "ed25519" {
		return "", false
	}
	key, known := v.byThumb[params["keyid"]]
	if !known {
		return "", false
	}
	if !withinValidity(now, params) {
		return "", false
	}
	sig, got := parseSignatureValue(req.Signature, label)
	if !got {
		return "", false
	}
	base, built := buildBase(comps, rawParams, req)
	if !built {
		return "", false
	}
	if !ed25519.Verify(key.Public, []byte(base), sig) {
		return "", false
	}
	return key.Origin, true
}

// buildBase reconstructs the RFC 9421 signature base: one line per covered
// component ("identifier": value) joined by newlines, then the trailing
// "@signature-params" line with no final newline.
func buildBase(comps []component, rawParams string, req Request) (string, bool) {
	var b strings.Builder
	for _, c := range comps {
		val, ok := componentValue(c, req)
		if !ok {
			return "", false
		}
		b.WriteString(c.id)
		b.WriteString(": ")
		b.WriteString(val)
		b.WriteByte('\n')
	}
	b.WriteString(`"@signature-params": `)
	b.WriteString(rawParams)
	return b.String(), true
}

// componentValue computes the canonical value of a covered component.
func componentValue(c component, req Request) (string, bool) {
	switch c.name {
	case "@method":
		return req.Method, true
	case "@authority":
		return req.Authority, true
	case "@path":
		if req.Path == "" {
			return "/", true
		}
		return req.Path, true
	case "signature-agent":
		// A field component; may select a Dictionary member via ;key="...".
		if k, ok := c.params["key"]; ok {
			return dictMember(req.SignatureAgent, k)
		}
		return strings.TrimSpace(req.SignatureAgent), true
	default:
		return "", false // an unknown covered component cannot be verified
	}
}

// dictMember extracts the value of member key from an RFC 8941 Dictionary field
// value (e.g. `sig1="https://x";type=directory`), serialized per RFC 9421 §2.1.2
// as the member's value *including its parameters* (so sig1 → the whole
// `"https://x";type=directory`).
func dictMember(field, key string) (string, bool) {
	for _, member := range splitTop(field, ',') {
		member = strings.TrimSpace(member)
		eq := strings.IndexByte(member, '=')
		if eq < 0 {
			continue
		}
		if strings.TrimSpace(member[:eq]) != key {
			continue
		}
		return strings.TrimSpace(member[eq+1:]), true
	}
	return "", false
}

// paramStart returns the index of the first ';' not inside a quoted string, or -1.
func paramStart(s string) int {
	inQ := false
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '"':
			inQ = !inQ
		case ';':
			if !inQ {
				return i
			}
		}
	}
	return -1
}

type component struct {
	id     string // the exact identifier token as in Signature-Input, e.g. `"signature-agent";key="sig1"`
	name   string // the bare name, e.g. signature-agent
	params map[string]string
}

// parseSignatureInput parses the (first) signature's covered-component list and
// parameters. rawParams is the value after `label=` (used verbatim as the
// @signature-params value).
func parseSignatureInput(h string) (label string, comps []component, params map[string]string, rawParams string, ok bool) {
	h = strings.TrimSpace(h)
	eq := strings.IndexByte(h, '=')
	if eq < 0 {
		return
	}
	label = strings.TrimSpace(h[:eq])
	rawParams = strings.TrimSpace(h[eq+1:])
	if len(rawParams) == 0 || rawParams[0] != '(' {
		return
	}
	rp := strings.IndexByte(rawParams, ')')
	if rp < 0 {
		return
	}
	for _, tok := range splitInnerList(rawParams[1:rp]) {
		comps = append(comps, parseComponent(tok))
	}
	params = map[string]string{}
	for _, p := range splitTop(rawParams[rp+1:], ';') {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		k, val, _ := strings.Cut(p, "=")
		params[strings.TrimSpace(k)] = unquote(strings.TrimSpace(val))
	}
	ok = true
	return
}

func parseComponent(tok string) component {
	c := component{id: tok, params: map[string]string{}}
	name := tok
	if i := paramStart(tok); i >= 0 {
		name = tok[:i]
		for _, p := range splitTop(tok[i:], ';') {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			k, v, _ := strings.Cut(p, "=")
			c.params[strings.TrimSpace(k)] = unquote(strings.TrimSpace(v))
		}
	}
	c.name = unquote(strings.TrimSpace(name))
	return c
}

// parseSignatureValue extracts the raw signature bytes for label from a Signature
// header value (`label=:base64:`).
func parseSignatureValue(h, label string) ([]byte, bool) {
	for _, member := range splitTop(h, ',') {
		member = strings.TrimSpace(member)
		k, v, found := strings.Cut(member, "=")
		if !found || strings.TrimSpace(k) != label {
			continue
		}
		v = strings.TrimSpace(v)
		if len(v) < 2 || v[0] != ':' || v[len(v)-1] != ':' {
			return nil, false
		}
		raw, err := base64.StdEncoding.DecodeString(v[1 : len(v)-1])
		if err != nil {
			return nil, false
		}
		return raw, true
	}
	return nil, false
}

func withinValidity(now time.Time, params map[string]string) bool {
	const skew = 300 // seconds of clock tolerance
	if c := params["created"]; c != "" {
		if ts, err := strconv.ParseInt(c, 10, 64); err == nil && now.Unix()+skew < ts {
			return false
		}
	}
	if e := params["expires"]; e != "" {
		if ts, err := strconv.ParseInt(e, 10, 64); err == nil && now.Unix()-skew > ts {
			return false
		}
	}
	return true
}

// --- small structured-field helpers ---

// splitInnerList splits a space-separated list, respecting quoted strings.
func splitInnerList(s string) []string {
	return splitTopFunc(s, ' ')
}

// splitTop splits on sep at the top level (not inside quotes).
func splitTop(s string, sep byte) []string {
	return splitTopFunc(s, sep)
}

func splitTopFunc(s string, sep byte) []string {
	var out []string
	var cur strings.Builder
	inQ := false
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case ch == '"':
			inQ = !inQ
			cur.WriteByte(ch)
		case ch == sep && !inQ:
			if cur.Len() > 0 || sep != ' ' {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteByte(ch)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

func unquote(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

// Thumbprint computes the RFC 7638 JWK thumbprint of an Ed25519 OKP public key
// given its base64url x coordinate — this is the keyid used in signatures.
func Thumbprint(x string) string {
	canonical := `{"crv":"Ed25519","kty":"OKP","x":"` + x + `"}`
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// jwks is the subset of a key directory we parse.
type jwks struct {
	Keys []struct {
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		X   string `json:"x"`
	} `json:"keys"`
}

// ParseDirectory parses a JWKS directory body into Ed25519 keys for origin.
func ParseDirectory(origin string, body []byte) ([]Key, error) {
	var set jwks
	if err := json.Unmarshal(body, &set); err != nil {
		return nil, err
	}
	var keys []Key
	for _, k := range set.Keys {
		if k.Kty != "OKP" || k.Crv != "Ed25519" || k.X == "" {
			continue
		}
		raw, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			continue
		}
		keys = append(keys, Key{Origin: origin, Thumbprint: Thumbprint(k.X), Public: ed25519.PublicKey(raw)})
	}
	return keys, nil
}
