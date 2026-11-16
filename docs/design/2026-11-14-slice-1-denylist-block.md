# Henbane Slice 1: Denylist → Block + fail2ban (Design Addendum)

- **Status:** Approved for planning
- **Date:** 2026-11-14
- **Builds on:** `docs/design/2026-11-13-henbane-design.md` (§4.2 tiers, §6.1 signals, §9.2 fail2ban, §13 slice plan)

## Goal

Turn the Slice-0 passthrough engine into a minimal real classifier: an operator
**denylist** (IP/CIDR + user-agent) produces a `Block` verdict → **HTTP 403**, and
each block emits a stable **fail2ban** line so operators can escalate to firewall bans.
Introduce **secure client-IP resolution** (trusted-proxy aware) so the denylist matches
the real client across all form factors.

## In scope
- `internal/clientip` resolver (stdlib): rightmost-non-trusted algorithm.
- Classifier upgrade: `Decide` returns `Block`/`Blocked` for denylisted clients.
- Proxy `ActionBlock` → 403 (fail-closed default remains the backstop).
- `fail2ban` sink + shipped `deploy/fail2ban/` filter and jail snippet.
- Config: `trusted_proxies`, `deny.cidrs`, `deny.user_agents`, `sinks.fail2ban`.

## Out of scope (deferred)
- Single-IP forwarding headers (`X-Real-IP`, Cloudflare `CF-Connecting-IP`): different parse; fast-follow.
- UA **regex** matching (substring only for now).
- RFC 7239 `Forwarded` header.
- Honeypot tripwire / confirmed tier (Slice 2), labyrinth/poison (Slice 3-4).

## Client-IP resolution (`internal/clientip`)

Security-grade "rightmost-non-trusted" algorithm (per adam-p / realclientip-go), reimplemented
in stdlib (`net/netip`, `net`, `strings`), **not** imported, to honor the zero-dep rule.

```
func NewResolver(trusted []netip.Prefix) *Resolver
func (r *Resolver) ClientIP(remoteAddr string, xff []string) netip.Addr
```

- **Trust nobody by default** (`trusted` empty): parse `remoteAddr` only; ignore all
  forwarding headers (attacker-controlled at the edge).
- With trusted proxies: merge **all** XFF header values (adapter passes
  `r.Header.Values("X-Forwarded-For")`, never `.Get`), parse **right→left**, skip
  trusted-proxy CIDRs, return the first untrusted valid IP.
- **Sanitize every entry**: strip appended `:port` (AWS ALB), strip IPv6 `[]`/quotes,
  skip empty/malformed entries (never key a decision on a non-IP).
- Fallback: if all XFF entries are trusted (misconfig/attack), use `remoteAddr` if it is
  itself untrusted; otherwise return an invalid `netip.Addr{}`.
- Pure and table-testable: `(remoteAddr, xff, trusted) → netip.Addr`, no HTTP needed.

**Placement (hexagonal):** the **proxy adapter** owns a `*Resolver` and `requestView.IP()`
returns `resolver.ClientIP(r.RemoteAddr, r.Header.Values("X-Forwarded-For"))`. The core
classifier still only sees `RequestView.IP()`. Arch purity holds. This also retires the
Slice-0 "`IP()` silently returns zero Addr" debt.

## Classifier (`internal/core`)

`Engine` gains an injected policy; empty policy = Slice-0 passthrough behavior.

```
type Policy struct {
    DenyCIDRs      []netip.Prefix
    DenyUserAgents []string // case-insensitive substrings
}
func NewEngine(policy Policy) *Engine
```

`Decide` order:
1. If `r.IP()` is valid and matches any `DenyCIDRs` → `Verdict{Block, Blocked, ["denylist_ip"]}`.
2. Else if `r.UserAgent()` contains (case-insensitive) any `DenyUserAgents` entry →
   `Verdict{Block, Blocked, ["denylist_ua"]}`.
3. Else → `Verdict{Allow, Pass}`.

Each path emits one `Event` with the matching `Action`/`Tier`/`Signals`. Core stays
stdlib + ports only (`net/netip`, `strings`).

## Proxy adapter

Add `case ports.ActionBlock:` → `http.Error(w, "forbidden", http.StatusForbidden)` and do
NOT proxy. The Slice-0 fail-closed `default` (500) remains for not-yet-implemented actions.
`proxy.New` additionally takes a `*clientip.Resolver`.

## fail2ban sink (`internal/adapters/sink/fail2ban.go`)

```
func NewFail2banSink(w io.Writer) *Fail2banSink
func (s *Fail2banSink) Emit(e ports.Event)
```

Writes a line ONLY for ban-worthy events (`e.Action == ports.ActionBlock`); ignores others.
Stable, greppable format (contract for the shipped filter):

```
henbane: action=ban ip=203.0.113.9 tier=blocked reason=denylist_ua ua="GPTBot/1.1"
```

- `reason` = first `Signal` (or `unknown`).
- `ua` is quoted; sanitize to strip newlines/quotes so a crafted UA can't forge log lines
  (log-injection guard).
- Non-blocking, never errors the request path (per `ports.Sink` contract).

Shipped assets:
- `deploy/fail2ban/henbane.conf`: filter with a `failregex` matching the line above.
- `deploy/fail2ban/jail.local`: example jail (`logpath`, `maxretry`, `bantime`).

## Configuration additions (`henbane.yaml`)

```yaml
trusted_proxies: []        # CIDRs; empty = edge mode (RemoteAddr only)
deny:
  cidrs: []                # e.g. ["203.0.113.0/24"]
  user_agents: []          # case-insensitive substrings, e.g. ["GPTBot","CCBot"]
sinks:
  fail2ban:
    enabled: false
    path: /var/log/henbane/ban.log
```

`config.Config` grows these fields; CIDR strings parse to `[]netip.Prefix` at load with
clear errors on invalid input. Flag overrides remain for `listen`/`upstream` only.

## Wiring (`cmd/henbane`)

`newHandler` builds: `clientip.NewResolver(trusted)` → passed to `proxy.New`;
`core.NewEngine(policy)` from `deny.*`; sinks = slog + (if enabled) fail2ban writing to an
opened `path`. Opening the fail2ban file is a `main`/wiring concern; the sink just takes an
`io.Writer`.

## Testing (TDD)
- `clientip`: table tests: edge mode; single trusted proxy; multi-hop; spoofed leftmost
  ignored; `:port` stripped; IPv6 brackets; malformed skipped; all-trusted fallback.
- `core`: deny-by-CIDR; deny-by-UA (case-insensitive); allow otherwise; correct Event/Signal.
- `proxy`: `ActionBlock` → 403 and upstream not hit.
- `fail2ban` sink: block event → exact line; non-block event → nothing; UA log-injection sanitized.
- `config`: parse trusted_proxies/deny; invalid CIDR → error.
- `cmd` integration: denylisted UA → 403 end-to-end; allowed → upstream body.

## Dependency / arch impact
- No new third-party module (stdlib only); allowlist unchanged.
- `internal/clientip` imports stdlib only; core/ports still import neither it nor net/http
  (arch purity test unchanged and still passing).
