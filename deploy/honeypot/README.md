# Honeypot setup

Henbane's honeypot flags any client that fetches a hidden "trap" path as a
confirmed bot. You place the bait; Henbane does the rest.

## 1. Enable it

    honeypot:
      enabled: true
      path: "/.well-known/hb-trap"   # any path prefix humans never visit
      flag_ttl: "1h"
      max_flagged: 100000

## 2. Disallow the trap in robots.txt

A well-behaved crawler obeys this and never trips the trap; one that fetches it
anyway is ignoring the rules and is flagged.

    User-agent: *
    Disallow: /.well-known/hb-trap

## 3. Plant a hidden, nofollow link on your pages

Invisible to humans, followed by greedy scrapers. Put it near the top of
`<body>`:

    <a href="/.well-known/hb-trap/a" rel="nofollow"
       aria-hidden="true" tabindex="-1"
       style="position:absolute;left:-9999px">unsubscribe</a>

## What happens

- A request under the trap path → the client is flagged (for `flag_ttl`) and
  gets 403.
- Subsequent requests from a flagged client → 403, with a `flagged` reason.
- Both emit a fail2ban line (`reason=honeypot` / `reason=flagged`) so you can
  escalate to a firewall ban using the shipped `deploy/fail2ban/` filter.

Flags are kept in memory, bounded by `max_flagged` (an entry evicted past the
cap), keyed on the resolved client IP.

## Cautions

- **Pick a unique, obscure trap path.** The prefix is matched as a substring, so
  `/trap` also traps `/trapeze`, and `/` would trap (and flag) every request.
  Use something like `/.well-known/hb-trap` that nothing else collides with.
- **Reflected-abuse guard.** Because the trap URL is public, an attacker could try
  to lure a victim's browser into loading it cross-site (e.g. `<img src=trap>`) to
  get that victim flagged. Henbane ignores trap hits that carry
  `Sec-Fetch-Site: cross-site`, which covers modern browsers. Keep `flag_ttl`
  modest, and if you sit behind a shared-IP CDN set `trusted_proxies` so clients
  resolve to their own IPs (otherwise one trap hit can flag everyone behind it).
