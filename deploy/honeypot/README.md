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

Flags are kept in memory, bounded by `max_flagged` (oldest evicted past the
cap), keyed on the resolved client IP.
