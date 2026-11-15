# Legitimate Interests Assessment — Federation reporter

This LIA covers the optional **federation reporter** (`federation.report_url`),
which contributes a deployment's confirmed-bad-bot detections to a shared feed.
It is a template operators should review and adapt; enabling the reporter is the
operator's decision, and the operator is the data controller for their traffic.

GDPR requires a lawful basis for processing personal data. An IP address is
personal data (*Breyer*, C-582/14). The basis relied on here is **Article 6(1)(f)
legitimate interests**, assessed in three parts.

## 1. Purpose test — is there a legitimate interest?

Yes. Detecting and sharing the IP addresses of automated clients that attack or
abusively scrape a site serves **network and information security**. GDPR
**Recital 49** states explicitly that processing "to the extent strictly
necessary and proportionate for the purposes of ensuring network and information
security" — including preventing unauthorised access, malicious code, and
denial-of-service — "constitutes a legitimate interest of the data controller
concerned." Sharing confirmed-bad indicators so other operators can defend
themselves is an established security practice (CSIRTs, CrowdSec, Spamhaus,
abuse.ch).

## 2. Necessity test — is the processing necessary?

Yes, and it is minimised:

- **Only confirmed-hostile events are reported** — tiers `Confirmed` and
  `Blocked`. A `Pass` or `Suspect` request (i.e. ordinary or merely-uncertain
  traffic, including humans) is never reported.
- **Only four fields leave the deployment**: the IP, the signal that fired
  (e.g. `honeypot`), the tier, and a timestamp. No request contents, no
  User-Agent, no path, no cookies, no logs — nothing beyond what the receiving
  party needs to act on the indicator.
- The IP is sent **unmodified rather than hashed**: a hashed IP is still personal
  data (EDPB 2025 guidance; Recital 26) and trivially reversible for IPv4, so
  hashing adds no real protection while breaking the cross-reporter matching that
  the feed needs to reach consensus before acting. Minimisation is achieved by
  limiting *which* events and *what* fields are shared, not by pseudonymisation.

## 3. Balancing test — do the individual's interests override?

The data subjects are operators of automated clients that have already tripped a
high-confidence trap (e.g. fetched a hidden honeypot path a human would never
visit) or matched an operator denylist. The impact of sharing is low and
security-specific; the expectation of privacy for a machine conducting
abusive automated access is limited. Safeguards keep the balance in favour of
processing:

- **Consensus before action.** An indicator should only affect others after
  corroboration across many independent reporters (the feed/control plane's job),
  so one reporter cannot cause an arbitrary IP to be blocked — this protects both
  the network and any individual against a malicious or mistaken report.
- **Automatic expiry.** Indicators are time-stamped and should age out when no
  longer observed (e.g. cleared after a fixed no-sighting window), so data is kept
  only as long as necessary.
- **Transparency.** The operator discloses this processing in their privacy
  notice; the reporter is **off by default** and opt-in.
- **Data subject rights.** The feed should provide a removal/appeal path
  (self-service de-listing with cooldowns is common practice).

## Outcome

With the minimisation and safeguards above, the legitimate-interests basis is
appropriate for the federation reporter. Operators must still: enter their own
details, publish the processing in their privacy notice, confirm the receiving
feed's lawful basis and retention, and record this assessment. This document is
guidance, not legal advice.
