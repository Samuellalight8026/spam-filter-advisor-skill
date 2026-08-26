# Pattern Guide

Detail behind the tiers in SKILL.md. Read this when you need to justify a
recommendation, when someone challenges one, or when the samples show a pattern
the main workflow does not cover.

## Contents

- [Why legitimate mail scores high on spam filters](#why-legitimate-mail-scores-high-on-spam-filters)
- [Character substitutions](#character-substitutions)
- [Misspellings](#misspellings)
- [Sending IP addresses](#sending-ip-addresses)
- [DKIM selectors](#dkim-selectors)
- [Sender display names and burner domains](#sender-display-names-and-burner-domains)
- [Structural traits that look useful but are not](#structural-traits-that-look-useful-but-are-not)
- [The unbiased sample problem](#the-unbiased-sample-problem)
- [Reasoning about a pattern not listed here](#reasoning-about-a-pattern-not-listed-here)

---

## Why legitimate mail scores high on spam filters

This is the single most useful thing to understand, because it explains why
spam-score-only rules fail and gives you the vocabulary to explain a false alarm
when someone brings you one.

Spam scores are additive. A message accumulates points from dozens of independent
tests and gets flagged when the total crosses a threshold — commonly 4.0 or 5.0.
Legitimate mail crosses it constantly without containing anything spammy, because
several of the tests measure infrastructure rather than content.

Real examples, with the point values that pushed each message over a threshold
of 4.0:

**A medical appointment reminder, scored 4.006.** Sent through Amazon SES, whose
shared IP pool carries mixed reputation, picking up `RCVD_IN_VALIDITY_RPBL` at
+1.31. The appointment link pointed at a third-level subdomain, adding
`URI_TRY_3LD` at +2.0. A neutral Bayesian verdict, `BAYES_50`, added +0.8.
Nothing about the message was suspicious; it was sent through a shared platform
and linked to a subdomain.

**A forwarded Gmail message, scored 5.3.** Forwarding breaks SPF, since the
forwarding server is not authorized to send for the original domain — that is
`SPF_SOFTFAIL` at +0.665. Gmail's long encoded bounce addresses trip
`AC_FROM_MANY_DOTS` at +2.5. `BAYES_50` adds another +0.8. The message was a
family photo.

**A university alumni newsletter, scored 4.3.** The bulk-mail platform's sending
IP was listed on SpamCop (+1.35) and Validity (+1.31), and the platform was not
properly authorized in the university's DMARC record, so DMARC failed.

The shape is consistent: shared sending infrastructure, forwarding artifacts, and
Bayesian uncertainty. None of it is about whether the message is spam.

**What follows from this:**

- Spam score is a reasonable *second* condition, ANDed with something specific.
  It is never a safe standalone rule.
- If someone asks why a particular message got caught, look for these markers
  before assuming the rule is wrong. Often the rule is fine and the message was
  genuinely borderline by infrastructure.
- A higher threshold buys real safety. In one case every legitimate false alarm
  scored between 4.0 and 5.3 while the actual spam scored 6 and above — moving
  the threshold from 4 to 6 would have eliminated every false alarm without
  losing meaningful coverage. Worth checking whether the same gap exists in the
  samples at hand: compare `spam_score` values in the clean set against the
  scores on any contaminated messages.

---

## Character substitutions

**Risk: effectively zero. Recommend freely.**

Substituting a visually similar character for a letter — `0` for O, capital `I`
for lowercase L, capital `O` for digit zero, `1` for L. The reader's eye corrects
it automatically; a string match does not.

Why this is safe to filter on: the substitution exists specifically to evade
filters keyed on the real brand name. A legitimate sender has no reason to
misspell their own name, and a real brand's marketing department would never ship
it. The technique and the fingerprint are the same thing, which is why these
rules keep working long after IP rules have gone stale.

**The critical operational detail: these strings cannot be retyped.**

`ParceI` (capital I) and `Parcel` (lowercase l) are indistinguishable in almost
every UI font. Someone typing a rule by hand will type the ordinary spelling. The
resulting rule matches all their real FedEx mail and none of the spam — a
double failure that is invisible until it causes damage.

Always deliver these as copy-paste blocks and say explicitly that they must be
copied rather than retyped.

The same trap applies in reverse when reviewing someone's existing rules. If they
show you a filter and ask whether it is right, you cannot tell by looking. Check
the code points:

```bash
python3 -c "s=input('paste the string: '); print(' '.join(f'{c!r} U+{ord(c):04X}' for c in s))"
```

Do this before telling anyone their rule has a typo. Assuming a typo from
appearance alone is a mistake in both directions.

**Non-ASCII homoglyphs** are the advanced version — Cyrillic `а` (U+0430) for
Latin `a`, Greek `ο` (U+03BF) for `o`. The word looks perfectly spelled because
every character is in the right place; they are just from the wrong alphabet. The
script detects these and reports the Unicode name. They are just as safe to
filter on, and even more impossible to type by hand.

---

## Misspellings

**Risk: very low for brand names, low-to-moderate for common words.**

Ordinary typos rather than character substitutions: `Marriot` for Marriott,
`Menbership` for Membership, `Stil` for Still.

These arise because the campaign's copy was written by someone not fluent in the
target language, or deliberately garbled to dodge exact-match filters. Either
way, consistency across many messages makes them a fingerprint.

Brand misspellings are the safer subset. A real company does not misspell its own
name in a subject line, and the word appears rarely enough in ordinary
correspondence that a false match is unlikely.

Common-word misspellings carry more risk, because human beings typing quickly
make the same errors. `Menbership` is safe — that specific transposition is rare.
Something like `recieve` is not, because a large fraction of people spell it that
way in ordinary email. Judge by whether a hurried human would plausibly produce
the same error, and rank accordingly.

---

## Sending IP addresses

**Risk: low when paired with a second condition. Effectiveness: decays in weeks.**

The connecting IP is in `Received-SPF` as `client-ip=`, or in the earliest
`Received` header. The script extracts it either way.

**Whether to recommend an IP rule at all depends entirely on the distribution.**

*Concentrated* — most messages from one or two adjacent /24 blocks — means the
campaign rented a block of addresses and is blasting from all of them. One rule
on the shared prefix catches the lot. This is the case worth acting on.

*Scattered* — nearly as many distinct /24s as there are messages, across
different continents — means a botnet of compromised machines. No practical
number of rules will keep up. Saying so is more useful than producing a list that
is stale within days.

Real campaigns do both at different times, sometimes alternating week to week. A
folder can contain one coordinated burst plus a scattered tail; recommend a rule
for the burst and be explicit that the tail is not addressable this way.

**Always pair an IP rule with a second condition, joined with AND.**

The pairing is insurance against reassignment. Address blocks get returned and
re-leased, and while ranges with heavy spam history tend to stay flagged in
reputation databases for a long time — legitimate senders who land on one
generally discover the problem fast and move rather than fight it — the pairing
costs nothing and removes the failure mode entirely.

A spam-score condition is the natural partner. It is also the reason the ANY/ALL
setting matters so much: with ANY, the pairing evaporates and the spam-score
condition runs alone against all incoming mail.

**On IP reputation claims:** do not tell someone a range is "known malicious"
without having actually looked it up in this conversation. Describing what the
samples show is honest and sufficient. Public reputation services exist if they
want to check, but their results should be reported as findings, not asserted
from memory.

**Reading a block from a set of addresses:** if the samples show `198.62.0.x` and
`198.62.1.x`, the filter string `198.62.` covers both. Match on the string with
the trailing dot so `198.62.` does not also match `198.621.x`. Do not extend to a
broader prefix than the samples support — jumping from `198.62.` to `198.` covers
millions of unrelated hosts.

---

## DKIM selectors

**Risk: unknown without testing. Flag, do not recommend blind.**

The DKIM selector is a label identifying which signing key a sender used —
`header.s=` in `Authentication-Results`, or `s=` in `DKIM-Signature`. Real
senders use recognizable ones: `google`, `selector1`, `default`, `k1`.

Campaigns that provision domains from a template often generate selectors from
the same pattern — a fixed prefix plus random characters, the same shape on every
message across dozens of unrelated burner domains. That is a genuine fingerprint,
and the script reports shared prefixes when it finds them.

The problem is that a spam-only folder cannot tell you whether it is safe. Real
senders also choose selectors, and a prefix like `mta` is a plausible thing for a
legitimate mail platform to use. The spam samples contain no information about
the person's own mail.

So: report it as a finding, explain what the test would be — scanning a random
sample of their ordinary inbox for selectors matching the prefix — and offer to
run that scan. Do not recommend the rule until the test comes back clean.

If someone pushes back that a selector rule seems too broad, they are reasoning
correctly. That instinct deserves agreement, not persuasion.

---

## Sender display names and burner domains

The display name (`Walmart Store`, `0maha Beef`) is a separate filter target from
the address, and in most clients a "From" rule matches both. Substitutions appear
in display names as often as in subjects, and the script counts them separately —
check the `fields` breakdown before choosing which field to filter on.

**Burner domains are not directly filterable.** These campaigns register throwaway
domains and use each for a handful of messages: `enoughpain.garden`,
`bearingappointed.bond`, `machinescash.beer`. Every message has a different one,
so there is nothing to match.

The TLD distribution is worth *mentioning* but rarely worth filtering. Campaigns
favour cheap new gTLDs — `.lat`, `.skin`, `.garden`, `.beer`, `.bond`, `.homes`,
`.lol` — and `from_domains.top_tlds` will often show them dominating. But real
businesses do use these, and the rule would be broad and permanent in exchange
for catching what a Tier 1 keyword rule already catches. Mention it as an
observation about how the campaign operates; recommend it only if the person
specifically wants aggressive filtering and understands the tradeoff.

---

## Structural traits that look useful but are not

The script reports these because they help characterize a campaign, but they are
poor filter material:

- **`Reply-To` equal to `From`.** Extremely common in spam. Also extremely common
  in ordinary automated mail.
- **`List-Unsubscribe` present.** Campaigns include it to look legitimate.
  Legitimate bulk mail includes it because it is required.
- **HTML-only body, no plain-text alternative.** True of most marketing mail.

Each contributes a little signal to a scoring system that weighs many factors
together, which is what spam scores already do. As a standalone binary rule, each
would catch enormous amounts of real mail.

---

## The unbiased sample problem

This comes up whenever someone wants to test whether a broad rule is safe, and it
is subtle enough to be worth stating carefully.

The intuitive test is: "I have a folder of messages my filters caught by mistake.
Let me check whether the new rule would have caught those too." That folder is
not a fair test. It exists precisely because those messages tripped a spam
threshold, so it is pre-selected for the messages most likely to trip another
one. A rule that looks clean against it may still be dangerous, and a rule that
looks dangerous against it may be fine.

The valid test is a random cross-section of ordinary mail — a few dozen messages
spanning different senders, newsletters, business correspondence, notifications,
personal mail — with no filtering applied in their selection.

If someone raises this objection themselves, they have understood something real.
Confirm it rather than working around it.

The script can be pointed at such a folder directly. Contamination flags will be
high, which is the expected and correct result for a folder of real mail; what
matters is whether the proposed pattern appears in `substitution_tokens`,
`misspelling_tokens`, or `dkim_selectors`.

---

## Reasoning about a pattern not listed here

Three questions, in order:

**1. Is there a reason a legitimate sender would never produce this?** Character
substitutions pass because the whole point is filter evasion. Spam scores fail
because legitimate mail trips them routinely. This is the question that
determines the tier.

**2. How much of the folder does it cover, and is the folder big enough to
trust?** A pattern in two of eighty messages is not worth a rule. Under about
fifteen messages, frequency counts are not yet meaningful — though character
substitutions remain trustworthy at any sample size, because they are
self-evidently deliberate rather than statistical.

**3. How long will it last?** Content patterns tend to persist because they are
load-bearing for the campaign. Infrastructure patterns rotate. Say which kind you
are recommending so the person knows what to expect.

A pattern that clears the first question can be recommended even if coverage is
modest — a safe rule that catches a quarter of the flood is worth having. A
pattern that fails the first question should not be recommended regardless of how
much it would catch.
