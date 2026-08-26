---
name: spam-filter-advisor
description: Analyze a folder of saved spam emails (.eml files) and recommend mail filter rules that catch them without eating legitimate mail. Use whenever someone has collected spam samples and wants help building filters, says their inbox is flooded with junk and they want rules to stop it, asks what patterns their spam shares, wants to know which keywords or sending IPs are safe to block, or wants help setting up rules in Apple Mail, Gmail, Outlook, or Thunderbird. Also when someone exports spam to a folder and asks "what can I do about this" without naming filters. Equally for tuning rules already in place — spam still slipping through, a filter catching real mail by mistake, asking why a message got flagged, or returning with a folder of misses and false alarms. Produces recommendations ranked by false-alarm risk with exact copy-paste strings, warns when the folder is contaminated with real mail, and can test existing rules to find which one misfired.
---

# Spam Filter Advisor

Someone has a folder of spam and wants filter rules. The job is to find the
patterns that are genuinely unique to the spam, rank them honestly by how likely
they are to catch real mail by mistake, and hand over rules the person can
actually install.

The reason this needs care rather than pattern-matching enthusiasm: a filter that
misses spam is an annoyance, but a filter that quietly diverts a job offer or a
medical result is a real harm the person may not discover for weeks. Those two
failure modes are not symmetric, and the recommendations should not treat them as
if they were. When in doubt, recommend the narrower rule.

## Workflow

### 1. Find the folder and confirm what is in it

Ask where the .eml files are if it is not obvious. Confirm the person understands
these should be **spam only** — messages they are confident are junk. If they say
they dragged in "everything from the last week" or seem unsure, flag now that
mixed-in real mail will produce filter rules that catch real mail.

**How many samples.** Recommend **30 to 50 recent examples**. That is the range where
frequency counts, IP clustering, and misspelling patterns all become dependable enough
to build rules on.

Below 30, say so before running and name what gets weaker: frequency counts and IP
clustering are the first things to become unreliable, while character-substitution
findings (Tier 1) stay trustworthy at any size, because a deliberate lookalike
misspelling is self-evidently deliberate whether it appears twice or forty times.

**15 is the floor for a useful run.** Between 15 and 29, run the analysis, present the
findings, and carry the warning through to the recommendations — call them provisional
and say that more samples would firm them up. Below 15, run it if they want, but lead
with the fact that patterns at that size could easily be coincidence, and recommend
collecting more before installing any rule.

Never refuse to run over sample size. The person with 18 messages still gets real Tier 1
findings; they just need to know which parts of the report to trust.

Also ask which mail program they use, since that determines what is even
possible. Apple Mail, Thunderbird, and desktop Outlook can filter on raw headers
like sending IP; consumer Gmail essentially cannot. Read
`references/mail-clients.md` for the specifics once they answer.

### 2. Run the analysis script

```bash
python3 scripts/analyze_spam_samples.py "/path/to/folder" \
    --json-out "/tmp/spam_report_$(date +%s).json"
```

Stdlib only, no install step. It prints a readable summary and writes full JSON.
Read the JSON for detail — the summary truncates.

Use a unique filename for `--json-out` rather than a fixed one. A shared path
like `/tmp/spam_report.json` can be overwritten by another process between
writing and reading it, and the failure is quiet — you get a valid-looking report
describing somebody else's folder. Before trusting the JSON, check that `folder`
and `message_count` match what you just analyzed.

The script does the parts that are unreliable by eye: pulling the connecting IP
out of whatever header carries it, reading half a dozen different spam-score
header formats, comparing characters at the code-point level, and clustering IPs
into network blocks.

### 3. Lead with contamination, before any recommendations

The report's `contamination` section lists messages that look like real mail. Say
this first, before the interesting findings, because everything downstream is
built on the assumption that the folder is clean.

Calibration from testing: a folder of genuine spam scores around 1% flagged. A
folder of legitimate mail scores over 90%. Anything above roughly 10% means the
sample is mixed and the patterns are unreliable.

Name the specific files and why each was flagged. Then continue with the analysis
of what remains, telling them the flagged ones were excluded. Do not stop and
demand they fix it — just make sure they know, so they can pull those files and
rerun if they want. If contamination is high, say plainly that the recommendations
are provisional until the folder is cleaned up.

Watch for one specific trap in what they tell you next. If they offer their
existing "these got caught by mistake" folder as proof a rule is safe, that folder
is not a fair test — it only contains mail that already tripped a spam threshold,
so it is pre-selected for exactly the messages most likely to trip another one. A
real safety test needs a random cross-section of their ordinary inbox.

### 4. Sort the findings into tiers, and explain the reasoning

Group everything by false-alarm risk rather than by how much spam it catches.
Someone who understands *why* a rule is safe can extend the thinking themselves
later; someone handed a flat list cannot.

**Tier 1 — Character substitutions. Effectively zero risk.**

The report's `substitution_tokens` section. These are deliberate misspellings
using lookalike characters: a digit `0` for the letter O, a capital `I` for a
lowercase L, a capital `O` for a digit zero. `0maha`, `C0STC0`, `SampIer`,
`ParceI`, `WaImart`, `5OO`.

Spammers do this to slip past filters that match on brand names. The side effect
is that it hands you a perfect fingerprint: no real company ever spells its own
name with a zero in it. A rule on one of these strings cannot realistically catch
legitimate mail.

Rank within the tier by `message_count`. A token in forty messages is a real
lever; one in a single message is a curiosity.

**Tier 2 — Consistent misspellings. Very low risk.**

The `misspelling_tokens` section, especially entries where `kind` is `brand`.
`Marriot` for Marriott, `Menbership` for Membership. Real marketing copy gets
proofread, so the same error across many messages is a campaign fingerprint.

Slightly riskier than Tier 1 because a human being typing quickly might make the
same error. Brand misspellings are safer than common-word misspellings for this
reason — nobody writes "Marriot" in a work email nearly as often as they write
ordinary words a bit wrong.

**Tier 3 — Sending IP blocks. Low risk, but they expire.**

Only worth recommending when `ip_analysis.concentration_note` reports
concentration. A campaign blasting from one rented /23 is catchable in a single
rule. A botnet scattered across thirty networks is not, and saying so plainly is
more useful than handing over thirty rules that will be stale next week.

Two conditions on any IP rule:

- **Pair it with a second condition**, typically a spam-score threshold, joined
  with AND. IP blocks get reassigned. Pairing means that if the range is later
  rented by somebody legitimate, their mail still gets through.
- **Say out loud that it will decay.** These campaigns rotate infrastructure
  every few weeks. Frame IP rules as buying quiet weeks, not a permanent fix.

Do not assert that a specific IP range is "known malicious" or "blocklisted"
unless you have actually checked a reputation service in this conversation.
Describe what the samples show and leave it there.

**Tier 4 — Things to flag but not recommend without testing.**

Patterns that look decisive on a spam-only sample but have never been tested
against the person's real mail. Two common ones:

- **DKIM selector patterns.** If `dkim_selectors.shared_prefixes` shows every
  message using a selector starting with the same few characters, that is a real
  fingerprint. But selectors are configuration strings that legitimate senders
  also choose, and a spam-only folder cannot tell you whether any of their real
  mail matches.
- **Spam score alone.** Tempting and always wrong as a standalone rule. See the
  next section.

Present these as "here is something interesting, and here is the test that would
tell us whether it is safe" — the test being a scan of a random sample of their
normal inbox. Offer to run that scan against a folder of ordinary mail if they
want to pursue it.

### 5. Offer the rules, do not just describe them

Once they have picked what they want, offer to write out the exact strings and
the exact rule structure for their mail program.

**The strings must be copy-pasteable, and you should say why.** Tier 1 findings
cannot be retyped reliably. `ParceI` and `Parcel` are visually identical in
almost every font — someone typing the rule by hand will type the ordinary
spelling, and the rule will then match all their real FedEx mail while missing
every spam. Put each string on its own line in a code block so it copies cleanly,
and tell them to copy rather than retype.

Give the field for each string too. Subject and sender display name are separate
filter targets, and the report's `fields` counts show where each token actually
appeared. A token seen only in From is wasted as a Subject rule.

### 6. Offer the known-campaign supplement, if it is relevant

`references/known-campaign-2026-06.json` holds findings from a 176-message corpus
collected from one mailbox over two weeks in June 2026 — a brand-impersonation
campaign using fake loyalty-point expiry notices, free-sampler offers, prize
shipments, and parcel-delivery warnings across roughly sixteen retail brands.

Offer it **after** presenting their own findings, never instead of them. Their own
samples are the thing actually tailored to what is hitting their mailbox; this is
for catching stragglers their sample happened not to include — useful mainly when
their folder is small or when the campaign is clearly the same family.

**Check relevance first.** Read the `how_to_use.relevance_test` field. If their
spam is a different genre entirely — invoices, crypto, dating, sextortion — this
file has nothing to offer and mentioning it is noise. Skip it silently.

**Staleness applies unevenly, and saying so precisely is the whole value here.**
Each tier in the file carries a `decay` field. The short version:

- **Tier 1 substitutions do not go stale.** The misspelling *is* the evasion
  technique, so it is load-bearing for the operator and expensive to abandon.
  `0maha` was never going to match legitimate mail and still will not. Offer
  these with confidence.
- **Tier 2 misspellings age slowly.** Copy gets rewritten between waves more
  often than the character tricks, but any that still appear remain safe.
- **Tier 3 IP blocks are almost certainly dead.** Present them as historical
  context — "here is what that campaign's infrastructure looked like" — not as
  rules to install. If someone wants them anyway, the ANDed spam-score condition
  is mandatory, since blocks get reassigned and a year-old block may now belong
  to somebody legitimate.

Present it the same way as everything else: their tier, their field, their
message counts, in a copy-paste block, with the same warning that these strings
must be copied rather than retyped. Do not dump the JSON at them.

Be plain about where it came from. Something like: *"Separately — I have a set of
findings from someone else's collection of what looks like the same campaign,
from June 2026. The keyword patterns from it don't really go stale, so they might
catch a few stragglers yours didn't include. The IP ranges in it are long dead.
Want them?"*

### 7. Offer setup help

Offer to walk through installing the rules. Read `references/mail-clients.md` for
the client-specific steps. Things worth mentioning unprompted:

- **Send to a review folder, not to trash.** A quarantine folder they can skim
  for a couple of weeks turns an invisible failure into a visible one. Suggest
  colour-coding too, if their client supports it — it makes a misfire obvious at
  a glance.
- **Rules are not retroactive** in most clients. Mail already sitting in the
  inbox stays there. If they add a rule and then find matching spam still in the
  inbox, that is expected, not a broken rule.
- **Check back in a week.** Ask them to save anything the rules got wrong in
  either direction — spam that slipped through in one folder, real mail that got
  caught in another. Tell them to keep their rules to hand too. That is the input
  for the follow-up loop below, which is where the rules stop needing attention.

## The follow-up loop

Someone comes back after a week or two with mail the rules got wrong — spam that
slipped through, legitimate mail that got caught, or both. This is where the
rules actually get good, and it is a different job from the first pass: the
question is no longer "what patterns exist" but "which rule misbehaved and why".

Recognize it when someone says a rule caught the wrong thing, that spam is still
getting through, that they have a folder of misses, or asks you to tune what you
gave them last time.

### Get their current rules

You cannot diagnose a rule you cannot see. Ask them to describe what they have
installed, or to screenshot the rule editor. Then write the rules to a file in
this format — one rule per line:

```
Rule name | any|all | Field:string ; Field:string ; ...
```

Real example:

```
Keywords    | any | Subject:0maha ; From:WaImart ; Subject:C0STC0
IP block    | all | X-Spam-Level:**** ; Received-SPF:198.62.
```

Capture the any/all setting exactly as they have it, not as it ought to be. The
whole point is to find out what the rule is really doing.

**If they send a screenshot, do not transcribe the strings by eye.** Ask them to
copy the text out of the rule fields instead, or treat any transcribed string as
unverified. A capital I read from an image and typed back as a lowercase l turns
a working rule into a broken one in your notes, and you will then diagnose the
wrong problem.

### Run the test

```bash
python3 scripts/analyze_spam_samples.py "/path/to/folder" --rules /path/to/rules.txt
```

Run it against each folder separately — misses and false catches are different
questions. The `rule_test` section reports, per rule: how many messages it
matched, how many it *would* have matched under the opposite any/all setting,
per-condition hit counts, and which conditions never matched anything.

### Diagnosing a false catch

Work down this list; the first three are configuration faults and are the common
answers.

**A rule matches almost everything as written but almost nothing under the other
mode.** That is the ANY/ALL fault, and the report makes it unmistakable. A rule
reading `[any] matched 13 messages (as 'all' it would match 0)` is one where a
broad condition — nearly always a spam score — is running alone against all
incoming mail while the narrow conditions contribute nothing. Fix: switch to
`all`. This is by far the most common cause and the cheapest fix.

**A condition shows zero hits.** Listed under `dead_conditions`, with code points.
In an `all` rule a dead condition makes the whole rule inert. In an `any` rule it
is harmless but useless, and worth telling them about since they think it is
working.

**A spam-score condition is doing the matching.** Legitimate mail crosses spam
thresholds constantly for infrastructure reasons. Read the message's
`X-Spam-Status` header — it names the individual tests and their point values, so
you can say precisely why it scored high. `references/pattern-guide.md` has worked
examples. Fix: AND it with something specific, or raise the threshold.

**No rule matched it at all.** Then something you are not looking at caught it —
their provider's own spam filter, or a rule they forgot to mention. Say so
rather than inventing an explanation.

**A rule matched it narrowly and correctly.** The keyword was genuinely too
broad. Retire that condition and say which one.

### Diagnosing a miss

**Dead conditions first.** A keyword with zero hits against a folder of the spam
it was written for usually means it was retyped rather than copied, and the
character substitution was lost. Compare code points against the
`substitution_tokens` the analysis finds in the same folder — you will often see
`Subject:'Sampler'` scoring zero while the folder is full of `SampIer`.

**Then coverage.** `messages_matched_by_no_rule` is the real gap. Run the normal
tiered analysis on the misses folder and treat the results as a fresh first pass:
new lookalike strings, new brands, a rotated IP block.

**Expect infrastructure to have moved.** A miss folder from a campaign that is
still running will usually show a fresh IP range while the keyword patterns hold
steady. That asymmetry is the thing to point out — it is the argument for leaning
on keywords and treating IP rules as temporary.

### Close the loop

Recommend the smallest change that fixes what actually broke. Flipping one
dropdown from `any` to `all` beats rewriting a rule set. Then ask them to keep
collecting, because two rounds of this is usually enough to get the rules to a
place where they stop needing attention.

## The mistakes that actually happen

These are worth active vigilance because they are silent — the rule looks right
and does the wrong thing.

**ANY versus ALL.** Every multi-condition rule has a setting for whether all
conditions must match or any single one is enough. Set to ANY, a rule combining
"spam score above 4" with "from this IP range" fires on the spam score alone, and
the IP condition does nothing. This one is common enough that it is worth
explicitly confirming with the person after they build a multi-condition rule.
The symptom is a sudden pile of legitimate mail in the quarantine folder.

**Filtering on spam score alone.** Never recommend this as a standalone rule.
Legitimate mail scores above spam thresholds constantly, for boring infrastructure
reasons that have nothing to do with content: a shared marketing-platform IP with
a mixed reputation, a forwarded message whose SPF broke in transit, an automated
notification that trips a Bayesian filter. `references/pattern-guide.md` has the
specifics. Spam score is a good *second* condition and a bad only condition.

**The wrong field.** In most clients "From" matches the display name and the
address together, "Subject" matches only the subject. Check the report's `fields`
counts and recommend accordingly.

**Assuming a header exists.** Header-based rules only work if the person's mail
provider adds that header. If `ip_analysis.total_ipv4_messages` is far below the
message count, or `spam_score` is null on most messages, the provider is not
adding what you would need. Say so rather than recommending a rule that silently
never fires.

## Setting expectations honestly

Someone in the middle of a spam flood wants it to stop permanently. It usually
does not work that way, and saying so early is kinder than letting them discover
it.

What tends to be true: keyword rules built on character substitutions keep
working for a long time, because the substitution is the whole point of the
technique and abandoning it costs the spammer their filter evasion. IP rules
decay in weeks. Volume usually subsides on its own — these campaigns rent
infrastructure, burn it, and move to fresh targets, so being flooded is often a
temporary condition of being on a currently-circulating list rather than a
permanent state.

That last point matters for a person's peace of mind. The flood is very likely to
pass whether or not the filters are perfect.

## Reference files

- `references/pattern-guide.md` — Detail on each pattern class: what makes it
  safe or risky, why legitimate mail scores high on spam filters, how to reason
  about a pattern not covered here.
- `references/mail-clients.md` — Rule construction per client: where the settings
  live, which fields exist, how to enable raw header matching, known limitations.
- `references/known-campaign-2026-06.json` — Curated findings from a 176-message
  corpus of the June 2026 retail brand-impersonation campaign, tiered and
  annotated with per-tier decay guidance. A supplement to offer in step 6, not a
  starting point.
