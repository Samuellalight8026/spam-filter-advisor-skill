# Spam Filter Advisor

**A Claude skill that turns a folder of saved spam into mail filter rules — ranked honestly by
how likely each one is to catch real mail.**

[![Download the skill](https://img.shields.io/badge/Download%20the%20skill-SpamFilterAdvisor%2Eskill-2ea44f?style=for-the-badge)](https://github.com/idea2go2go/spam-filter-advisor-skill/raw/main/SpamFilterAdvisor.skill)

---

For the kind of spam you can't unsubscribe from — because the unsubscribe link is part of the
scam.

Save 30 to 50 recent examples into a folder, point Claude at it, and get back filter rules you
can actually install: exact strings, the exact field to match, and a straight answer about what
each rule might cost you. (The analyzer needs at least 15 messages before frequency counts and
IP clustering mean anything; 30 to 50 gives comfortable margin.)

The asymmetry that shapes everything here: **a filter that misses spam is an annoyance; a filter
that quietly diverts a job offer or a medical result is a real harm you may not discover for
weeks.** Those two failure modes are not symmetric, and the recommendations don't pretend they
are. When in doubt, the narrower rule wins.

## What you get back

Findings sorted by false-alarm risk rather than by how much spam they catch — because someone
who understands *why* a rule is safe can extend the reasoning later, and someone handed a flat
list cannot.

| Tier | What it is | Risk |
|---|---|---|
| **1** | Character substitutions — `0maha`, `C0STC0`, `SampIer`, `WaImart` | Effectively zero |
| **2** | Consistent misspellings — `Marriot`, `Menbership` | Very low |
| **3** | Sending IP blocks | Low, but they expire |
| **4** | DKIM selectors, spam-score patterns | Flagged, not recommended without a test |

Tier 1 works because the misspelling *is* the filter-evasion technique — no real company spells
its own name with a zero in it, and abandoning the trick would cost the spammer the evasion.
Tier 3 is honest about decay: campaigns rotate infrastructure every few weeks, so an IP rule
buys quiet weeks, not a permanent fix, and it always ships paired with a second condition so
that a reassigned block doesn't start eating a stranger's legitimate mail.

Strings come back in copy-paste blocks with an explicit instruction to copy rather than retype —
`ParceI` and `Parcel` are visually identical in almost every font, and a hand-typed rule would
match all your real FedEx mail while missing every piece of spam.

## It checks your sample before trusting it

Everything downstream assumes the folder is actually spam, so contamination gets reported
*first*, before any findings. Calibration from testing: genuine spam scores around 1% flagged,
a folder of legitimate mail scores over 90%, and anything above roughly 10% means the sample is
mixed and the patterns are unreliable.

It also knows one specific trap — offering your existing "these got caught by mistake" folder as
proof a rule is safe. That folder only contains mail that already tripped a spam threshold, so
it's pre-selected for exactly the messages most likely to trip another one. A real safety test
needs a random cross-section of ordinary inbox mail.

## Tuning rules you already have

The skill works the other direction too: hand it your current rules and a folder of misses or
false catches, and it will identify which specific rule misfired and why.

```bash
python3 scripts/analyze_spam_samples.py /path/to/folder --rules current-rules.txt
```

## Your mail program matters

Apple Mail, Thunderbird, and desktop Outlook can filter on raw headers including sending IP.
Consumer Gmail essentially cannot. The skill asks which one you use before recommending anything,
and `references/mail-clients.md` carries the specifics.

## Runs locally, on your machine

`scripts/analyze_spam_samples.py` is Python standard library only — no install step, no
dependencies, no network calls. Your mail is parsed on your own machine and never uploaded
anywhere. The script does the parts that are unreliable by eye: pulling the connecting IP out
of whatever header carries it, reading half a dozen spam-score header formats, comparing
characters at the code-point level, and clustering IPs into network blocks.

## Install

**Claude desktop app / Cowork**

[**Download SpamFilterAdvisor.skill**](https://github.com/idea2go2go/spam-filter-advisor-skill/raw/main/SpamFilterAdvisor.skill), then either double-click it, or
open Claude → **Settings → Skills** and upload the file.

**Claude Code**

```
/plugin marketplace add idea2go2go/spam-filter-advisor-skill
/plugin install spam-filter-advisor@spam-filter-advisor
```

Then `/reload-plugins`. The first command registers the catalog; the second installs.

## What's in the box

| File | What it does |
|---|---|
| `SKILL.md` | The workflow Claude follows |
| `scripts/analyze_spam_samples.py` | The analyzer — stdlib only, ~1,000 lines |
| `references/pattern-guide.md` | How each pattern class behaves and what it costs |
| `references/mail-clients.md` | What Apple Mail, Gmail, Outlook, and Thunderbird can each filter on |
| `references/known-campaign-2026-06.json` | Findings from a 176-message brand-impersonation corpus, June 2026, offered as a supplement to your own samples and never as a substitute |

## License

Prose and documentation: CC BY 4.0. `analyze_spam_samples.py`: MIT. See [LICENSE](LICENSE).
© 2026 Paul Hess.
