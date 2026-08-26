# Mail Client Reference

How to build the recommended rules in each client, and what each one can and
cannot do.

Menu paths shift between versions. If someone reports that a menu is not where
this says it is, trust them and help them find it rather than insisting.

## Contents

- [Capability summary](#capability-summary)
- [Apple Mail](#apple-mail)
- [Thunderbird](#thunderbird)
- [Outlook (desktop)](#outlook-desktop)
- [Outlook.com and new Outlook](#outlookcom-and-new-outlook)
- [Gmail](#gmail)
- [Delivering rules to someone](#delivering-rules-to-someone)

---

## Capability summary

| Client | Subject / sender rules | Raw header rules (IP, spam score) | AND/OR control |
|---|---|---|---|
| Apple Mail | Yes | Yes, after adding headers to its list | Explicit any/all dropdown |
| Thunderbird | Yes | Yes, via Customize in the field list | Explicit any/all |
| Outlook desktop | Yes | Yes, "specific words in the message header" | Conditions combine with AND |
| Outlook.com / new Outlook | Yes | No | AND across conditions |
| Gmail | Yes | No | AND across fields, OR within a field |

The practical consequence: Tier 1 and Tier 2 keyword rules work everywhere. Tier
3 IP rules only work in the top three. For someone on Gmail or Outlook.com, lead
with keywords and mention the IP finding as background rather than a rule.

---

## Apple Mail

**Where:** Mail → Settings (or Preferences) → Rules → Add Rule.

**The any/all dropdown is at the top** — "If [any|all] of the following
conditions are met". This is the single most consequential control in the dialog.
`all` means AND, `any` means OR.

A rule with `any` and two conditions is really two independent rules. Combining
"spam score above threshold" with "from this IP range" under `any` means the spam
score condition fires alone on every incoming message, and legitimate mail with a
high score gets caught while the IP condition contributes nothing. This is worth
confirming explicitly after someone builds a multi-condition rule — the symptom
is a sudden pile of real mail in the quarantine folder.

Keyword rules with several unrelated strings *should* use `any`, since each
string is independently sufficient. IP-plus-score rules must use `all`. If
someone is building both kinds, they need two separate rules, and mixing them
into one is what produces the failure above.

**Adding headers not in the default list:** open the condition dropdown and
scroll to the bottom for **Edit Header List…**, then add the header names. Useful
ones:

```
X-Spam-Level
Received-SPF
DKIM-Signature
Authentication-Results
X-Spam-Status
```

Once added they appear in the dropdown alongside From and Subject.

**Field behaviour:**

- **From** matches the display name and the address together, so a rule on
  `0maha` catches `0maha Beef <mahabeef@example.com>`.
- **Subject** matches only the subject.
- **Received-SPF** contains `client-ip=`, so a "contains" match on `198.62.`
  catches any sender in that range.
- **X-Spam-Level** is a row of asterisks, one per point. **Apple Mail treats
  these as literal characters, not wildcards** — `****` means "four or more
  asterisks somewhere in the value", which is exactly the threshold test wanted.

**Actions:** Move Message → to a folder, and Set Color are the useful pair. A
coloured quarantine folder makes a misfire visible on a glance rather than
discovered weeks later.

**Rules are not retroactive.** They run on incoming mail. Anything already in the
inbox stays put — this reliably confuses people who add a rule and then find
matching spam still sitting there. To apply manually: select the messages and use
Message → Apply Rules.

**Example — keyword rule (any):**

```
Description: Spam keywords
If [any] of the following conditions are met:
  Subject  contains  0maha
  From     contains  0maha
  Subject  contains  C0STC0
  Subject  contains  Menbership
  Subject  contains  SampIer
  From     contains  WaImart
Perform: Move Message to mailbox: Junk-Review
         Set Color of background: Yellow
```

**Example — IP plus score rule (all):**

```
Description: Spam IP block 198.62
If [all] of the following conditions are met:
  X-Spam-Level   contains  ****
  Received-SPF   contains  198.62.
Perform: Move Message to mailbox: Junk-Review
         Set Color of background: Orange
```

---

## Thunderbird

**Where:** Tools → Message Filters → New. Per-account, so make sure the right
account is selected.

**Arbitrary headers:** the field dropdown ends with **Customize…**, where header
names can be added. Same list as Apple Mail above.

**Matching mode:** "Match all of the following" / "Match any of the following"
radio buttons at the top. Same AND/OR consequences as Apple Mail.

**Retroactive:** Thunderbird can run filters on an existing folder — select the
folder, then Tools → Run Filters on Folder. More convenient than most clients for
testing a rule against mail already collected.

---

## Outlook (desktop)

**Where:** File → Manage Rules & Alerts → New Rule → "Apply rule on messages I
receive". Wording varies by version.

**Raw headers:** the condition list includes **"with specific words in the
message header"**, which matches against the full header block. This is how IP
and spam-score rules get built — it will match `client-ip=198.62.` anywhere in
the headers.

Note the distinction from "with specific words in the subject" and "with specific
words in the sender's address", which are separate conditions.

**AND/OR:** conditions selected within a single rule combine with AND. For OR
behaviour across several keywords, put multiple words into one condition's word
list — a single condition with several words matches if *any* of them appear —
or create separate rules.

**Retroactive:** the rules dialog has a "Run Rules Now" option that applies a
rule to an existing folder.

---

## Outlook.com and new Outlook

**Where:** Settings → Mail → Rules → Add new rule.

**Limitation:** no raw header access. Conditions cover From, To, Subject, body
keywords, attachments, importance, and similar. IP and spam-score rules are not
available.

For someone here, recommend keyword rules only and explain that header-level
filtering needs desktop Outlook or a different client. Do not hand over an IP
rule they cannot build.

---

## Gmail

**Where:** Settings → See all settings → Filters and Blocked Addresses → Create a
new filter. Also reachable from the search box's filter icon.

**Fields:** From, To, Subject, Has the words, Doesn't have the words, Size, Has
attachment.

**Limitation:** consumer Gmail cannot filter on arbitrary headers. There is no
way to express "sending IP is in this range" or "spam score above four". Google
Workspace administrators have more capability through admin-level content
compliance rules, but that is an admin feature, not a user one.

**What works well:** keyword filters. The "Has the words" field accepts search
operators, and `OR` plus braces let several strings share one filter:

```
subject:(0maha OR C0STC0 OR Menbership OR SampIer)
```

Braces are equivalent to OR in Gmail syntax: `subject:{0maha C0STC0 Menbership}`.

Fields combine with AND, so From and Subject in the same filter both have to
match.

**Character substitutions work fine here** as long as the strings are pasted
rather than typed. Gmail search is case-insensitive, which does not affect these
rules — `SampIer` and `sampier` differ in a character identity, not case.

**Actions:** "Skip the Inbox (Archive it)" plus "Apply the label" is the
quarantine equivalent. Prefer that over "Delete it", which sends matches to Trash
and auto-purges after 30 days. Avoid "Never send it to Spam" here — that is the
opposite of the intent.

**Retroactive:** the final screen has "Also apply filter to matching
conversations", which applies to existing mail. Gmail is unusually good at this.

---

## Delivering rules to someone

Put each string on its own line in a code block, so it can be copied cleanly one
at a time without picking up surrounding prose:

```
0maha
C0STC0
Menbership
SampIer
```

State the field for each. A token that only ever appeared in a sender display
name is wasted as a Subject rule, and the analysis report's `fields` counts say
which is which.

**Say explicitly that the strings must be copied, not retyped.** For Tier 1
findings this is not a stylistic preference — `SampIer` and `Sampler` are
indistinguishable on screen, and a retyped rule fails in both directions at once:
it stops matching the spam and starts matching real mail. This is worth one
sentence every time.
