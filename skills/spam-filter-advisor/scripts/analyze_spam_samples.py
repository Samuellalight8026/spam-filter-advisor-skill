#!/usr/bin/env python3
"""
analyze_spam_samples.py - Extract filterable patterns from a folder of .eml samples.

Reads every .eml in a folder and reports, as JSON:
  * per-message facts: sender, subject, connecting IP, spam score, DKIM selector
  * character-substitution candidates (homoglyphs) found in Subject and From
  * misspelling candidates near known brand names and common words
  * IP clustering by /24 and /16, so coordinated bursts stand out from botnet scatter
  * contamination flags: messages that look like legitimate mail, not spam

Why a script instead of eyeballing headers: the highest-value patterns in
brand-impersonation spam are character substitutions - capital I standing in for
lowercase l, digit 0 for letter O. Those are invisible to the eye in almost every
font. Only a code-point comparison can tell you which one you are looking at, and
getting it wrong in either direction produces a filter that silently does nothing
or silently eats real mail.

Stdlib only. Python 3.8+.

Usage:
    python3 analyze_spam_samples.py /path/to/folder
    python3 analyze_spam_samples.py /path/to/folder --json-out report.json
    python3 analyze_spam_samples.py /path/to/folder --quiet   # JSON only, no summary
"""

import argparse
import email
import email.header
import json
import os
import re
import sys
import unicodedata
from collections import Counter, defaultdict
from pathlib import Path

# ---------------------------------------------------------------------------
# Reference data
# ---------------------------------------------------------------------------

# Brands commonly impersonated in reward/prize/delivery phishing. Used for
# misspelling detection ("Marriot" for "Marriott") and for normalizing
# substituted spellings back to a recognizable name ("0maha" -> "omaha").
KNOWN_BRANDS = [
    "omaha", "kroger", "walmart", "costco", "lowes", "mylowes", "kobalt",
    "marriott", "hilton", "target", "cvs", "walgreens", "sams", "samsclub",
    "fedex", "ups", "usps", "dhl", "amazon", "paypal", "netflix", "apple",
    "microsoft", "google", "verizon", "att", "tmobile", "comcast", "xfinity",
    "chase", "wellsfargo", "bankofamerica", "citibank", "amex", "visa",
    "mastercard", "discover", "harborfreight", "basspro", "cabelas", "yeti",
    "homedepot", "menards", "bestbuy", "hexclad", "ring", "dyson", "traeger",
    "starbucks", "mcdonalds", "dunkin", "publix", "safeway", "wegmans",
    "instacart", "doordash", "ubereats", "grubhub", "dollargeneral",
    "temu", "shein", "wayfair", "ikea", "macys", "kohls", "nordstrom",
    "delta", "united", "southwest", "american", "hyatt", "ihg", "wyndham",
    "membership", "rewards", "points", "voucher", "sampler", "complimentary",
    "delivery", "package", "parcel", "shipment", "expire", "expiration",
]

# Ordinary English words that show up in these subject lines. Misspelling one of
# these is a strong spam tell because real marketing copy gets proofread.
COMMON_WORDS = [
    "membership", "complimentary", "complementary", "sampler", "sample",
    "voucher", "rewards", "reward", "points", "point", "expire", "expires",
    "expiring", "expiration", "still", "only", "today", "tomorrow", "tonight",
    "remaining", "remain", "left", "delivery", "delivered", "shipping",
    "shipped", "package", "parcel", "returned", "confirm", "confirmation",
    "account", "balance", "redeem", "convert", "claim", "gift", "free",
    "exclusive", "limited", "urgent", "final", "deadline", "notice",
    "customer", "member", "selected", "receive", "receiving", "thank",
]

# HELO hostname fragments belonging to large legitimate senders and ESPs.
# A message arriving through one of these is very unlikely to be part of a
# burner-domain spam campaign, so it is a contamination signal.
REPUTABLE_HELO_FRAGMENTS = [
    "google.com", "googlemail.com", "gmail.com", "amazonses.com",
    "outlook.com", "hotmail.com", "protection.outlook.com", "office365.com",
    "icloud.com", "apple.com", "me.com", "yahoo.com", "yahoodns.net",
    "sendgrid.net", "mailgun.org", "mailgun.net", "mandrillapp.com",
    "klaviyomail.com", "mcsv.net", "mcdlv.net", "mailchimp.com",
    "rsgsv.net", "constantcontact.com", "ccsend.com", "exacttarget.com",
    "salesforce.com", "mktdns.com", "marketo.com", "hubspot.com",
    "postmarkapp.com", "sparkpostmail.com", "mailjet.com", "zoho.com",
    "zohomail.com", "sendinblue.com", "brevo.com", "intercom.io",
    "atlassian.net", "slack.com", "zendesk.com", "notion.so", "dropbox.com",
    "box.com", "docusign.net", "adobe.com", "linkedin.com", "stripe.com",
    "squareup.com", "shopify.com", "bigcommerce.com", "imodules.com",
    "eclinicalmail.com", "ecwmail.com", "athenahealth.com", "epic.com",
    "paypal.com", "ebay.com", "intuit.com", "quickbooks.com",
]

# DKIM selectors used by mainstream providers and ESPs. Seeing one of these is a
# contamination signal; it is also the list to check a proposed selector-based
# rule against before recommending one.
COMMON_LEGITIMATE_SELECTORS = [
    "google", "selector1", "selector2", "s1", "s2", "k1", "k2", "k3",
    "default", "dkim", "mail", "email", "smtp", "mta1", "20230601",
    "20240101", "scph", "pm", "sm", "sig1", "sig2", "ctct1", "ctct2",
    "dkim1", "dkim2", "m1", "mailjet", "mandrill", "sendgrid", "amazonses",
    "zoho", "protonmail", "fm1", "fm2", "fm3", "def1", "mtd1",
]

# Spam-score header formats seen across providers. Each entry is
# (header name, extractor function returning a float, or None).
def _count_char_score(value, char):
    """SpamAssassin-style repeated-character scores: '****' = 4, 'ssss' = 4."""
    stripped = value.strip()
    if stripped and all(c == char for c in stripped):
        return float(len(stripped))
    return None


def _numeric_score(value):
    m = re.search(r"-?\d+(?:\.\d+)?", value)
    return float(m.group(0)) if m else None


def _spam_status_score(value):
    m = re.search(r"score=(-?\d+(?:\.\d+)?)", value, re.I)
    return float(m.group(1)) if m else None


SCORE_EXTRACTORS = [
    ("X-Spam-Level", lambda v: _count_char_score(v, "*")),
    ("X-edns-Libra-ESVA-SpamScore", lambda v: _count_char_score(v, "s")),
    ("X-Spam-Status", _spam_status_score),
    ("X-Spam-Score", _numeric_score),
    ("X-Spam-Report", _spam_status_score),
    ("X-Proofpoint-Spam-Score", _numeric_score),
    ("X-Barracuda-Spam-Score", _numeric_score),
    ("X-MS-Exchange-Organization-SCL", _numeric_score),
    ("X-Microsoft-Antispam", lambda v: None),
]


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def decode_header_value(raw):
    """Decode RFC 2047 encoded headers ('=?utf-8?B?...?=') into plain text."""
    if raw is None:
        return ""
    try:
        parts = email.header.decode_header(raw)
    except Exception:
        return str(raw)
    out = []
    for text, charset in parts:
        if isinstance(text, bytes):
            try:
                out.append(text.decode(charset or "utf-8", errors="replace"))
            except (LookupError, TypeError):
                out.append(text.decode("utf-8", errors="replace"))
        else:
            out.append(text)
    return "".join(out)


def levenshtein(a, b, cap=3):
    """Edit distance with an early bail-out once it exceeds `cap`."""
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        if min(cur) > cap:
            return cap + 1
        prev = cur
    return prev[-1]


TOKEN_RE = re.compile(r"[^\s\-_/\\,;:()\[\]{}<>\"!?.]+")


def tokenize(text):
    """Split on whitespace and punctuation but keep word-internal characters,
    so 'SampIer' stays intact while '1,256.00' breaks into harmless numbers.

    Apostrophes stay attached ("MyLowe's" stays one token) because splitting
    them off manufactures fake misspellings - a bare "MyLowe" looks like a
    truncation of "MyLowes" when nothing was actually misspelled."""
    return [t.strip("'") for t in TOKEN_RE.findall(text or "") if t.strip("'")]


# ---------------------------------------------------------------------------
# Character-substitution (homoglyph) detection
# ---------------------------------------------------------------------------

# Maps a substituted character to what it is standing in for.
SUBSTITUTION_MAP = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "6": "g",
    "7": "t", "8": "b", "9": "g", "@": "a", "$": "s",
    "I": "l", "l": "i", "O": "0", "|": "l",
}

# Non-ASCII characters that render nearly identically to a Latin letter. These
# are the nastiest variety because the word looks perfectly spelled.
UNICODE_CONFUSABLES = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "у": "y", "х": "x", "А": "A", "Е": "E", "О": "O",
    "Р": "P", "С": "C", "У": "Y", "Х": "X", "М": "M",
    "Н": "H", "К": "K", "В": "B", "І": "I", "і": "i",
    "ο": "o", "α": "a", "ε": "e", "ρ": "p", "ν": "v",
    "Ο": "O", "Α": "A", "Β": "B", "Ε": "E", "Η": "H",
    "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ρ": "P",
    "Τ": "T", "Χ": "X", "‐": "-", "–": "-", "—": "-",
}


# Only the one-way, unambiguous folds. Deliberately excludes 'l' -> 'i' and
# 'O' -> '0', which are the reverse direction: applying those would rewrite
# correctly spelled words ('Walmart' -> 'waimart') and make every real brand
# name look like a misspelling of itself.
UNAMBIGUOUS_FOLDS = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "6": "g",
    "7": "t", "8": "b", "9": "g", "@": "a", "$": "s", "|": "l",
}


def normalize_token(token):
    """Fold substituted characters back to their intended letters, so a
    normalized token can be matched against a real word or brand name.

    Two deliberate asymmetries here, both learned the hard way:

    The folds run one direction only. A digit 0 inside a word is almost
    certainly standing in for an 'o', but a letter 'l' is usually just an 'l'.
    Folding both ways would put every correctly spelled word one edit from
    itself and bury the real findings.

    Capital I folds to 'l' only when a lowercase letter sits beside it. In an
    all-caps word like DELIVERY the capital I is simply a capital I, and folding
    it unconditionally would turn a perfectly normal subject line into an
    apparent misspelling."""
    out = []
    for i, ch in enumerate(token):
        if ch in UNICODE_CONFUSABLES:
            out.append(UNICODE_CONFUSABLES[ch].lower())
        elif ch in UNAMBIGUOUS_FOLDS:
            out.append(UNAMBIGUOUS_FOLDS[ch])
        elif ch == "I":
            neighbors = []
            if i > 0:
                neighbors.append(token[i - 1])
            if i < len(token) - 1:
                neighbors.append(token[i + 1])
            out.append("l" if any(n.islower() for n in neighbors) else "i")
        else:
            out.append(ch.lower())
    return "".join(out)


def find_substitutions(text, field_name):
    """Scan one header value for character-substitution tricks.

    Returns a list of findings, each recording the exact token, the code points
    involved, and which rule fired. The code points matter: the recommendation
    that comes out of this has to be copied, not retyped, and the user needs to
    be able to see that 'ParceI' and 'Parcel' are genuinely different strings."""
    findings = []
    for token in tokenize(text):
        if len(token) < 3:
            continue
        if token.isdigit():
            continue

        reasons = []

        # Rule 1: a non-ASCII character sitting inside an otherwise-Latin word.
        confusable_chars = [c for c in token if c in UNICODE_CONFUSABLES]
        if confusable_chars and any(c.isascii() and c.isalpha() for c in token):
            names = [f"{c!r} (U+{ord(c):04X}, {unicodedata.name(c, 'unknown')})"
                     for c in confusable_chars]
            reasons.append("non-ASCII lookalike character: " + "; ".join(names))

        # Rule 2: a digit pressed up against letters inside one word
        # ('0maha', 'K0BALT', '5OO'). Numbers standing alone are already gone,
        # since tokenizing split '1,256.00' into pure-digit chunks.
        for i, ch in enumerate(token):
            if ch.isdigit():
                neighbors = []
                if i > 0:
                    neighbors.append(token[i - 1])
                if i < len(token) - 1:
                    neighbors.append(token[i + 1])
                if any(n.isalpha() and n.isascii() for n in neighbors):
                    reasons.append(
                        f"digit {ch!r} (U+{ord(ch):04X}) adjacent to letters - "
                        f"likely standing in for {SUBSTITUTION_MAP.get(ch, '?')!r}"
                    )
                    break

        # Rule 3: a capital I mid-word with lowercase letters beside it. This is
        # the single most common trick in brand-impersonation subject lines and
        # the one no human reader will ever catch unaided.
        for i, ch in enumerate(token):
            if ch == "I" and i > 0:
                neighbors = [token[i - 1]]
                if i < len(token) - 1:
                    neighbors.append(token[i + 1])
                if any(n.islower() for n in neighbors):
                    reasons.append(
                        "capital 'I' (U+0049) mid-word beside lowercase letters - "
                        "almost certainly standing in for lowercase 'l' (U+006C)"
                    )
                    break

        # Rule 4: a capital O wedged among digits ('5OO', '1OO').
        for i, ch in enumerate(token):
            if ch == "O":
                neighbors = []
                if i > 0:
                    neighbors.append(token[i - 1])
                if i < len(token) - 1:
                    neighbors.append(token[i + 1])
                if any(n.isdigit() for n in neighbors):
                    reasons.append(
                        "capital 'O' (U+004F) adjacent to digits - "
                        "likely standing in for digit '0' (U+0030)"
                    )
                    break

        if not reasons:
            continue

        normalized = normalize_token(token)
        brand_match = None
        for brand in KNOWN_BRANDS:
            if brand in normalized or normalized in brand:
                brand_match = brand
                break

        findings.append({
            "field": field_name,
            "token": token,
            "code_points": " ".join(f"U+{ord(c):04X}" for c in token),
            "normalized": normalized,
            "resembles": brand_match,
            "reasons": reasons,
        })
    return findings


# Ordinary English words that sit one edit away from something in the
# vocabulary and would otherwise be reported as misspellings forever.
MISSPELLING_STOPLIST = {
    "thanks", "thank", "shopping", "shipping", "confirms", "confirmed",
    "expiry", "expires", "expired", "points", "point", "cards", "card",
    "hours", "hour", "tonight", "tomorrow", "orders", "order", "offers",
    "offer", "deals", "deal", "items", "item", "store", "stores", "value",
    "values", "prize", "prizes", "bonus", "extra", "notice", "update",
    "updates", "alert", "alerts", "please", "before", "after", "still",
    "there", "their", "these", "those", "where", "which", "while", "about",
}

# Suffixes that turn a vocabulary word into an ordinary inflected form rather
# than a misspelling. "confirms" is not a typo for "confirm".
INFLECTIONS = ("s", "es", "ed", "d", "ing", "er", "ers", "y", "ly", "'s")


def find_misspellings(text, field_name):
    """Flag tokens one edit away from a known brand or common word.

    Real marketing copy from a real company gets proofread, so a consistent
    misspelling across many messages is a campaign fingerprint rather than
    noise. The value is in consistency: a brand name misspelled the same way in
    forty messages is a free filter, because the real company never sends mail
    that way.

    Brand misspellings are separated from common-word misspellings because they
    carry very different false-positive risk. Nobody legitimately writes
    "Marriot"; plenty of people legitimately write slightly odd English."""
    findings = []
    brands = set(KNOWN_BRANDS)
    vocabulary = brands | set(COMMON_WORDS)

    for token in tokenize(text):
        if len(token) < 5:
            continue
        low = re.sub(r"[^a-z]", "", normalize_token(token))
        if not low or low in vocabulary or low in MISSPELLING_STOPLIST:
            continue

        # Skip ordinary inflected forms of vocabulary words.
        if any(low.endswith(suf) and low[: -len(suf)] in vocabulary
               for suf in INFLECTIONS):
            continue

        best = None
        for word in vocabulary:
            if abs(len(low) - len(word)) > 1 or len(word) < 5:
                continue
            if levenshtein(low, word, cap=1) == 1:
                # Prefer a brand match; it is the more actionable finding.
                if best is None or (word in brands and best not in brands):
                    best = word
        if best:
            findings.append({
                "field": field_name,
                "token": token,
                "resembles": best,
                "kind": "brand" if best in brands else "common-word",
                "edit_distance": 1,
            })
    return findings


# ---------------------------------------------------------------------------
# Per-message extraction
# ---------------------------------------------------------------------------

RECEIVED_IP_RE = re.compile(r"\[?(\d{1,3}(?:\.\d{1,3}){3})\]?")
CLIENT_IP_RE = re.compile(r"client-ip=([0-9a-fA-F:.]+)", re.I)
HELO_RE = re.compile(r"helo=([^\s;]+)", re.I)
SELECTOR_RE = re.compile(r"\bs=([A-Za-z0-9_.-]+)", re.I)
AUTH_SELECTOR_RE = re.compile(r"header\.s=([A-Za-z0-9_.-]+)", re.I)


def extract_connecting_ip(msg):
    """Prefer Received-SPF's client-ip. Fall back to the last Received header,
    which is the earliest hop and therefore closest to the true sender."""
    spf = msg.get("Received-SPF", "")
    m = CLIENT_IP_RE.search(spf or "")
    if m:
        return m.group(1), "Received-SPF client-ip"

    received = msg.get_all("Received") or []
    if received:
        for candidate in reversed(received):
            for ip in RECEIVED_IP_RE.findall(candidate):
                if not ip.startswith(("127.", "10.", "192.168.", "0.")):
                    return ip, "earliest Received header"
    return None, None


def extract_spam_score(msg):
    for header, extractor in SCORE_EXTRACTORS:
        value = msg.get(header)
        if value is None:
            continue
        score = extractor(value)
        if score is not None:
            return {"header": header, "raw": value.strip()[:80], "score": score}
    return None


def extract_dkim_selector(msg):
    auth = " ".join(msg.get_all("Authentication-Results") or [])
    m = AUTH_SELECTOR_RE.search(auth)
    if m:
        return m.group(1)
    sig = msg.get("DKIM-Signature", "")
    m = SELECTOR_RE.search(sig or "")
    return m.group(1) if m else None


def parse_message(path):
    with open(path, "rb") as fh:
        msg = email.message_from_binary_file(fh)

    subject = decode_header_value(msg.get("Subject"))
    from_raw = decode_header_value(msg.get("From"))
    reply_to = decode_header_value(msg.get("Reply-To"))
    to_addr = decode_header_value(msg.get("To"))

    # Split "Display Name <addr@domain>" into its two halves; the display name
    # is where impersonation shows up and is a separate filter target from the
    # address itself in most mail clients.
    m = re.match(r"\s*(.*?)\s*<([^>]+)>\s*$", from_raw)
    if m:
        from_display, from_addr = m.group(1).strip().strip('"'), m.group(2).strip()
    else:
        from_display, from_addr = "", from_raw.strip()

    from_domain = from_addr.split("@")[-1].lower() if "@" in from_addr else ""
    ip, ip_source = extract_connecting_ip(msg)
    helo_match = HELO_RE.search(msg.get("Received-SPF", "") or "")
    helo = helo_match.group(1).lower() if helo_match else ""

    # Keep the raw header block for rule testing. Stripped before serializing.
    raw_headers = {}
    for key in msg.keys():
        vals = msg.get_all(key) or []
        raw_headers.setdefault(key.lower(), []).extend(str(v) for v in vals)

    record = {
        "_headers": raw_headers,
        "file": os.path.basename(path),
        "subject": subject,
        "from_display": from_display,
        "from_address": from_addr,
        "from_domain": from_domain,
        "reply_to": reply_to,
        "to": to_addr,
        "date": decode_header_value(msg.get("Date")),
        "connecting_ip": ip,
        "ip_source": ip_source,
        "helo": helo,
        "spam_score": extract_spam_score(msg),
        "dkim_selector": extract_dkim_selector(msg),
        "has_list_unsubscribe": bool(msg.get("List-Unsubscribe")),
        "reply_to_equals_from": bool(reply_to) and reply_to.strip() == from_raw.strip(),
        "substitutions": (find_substitutions(subject, "Subject")
                          + find_substitutions(from_display, "From")),
        "misspellings": (find_misspellings(subject, "Subject")
                         + find_misspellings(from_display, "From")),
    }
    return record


# ---------------------------------------------------------------------------
# Contamination detection
# ---------------------------------------------------------------------------

def assess_contamination(record, spam_threshold):
    """Decide whether a message looks like it does not belong in a spam folder.

    Getting this wrong in the permissive direction is the expensive mistake: one
    legitimate newsletter in the pile can suggest a keyword that then eats a
    whole category of the user's real mail. So the signals here are deliberately
    ordinary things - a recognizable sending platform, a normal DKIM selector,
    an absent or low spam score - rather than anything clever."""
    strong, weak = [], []

    score_info = record.get("spam_score")
    if score_info is None:
        strong.append("no spam-score header at all - the mail server never flagged it")
    elif spam_threshold is not None and score_info["score"] < spam_threshold:
        strong.append(
            f"spam score {score_info['score']:g} is below the {spam_threshold:g} "
            f"threshold seen across the rest of the folder"
        )

    helo = record.get("helo") or ""
    for fragment in REPUTABLE_HELO_FRAGMENTS:
        if fragment in helo or (record.get("from_domain", "").endswith(fragment)):
            strong.append(f"arrived through {fragment}, a mainstream sending platform")
            break

    selector = (record.get("dkim_selector") or "").lower()
    if selector and selector in COMMON_LEGITIMATE_SELECTORS:
        weak.append(f"DKIM selector '{selector}' is a standard one used by real senders")

    if not record["substitutions"] and not record["misspellings"]:
        weak.append("no character substitutions or misspellings in subject or sender")

    # The bar is at least one strong signal plus a second signal of any kind.
    #
    # The strong/weak split matters because the weak signals are absence-of-
    # evidence: "no lookalike characters" and "ordinary DKIM selector" are both
    # true of any spam genre that simply doesn't use homoglyph tricks - fake
    # invoices, crypto pitches, credential phishing. Counting two weak signals as
    # contamination flagged an entire folder of genuine spam as legitimate. A
    # strong signal is positive evidence that a real sender is behind the
    # message, which is what the caller actually needs to know.
    if strong and len(strong) + len(weak) >= 2:
        return strong + weak
    return []


# ---------------------------------------------------------------------------
# Rule testing (the follow-up loop)
# ---------------------------------------------------------------------------

def parse_rules_file(path):
    """Read a rules file describing filters the user already has installed.

    One rule per line:

        Rule name | any|all | Field:string ; Field:string ; ...

    Lines beginning with # are comments. Example:

        Keywords   | any | Subject:0maha ; From:WaImart ; Subject:C0STC0
        IP block   | all | X-Spam-Level:**** ; Received-SPF:198.62.

    The any/all token is not decoration. It is the setting that most often makes
    a rule behave differently than its author intended, and testing a rule
    without it would miss the most common real-world failure."""
    rules = []
    for lineno, line in enumerate(Path(path).read_text().splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 3:
            print(f"Skipping malformed rule on line {lineno}: {line}", file=sys.stderr)
            continue
        name, mode, conds_raw = parts[0], parts[1].lower(), "|".join(parts[2:])
        if mode not in ("any", "all"):
            print(f"Line {lineno}: mode must be 'any' or 'all', got {mode!r}",
                  file=sys.stderr)
            continue
        conditions = []
        for cond in conds_raw.split(";"):
            cond = cond.strip()
            if not cond or ":" not in cond:
                continue
            field, _, needle = cond.partition(":")
            conditions.append({"field": field.strip(), "needle": needle.strip()})
        if conditions:
            rules.append({"name": name, "mode": mode, "conditions": conditions})
    return rules


# Which record fields a rule field name should be tested against. Mirrors how
# mail clients behave: "From" matches the display name and the address together,
# "Subject" matches only the subject.
FIELD_SOURCES = {
    "from": lambda r: [r["from_display"], r["from_address"]],
    "to": lambda r: [r["to"]],
    "subject": lambda r: [r["subject"]],
    "reply-to": lambda r: [r["reply_to"]],
}


def condition_matches(record, field, needle):
    """Case-insensitive substring test, matching how mail clients evaluate
    'contains'.

    Case folding is safe for character-substitution strings and does not blunt
    them: a capital I folds to 'i' while a lowercase l stays 'l', so 'SampIer'
    still fails to match 'Sampler'. The distinction being tested is character
    identity, not case."""
    needle_l = needle.lower()
    key = field.lower()

    if key in FIELD_SOURCES:
        haystacks = FIELD_SOURCES[key](record)
    else:
        haystacks = record.get("_headers", {}).get(key, [])

    return any(needle_l in (h or "").lower() for h in haystacks)


def test_rules(records, rules):
    """Evaluate each rule against every message.

    Reports, per rule, what it matches as written and what it would match under
    the opposite any/all setting. That comparison is the point: a rule set to
    'any' that matches far more than the same rule set to 'all' is the classic
    misconfiguration, where one broad condition runs loose and the narrow
    conditions contribute nothing."""
    results = []
    matched_any_rule = set()

    for rule in rules:
        per_condition = []
        matched_files = []
        would_match_other_mode = 0

        for cond in rule["conditions"]:
            hits = [r["file"] for r in records
                    if condition_matches(r, cond["field"], cond["needle"])]
            per_condition.append({
                "field": cond["field"],
                "needle": cond["needle"],
                "code_points": " ".join(f"U+{ord(c):04X}" for c in cond["needle"]),
                "matches": len(hits),
            })

        for r in records:
            flags = [condition_matches(r, c["field"], c["needle"])
                     for c in rule["conditions"]]
            as_written = all(flags) if rule["mode"] == "all" else any(flags)
            as_other = any(flags) if rule["mode"] == "all" else all(flags)
            if as_written:
                matched_files.append(r["file"])
                matched_any_rule.add(r["file"])
            if as_other:
                would_match_other_mode += 1

        dead = [c for c in per_condition if c["matches"] == 0]
        results.append({
            "name": rule["name"],
            "mode": rule["mode"],
            "matched": len(matched_files),
            "matched_files": matched_files[:20],
            "conditions": per_condition,
            "dead_conditions": [f"{c['field']}:{c['needle']}" for c in dead],
            "would_match_as_%s" % ("any" if rule["mode"] == "all" else "all"):
                would_match_other_mode,
        })

    unmatched = [r["file"] for r in records if r["file"] not in matched_any_rule]
    return {
        "rules": results,
        "messages_matched_by_no_rule": len(unmatched),
        "unmatched_files": unmatched[:40],
    }


def print_rule_results(rt):
    print("--- EXISTING RULE TEST ---")
    for r in rt["rules"]:
        other_key = next(k for k in r if k.startswith("would_match_as_"))
        other_mode = other_key.rsplit("_", 1)[1]
        print(f"  {r['name']!r} [{r['mode']}] matched {r['matched']} messages "
              f"(as '{other_mode}' it would match {r[other_key]})")
        for c in r["conditions"]:
            flag = "  <-- never matches" if c["matches"] == 0 else ""
            print(f"      {c['field']}:{c['needle']!r}  {c['matches']} hits{flag}")
            if c["matches"] == 0:
                print(f"          {c['code_points']}")
    print(f"\n  Messages matched by no rule: {rt['messages_matched_by_no_rule']}")
    for f in rt["unmatched_files"][:10]:
        print(f"      {f}")
    print()


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------

def cluster_ips(records):
    """Group sending IPs by /24 and /16.

    The shape of this distribution decides whether an IP-based rule is worth
    writing at all. A handful of /24s covering most of the folder means a
    coordinated burst off rented infrastructure, and one or two rules will catch
    a lot. Fifteen /24s across fifteen messages means a distributed botnet, and
    no list of IP rules will ever keep pace with it."""
    slash24 = Counter()
    slash16 = Counter()
    for r in records:
        ip = r.get("connecting_ip")
        if not ip or ":" in ip:
            continue
        parts = ip.split(".")
        if len(parts) != 4:
            continue
        slash24[".".join(parts[:3]) + ".x"] += 1
        slash16[".".join(parts[:2]) + ".x.x"] += 1

    total = sum(slash24.values())
    return {
        "total_ipv4_messages": total,
        "distinct_slash24": len(slash24),
        "distinct_slash16": len(slash16),
        "by_slash24": [
            {"block": b, "count": c, "share": round(c / total, 3) if total else 0}
            for b, c in slash24.most_common()
        ],
        "by_slash16": [
            {"block": b, "count": c, "share": round(c / total, 3) if total else 0}
            for b, c in slash16.most_common()
        ],
        "concentration_note": _describe_concentration(slash24, slash16, total),
    }


def _describe_concentration(slash24, slash16, total):
    if total == 0:
        return "No IPv4 sending addresses could be extracted from these messages."
    top16_share = slash16.most_common(1)[0][1] / total if slash16 else 0
    ratio = len(slash24) / total
    if top16_share >= 0.6:
        return (
            f"Concentrated: {top16_share:.0%} of messages come from a single /16. "
            "This looks like a coordinated burst from rented infrastructure, and a "
            "single IP-prefix rule would catch most of it."
        )
    if ratio >= 0.7:
        return (
            f"Scattered: {len(slash24)} distinct /24 blocks across {total} messages. "
            "This looks like a distributed botnet. IP rules will age out within days "
            "and are not worth chasing here."
        )
    return (
        f"Mixed: {len(slash24)} distinct /24 blocks across {total} messages, "
        "largest /16 covering {:.0%}. Some clustering, but expect partial coverage."
        .format(top16_share)
    )


def aggregate_tokens(records, key):
    """Count how often each suspicious token appears, and in which field.

    Frequency is what separates a rule worth writing from a one-off curiosity: a
    token appearing in one message out of forty buys almost nothing, while one
    appearing in half of them is a real lever."""
    buckets = defaultdict(lambda: {"count": 0, "fields": Counter(), "files": [],
                                   "detail": None})
    for r in records:
        seen_in_message = set()
        for finding in r[key]:
            token = finding["token"]
            marker = (token, finding["field"])
            if marker in seen_in_message:
                continue
            seen_in_message.add(marker)
            bucket = buckets[token]
            bucket["count"] += 1
            bucket["fields"][finding["field"]] += 1
            if len(bucket["files"]) < 5:
                bucket["files"].append(r["file"])
            if bucket["detail"] is None:
                bucket["detail"] = finding

    out = []
    for token, data in buckets.items():
        entry = {
            "token": token,
            "message_count": data["count"],
            "fields": dict(data["fields"]),
            "example_files": data["files"],
        }
        entry.update({k: v for k, v in (data["detail"] or {}).items()
                      if k not in ("field", "token")})
        out.append(entry)
    out.sort(key=lambda e: (-e["message_count"], e["token"]))
    return out


def infer_spam_threshold(records):
    """Guess the spam-score cutoff this mail server is using.

    SpamAssassin's default is 5.0 but providers routinely lower it, and the
    X-Spam-Status header often states the actual value. Reading it beats
    assuming it, because a filter built around the wrong threshold either
    over-matches or never fires."""
    for r in records:
        info = r.get("spam_score")
        if info and info["header"] == "X-Spam-Status":
            m = re.search(r"required=(-?\d+(?:\.\d+)?)", info["raw"], re.I)
            if m:
                return float(m.group(1))
    scores = [r["spam_score"]["score"] for r in records if r.get("spam_score")]
    if not scores:
        return None
    return float(min(scores))


def analyze(folder, rules_path=None):
    folder = Path(folder)
    paths = sorted(p for p in folder.glob("*.eml") if p.is_file())
    if not paths:
        return {"error": f"No .eml files found in {folder}"}

    records, failures = [], []
    for path in paths:
        try:
            records.append(parse_message(path))
        except Exception as exc:  # keep going; one bad file should not stop the run
            failures.append({"file": path.name, "error": str(exc)})

    threshold = infer_spam_threshold(records)

    clean, suspect = [], []
    for r in records:
        signals = assess_contamination(r, threshold)
        if signals:
            r["contamination_signals"] = signals
            suspect.append(r)
        else:
            clean.append(r)

    recipients = Counter(r["to"] for r in records if r["to"])
    selectors = Counter(r["dkim_selector"] for r in records if r["dkim_selector"])
    from_domains = Counter(r["from_domain"] for r in records if r["from_domain"])
    tlds = Counter(d.rsplit(".", 1)[-1] for d in from_domains if "." in d)

    # Selector prefix analysis: campaigns often provision selectors from one
    # template, so a shared prefix across otherwise-unrelated domains is a
    # fingerprint. Whether it is *safe* to filter on is a separate question that
    # depends on the user's own legitimate mail - flagged, not recommended.
    selector_prefixes = Counter()
    for sel in selectors:
        if len(sel) >= 4:
            selector_prefixes[sel[:3].lower()] += 1

    # Rule testing runs against every message, contaminated or not. When the
    # folder is "mail my filters caught by mistake", the contaminated messages
    # ARE the subject of the investigation.
    rule_test = None
    if rules_path:
        rule_test = test_rules(records, parse_rules_file(rules_path))

    report = {
        "folder": str(folder),
        "message_count": len(records),
        "parse_failures": failures,
        "inferred_spam_threshold": threshold,
        "sample_size_note": _sample_size_note(len(clean)),
        "contamination": {
            "suspect_count": len(suspect),
            "suspect_share": round(len(suspect) / len(records), 3) if records else 0,
            "messages": [
                {
                    "file": r["file"],
                    "subject": r["subject"][:100],
                    "from": r["from_address"],
                    "signals": r["contamination_signals"],
                }
                for r in suspect
            ],
        },
        "recipients": [{"address": a, "count": c} for a, c in recipients.most_common()],
        # Coverage is computed over every message, not just the clean ones, so
        # "the provider isn't adding this header" stays a safe inference even
        # when contamination filtering has emptied the clean set.
        "header_coverage": {
            "messages_with_connecting_ip": sum(1 for r in records if r["connecting_ip"]),
            "messages_with_spam_score": sum(1 for r in records if r["spam_score"]),
            "total_messages": len(records),
        },
        "ip_analysis": cluster_ips(clean if clean else records),
        "substitution_tokens": aggregate_tokens(clean, "substitutions"),
        "misspelling_tokens": aggregate_tokens(clean, "misspellings"),
        "dkim_selectors": {
            "distinct_count": len(selectors),
            "shared_prefixes": [
                {"prefix": p, "distinct_selectors": c}
                for p, c in selector_prefixes.most_common(5) if c > 1
            ],
            "examples": [s for s, _ in selectors.most_common(10)],
        },
        "from_domains": {
            "distinct_count": len(from_domains),
            "top_tlds": [{"tld": t, "count": c} for t, c in tlds.most_common(10)],
        },
        "structural_traits": {
            "reply_to_equals_from": sum(1 for r in clean if r["reply_to_equals_from"]),
            "has_list_unsubscribe": sum(1 for r in clean if r["has_list_unsubscribe"]),
        },
        "messages": clean,
    }

    if rule_test is not None:
        report["rule_test"] = rule_test

    # Raw headers were only needed for rule matching; they would bloat the JSON.
    for r in records:
        r.pop("_headers", None)

    return report


def _sample_size_note(n):
    if n < 5:
        return ("Very small sample. Any pattern found here could easily be "
                "coincidence. Treat every recommendation as provisional and "
                "collect more examples before building rules around them.")
    if n < 15:
        return ("Small sample. Character-substitution findings are still "
                "trustworthy because they are self-evidently deliberate, but "
                "frequency counts and IP clustering are not yet reliable.")
    if n < 30:
        return ("Below the recommended 30-50 range. Usable, but treat frequency "
                "counts and IP clustering as provisional; character-substitution "
                "findings remain trustworthy. More samples would firm these up.")
    return "Sample size is adequate for both pattern and frequency analysis."


# ---------------------------------------------------------------------------
# Human-readable summary
# ---------------------------------------------------------------------------

def print_summary(report):
    if "error" in report:
        print(report["error"], file=sys.stderr)
        return

    print(f"\n{'=' * 70}")
    print(f"  {report['message_count']} messages analyzed from {report['folder']}")
    print(f"{'=' * 70}\n")
    print(report["sample_size_note"], "\n")

    cont = report["contamination"]
    if cont["suspect_count"]:
        print(f"--- POSSIBLE NON-SPAM ({cont['suspect_count']} of "
              f"{report['message_count']}, {cont['suspect_share']:.0%}) ---")
        for m in cont["messages"]:
            print(f"  * {m['file']}")
            print(f"      from: {m['from']}")
            for s in m["signals"]:
                print(f"      - {s}")
        print("  These are excluded from the pattern analysis below.\n")
    else:
        print("--- No obviously legitimate mail detected in this folder ---\n")

    subs = report["substitution_tokens"]
    if subs:
        print(f"--- CHARACTER SUBSTITUTIONS ({len(subs)} distinct) ---")
        for s in subs[:25]:
            fields = "/".join(s["fields"])
            resembles = f"  ~ {s['resembles']}" if s.get("resembles") else ""
            print(f"  {s['token']!r}  x{s['message_count']}  [{fields}]{resembles}")
            print(f"      {s['code_points']}")
        print()

    miss = report["misspelling_tokens"]
    if miss:
        print(f"--- MISSPELLINGS ({len(miss)} distinct) ---")
        for m in miss[:20]:
            fields = "/".join(m["fields"])
            print(f"  {m['token']!r}  x{m['message_count']}  [{fields}]  "
                  f"~ {m.get('resembles')}")
        print()

    ip = report["ip_analysis"]
    print("--- SENDING IP DISTRIBUTION ---")
    print(f"  {ip['concentration_note']}")
    for b in ip["by_slash24"][:10]:
        print(f"    {b['block']:<20} {b['count']:>3}  ({b['share']:.0%})")
    print()

    if report.get("rule_test"):
        print_rule_results(report["rule_test"])

    rec = report["recipients"]
    if len(rec) == 1:
        print(f"--- All messages addressed to {rec[0]['address']} ---\n")
    elif rec:
        print("--- RECIPIENTS ---")
        for r in rec[:5]:
            print(f"    {r['address']:<40} {r['count']}")
        print()


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("folder", help="Folder containing .eml sample files")
    ap.add_argument("--json-out", help="Write the full JSON report to this path")
    ap.add_argument("--quiet", action="store_true",
                    help="Suppress the readable summary; emit JSON to stdout")
    ap.add_argument("--rules", metavar="FILE",
                    help="Test existing filter rules against this folder. One rule "
                         "per line: 'Name | any|all | Field:string ; Field:string'")
    args = ap.parse_args()

    report = analyze(args.folder, rules_path=args.rules)

    if args.json_out:
        Path(args.json_out).write_text(json.dumps(report, indent=2, ensure_ascii=False))

    if args.quiet:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print_summary(report)
        if args.json_out:
            print(f"Full JSON report written to {args.json_out}")

    return 0 if "error" not in report else 1


if __name__ == "__main__":
    sys.exit(main())
