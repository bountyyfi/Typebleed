# TypeBleed

**Your fonts are leaking data.**

TypeBleed demonstrates that CSS `unicode-range` font subsetting is a zero-JavaScript data exfiltration side channel. A webpage can determine exactly which characters appear on your screen by splitting fonts into per-character files and monitoring HTTP requests.

No scripts. No cookies. No fingerprinting. Just CSS.

> Security research by [Bountyy Oy](https://bountyy.fi) / Mihalis Haatainen

---

## The Attack

```
┌─────────────────────┐     CSS @font-face      ┌──────────────────────┐
│                     │     unicode-range        │                      │
│   Browser renders   │ ──────────────────────►  │   Server logs which  │
│   "€12,847.50"      │   GET /fonts/t/sid/      │   characters were    │
│                     │     20AC.woff2 (€)       │   rendered on screen │
│                     │     0031.woff2 (1)       │                      │
│                     │     0032.woff2 (2)       │   Detected: €12847.50│
│                     │     002C.woff2 (,)       │                      │
│                     │     ...                  │                      │
└─────────────────────┘                          └──────────────────────┘
```

Each character on screen = one HTTP font request = one confirmed character in the server logs.

## What's Affected

- **Every browser** — Chrome, Firefox, Safari, Edge, Tor Browser
- **CSP does not block it** — fonts are allowed by default
- **Ad blockers do not detect it** — this is normal font loading behavior
- **Privacy browsers do not prevent it** — Tor Browser permits font loading
- **No security scanner flags it** — it's valid, spec-compliant CSS

## Demo

The PoC includes a realistic banking dashboard. When the page loads, the server reconstructs which characters appeared on screen from font requests alone.

**Left:** Banking page in browser. **Right:** Server dashboard showing captured characters in real-time.

## Quick Start

```bash
git clone https://github.com/bountyyfi/typebleed.git
cd typebleed

# Install dependencies
pip install -r server/requirements.txt

# Generate per-character font files
python fonts/generate.py

# Start the server
python server/server.py

# Open the demo
# Banking page:  http://localhost:8080
# Dashboard:     http://localhost:8080/dashboard
```

## How It Works

CSS `unicode-range` tells the browser to load a font file only when characters in the specified range are rendered on screen. TypeBleed exploits this by splitting a font into one file per character:

```css
@font-face {
  font-family: 'TypeBleed';
  src: url('/fonts/t/SESSION_ID/0041.woff2') format('woff2');
  unicode-range: U+0041; /* A */
}

@font-face {
  font-family: 'TypeBleed';
  src: url('/fonts/t/SESSION_ID/0042.woff2') format('woff2');
  unicode-range: U+0042; /* B */
}

/* ... one rule per character */
```

When the browser renders the text "Hello", it requests only:
- `0048.woff2` (H)
- `0065.woff2` (e)
- `006C.woff2` (l)
- `006F.woff2` (o)

The server now knows the page contained exactly these characters: `{H, e, l, o}`

### What the server learns

| Signal | Description |
|--------|-------------|
| **Character set** | Exact set of characters rendered on screen |
| **Request timing** | Character-level render timing via request timestamps |
| **Per-session tracking** | Unique font URL paths per visitor (no cookies needed) |
| **Content reconstruction** | Character set + known page template = partial/full text recovery |

### The reconstruction attack

If the server knows the page template (because it controls the page), it can subtract known static characters to isolate **dynamic content** — account balances, search queries, chat messages, personal information.

## Impact

A malicious page operator who displays user-specific content (account balances, search results, messages, personal data) can infer that content purely from CSS font loading behavior.

This works because:
1. CSS `unicode-range` causes browsers to fetch fonts lazily, per character
2. Each font subset = one HTTP request = one confirmed character
3. Server logs = complete character set of rendered page
4. Character frequency + page template = content reconstruction

The attack requires **zero JavaScript**. It passes Content Security Policy. It works through ad blockers. It works in Tor Browser. No security scanner on earth flags it.

## Project Structure

```
typebleed/
├── README.md              # This file
├── LICENSE                # MIT
├── server/
│   ├── server.py          # Flask server with logging + real-time dashboard
│   └── requirements.txt   # Python dependencies
├── fonts/
│   └── generate.py        # Split base font into per-character .woff2 files
├── demo/
│   ├── index.html         # Banking dashboard demo page
│   ├── style.css          # Demo styling
│   └── exfil.css          # Generated @font-face rules (standalone)
├── analysis/
│   └── reconstruct.py     # Log analysis and text reconstruction
└── docs/
    ├── TECHNICAL.md       # Deep technical writeup
    └── DEFENSE.md         # Detection and prevention guide
```

## Defense

See [DEFENSE.md](docs/DEFENSE.md) for detailed mitigations. Key recommendations:

- **Self-host fonts as single files** — don't split by unicode-range
- **Browser vendors:** Batch unicode-range requests or add minimum subset size thresholds
- **CSP:** Consider `font-src` restrictions that limit per-origin font file counts
- **Network monitoring:** Flag pages loading >50 font files from the same origin

## Responsible Disclosure

This research was disclosed to major browser vendors before publication. TypeBleed exploits spec-compliant behavior — there is no "bug" to patch. The mitigation requires either spec changes or browser-level heuristics.

## Related Research

Part of the **Invisible Web Attack Surface** research series by Bountyy Oy:

- [DeadPixel](https://github.com/bountyyfi/deadpixel) — Favicon-based browser tracking
- [ComfortSans](https://github.com/bountyyfi/ComfortSans) — Font ligature phishing
- [GhostDirective](https://github.com/bountyyfi/ghostdirective) — AI metadata poisoning

## License

MIT — See [LICENSE](LICENSE)

---

**Bountyy Oy** — [bountyy.fi](https://bountyy.fi) — Security research for the invisible web.
