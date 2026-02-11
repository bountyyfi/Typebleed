# TypeBleed — Technical Deep Dive

## Overview

TypeBleed exploits the CSS `unicode-range` descriptor in `@font-face` rules to create a per-character data exfiltration channel. This document explains the underlying browser behavior, the attack mechanics, and the information-theoretic limits of the technique.

## Background: CSS unicode-range

The `unicode-range` descriptor was introduced in CSS3 to enable efficient font subsetting. It tells the browser: "only download this font file when characters in the specified range need to be rendered."

```css
@font-face {
  font-family: 'MyFont';
  src: url('latin.woff2') format('woff2');
  unicode-range: U+0000-00FF; /* Basic Latin */
}

@font-face {
  font-family: 'MyFont';
  src: url('greek.woff2') format('woff2');
  unicode-range: U+0370-03FF; /* Greek */
}
```

This is a performance optimization: if a page only uses Latin characters, the browser never downloads the Greek subset. Google Fonts uses this extensively to serve fonts efficiently.

**The security implication:** The browser's font download behavior reveals which characters are present in the rendered page.

## Attack Mechanics

### Step 1: Font Splitting

TypeBleed takes this to the extreme by creating **one font file per character**:

```css
@font-face {
  font-family: 'TypeBleed';
  src: url('/fonts/t/SESSION/0041.woff2') format('woff2');
  unicode-range: U+0041; /* A */
}
```

With ~80 characters covered (a-z, A-Z, 0-9, punctuation, currency), the CSS contains ~80 `@font-face` rules.

### Step 2: Lazy Loading

When the browser encounters text styled with the TypeBleed font family, it:

1. Parses the text content to determine which Unicode codepoints are needed
2. Matches each codepoint against `unicode-range` descriptors
3. Downloads **only** the font files for codepoints actually present in the rendered text
4. Caches the font files per the normal HTTP caching rules

This is spec-compliant behavior defined in the [CSS Fonts Module Level 4](https://www.w3.org/TR/css-fonts-4/#unicode-range-desc).

### Step 3: Server-Side Logging

Each font request hits a unique URL: `/fonts/t/{session_id}/{codepoint}.woff2`

The server logs:
- **Timestamp** — when the request arrived
- **Session ID** — unique per page load (embedded in the URL path)
- **Codepoint** — which character was needed
- **Client IP** — standard HTTP metadata
- **User-Agent** — standard HTTP metadata

### Step 4: Reconstruction

Given the set of characters `{€, 1, 2, 8, 4, 7, ., 5, 0}` and knowledge that the page template displays an account balance in the format `€XX,XXX.XX`, the server can reconstruct `€12,847.50` (or a small number of permutations).

## Information Leakage Analysis

### What is leaked

The attack reveals the **character set** of rendered text — which unique characters appear on screen. It does **not** reveal:

- Character frequency (each character is requested once regardless of how many times it appears)
- Character order or position
- Which specific DOM element contains which character

### Information content

For a character set of size N drawn from an alphabet of size A:

```
Information leaked = log2(C(A, N)) bits
```

Where C(A, N) is the binomial coefficient "A choose N".

For a typical page rendering 40 unique characters from an 80-character alphabet:
```
log2(C(80, 40)) ≈ 76 bits
```

This is significant. Combined with template knowledge, it's often sufficient to reconstruct dynamic content.

### Template subtraction

If the attacker controls the page (which they do — they're the page operator), they know which characters appear in static content (navigation, labels, headings). Subtracting these reveals the character set of **dynamic content only**.

Example:
- Total characters captured: `{A, B, C, ..., a, b, c, ..., 0, 1, 2, €, .}`
- Known static characters: `{A, B, C, ..., a, b, c, ...}` (from template)
- Dynamic-only characters: `{0, 1, 2, €, .}` (the account balance)

### Timing side channel

Request timestamps provide additional information:
- Characters in above-the-fold content are requested first
- Characters in dynamically inserted content arrive later
- The timing pattern can reveal page structure and user interactions

## Browser Behavior

### Chrome / Chromium

Chrome implements aggressive unicode-range subsetting. Font files are requested as soon as the layout engine determines which characters need rendering. Requests are made in parallel for all needed subsets.

### Firefox

Firefox also implements unicode-range subsetting per the spec. The request pattern is nearly identical to Chrome.

### Safari / WebKit

Safari implements unicode-range subsetting. Behavior is consistent with other engines.

### Tor Browser

Tor Browser is based on Firefox ESR and does **not** disable unicode-range font loading. While it routes requests through Tor (hiding the user's IP), it does not prevent the page operator from correlating font requests with the session.

**Key insight:** TypeBleed targets the **page operator** threat model. Tor Browser protects against network observers but not against the server you're communicating with.

## Why Existing Defenses Fail

### Content Security Policy (CSP)

CSP's `font-src` directive controls where fonts can be loaded from, but:
- The fonts are loaded from the **same origin** as the page
- `font-src 'self'` explicitly allows this
- There is no CSP directive to limit the **number** of font files

### Ad Blockers

Ad blockers use filter lists targeting known tracking domains and URL patterns. TypeBleed fonts:
- Are served from the same domain as the page
- Use paths that look like normal font files
- Don't match any tracking patterns

### Privacy Extensions

Extensions like Privacy Badger, uBlock Origin, and NoScript:
- Don't block same-origin font loading
- Don't monitor font request patterns
- NoScript only blocks JavaScript, not CSS fonts

### Subresource Integrity (SRI)

SRI verifies that fetched resources haven't been tampered with. It doesn't prevent the fetch from happening or the server from logging it.

## Limitations

1. **Character set only** — No frequency or order information
2. **Caching** — If the same font URL is cached, repeat visits don't generate new requests (mitigated by per-session URLs)
3. **Shared characters** — Static and dynamic content share characters, reducing signal
4. **Requires page control** — The attacker must control the page serving the content
5. **No cross-origin exfil** — Can only observe characters on pages you serve (not other sites)

## Comparison with Other Side Channels

| Technique | Requires JS | Cross-Origin | Information | Detectability |
|-----------|-------------|--------------|-------------|---------------|
| TypeBleed | No | No | Character set | Very Low |
| CSS :visited | No | Yes* | Link history | Medium |
| Timing attacks | Yes | Yes | Various | Medium |
| Cache probing | Yes | Yes | Resource presence | Medium |
| Pixel tracking | No | N/A | View confirmation | Low |

*`:visited` attacks have been significantly mitigated in modern browsers.

## References

- [CSS Fonts Module Level 4 — unicode-range](https://www.w3.org/TR/css-fonts-4/#unicode-range-desc)
- [Google Fonts — unicode-range subsetting](https://developers.google.com/fonts/docs/getting_started#specifying_script_subsets)
- [HTTP Archive — Font usage statistics](https://httparchive.org/reports/page-weight#bytesFont)

---

Security Research by [Bountyy Oy](https://bountyy.fi) — Mihalis Haatainen
