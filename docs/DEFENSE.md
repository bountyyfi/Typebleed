# TypeBleed — Defense Guide

## Overview

TypeBleed exploits spec-compliant CSS `unicode-range` behavior to exfiltrate character data through font loading requests. Because the attack uses standard CSS features, defense requires a layered approach.

## Threat Model

TypeBleed is a **page operator** attack. The threat actor controls the page you're visiting. This is relevant for:

- Malicious sites displaying user-specific content (search results, account data)
- Compromised sites where an attacker has injected CSS
- Third-party CSS includes (CDN compromise, malicious stylesheets)
- Advertising iframes with access to page content

## Defenses

### For Website Operators

#### 1. Self-host fonts as single files

Don't split fonts by unicode-range. Serve one font file per weight/style.

```css
/* GOOD: Single file per font weight */
@font-face {
  font-family: 'MyFont';
  src: url('/fonts/myfont-regular.woff2') format('woff2');
  /* No unicode-range = download entire font always */
}

/* BAD: Per-range splitting enables TypeBleed */
@font-face {
  font-family: 'MyFont';
  src: url('/fonts/myfont-latin.woff2') format('woff2');
  unicode-range: U+0000-00FF;
}
```

#### 2. Audit third-party CSS

Review any externally loaded CSS for excessive `@font-face` rules with narrow `unicode-range` values. A stylesheet with dozens of single-codepoint font rules is suspicious.

#### 3. Use CSP font-src restrictively

Limit font sources to trusted origins:

```
Content-Security-Policy: font-src 'self' https://fonts.gstatic.com;
```

This doesn't prevent same-origin TypeBleed attacks but blocks cross-origin exfiltration fonts.

#### 4. Inline critical text as images

For extremely sensitive values (OTPs, tokens), render as server-generated images rather than text. This prevents CSS font-based exfiltration but hurts accessibility.

### For Browser Vendors

#### 1. Request batching / minimum subset size

Browsers could refuse to honor `unicode-range` descriptors that cover fewer than N codepoints (e.g., minimum 16 characters per range). This would make per-character subsetting impossible while still allowing legitimate multi-range fonts.

```
Proposed: Ignore unicode-range if it covers < 16 codepoints
```

#### 2. unicode-range request coalescing

Instead of making one request per matched `@font-face` rule, the browser could coalesce requests for the same font-family within a time window and report them as a single request.

#### 3. Privacy budget for font requests

Similar to the Privacy Budget proposal, browsers could limit the number of distinct font file requests per page load per font-family.

#### 4. Prefetch all declared subsets

A more aggressive mitigation: when the browser encounters multiple `@font-face` rules for the same font-family with different `unicode-range` values, prefetch **all** declared subsets regardless of which characters are actually needed. This eliminates the information leakage at the cost of bandwidth.

### For Network Defenders / Security Teams

#### 1. Monitor font request volume

Flag pages that generate an unusually high number of font file requests. Normal pages typically load 1-10 font files. TypeBleed pages load 40-80+.

**Detection rule (pseudo-code):**
```
IF font_requests_per_page > 30
AND all_fonts_same_family
AND each_font_file < 5KB
THEN alert("Possible TypeBleed-style exfiltration")
```

#### 2. Inspect CSS for single-codepoint unicode-range

Scan stylesheets for patterns like:
```
unicode-range: U+0041;  /* Single codepoint */
unicode-range: U+0042;
unicode-range: U+0043;
...
```

Multiple single-codepoint `unicode-range` rules for the same font-family is a strong indicator.

#### 3. WAF rules

Web Application Firewalls can inspect CSS responses for excessive `@font-face` declarations:

```
# Pseudo-rule
if response.content_type == "text/css"
   and count("@font-face") > 30
   and count("unicode-range: U+") > 30:
   flag_as_suspicious()
```

### For End Users

#### 1. Disable remote font loading

Most browsers allow disabling remote font loading:

- **Firefox:** `about:config` → `gfx.downloadable_fonts.enabled` = `false`
- **Tor Browser:** Consider the Security Level slider (higher levels disable fonts)

**Trade-off:** Many websites rely on custom fonts and will look broken.

#### 2. Use browser extensions

Extensions that block font loading or strip `@font-face` rules:

- uBlock Origin custom filters can block font requests
- NoScript in strict mode blocks font loading

#### 3. Be aware of the threat model

TypeBleed only works when the **page operator** is the adversary. If you trust the site you're visiting, TypeBleed is not a concern. It's relevant when:

- Visiting sites you don't fully trust
- Using services that display your private data and might have malicious CSS injection
- Concerned about third-party CSS on pages you visit

## Detection Indicators

| Indicator | Confidence | Description |
|-----------|-----------|-------------|
| >30 font requests per page | High | Normal pages load few font files |
| Font files < 2KB each | Medium | Per-character subsets are very small |
| Single-codepoint unicode-range | High | Legitimate fonts use wider ranges |
| Sequential codepoint URLs | High | URL pattern like `0041.woff2`, `0042.woff2` |
| Unique font URL paths per visit | Medium | Session tracking via font paths |
| No-cache headers on font files | Medium | Preventing cached font reuse |

## Future Considerations

The CSS Fonts Module continues to evolve. Proposals like [Incremental Font Transfer](https://www.w3.org/TR/IFT/) could either mitigate or amplify this class of attack depending on implementation. Browser vendors should consider exfiltration resistance as a design requirement for font loading features.

---

Security Research by [Bountyy Oy](https://bountyy.fi) — Mihalis Haatainen
