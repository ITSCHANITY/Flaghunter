#!/usr/bin/env python3
"""
flaghunter.py — Authorized CTF Web Recon & Flag Hunter
=======================================================
Run:
    python3 flaghunter.py --authorized https://ctf-target.example
    python3 flaghunter.py --authorized --flag-format 'MYCTF\\{[^}]+\\}' http://host:8000
    python3 flaghunter.py --authorized --json http://host:8000 > findings.json
    python3 flaghunter.py --selftest

PURPOSE
    A recon helper for CAPTURE-THE-FLAG web challenges. It assumes you are
    attacking a target you are explicitly allowed to attack (your own box, a
    practice VM, HackTheBox/picoCTF-style challenge, etc). It hunts for flags
    and the usual low-hanging CTF web exposures, decodes obvious encodings,
    and extracts hashes so you can hand them to a cracker/identifier.

    This is a SEPARATE tool from webscan.py. webscan is a defensive, authorized
    vulnerability scanner that reports misconfigurations; flaghunter is an
    offensive-recon helper whose goal is to *find the flag* on a target you own.

DESIGN (shared with the rest of the arsenal)
    * Standard library only — nothing to pip install, runs on any CTF box.
    * TLS verification ON by default; --insecure opts out (CTF boxes often use
      self-signed certs, so this is a common, explicit opt-out here).
    * A required --authorized flag gates all network activity.
    * A shared rate limiter (--delay) between requests.
    * A --selftest mode validates every detector against a local server with
      deliberately planted flags/exposures — ground truth, not trust.

NOTE ON HANDOFF
    Hash-looking strings are extracted and reported so you can pipe them into
    the arsenal's hash-identifier:
        python3 flaghunter.py --authorized --json URL | ... | hash-identifier
"""

import argparse
import base64
import binascii
import http.server
import json
import re
import socket
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser


# ── Colors ──────────────────────────────────────────────────────────────────
class C:
    R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"; C = "\033[96m"
    M = "\033[95m"; W = "\033[97m"; DIM = "\033[90m"; B = "\033[1m"; RESET = "\033[0m"


# ── Global config (set from CLI) ──────────────────────────────────────────────
RATE_DELAY = 0.3
ALLOW_INSECURE = False
_last_request = [0.0]


# ── Findings model ────────────────────────────────────────────────────────────
findings = []  # list of {"type", "severity", "source", "detail"}


def record(ftype, severity, source, detail):
    findings.append(
        {"type": ftype, "severity": severity, "source": source, "detail": detail}
    )


# ── Flag detection ─────────────────────────────────────────────────────────────
# Default flag formats seen across common CTF platforms. Users can add their own
# with --flag-format (a regex). Kept deliberately specific so random text that
# happens to contain "flag" doesn't produce noise.
DEFAULT_FLAG_PATTERNS = [
    r"\bflag\{[^}\r\n]{1,200}\}",
    r"\bCTF\{[^}\r\n]{1,200}\}",
    r"\bHTB\{[^}\r\n]{1,200}\}",
    r"\bpicoCTF\{[^}\r\n]{1,200}\}",
    r"\bFLAG\{[^}\r\n]{1,200}\}",
]

# Hash shapes worth extracting for handoff to hash-identifier.
HASH_PATTERNS = [
    (re.compile(r"\b[a-fA-F0-9]{32}\b"), "possible MD5/NTLM (32 hex)"),
    (re.compile(r"\b[a-fA-F0-9]{40}\b"), "possible SHA-1 (40 hex)"),
    (re.compile(r"\b[a-fA-F0-9]{64}\b"), "possible SHA-256 (64 hex)"),
    (re.compile(r"\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}"), "bcrypt hash"),
    (re.compile(r"\$6\$[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{86}"), "SHA-512 crypt"),
]


def compile_flag_patterns(custom=None):
    patterns = list(DEFAULT_FLAG_PATTERNS)
    if custom:
        patterns.append(custom)
    compiled = []
    for p in patterns:
        try:
            compiled.append(re.compile(p))
        except re.error as exc:
            print(f"{C.R}[!] Invalid flag regex {p!r}: {exc}{C.RESET}", file=sys.stderr)
    return compiled


def scan_for_flags(text, source, flag_res):
    """Scan text for any flag pattern; record each unique hit."""
    seen = set()
    for rx in flag_res:
        for m in rx.finditer(text):
            flag = m.group(0)
            if flag not in seen:
                seen.add(flag)
                record("FLAG", "CRITICAL", source, flag)
    return seen


def scan_for_hashes(text, source):
    for rx, label in HASH_PATTERNS:
        for m in rx.finditer(text):
            record("HASH", "INFO", source, f"{label}: {m.group(0)}")


# ── Encoding auto-decode ────────────────────────────────────────────────────────
_B64_CANDIDATE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_HEX_CANDIDATE = re.compile(r"\b(?:[A-Fa-f0-9]{2}){8,}\b")


def _printable_ratio(data):
    if not data:
        return 0.0
    printable = sum(1 for b in data if 9 <= b <= 13 or 32 <= b <= 126)
    return printable / len(data)


def auto_decode_and_scan(text, source, flag_res):
    """Find base64/hex substrings, decode the ones that look like text, and
    re-scan the decoded output for flags. Returns the decoded strings found."""
    decoded_hits = []

    for m in _B64_CANDIDATE.finditer(text):
        blob = m.group(0)
        try:
            raw = base64.b64decode(blob, validate=True)
        except (binascii.Error, ValueError):
            continue
        if _printable_ratio(raw) < 0.9:
            continue
        decoded = raw.decode("utf-8", "replace")
        if decoded.strip():
            found = scan_for_flags(decoded, f"{source} (base64-decoded)", flag_res)
            if found:
                decoded_hits.append(decoded)

    for m in _HEX_CANDIDATE.finditer(text):
        blob = m.group(0)
        try:
            raw = bytes.fromhex(blob)
        except ValueError:
            continue
        if _printable_ratio(raw) < 0.9:
            continue
        decoded = raw.decode("utf-8", "replace")
        if decoded.strip():
            found = scan_for_flags(decoded, f"{source} (hex-decoded)", flag_res)
            if found:
                decoded_hits.append(decoded)

    return decoded_hits


# ── HTML comment extraction ───────────────────────────────────────────────────
class _CommentExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.comments = []

    def handle_comment(self, data):
        self.comments.append(data)


def extract_comments(html):
    parser = _CommentExtractor()
    try:
        parser.feed(html)
    except Exception:
        pass
    return parser.comments


# ── HTTP ─────────────────────────────────────────────────────────────────────
def _rate_limit():
    elapsed = time.time() - _last_request[0]
    if elapsed < RATE_DELAY:
        time.sleep(RATE_DELAY - elapsed)
    _last_request[0] = time.time()


def _ssl_context():
    if ALLOW_INSECURE:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    return ssl.create_default_context()


def http_get(url, timeout=10):
    """GET a URL. Returns (status, headers_dict, body_text) or (None, {}, "")."""
    _rate_limit()
    req = urllib.request.Request(url, headers={"User-Agent": "flaghunter/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ssl_context()) as resp:
            raw = resp.read(2_000_000)  # cap at 2MB
            headers = {k: v for k, v in resp.headers.items()}
            body = raw.decode("utf-8", "replace")
            return resp.status, headers, body
    except urllib.error.HTTPError as e:
        raw = b""
        try:
            raw = e.read(2_000_000)
        except Exception:
            pass
        headers = {k: v for k, v in (e.headers.items() if e.headers else [])}
        return e.code, headers, raw.decode("utf-8", "replace")
    except (urllib.error.URLError, socket.timeout, ssl.SSLError, ConnectionError):
        return None, {}, ""


# ── JWT inspection ─────────────────────────────────────────────────────────────
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")


def _b64url_decode(segment):
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def inspect_jwt(token, source):
    parts = token.split(".")
    if len(parts) < 2:
        return
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except Exception:
        return
    record("JWT", "INFO", source, f"JWT header={header} payload={payload}")
    alg = str(header.get("alg", "")).lower()
    if alg == "none":
        record("JWT", "HIGH", source,
               "JWT uses alg:none — signature not verified; forge-able token.")


# ── Target normalization / discovery lists ─────────────────────────────────────
COMMON_PATHS = [
    "robots.txt", "sitemap.xml", ".env", ".git/HEAD", ".git/config",
    "backup.zip", "backup.tar.gz", "index.php.bak", "index.html.bak",
    "config.php.bak", ".htaccess", "admin/", "flag.txt", "flag",
    "secret.txt", "hidden/", "wp-config.php.bak", "server-status",
    ".DS_Store", "debug", "test.php", "phpinfo.php",
]

BACKUP_SUFFIXES = ["~", ".bak", ".old", ".orig", ".save", ".swp"]


def normalize_target(target):
    target = target.strip().rstrip("/")
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    return target


def join(base, path):
    return base + "/" + path.lstrip("/")


# ── Scan modules ───────────────────────────────────────────────────────────────
def scan_response(url, status, headers, body, flag_res, source_label):
    """Run every content detector over one HTTP response."""
    if not body and not headers:
        return
    header_blob = "\n".join(f"{k}: {v}" for k, v in headers.items())

    # Flags + hashes in body and headers
    scan_for_flags(body, f"{source_label} body", flag_res)
    scan_for_flags(header_blob, f"{source_label} headers", flag_res)
    scan_for_hashes(body, f"{source_label} body")

    # HTML comments
    for comment in extract_comments(body):
        scan_for_flags(comment, f"{source_label} HTML comment", flag_res)
        if "flag" in comment.lower() or "todo" in comment.lower() or "pass" in comment.lower():
            record("COMMENT", "LOW", f"{source_label} HTML comment", comment.strip()[:200])

    # Encoding auto-decode (body + headers)
    auto_decode_and_scan(body, f"{source_label} body", flag_res)
    auto_decode_and_scan(header_blob, f"{source_label} headers", flag_res)

    # Cookies / JWT
    set_cookie = headers.get("Set-Cookie", "")
    for jm in _JWT_RE.finditer(body + " " + header_blob + " " + set_cookie):
        inspect_jwt(jm.group(0), source_label)
    if set_cookie:
        record("COOKIE", "INFO", source_label, f"Set-Cookie: {set_cookie}")


def check_exposures(base, flag_res):
    """Probe common CTF-exposed paths and known-sensitive files."""
    for path in COMMON_PATHS:
        url = join(base, path)
        status, headers, body = http_get(url)
        if status is None:
            continue
        if status == 200 and body.strip():
            sev = "HIGH" if path in (".env", ".git/HEAD", ".git/config") else "MEDIUM"
            preview = body.strip().replace("\n", " ")[:120]
            record("EXPOSURE", sev, url, f"{status} ({len(body)} bytes): {preview}")
            scan_response(url, status, headers, body, flag_res, f"exposure:{path}")


def check_backups_of(base, filenames, flag_res):
    """For each known page, try common editor/backup suffixes."""
    for name in filenames:
        for suffix in BACKUP_SUFFIXES:
            url = join(base, name + suffix)
            status, headers, body = http_get(url)
            if status == 200 and body.strip():
                record("BACKUP", "HIGH", url, f"backup file reachable ({len(body)} bytes)")
                scan_response(url, status, headers, body, flag_res, f"backup:{name}{suffix}")


# ── Orchestration ──────────────────────────────────────────────────────────────
def hunt(target, flag_res, do_discovery=True):
    base = normalize_target(target)

    # 1. Fetch the landing page.
    status, headers, body = http_get(base)
    if status is None:
        record("ERROR", "INFO", base, "could not connect to target")
        return
    record("INFO", "INFO", base, f"landing page status {status}, {len(body)} bytes")
    scan_response(base, status, headers, body, flag_res, "landing")

    # 2. Common exposures + path discovery.
    if do_discovery:
        check_exposures(base, flag_res)
        check_backups_of(base, ["index.php", "index.html", "config.php"], flag_res)


# ── Reporting ──────────────────────────────────────────────────────────────────
SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEV_COLORS = {"CRITICAL": C.R, "HIGH": C.R, "MEDIUM": C.Y, "LOW": C.C, "INFO": C.DIM}


def print_report(target, elapsed):
    flags = [f for f in findings if f["type"] == "FLAG"]
    print(f"\n{C.C}{C.B}{'='*60}{C.RESET}")
    print(f"{C.B}  FLAGHUNTER REPORT — {target}{C.RESET}")
    print(f"{C.C}{C.B}{'='*60}{C.RESET}")
    print(f"  Time: {elapsed:.1f}s   Findings: {len(findings)}   "
          f"{C.G if flags else C.DIM}Flags: {len(flags)}{C.RESET}\n")

    if flags:
        print(f"{C.G}{C.B}  >>> FLAGS FOUND <<<{C.RESET}")
        for f in flags:
            print(f"    {C.G}{C.B}{f['detail']}{C.RESET}  {C.DIM}[{f['source']}]{C.RESET}")
        print()

    for sev in SEV_ORDER:
        group = [f for f in findings if f["severity"] == sev and f["type"] != "FLAG"]
        if not group:
            continue
        col = SEV_COLORS[sev]
        print(f"{col}{C.B}  {sev}{C.RESET}")
        for f in group:
            print(f"    {col}•{C.RESET} [{f['type']}] {f['detail']}  {C.DIM}({f['source']}){C.RESET}")
        print()

    hashes = [f for f in findings if f["type"] == "HASH"]
    if hashes:
        print(f"{C.M}  Hand these off to hash-identifier:{C.RESET}")
        for h in hashes:
            print(f"    {h['detail']}")
        print()


def json_report(target, elapsed):
    print(json.dumps({
        "tool": "flaghunter",
        "version": "1.0",
        "target": target,
        "elapsed_seconds": round(elapsed, 2),
        "flags": [f["detail"] for f in findings if f["type"] == "FLAG"],
        "findings": findings,
    }, indent=2))


# ── Authorization gate ─────────────────────────────────────────────────────────
def require_authorization(flag_given):
    if flag_given:
        return True
    print(f"{C.Y}This tool performs active requests against the target.{C.RESET}")
    print(f"{C.Y}Only use it on targets you are authorized to test (your own CTF box).{C.RESET}")
    try:
        answer = input("Type 'yes' to confirm you are authorized: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    return answer == "yes"


# ── Selftest: planted-flag local server ─────────────────────────────────────────
def _selftest_handler():
    # A base64 string that decodes to a flag, and a valid alg:none JWT.
    b64_flag = base64.b64encode(b"flag{base64_decoded_me}").decode()
    jwt_none = (
        base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip("=")
        + "."
        + base64.urlsafe_b64encode(b'{"user":"admin"}').decode().rstrip("=")
        + "."
    )

    pages = {
        "/": (
            "<html><head><!-- TODO: remove debug flag{html_comment_flag} -->"
            "</head><body>Welcome to the challenge. "
            f"Here is a token: {b64_flag}</body></html>"
        ).encode(),
        "/robots.txt": b"User-agent: *\nDisallow: /secret/\nDisallow: /flag.txt\n",
        "/.env": b"SECRET_KEY=flag{dotenv_exposed}\nDB_PASS=hunter2\n",
        "/flag.txt": b"flag{direct_flag_file}\n",
    }

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass  # keep selftest output clean

        def do_GET(self):
            path = self.path.split("?", 1)[0]
            if path in pages:
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                if path == "/":
                    self.send_header("Set-Cookie", f"session={jwt_none}")
                self.end_headers()
                self.wfile.write(pages[path])
            else:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"not found")

    return Handler


def cmd_selftest():
    print(f"{C.C}{C.B}FLAGHUNTER SELFTEST{C.RESET}")
    print("Starting a local server with planted flags/exposures to validate detectors.\n")

    handler = _selftest_handler()
    server = http.server.HTTPServer(("127.0.0.1", 0), handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    global RATE_DELAY
    RATE_DELAY = 0.0  # no need to be polite to ourselves
    findings.clear()

    base = f"http://127.0.0.1:{port}"
    flag_res = compile_flag_patterns()
    try:
        hunt(base, flag_res, do_discovery=True)
    finally:
        server.shutdown()

    flag_details = {f["detail"] for f in findings if f["type"] == "FLAG"}
    checks = [
        ("Flag in HTML comment", "flag{html_comment_flag}" in flag_details),
        ("Flag via base64 auto-decode", "flag{base64_decoded_me}" in flag_details),
        ("Flag in exposed .env", "flag{dotenv_exposed}" in flag_details),
        ("Flag in exposed flag.txt", "flag{direct_flag_file}" in flag_details),
        ("robots.txt exposure recorded",
         any(f["type"] == "EXPOSURE" and "robots.txt" in f["source"] for f in findings)),
        (".env flagged HIGH",
         any(f["type"] == "EXPOSURE" and f["severity"] == "HIGH" and ".env" in f["source"]
             for f in findings)),
        ("JWT alg:none detected",
         any(f["type"] == "JWT" and "alg:none" in f["detail"] for f in findings)),
    ]

    passed = 0
    for name, ok in checks:
        tag = f"{C.G}[PASS]{C.RESET}" if ok else f"{C.R}[FAIL]{C.RESET}"
        print(f"  {tag} {name}")
        passed += 1 if ok else 0

    total = len(checks)
    print(f"\n{C.B}RESULTS: {passed}/{total} checks passed{C.RESET}")
    return passed == total


# ── CLI ────────────────────────────────────────────────────────────────────────
def build_parser():
    p = argparse.ArgumentParser(
        prog="flaghunter",
        description="Authorized CTF web recon & flag hunter (standard library only).",
    )
    p.add_argument("target", nargs="?", help="URL or host of the CTF target")
    p.add_argument("--authorized", action="store_true",
                   help="Confirm you are authorized to test this target (skips the prompt)")
    p.add_argument("--flag-format", default=None,
                   help="Extra flag regex, e.g. 'MYCTF\\{[^}]+\\}'")
    p.add_argument("--delay", type=float, default=0.3,
                   help="Seconds between requests (default: 0.3)")
    p.add_argument("--insecure", action="store_true",
                   help="Disable TLS verification (common for CTF boxes with self-signed certs)")
    p.add_argument("--no-discovery", action="store_true",
                   help="Only scan the landing page; skip path/backup probing")
    p.add_argument("--json", action="store_true",
                   help="Emit findings as JSON on stdout (status goes to stderr)")
    p.add_argument("--selftest", action="store_true",
                   help="Validate detectors against a local planted-flag server")
    return p


def main():
    global RATE_DELAY, ALLOW_INSECURE
    args = build_parser().parse_args()

    if args.selftest:
        sys.exit(0 if cmd_selftest() else 1)

    if not args.target:
        print(f"{C.R}[!] No target given. Use --selftest or provide a URL.{C.RESET}", file=sys.stderr)
        sys.exit(2)

    RATE_DELAY = max(0.0, args.delay)
    ALLOW_INSECURE = args.insecure

    if not require_authorization(args.authorized):
        print(f"{C.R}[!] Authorization not confirmed — exiting.{C.RESET}", file=sys.stderr)
        sys.exit(1)

    # Keep stdout clean for JSON consumers.
    real_stdout = sys.stdout
    if args.json:
        sys.stdout = sys.stderr

    target = normalize_target(args.target)
    flag_res = compile_flag_patterns(args.flag_format)

    print(f"{C.C}Hunting {target} …{C.RESET}", file=sys.stderr if args.json else sys.stdout)
    t0 = time.time()
    findings.clear()
    hunt(target, flag_res, do_discovery=not args.no_discovery)
    elapsed = time.time() - t0

    if args.json:
        sys.stdout = real_stdout
        json_report(target, elapsed)
    else:
        print_report(target, elapsed)

    # Exit 0 if a flag was found, 1 otherwise — handy in scripts.
    sys.exit(0 if any(f["type"] == "FLAG" for f in findings) else 1)


if __name__ == "__main__":
    main()
