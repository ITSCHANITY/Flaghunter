# flaghunter

**Authorized CTF web recon & flag hunter — standard library only.**

flaghunter is a recon helper for **Capture-The-Flag web challenges**. It assumes
you are testing a target you are explicitly allowed to attack (your own box, a
practice VM, an HTB/picoCTF-style challenge). Its goal is to *find the flag* and
surface the usual low-hanging CTF web exposures fast.

This is a **separate tool** from `webscan`. `webscan` is a defensive, authorized
vulnerability scanner that reports misconfigurations to fix. `flaghunter` is an
offensive-recon helper for CTFs you own/are permitted to solve.

## Requirements

Python 3 standard library only — nothing to install. Runs anywhere Python runs,
including a minimal CTF box.

## Usage

```bash
# Validate every detector against a local planted-flag server (no target needed)
python3 flaghunter.py --selftest

# Hunt a target (you must confirm authorization)
python3 flaghunter.py --authorized https://ctf-target.example

# Add a custom flag format (regex)
python3 flaghunter.py --authorized --flag-format 'MYCTF\{[^}]+\}' http://host:8000

# Machine-readable output (stdout = JSON, status goes to stderr)
python3 flaghunter.py --authorized --json http://host:8000 > findings.json

# CTF boxes often have self-signed certs:
python3 flaghunter.py --authorized --insecure https://10.10.10.10
```

### Flags / options

| Flag | Meaning |
|------|---------|
| `--authorized` | Confirm you may test this target (skips the prompt) |
| `--flag-format REGEX` | Extra flag pattern to hunt for |
| `--delay SECONDS` | Rate limit between requests (default 0.3) |
| `--insecure` | Disable TLS verification (self-signed CTF certs) |
| `--no-discovery` | Only scan the landing page; skip path/backup probing |
| `--json` | Emit findings as JSON on stdout |
| `--selftest` | Run the built-in detector validation suite |

Exit code is `0` when at least one flag was found, `1` otherwise — handy in scripts.

## What it checks

- **Flag formats**: `flag{}`, `CTF{}`, `HTB{}`, `picoCTF{}`, `FLAG{}`, plus any `--flag-format`
- **Common exposures**: `robots.txt`, `sitemap.xml`, `/.git/HEAD`, `/.env`, backup files, etc.
- **HTML comments** (classic place to stash a flag or hint)
- **Response headers** and **cookies**
- **Encoding auto-decode**: base64/hex substrings are decoded and re-scanned for flags
- **JWT inspection**: decodes header/payload, flags `alg:none`
- **Hash extraction**: MD5/SHA-1/SHA-256/bcrypt/SHA-512-crypt shapes are pulled out
  so you can hand them to the arsenal's `hash-identifier`:

```bash
python3 flaghunter.py --authorized --json URL   # includes extracted hashes
# then feed a hash into:
python3 ../../PROJECTS/hash-identifier/hash-identifier.py '<hash>'
```

## Authorization & scope

flaghunter makes active requests. Only run it against targets you own or are
explicitly authorized to test. The `--authorized` flag (or the interactive
prompt) is a required gate before any network activity.
