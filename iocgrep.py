#!/usr/bin/env python3
"""
iocgrep - quick static triage: scan files for indicators of compromise.

When I'm doing a first pass over a suspicious directory (downloaded
scripts, an extracted archive, a web shell someone found) I want a fast
"does anything here look obviously bad" pass before going deeper. This
walks a path, applies a small set of built-in patterns (IPs, URLs, base64
blobs, common LOLBin/PowerShell abuse strings) plus whatever custom IOCs
you feed it, and prints every hit with file + line number.

Usage:
    python3 iocgrep.py ./suspicious_dir
    python3 iocgrep.py ./suspicious_dir --iocs my_iocs.txt
    python3 iocgrep.py webshell.php --csv hits.csv
"""

import argparse
import csv
import os
import re
import sys

# (name, compiled pattern) - kept short and readable on purpose. This is a
# triage aid, not a signature engine; it will both miss things and flag
# harmless matches (an IP in a comment, a legit base64 image blob, etc).
BUILTIN_PATTERNS = [
    ("ipv4", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("url", re.compile(r"\bhttps?://[^\s'\"<>]+", re.IGNORECASE)),
    ("base64_blob", re.compile(r"\b[A-Za-z0-9+/]{60,}={0,2}\b")),
    ("powershell_encoded", re.compile(r"-enc(?:odedcommand)?\b", re.IGNORECASE)),
    ("powershell_download", re.compile(r"(?:DownloadString|DownloadFile|Net\.WebClient)", re.IGNORECASE)),
    ("powershell_hidden", re.compile(r"-(?:nop|noprofile)\b.*-(?:w|windowstyle)\s+hidden", re.IGNORECASE)),
    ("invoke_expression", re.compile(r"\bIEX\s*\(|Invoke-Expression\b", re.IGNORECASE)),
    ("base64_decode_call", re.compile(r"FromBase64String|base64_decode|atob\s*\(", re.IGNORECASE)),
    ("certutil_abuse", re.compile(r"certutil\s+.*-decode", re.IGNORECASE)),
    ("reverse_shell_hint", re.compile(r"/dev/tcp/|nc\s+-e\s|bash\s+-i\s+>&", re.IGNORECASE)),
    ("eval_exec", re.compile(r"\beval\s*\(\s*(base64_decode|gzinflate|str_rot13)", re.IGNORECASE)),
    ("suspicious_keyword", re.compile(
        r"\b(mimikatz|cobaltstrike|meterpreter|psexec\.exe|lsass\.dmp)\b", re.IGNORECASE)),
]

TEXT_EXTENSIONS_HINT = None  # we sniff by trying to decode, not by extension
BINARY_SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".gz", ".exe",
                    ".dll", ".so", ".pyc", ".woff", ".woff2", ".ico"}


def load_custom_iocs(path):
    patterns = []
    with open(path, "r", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                patterns.append(("custom", re.compile(line, re.IGNORECASE)))
            except re.error:
                # not valid regex - fall back to a literal substring match
                patterns.append(("custom", re.compile(re.escape(line), re.IGNORECASE)))
    return patterns


def iter_target_files(path):
    if os.path.isfile(path):
        yield path
        return
    for dirpath, dirnames, filenames in os.walk(path):
        dirnames[:] = [d for d in dirnames if d not in (".git", "__pycache__", "node_modules")]
        for name in filenames:
            if os.path.splitext(name)[1].lower() in BINARY_SKIP_EXT:
                continue
            yield os.path.join(dirpath, name)


def scan_file(path, patterns, max_matches_per_file):
    hits = []
    try:
        with open(path, "r", errors="ignore") as f:
            for lineno, line in enumerate(f, start=1):
                for name, pattern in patterns:
                    m = pattern.search(line)
                    if m:
                        snippet = m.group(0)
                        if len(snippet) > 100:
                            snippet = snippet[:100] + "..."
                        hits.append((path, lineno, name, snippet))
                        if len(hits) >= max_matches_per_file:
                            return hits
    except (OSError, UnicodeDecodeError):
        pass
    return hits


def main():
    ap = argparse.ArgumentParser(description="Scan files for indicators of compromise (IOC triage helper).")
    ap.add_argument("target", help="file or directory to scan")
    ap.add_argument("--iocs", metavar="FILE",
                     help="extra file of custom patterns/strings, one per line (# for comments)")
    ap.add_argument("--csv", metavar="FILE", help="write all hits to a CSV file")
    ap.add_argument("--max-per-file", type=int, default=200,
                     help="stop scanning a single file after this many hits (default: 200)")
    ap.add_argument("--category", action="append", dest="categories",
                     help="only report this category of hit (repeatable, e.g. --category ipv4)")
    args = ap.parse_args()

    if not os.path.exists(args.target):
        print(f"[!] No such file or directory: {args.target}", file=sys.stderr)
        sys.exit(1)

    patterns = list(BUILTIN_PATTERNS)
    if args.iocs:
        patterns += load_custom_iocs(args.iocs)

    if args.categories:
        wanted = set(args.categories)
        patterns = [(n, p) for n, p in patterns if n in wanted]

    all_hits = []
    files_scanned = 0
    for path in iter_target_files(args.target):
        files_scanned += 1
        all_hits.extend(scan_file(path, patterns, args.max_per_file))

    print(f"[*] Scanned {files_scanned} file(s), {len(all_hits)} hit(s)\n")

    by_category = {}
    for path, lineno, category, snippet in all_hits:
        by_category.setdefault(category, 0)
        by_category[category] += 1
        print(f"{path}:{lineno}  [{category}]  {snippet}")

    if by_category:
        print("\n[*] Summary:")
        for cat, count in sorted(by_category.items(), key=lambda x: -x[1]):
            print(f"  {cat:<22} {count}")

    if args.csv:
        with open(args.csv, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["file", "line", "category", "snippet"])
            writer.writerows(all_hits)
        print(f"\n[*] Full results written to {args.csv}")


if __name__ == "__main__":
    main()
