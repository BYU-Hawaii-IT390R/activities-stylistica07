"""Template script for IT 390R log‑analysis lab

Run examples
------------
# Required tasks:
python analyze_log.py cowrie-tiny.log --task failed-logins --min-count 1
python analyze_log.py cowrie-tiny.log --task successful-creds

# Optional Extra Credit:
python analyze_log.py cowrie-tiny.log --task top-commands
"""

import argparse
import re
from collections import Counter, defaultdict
from datetime import datetime

# ── Regex patterns ──────────────────────────────────────────────────────────
FAILED_LOGIN_PATTERN = re.compile(
    r"\[HoneyPotSSHTransport,\d+,(?P<ip>\d+\.\d+\.\d+\.\d+)\].*?"
    r"login attempt \[.*?/.*?\] failed"
)

NEW_CONN_PATTERN = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?)Z "
    r"\[cowrie\.ssh\.factory\.CowrieSSHFactory\] New connection: "
    r"(?P<ip>\d+\.\d+\.\d+\.\d+):\d+"
)

SUCCESS_LOGIN_PATTERN = re.compile(
    r"\[HoneyPotSSHTransport,\d+,(?P<ip>\d+\.\d+\.\d+\.\d+)\].*?"
    r"login attempt \[(?P<user>[^/]+)/(?P<pw>[^\]]+)\] succeeded"
)

FINGERPRINT_PATTERN = re.compile(
    r"\[HoneyPotSSHTransport,\d+,(?P<ip>\d+\.\d+\.\d+\.\d+)\].*?"
    r"SSH client hassh fingerprint: (?P<fp>[0-9a-f:]{32})"
)

# ── Helper to print tables ──────────────────────────────────────────────────

def _print_counter(counter: Counter, head1: str, head2: str, sort_keys=False):
    """Nicely format a Counter as a two‑column table."""
    width = max((len(str(k)) for k in counter), default=len(head1))
    print(f"{head1:<{width}} {head2:>8}")
    print("-" * (width + 9))
    items = sorted(counter.items()) if sort_keys else counter.most_common()
    for key, cnt in items:
        print(f"{key:<{width}} {cnt:>8}")

# ── ✅ Task 1: analyze_failed_logins ────────────────────────────────────────

def analyze_failed_logins(path: str, min_count: int):
    """Parse *failed* SSH login attempts and show a count per source IP."""
    counter = Counter()

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            # regex assisted by ChatGPT: prompt "regex for failed SSH login IP from Cowrie logs"
            match = FAILED_LOGIN_PATTERN.search(line)
            if match:
                ip = match.group("ip")
                counter[ip] += 1

    filtered = Counter({ip: count for ip, count in counter.items() if count >= min_count})
    _print_counter(filtered, "Source IP", "Attempts")

# ── Task 2: connections (already implemented) ───────────────────────────────

def connections(path: str):
    per_min = Counter()
    with open(path, encoding="utf-8") as fp:
        for line in fp:
            m = NEW_CONN_PATTERN.search(line)
            if m:
                dt = datetime.strptime(m.group("ts")[:19], "%Y-%m-%dT%H:%M:%S")
                per_min[dt.strftime("%Y-%m-%d %H:%M")] += 1
    print("Connections per minute")
    _print_counter(per_min, "Timestamp", "Count", sort_keys=True)

# ── ✅ Task 3: analyze_successful_creds ──────────────────────────────────────

def analyze_successful_creds(path: str):
    """Display username/password pairs that *succeeded* and how many unique IPs used each."""
    creds = defaultdict(set)

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            # regex assisted by ChatGPT: prompt "regex for successful SSH login with user/pass/IP from Cowrie logs"
            match = SUCCESS_LOGIN_PATTERN.search(line)
            if match:
                user = match.group("user")
                pw = match.group("pw")
                ip = match.group("ip")
                creds[(user, pw)].add(ip)

    sorted_creds = sorted(creds.items(), key=lambda item: len(item[1]), reverse=True)

    print(f"{'Username':<15} {'Password':<15} {'# Unique IPs'}")
    print("-" * 45)
    for (user, pw), ip_set in sorted_creds:
        print(f"{user:<15} {pw:<15} {len(ip_set)}")

# ── Task 4: identify_bots (already implemented) ─────────────────────────────

def identify_bots(path: str, min_ips: int):
    fp_map = defaultdict(set)
    with open(path, encoding="utf-8") as fp:
        for line in fp:
            m = FINGERPRINT_PATTERN.search(line)
            if m:
                fp_map[m.group("fp")].add(m.group("ip"))
    bots = {fp: ips for fp, ips in fp_map.items() if len(ips) >= min_ips}
    print(f"Fingerprints seen from ≥ {min_ips} unique IPs")
    print(f"{'Fingerprint':<47} {'IPs':>6}")
    print("-" * 53)
    for fp, ips in sorted(bots.items(), key=lambda x: len(x[1]), reverse=True):
        print(f"{fp:<47} {len(ips):>6}")

# ── ⭐ Extra Credit Task: --top-commands ─────────────────────────────────────

def analyze_top_commands(path: str):
    """⭐ Extra Credit: List the most common shell commands attempted during sessions."""
    command_pattern = re.compile(r"CMD: (.+)")
    commands = Counter()

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            # regex assisted by ChatGPT: prompt "regex to extract command after CMD: from Cowrie logs"
            match = command_pattern.search(line)
            if match:
                cmd = match.group(1).strip()
                commands[cmd] += 1

    print("Most common shell commands")
    _print_counter(commands, "Command", "Count")

# ── CLI ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Cowrie log analyzer — student template")
    parser.add_argument("logfile", help="Path to log file")
    parser.add_argument("--task",
                        required=True,
                        choices=["failed-logins", "connections",
                                 "successful-creds", "identify-bots", "top-commands"],
                        help="Which analysis to run")
    parser.add_argument("--min-count", type=int, default=1,
                        help="Min events to report (failed-logins)")
    parser.add_argument("--min-ips", type=int, default=3,
                        help="Min IPs per fingerprint (identify-bots)")
    args = parser.parse_args()

    if args.task == "failed-logins":
        analyze_failed_logins(args.logfile, args.min_count)
    elif args.task == "connections":
        connections(args.logfile)
    elif args.task == "successful-creds":
        analyze_successful_creds(args.logfile)
    elif args.task == "identify-bots":
        identify_bots(args.logfile, args.min_ips)
    elif args.task == "top-commands":
        analyze_top_commands(args.logfile)

if __name__ == "__main__":
    main()
