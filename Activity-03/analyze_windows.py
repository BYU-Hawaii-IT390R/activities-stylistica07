"""Windows Admin Toolkit – reference solution
-------------------------------------------------
Requires **pywin32** (``pip install pywin32``) and works on Win10/11.

Implemented tasks (select with ``--task``):

* **win-events**       – failed & successful logons from the Security log
* **win-pkgs**         – list installed software (DisplayName + Version)
* **win-services**     – check service states; auto‑start if ``--fix`` flag supplied
* **win-startup**      – list user startup items from registry
* **win-firewall**     – show inbound firewall rules with IP 0.0.0.0/0
"""

from __future__ import annotations
import argparse
import collections
import csv
import datetime as _dt
import io
import re
import subprocess
import sys
from pathlib import Path
from xml.etree import ElementTree as ET

try:
    import win32evtlog  # type: ignore
    import winreg  # std‑lib but Windows‑only
except ImportError:
    sys.stderr.write("pywin32 required → pip install pywin32\n")
    sys.exit(1)

# ── Constants / regex ──────────────────────────────────────────────────────
SECURITY_CHANNEL = "Security"
EVENT_FAILED = "4625"
EVENT_SUCCESS = "4624"
IP_RE = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")

# ── Utility: pretty Counter table ──────────────────────────────────────────

def _print_counter(counter: dict, h1: str, h2: str):
    if not counter:
        print("(no data)\n")
        return
    width = max(len(str(k)) for k in counter)
    print(f"{h1:<{width}} {h2:>8}")
    print("-" * (width + 9))
    for k, v in sorted(counter.items(), key=lambda item: item[1], reverse=True):
        print(f"{k:<{width}} {v:>8}")
    print()

# ══════════════════════════════════════════════════════════════════════════
# Task 1: Event‑Log triage (win-events)
# ══════════════════════════════════════════════════════════════════════════

def _query_security_xml(hours_back: int):
    delta_sec = hours_back * 3600
    q = (
        f"*[(System/TimeCreated[timediff(@SystemTime) <= {delta_sec}] "
        f"and (System/EventID={EVENT_FAILED} or System/EventID={EVENT_SUCCESS}))]"
    )
    try:
        h = win32evtlog.EvtQuery(SECURITY_CHANNEL, win32evtlog.EvtQueryReverseDirection, q)
    except Exception as e:
        if getattr(e, "winerror", None) == 5:
            sys.exit("❌ Access denied – run as Administrator or add your account to *Event Log Readers* group.")
        raise
    while True:
        try:
            ev = win32evtlog.EvtNext(h, 1)[0]
        except IndexError:
            break
        yield win32evtlog.EvtRender(ev, win32evtlog.EvtRenderEventXml)

def _parse_event(xml_str: str):
    root = ET.fromstring(xml_str)
    eid = root.findtext("./System/EventID")
    data = {n.attrib.get("Name"): n.text for n in root.findall("./EventData/Data")}
    user = data.get("TargetUserName") or data.get("SubjectUserName") or "?"
    ip = data.get("IpAddress") or "?"
    if ip == "?":
        m = IP_RE.search(xml_str)
        if m:
            ip = m.group()
    return eid, user, ip

def win_events(hours_back: int, min_count: int):
    failed = collections.Counter()
    success = collections.defaultdict(set)
    for xml_str in _query_security_xml(hours_back):
        eid, user, ip = _parse_event(xml_str)
        if eid == EVENT_FAILED and ip != "?":
            failed[ip] += 1
        elif eid == EVENT_SUCCESS and user not in ("-", "?"):
            success[user].add(ip)

    print(f"\n❌ Failed logons ≥{min_count} (last {hours_back}h)")
    _print_counter({ip: c for ip, c in failed.items() if c >= min_count}, "Source IP", "Count")

    print(f"✅ Successful logons ≥{min_count} IPs (last {hours_back}h)")
    succ = {u: ips for u, ips in success.items() if len(ips) >= min_count}
    width = max((len(u) for u in succ), default=8)
    print(f"{'Username':<{width}} {'IPs':>8}")
    print("-" * (width + 9))
    for user, ips in sorted(succ.items(), key=lambda item: len(item[1]), reverse=True):
        print(f"{user:<{width}} {len(ips):>8}")
    print()

# ══════════════════════════════════════════════════════════════════════════
# Task 2: Installed software audit (win-pkgs)
# ══════════════════════════════════════════════════════════════════════════

UNINSTALL_PATHS = [
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
]

def win_pkgs(csv_path: str | None):
    rows: list[tuple[str, str]] = []
    for root, path in UNINSTALL_PATHS:
        try:
            hive = winreg.OpenKey(root, path)
        except FileNotFoundError:
            continue
        for i in range(winreg.QueryInfoKey(hive)[0]):
            try:
                sub = winreg.OpenKey(hive, winreg.EnumKey(hive, i))
                name, _ = winreg.QueryValueEx(sub, "DisplayName")
                ver, _ = winreg.QueryValueEx(sub, "DisplayVersion")
                rows.append((name, ver))
            except FileNotFoundError:
                continue
    print(f"\n🗃 Installed software ({len(rows)} entries)")
    width = max(len(n) for n, _ in rows)
    print(f"{'DisplayName':<{width}} Version")
    print("-" * (width + 8))
    for name, ver in sorted(rows):
        print(f"{name:<{width}} {ver}")
    print()
    if csv_path:
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerows(rows)
        print(f"📑 CSV exported → {csv_path}\n")

# ══════════════════════════════════════════════════════════════════════════
# Task 3: Service status checker (win-services)
# ══════════════════════════════════════════════════════════════════════════

COLOR_OK = "\033[92m"
COLOR_BAD = "\033[91m"
COLOR_RESET = "\033[0m"

def _service_state(name: str) -> str:
    out = subprocess.check_output(["sc", "query", name], text=True, stderr=subprocess.STDOUT)
    return "RUNNING" if "RUNNING" in out else "STOPPED"

def win_services(watch: list[str], auto_fix: bool):
    if not watch:
        watch = ["Spooler", "wuauserv"]
    print("\n🩺 Service status")
    for svc in watch:
        state = _service_state(svc)
        ok = state == "RUNNING"
        colour = COLOR_OK if ok else COLOR_BAD
        print(f"{svc:<20} {colour}{state}{COLOR_RESET}")
        if not ok and auto_fix:
            print(f"  ↳ attempting to start {svc} …", end="")
            subprocess.call(["sc", "start", svc], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            state = _service_state(svc)
            print("done" if state == "RUNNING" else "failed")
    print()

# ══════════════════════════════════════════════════════════════════════════
# Task 4: Startup Programs Audit (win-startup)
# ══════════════════════════════════════════════════════════════════════════

# ChatGPT-assisted snippet: Registry read loop and error messaging
def win_startup():
    print("\n🚀 Startup Programs from HKCU\\...\\Run")
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run")
        i = 0
        while True:
            try:
                name, value, _ = winreg.EnumValue(key, i)
                print(f"{name:<30} {value}")
                i += 1
            except OSError:
                break
        winreg.CloseKey(key)
    except PermissionError:
        print("❌ Access denied – run as Administrator.")
    except Exception as e:
        print(f"⚠️ Error reading startup items: {e}")

# ══════════════════════════════════════════════════════════════════════════
# Task 5: Inbound Firewall Rule Audit (win-firewall)
# ══════════════════════════════════════════════════════════════════════════

# ChatGPT-assisted snippet: Parsed netsh rule output
def win_firewall():
    print("\n🧱 Inbound Firewall Rules Allowing 0.0.0.0/0")
    try:
        result = subprocess.run(['netsh', 'advfirewall', 'firewall', 'show', 'rule', 'name=all'],
                                capture_output=True, text=True)
        rules = result.stdout.split("-------------------------------------------------------------------")
        for rule in rules:
            if "Direction: In" in rule and "RemoteIP: 0.0.0.0/0" in rule:
                match = re.search(r"Rule Name:\s+(.*)", rule)
                if match:
                    print(f"⚠️ {match.group(1)}")
    except subprocess.SubprocessError as e:
        print(f"❌ netsh command failed: {e}")
    except Exception as e:
        print(f"⚠️ Unexpected error: {e}")

# ══════════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════════

def main():
    p = argparse.ArgumentParser(description="Windows admin toolkit (IT 390R)")
    p.add_argument("--task", required=True,
                   choices=["win-events", "win-pkgs", "win-services", "win-startup", "win-firewall"],
                   help="Which analysis to run")

    p.add_argument("--hours", type=int, default=24,
                   help="Look‑back window for Security log (win-events)")
    p.add_argument("--min-count", type=int, default=1,
                   help="Min occurrences before reporting (win-events)")

    p.add_argument("--csv", metavar="FILE", default=None,
                   help="Export installed-software list to CSV (win-pkgs)")

    p.add_argument("--watch", nargs="*", metavar="SVC", default=[],
                   help="Service names to check (win-services)")
    p.add_argument("--fix", action="store_true",
                   help="Attempt to start stopped services (win-services)")

    args = p.parse_args()

    if args.task == "win-events":
        win_events(args.hours, args.min_count)
    elif args.task == "win-pkgs":
        win_pkgs(args.csv)
    elif args.task == "win-services":
        win_services(args.watch, args.fix)
    elif args.task == "win-startup":
        win_startup()
    elif args.task == "win-firewall":
        win_firewall()

if __name__ == "__main__":
    main()
