#!/usr/bin/env python3
"""
================================================================================
  AuthGuard Log Analyzer v1.2
  Author: Jayden Harper
  GitHub: github.com/jhars2/authguard-log-analyzer

  Description:
      A cross-platform authentication log analysis tool built for SOC
      (Security Operations Center) use. Detects suspicious login behavior,
      privilege abuse, and brute-force patterns in system auth logs.
      Outputs color-coded terminal findings and a structured incident report.

  Supported Platforms:
      - Linux   (auto-detects journald or flat log files)
      - Windows (Security Event Log via pywin32)

  Detections:
      1.  Brute Force Attempts
      2.  Successful Login After Multiple Failures (Possible Compromise)
      3.  Logins at Unusual Hours
      4.  Unknown User Login
      5.  Credential Stuffing (Multiple Source IPs per User)
      6.  Root / Admin Login Attempts
      7.  Logins from Unknown IPs
      8.  Account Lockouts
      9.  Privilege Escalation (sudo failures + unknown sudo usage)
      10. SSH Anomalies (invalid users, pre-auth scan behavior)

  Usage:
      python3 log_analyzer.py              # Auto-detects log source
      python3 log_analyzer.py --sample     # Run against the included demo log
      sudo python3 log_analyzer.py         # Required on most Linux systems
================================================================================
"""

import re
import os
import sys
import shutil
import platform
import subprocess
from datetime import datetime, timedelta
from collections import defaultdict


# ──────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# These values control detection sensitivity. Adjust them to fit the system
# being analyzed — a high-traffic server needs different thresholds than
# a personal workstation.
# ──────────────────────────────────────────────────────────────────────────────

# How many failed logins within the time window triggers a brute force alert
BRUTE_FORCE_THRESHOLD = 5

# The time window (in minutes) for the brute force sliding window check
BRUTE_FORCE_WINDOW_MINUTES = 10

# Business hours (24h). Logins outside this range get flagged.
NORMAL_HOURS_START = 7    # 7:00 AM
NORMAL_HOURS_END   = 20   # 8:00 PM

# Expected/known usernames on this system. Customize per deployment.
# Logins from accounts NOT in this list are flagged as unknown users.
KNOWN_USERS = {"root", "admin", "administrator", "vagrant"}

# Trusted IP addresses. Logins from IPs NOT in this list are flagged.
# Add your office IP, VPN range, etc. for meaningful results.
KNOWN_IPS = {"127.0.0.1", "::1"}

# Candidate flat log file paths — tried in order if journald is not available.
# Debian/Ubuntu (older) → auth.log
# RHEL/CentOS/Fedora   → secure
# Fallback              → syslog
LINUX_LOG_CANDIDATES = [
    "/var/log/auth.log",
    "/var/log/secure",
    "/var/log/syslog",
]

# Output report filename — timestamped so each run produces a unique file
REPORT_FILENAME = f"authguard_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

# Populated at runtime by prompting the analyst
ANALYST_NAME = "Not specified"
SYSTEM_LABEL = platform.node()


# ──────────────────────────────────────────────────────────────────────────────
# REGEX PATTERNS
# Compiled once at startup for performance. Pre-compiling avoids rebuilding
# the pattern object on every log line — important for large log files.
# ──────────────────────────────────────────────────────────────────────────────

# Failed SSH password attempt
# Example: "Apr  1 03:22:11 server sshd[1234]: Failed password for root from 192.168.1.5 port 22 ssh2"
LINUX_FAIL_PATTERN = re.compile(
    r'(\w{3}\s+\d+\s[\d:]+).*Failed password for (?:invalid user )?(\S+) from ([\d.]+)'
)

# Successful SSH login (password or public key)
LINUX_SUCCESS_PATTERN = re.compile(
    r'(\w{3}\s+\d+\s[\d:]+).*Accepted (?:password|publickey) for (\S+) from ([\d.]+)'
)

# SSH attempt using a username that doesn't exist on the system
# Example: "Invalid user oracle from 198.51.100.8"
LINUX_INVALID_USER_PATTERN = re.compile(
    r'(\w{3}\s+\d+\s[\d:]+).*Invalid user (\S+) from ([\d.]+)'
)

# Unauthorized sudo attempt (classic auth.log format)
# Example: "server sudo: jay : command not allowed ; TTY=pts/0 ..."
LINUX_SUDO_FAIL_PATTERN = re.compile(
    r'(\w{3}\s+\d+\s[\d:]+).*sudo:\s+(\w+)\s+:.*command not allowed'
)

# Successful sudo usage (journald format)
# Example: "sudo[1234]:   j : TTY=pts/0 ; USER=root ; COMMAND=/bin/bash"
# Used to flag sudo usage by accounts not in KNOWN_USERS.
LINUX_SUDO_USE_PATTERN = re.compile(
    r'(\w{3}\s+\d+\s[\d:]+).*sudo\[\d+\]:\s+(\w+)\s+:.*USER=(\w+).*COMMAND=(\S+)'
)

# SSH pre-authentication disconnect — strong indicator of automated scanning
LINUX_PREAUTH_PATTERN = re.compile(
    r'(\w{3}\s+\d+\s[\d:]+).*Received disconnect from ([\d.]+).*\[preauth\]'
)

# PAM account lockout
LINUX_LOCKOUT_PATTERN = re.compile(
    r'(\w{3}\s+\d+\s[\d:]+).*pam_tally.*user (\S+) \((\d+)\)'
)


# ──────────────────────────────────────────────────────────────────────────────
# LOG SOURCE DETECTION
# ──────────────────────────────────────────────────────────────────────────────

def has_journald() -> bool:
    """
    Check whether systemd-journald is the active logging system.

    Modern Debian, Ubuntu, and most systemd-based distros use journald
    as their primary log store instead of flat files. We detect it by
    checking for the journalctl binary and the journal store directory.

    Returns:
        bool: True if journald should be used as the log source.
    """
    return shutil.which("journalctl") is not None and (
        os.path.isdir("/var/log/journal") or os.path.isdir("/run/log/journal")
    )


def read_journal_lines() -> list[str]:
    """
    Pull auth-related log entries from the systemd journal.

    Uses --grep to filter for SSH and sudo keywords across all units,
    which is more reliable than filtering by unit name (unit names vary
    by distro and SSH server package). Output is in 'short' format,
    which produces syslog-style lines compatible with our regex patterns.

    Returns:
        list[str]: Filtered log lines, or empty list on failure.
    """
    try:
        result = subprocess.run(
            [
                "journalctl",
                "--no-pager",
                "-o", "short",
                "--since", "30 days ago",
                "--grep", "sshd|sudo|Failed password|Accepted|Invalid user|pam_unix",
            ],
            capture_output=True,
            text=True,
            timeout=30
        )
        lines = result.stdout.splitlines()
        # Strip journalctl separator lines (e.g. "-- Boot abc123 --")
        return [l for l in lines if not l.startswith("--")]
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []


def find_linux_log() -> str | None:
    """
    Find a flat auth log file on this system.

    Tries known log paths in order. Returns the first one that exists,
    or None if none are found (in which case journald is likely in use).

    Returns:
        str | None: Path to the log file, or None.
    """
    for path in LINUX_LOG_CANDIDATES:
        if os.path.exists(path):
            return path
    return None


# ──────────────────────────────────────────────────────────────────────────────
# UTILITY FUNCTIONS
# ──────────────────────────────────────────────────────────────────────────────

def parse_linux_timestamp(raw_ts: str) -> datetime:
    """
    Parse a syslog-style timestamp string into a datetime object.

    Linux auth logs and journald short format both use timestamps like
    "Apr  1 03:22:11" — no year included. We substitute the current year,
    which works correctly for logs from the current calendar year.

    Args:
        raw_ts (str): Timestamp string, e.g. "Apr  1 03:22:11"

    Returns:
        datetime: Parsed datetime, or datetime.min on failure.
    """
    try:
        return datetime.strptime(f"{datetime.now().year} {raw_ts.strip()}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return datetime.min


def is_unusual_hour(dt: datetime) -> bool:
    """
    Return True if the datetime falls outside configured business hours.

    Args:
        dt (datetime): The datetime to evaluate.

    Returns:
        bool: True if outside NORMAL_HOURS_START to NORMAL_HOURS_END.
    """
    return not (NORMAL_HOURS_START <= dt.hour < NORMAL_HOURS_END)


def severity_sort_key(finding: dict) -> int:
    """Numeric sort key so findings display CRITICAL first."""
    return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(
        finding["severity"], 99
    )


# ──────────────────────────────────────────────────────────────────────────────
# CORE DETECTION ENGINE — LINUX
# ──────────────────────────────────────────────────────────────────────────────

def analyze_linux_logs(log_path: str | None = None, lines: list[str] | None = None) -> list[dict]:
    """
    Run all detection logic against Linux auth log entries.

    Accepts either a file path (flat log) or a pre-loaded list of lines
    (from journald). Both produce the same syslog-style text, so the same
    regex patterns apply to both without modification.

    Detection strategy:
        - Single O(n) pass through all lines
        - Per-user state is accumulated as we go
        - Threshold-based checks (brute force, credential stuffing) run
          after the full pass when the complete picture is available

    Args:
        log_path (str | None): Path to a flat auth log file.
        lines (list[str] | None): Pre-loaded lines from journald.

    Returns:
        list[dict]: Findings, each with 'severity', 'detection',
                    'detail', and 'timestamp' keys.
    """
    findings = []

    # State tracked across the full log pass
    fail_times    = defaultdict(list)  # user  → [datetime, ...] of failures
    fail_ips      = defaultdict(set)   # user  → {IPs} that attempted failures
    seen_users    = set()              # users with at least one successful login
    preauth_count = defaultdict(int)   # IP    → count of pre-auth disconnects

    # ── Resolve line source ──
    if lines is not None:
        log_lines = lines
    elif log_path is not None:
        if not os.path.exists(log_path):
            print(f"\n  [!] Log file not found: {log_path}")
            print(f"      Try running with sudo for read access.")
            return findings
        with open(log_path, "r", errors="replace") as fh:
            log_lines = fh.readlines()
    else:
        print("\n  [!] No log source provided.")
        return findings

    # ── Single pass through all lines ──
    for line in log_lines:

        # Detection 1/2/6/7/3 — Failed login attempt
        match = LINUX_FAIL_PATTERN.search(line)
        if match:
            raw_ts, user, ip = match.groups()
            dt = parse_linux_timestamp(raw_ts)
            fail_times[user].append(dt)
            fail_ips[user].add(ip)

            if user.lower() in ("root", "admin", "administrator"):
                findings.append({
                    "severity":  "HIGH",
                    "detection": "Root/Admin Login Attempt",
                    "detail":    f"Failed login for privileged account '{user}' from {ip}",
                    "timestamp": raw_ts.strip()
                })

            if ip not in KNOWN_IPS:
                findings.append({
                    "severity":  "MEDIUM",
                    "detection": "Login from Unknown IP",
                    "detail":    f"User '{user}' login attempt from unrecognized IP {ip}",
                    "timestamp": raw_ts.strip()
                })

            if is_unusual_hour(dt):
                findings.append({
                    "severity":  "MEDIUM",
                    "detection": "Login Attempt at Unusual Hour",
                    "detail":    f"Failed login for '{user}' from {ip} at {dt.strftime('%H:%M')} — outside business hours",
                    "timestamp": raw_ts.strip()
                })
            continue

        # Detection 2/4/3 — Successful login
        match = LINUX_SUCCESS_PATTERN.search(line)
        if match:
            raw_ts, user, ip = match.groups()
            dt = parse_linux_timestamp(raw_ts)
            seen_users.add(user)

            if fail_times[user]:
                findings.append({
                    "severity":  "CRITICAL",
                    "detection": "Successful Login After Multiple Failures",
                    "detail":    f"'{user}' logged in from {ip} after {len(fail_times[user])} failure(s) — possible credential compromise",
                    "timestamp": raw_ts.strip()
                })

            if user not in KNOWN_USERS:
                findings.append({
                    "severity":  "MEDIUM",
                    "detection": "Unknown User Login",
                    "detail":    f"'{user}' is not in the known-users baseline — login from {ip}",
                    "timestamp": raw_ts.strip()
                })

            if is_unusual_hour(dt):
                findings.append({
                    "severity":  "HIGH",
                    "detection": "Successful Login at Unusual Hour",
                    "detail":    f"'{user}' logged in from {ip} at {dt.strftime('%H:%M')} — outside business hours",
                    "timestamp": raw_ts.strip()
                })
            continue

        # Detection 10 — SSH invalid user (recon indicator)
        match = LINUX_INVALID_USER_PATTERN.search(line)
        if match:
            raw_ts, user, ip = match.groups()
            findings.append({
                "severity":  "MEDIUM",
                "detection": "SSH Invalid User Attempt",
                "detail":    f"SSH attempt for non-existent user '{user}' from {ip} — possible reconnaissance",
                "timestamp": raw_ts.strip()
            })
            continue

        # Detection 9a — Unauthorized sudo (classic format)
        match = LINUX_SUDO_FAIL_PATTERN.search(line)
        if match:
            raw_ts, user = match.groups()
            findings.append({
                "severity":  "HIGH",
                "detection": "Unauthorized Sudo Attempt",
                "detail":    f"'{user}' attempted a sudo command they are not permitted to run",
                "timestamp": raw_ts.strip()
            })
            continue

        # Detection 9b — Sudo usage by unknown user (journald format)
        match = LINUX_SUDO_USE_PATTERN.search(line)
        if match:
            raw_ts, user, target_user, command = match.groups()
            if user not in KNOWN_USERS:
                findings.append({
                    "severity":  "MEDIUM",
                    "detection": "Sudo Usage by Unknown User",
                    "detail":    f"'{user}' ran a privileged command as '{target_user}': {command}",
                    "timestamp": raw_ts.strip()
                })
            continue

        # Detection 10 — Pre-auth SSH disconnect (scan behavior)
        match = LINUX_PREAUTH_PATTERN.search(line)
        if match:
            raw_ts, ip = match.groups()
            preauth_count[ip] += 1
            continue

    # ── Post-pass: threshold-based detections ──

    # Detection 1 — Brute force: sliding window over per-user failure timestamps
    for user, timestamps in fail_times.items():
        timestamps.sort()
        window = timedelta(minutes=BRUTE_FORCE_WINDOW_MINUTES)
        for i, start_time in enumerate(timestamps):
            count = sum(1 for t in timestamps[i:] if t - start_time <= window)
            if count >= BRUTE_FORCE_THRESHOLD:
                findings.append({
                    "severity":  "CRITICAL",
                    "detection": "Brute Force Attempt",
                    "detail":    f"'{user}' had {count} failed logins within {BRUTE_FORCE_WINDOW_MINUTES} minutes — source IPs: {', '.join(fail_ips[user])}",
                    "timestamp": timestamps[i].strftime("%b %d %H:%M:%S")
                })
                break

    # Detection 5 — Credential stuffing: same user targeted from 3+ IPs
    for user, ips in fail_ips.items():
        if len(ips) >= 3:
            findings.append({
                "severity":  "HIGH",
                "detection": "Credential Stuffing / Multi-Source Attack",
                "detail":    f"'{user}' received login attempts from {len(ips)} distinct IPs: {', '.join(ips)}",
                "timestamp": "Multiple"
            })

    # Detection 10 — High pre-auth disconnect count = likely automated scanner
    for ip, count in preauth_count.items():
        if count >= 10:
            findings.append({
                "severity":  "MEDIUM",
                "detection": "SSH Pre-Auth Scan Behavior",
                "detail":    f"IP {ip} caused {count} pre-auth disconnects — consistent with automated scanning",
                "timestamp": "Multiple"
            })

    return findings


# ──────────────────────────────────────────────────────────────────────────────
# CORE DETECTION ENGINE — WINDOWS
# ──────────────────────────────────────────────────────────────────────────────

def analyze_windows_logs() -> list[dict]:
    """
    Parse the Windows Security Event Log for authentication anomalies.

    Requires pywin32: pip install pywin32

    Relevant Event IDs:
        4625 — Failed logon
        4624 — Successful logon
        4672 — Special privileges assigned (privilege escalation indicator)
        4740 — Account lockout

    Returns:
        list[dict]: Findings in the same structure as analyze_linux_logs.
    """
    findings = []

    try:
        import win32evtlog
    except ImportError:
        findings.append({
            "severity":  "INFO",
            "detection": "Windows Module Missing",
            "detail":    "pywin32 is required for Windows analysis. Install with: pip install pywin32",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })
        return findings

    fail_times = defaultdict(list)
    fail_ips   = defaultdict(set)

    log_handle = win32evtlog.OpenEventLog(None, "Security")
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

    while True:
        events = win32evtlog.ReadEventLog(log_handle, flags, 0)
        if not events:
            break

        for event in events:
            event_id = event.EventID & 0xFFFF
            raw_ts   = event.TimeGenerated.Format()
            dt       = datetime.strptime(raw_ts, "%c")
            strings  = event.StringInserts or []

            if event_id == 4625 and len(strings) >= 13:
                user = strings[5]
                ip   = strings[19] if len(strings) > 19 else "N/A"
                fail_times[user].append(dt)
                fail_ips[user].add(ip)
                if user.lower() in ("administrator", "admin", "root"):
                    findings.append({
                        "severity":  "HIGH",
                        "detection": "Admin Login Attempt",
                        "detail":    f"Failed logon for privileged account '{user}' from {ip}",
                        "timestamp": raw_ts
                    })
                if is_unusual_hour(dt):
                    findings.append({
                        "severity":  "MEDIUM",
                        "detection": "Login Attempt at Unusual Hour",
                        "detail":    f"Failed logon for '{user}' from {ip} at {dt.strftime('%H:%M')}",
                        "timestamp": raw_ts
                    })

            elif event_id == 4624 and len(strings) >= 13:
                user = strings[5]
                ip   = strings[18] if len(strings) > 18 else "N/A"
                if fail_times[user]:
                    findings.append({
                        "severity":  "CRITICAL",
                        "detection": "Successful Login After Failures",
                        "detail":    f"'{user}' succeeded from {ip} after {len(fail_times[user])} prior failure(s)",
                        "timestamp": raw_ts
                    })
                if is_unusual_hour(dt):
                    findings.append({
                        "severity":  "HIGH",
                        "detection": "Successful Login at Unusual Hour",
                        "detail":    f"'{user}' logged in from {ip} at {dt.strftime('%H:%M')}",
                        "timestamp": raw_ts
                    })

            elif event_id == 4740 and strings:
                findings.append({
                    "severity":  "HIGH",
                    "detection": "Account Lockout",
                    "detail":    f"Account '{strings[0]}' was locked out — likely repeated failed attempts",
                    "timestamp": raw_ts
                })

            elif event_id == 4672 and strings:
                user = strings[1]
                if user.lower() not in KNOWN_USERS:
                    findings.append({
                        "severity":  "HIGH",
                        "detection": "Privilege Escalation (Event 4672)",
                        "detail":    f"Special privileges assigned to '{user}' — verify this is authorized",
                        "timestamp": raw_ts
                    })

    win32evtlog.CloseEventLog(log_handle)

    for user, timestamps in fail_times.items():
        timestamps.sort()
        window = timedelta(minutes=BRUTE_FORCE_WINDOW_MINUTES)
        for i, start_time in enumerate(timestamps):
            count = sum(1 for t in timestamps[i:] if t - start_time <= window)
            if count >= BRUTE_FORCE_THRESHOLD:
                findings.append({
                    "severity":  "CRITICAL",
                    "detection": "Brute Force Attempt",
                    "detail":    f"'{user}' had {count} failed logons within {BRUTE_FORCE_WINDOW_MINUTES} minutes",
                    "timestamp": timestamps[i].strftime("%Y-%m-%d %H:%M:%S")
                })
                break

    return findings


# ──────────────────────────────────────────────────────────────────────────────
# REPORT BUILDER
# ──────────────────────────────────────────────────────────────────────────────

def build_report(findings: list[dict], os_name: str, log_source: str) -> str:
    """
    Build a formatted incident report string from findings.

    Structure mirrors standard SOC documentation:
        1. Header with scan metadata
        2. Executive summary with severity counts
        3. Detailed findings sorted by severity
        4. Contextual recommendations
        5. Footer

    Args:
        findings   (list[dict]): Findings from the detection engine.
        os_name    (str):        OS name (e.g. "Linux", "Windows").
        log_source (str):        Log path or source label.

    Returns:
        str: Complete formatted report.
    """
    now    = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    DIV    = "=" * 80
    SUBDIV = "-" * 80

    sorted_findings = sorted(findings, key=severity_sort_key)
    counts = defaultdict(int)
    for f in findings:
        counts[f["severity"]] += 1

    lines = [
        DIV,
        "  AUTHGUARD LOG ANALYZER — SECURITY INCIDENT REPORT",
        DIV,
        f"  Report Generated : {now}",
        f"  Analyzed System  : {os_name}",
        f"  Log Source       : {log_source}",
        f"  Tool Version     : AuthGuard v1.2",
        f"  Analyst          : {ANALYST_NAME}",
        f"  Host / Label     : {SYSTEM_LABEL}",
        DIV, "",
        "  EXECUTIVE SUMMARY",
        SUBDIV,
        f"  Total Findings   : {len(findings)}",
        f"  CRITICAL         : {counts.get('CRITICAL', 0)}",
        f"  HIGH             : {counts.get('HIGH', 0)}",
        f"  MEDIUM           : {counts.get('MEDIUM', 0)}",
        f"  LOW              : {counts.get('LOW', 0)}",
        f"  INFO             : {counts.get('INFO', 0)}",
        "",
    ]

    if counts.get("CRITICAL", 0) > 0:
        lines.append("  *** IMMEDIATE ATTENTION REQUIRED — CRITICAL FINDINGS PRESENT ***")
    elif counts.get("HIGH", 0) > 0:
        lines.append("  *** HIGH-SEVERITY FINDINGS REQUIRE PROMPT REVIEW ***")
    elif findings:
        lines.append("  No critical or high-severity findings detected.")
    else:
        lines.append("  No suspicious activity detected in this log source.")

    lines += ["", DIV, "  DETAILED FINDINGS", DIV, ""]

    if not findings:
        lines.append("  Nothing flagged. Either the system is clean or the log source")
        lines.append("  may need a broader time window or elevated permissions.")
    else:
        for idx, f in enumerate(sorted_findings, start=1):
            lines += [
                f"  Finding #{idx:03}",
                SUBDIV,
                f"  Severity   : {f['severity']}",
                f"  Detection  : {f['detection']}",
                f"  Timestamp  : {f['timestamp']}",
                f"  Detail     : {f['detail']}",
                "",
            ]

    lines += [DIV, "  RECOMMENDATIONS", DIV]

    if counts.get("CRITICAL", 0) > 0:
        lines += [
            "  [CRITICAL] Review all critical findings immediately.",
            "  [CRITICAL] Consider isolating affected accounts pending investigation.",
            "  [CRITICAL] Cross-reference affected usernames with Active Directory / LDAP.",
        ]
    if counts.get("HIGH", 0) > 0:
        lines += [
            "  [HIGH]     Audit privileged account usage and enforce least-privilege.",
            "  [HIGH]     Review after-hours login policy and notify system owners.",
        ]
    if counts.get("MEDIUM", 0) > 0:
        lines += [
            "  [MEDIUM]   Update KNOWN_IPS and KNOWN_USERS baselines in the config section.",
            "  [MEDIUM]   Consider IP allowlisting for SSH/RDP access.",
        ]

    lines += [
        "  [GENERAL]  Enforce multi-factor authentication (MFA) on all accounts.",
        "  [GENERAL]  Forward logs to a SIEM (e.g. Splunk, Elastic) for correlation.",
        "  [GENERAL]  Schedule recurring log review — daily minimum for production systems.",
        "",
        DIV,
        "  END OF REPORT — AUTHGUARD v1.2",
        DIV,
    ]

    return "\n".join(lines)


# ──────────────────────────────────────────────────────────────────────────────
# TERMINAL OUTPUT
# ──────────────────────────────────────────────────────────────────────────────

COLORS = {
    "CRITICAL": "\033[91m",  # Bright red
    "HIGH":     "\033[93m",  # Yellow
    "MEDIUM":   "\033[94m",  # Blue
    "LOW":      "\033[92m",  # Green
    "INFO":     "\033[90m",  # Gray
    "RESET":    "\033[0m",
    "BOLD":     "\033[1m",
    "DIM":      "\033[2m",
}

def print_banner():
    """Print the startup banner."""
    b, r = COLORS["BOLD"], COLORS["RESET"]
    print(f"\n{b}{'=' * 70}{r}")
    print(f"{b}  AuthGuard Log Analyzer v1.2{r}")
    print(f"{b}{'=' * 70}{r}\n")

def print_to_terminal(findings: list[dict], os_name: str, log_source: str):
    """
    Print a colorized summary of findings to stdout.

    Findings are sorted by severity (CRITICAL first) and formatted
    for quick human readability during live analysis.

    Args:
        findings   (list[dict]): Findings from the detection engine.
        os_name    (str):        OS name for the header.
        log_source (str):        Log source for the header.
    """
    b, r, dim = COLORS["BOLD"], COLORS["RESET"], COLORS["DIM"]
    div = "=" * 70

    print(f"\n{b}{div}{r}")
    print(f"{b}  SCAN RESULTS — {os_name.upper()}{r}")
    print(f"{dim}  Source: {log_source}{r}")
    print(f"{b}{div}{r}")
    print(f"  Completed : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Findings  : {len(findings)}\n")

    if not findings:
        print(f"  {COLORS['INFO']}[INFO] No suspicious activity detected.{r}")
        print(f"  {dim}If you expected results, try running with sudo or use --sample.{r}\n")
        return

    counts = defaultdict(int)
    for f in findings:
        counts[f["severity"]] += 1

    # Severity summary bar
    for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if counts[level]:
            color = COLORS[level]
            print(f"  {color}[{level}]{r}  {counts[level]} finding(s)")
    print()

    # Detailed findings
    for idx, f in enumerate(sorted(findings, key=severity_sort_key), start=1):
        color = COLORS.get(f["severity"], r)
        print(f"  {color}[{f['severity']}]{r} #{idx:03} — {b}{f['detection']}{r}")
        print(f"  {dim}       Time   : {f['timestamp']}{r}")
        print(f"         Detail : {f['detail']}\n")

    print(f"{b}{div}{r}\n")


# ──────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ──────────────────────────────────────────────────────────────────────────────

def main():
    """
    Main execution function.

    Flow:
        1. Parse --sample flag if present
        2. Auto-detect OS and log source
        3. Prompt analyst for name and system label
        4. Run the appropriate detection engine
        5. Print colorized results to terminal
        6. Write structured incident report to disk
    """
    global ANALYST_NAME, SYSTEM_LABEL

    use_sample = "--sample" in sys.argv

    print_banner()

    if use_sample:
        print("  Mode     : Sample / Demo")
    
    # Analyst prompt
    name_input   = input("  Analyst name (Enter to skip) : ").strip()
    system_input = input("  System label (e.g. web-01)   : ").strip()
    ANALYST_NAME = name_input   if name_input   else "Not specified"
    SYSTEM_LABEL = system_input if system_input else platform.node()
    print()

    os_name = platform.system()
    print(f"  OS detected : {os_name}")

    # ── Route to appropriate engine ──
    if use_sample:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        log_source = os.path.join(script_dir, "sample_auth.log")
        if not os.path.exists(log_source):
            print("\n  [!] sample_auth.log not found.")
            print("      Place it in the same directory as this script.")
            sys.exit(1)
        print(f"  Log source  : {log_source}\n")
        findings = analyze_linux_logs(log_path=log_source)

    elif os_name == "Linux":
        if has_journald():
            log_source = "systemd journal (journalctl)"
            print(f"  Log source  : {log_source}")
            print(f"  Querying journal for auth events...\n")
            journal_lines = read_journal_lines()
            if not journal_lines:
                print("  [*] No matching entries found in the journal.")
                print("  [*] This may mean the system has no recent SSH or sudo activity,")
                print("      or that elevated permissions are needed (try sudo).")
                findings = []
            else:
                print(f"  [*] {len(journal_lines)} entries retrieved\n")
                findings = analyze_linux_logs(lines=journal_lines)
        else:
            log_source = find_linux_log()
            if log_source is None:
                print("\n  [!] No auth log found. Tried:")
                for p in LINUX_LOG_CANDIDATES:
                    print(f"      {p}")
                print("\n  Try running with sudo, or use --sample for the demo log.")
                sys.exit(1)
            print(f"  Log source  : {log_source}\n")
            findings = analyze_linux_logs(log_path=log_source)

    elif os_name == "Windows":
        log_source = "Windows Security Event Log"
        print(f"  Log source  : {log_source}\n")
        findings = analyze_windows_logs()

    elif os_name == "Darwin":
        log_source = "/var/log/system.log"
        print(f"  Log source  : {log_source}")
        print(f"  [!] macOS detected — some detections may not apply.\n")
        findings = analyze_linux_logs(log_path=log_source)

    else:
        print(f"\n  [!] Unsupported OS: {os_name}")
        sys.exit(1)

    # ── Output ──
    print_to_terminal(findings, os_name, log_source)

    report_text = build_report(findings, os_name, log_source)
    with open(REPORT_FILENAME, "w") as f:
        f.write(report_text)

    print(f"  [✓] Report saved → {REPORT_FILENAME}")
    print(f"  [✓] Done.\n")


if __name__ == "__main__":
    main()
