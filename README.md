# AuthGuard Log Analyzer

A cross-platform authentication log analysis tool built for SOC (Security Operations Center) use. Point it at your system logs and it automatically detects the attack patterns that matter — brute force attempts, credential compromise, privilege escalation, and more — then generates a structured incident report.

---

## What It Detects

| # | Detection | Severity |
|---|-----------|----------|
| 1 | Brute Force Attempts | CRITICAL |
| 2 | Successful Login After Multiple Failures | CRITICAL |
| 3 | Root / Admin Login Attempts | HIGH |
| 4 | Credential Stuffing (Multi-IP per User) | HIGH |
| 5 | Privilege Escalation Attempts (sudo / Event 4672) | HIGH |
| 6 | Account Lockouts | HIGH |
| 7 | Logins at Unusual Hours | HIGH / MEDIUM |
| 8 | New / Unknown User Login | MEDIUM |
| 9 | Logins from Unknown IPs | MEDIUM |
| 10 | SSH Anomalies (invalid users, pre-auth scans) | MEDIUM |

---

## Features

- **Auto-detects OS and log source** — routes to Linux (journald or flat log files) or Windows Security Event Log automatically. No arguments needed.
- **Memory-efficient** — reads logs line-by-line using generators. Handles large production logs without loading them into memory.
- **Single O(n) pass** — one read through the log, all 10 detections evaluated simultaneously.
- **Colorized terminal output** — severity-coded findings printed inline as the scan runs.
- **Professional incident report** — auto-generated `.txt` report with executive summary, detailed findings, and actionable recommendations.
- **Tunable thresholds** — brute force window, business hours, and trusted user/IP baselines are all configurable at the top of the script.

---

## Usage

```bash
# Clone the repo
git clone https://github.com/jhars2/authguard-log-analyzer.git
cd authguard-log-analyzer

# Run against your system logs (requires sudo on most Linux systems)
sudo python3 log_analyzer.py

# Run against the included sample log — no sudo needed, works on any OS
python3 log_analyzer.py --sample
```

**Windows** — requires `pywin32`:
```bash
pip install pywin32
python log_analyzer.py
```

---

## Sample Output

![AuthGuard terminal output](screenshot.png)

```
======================================================================
  AuthGuard Log Analyzer v1.2
======================================================================
  Analyst name (Enter to skip) : Jayden Harper
  System label (e.g. web-01)   : debian-homelab

  OS detected : Linux
  Log source  : systemd journal (journalctl)
  Querying journal for auth events...

  [*] 1254 entries retrieved

======================================================================
  SCAN RESULTS — LINUX
  Source: systemd journal (journalctl)
======================================================================
  Completed : 2026-04-07 18:08:48
  Findings  : 24

  [CRITICAL]  1 finding(s)
  [HIGH]      18 finding(s)
  [MEDIUM]    5 finding(s)

  [CRITICAL] #001 — Brute Force Attempt
             Time   : Apr 07 17:42:49
             Detail : 'root' had 11 failed logins within 10 minutes — source IPs: ::1
  ...
```

A full `.txt` incident report is saved automatically in the same directory.

---

## Configuration

At the top of `log_analyzer.py`, adjust these constants to fit the system being analyzed:

```python
BRUTE_FORCE_THRESHOLD      = 5    # failed logins to trigger brute force alert
BRUTE_FORCE_WINDOW_MINUTES = 10   # time window for brute force detection
NORMAL_HOURS_START         = 7    # business hours start (24h)
NORMAL_HOURS_END           = 20   # business hours end (24h)
KNOWN_USERS = {"root", "admin"}   # expected accounts on this system
KNOWN_IPS   = {"127.0.0.1"}       # trusted IP addresses
```

---

## How It Works

The analyzer performs a single O(n) pass through the log file, running all regex patterns against each line simultaneously rather than making multiple passes. Per-user state (failure counts, source IPs, timestamps) is accumulated during the pass, and threshold-based detections like brute force are evaluated after the full log has been read.

On modern Linux systems (Debian, Ubuntu, Arch), logs are read directly from the systemd journal via `journalctl`. On older systems or RHEL-based distros, it falls back to flat log files (`/var/log/auth.log`, `/var/log/secure`). Windows pulls from the Security Event Log via `pywin32`.

---

## Sample Log

A realistic `sample_auth.log` is included for testing and demo purposes. It contains examples of every detection type and can be used on any OS without elevated permissions:

```bash
python3 log_analyzer.py --sample
```

---

## Future Improvements

- [ ] Geolocation lookup for flagged IPs (MaxMind GeoLite2)
- [ ] Threat intel feed matching (AbuseIPDB API)
- [ ] HTML report output
- [ ] SIEM integration (Elastic/Splunk forwarder)
- [ ] Email alerting on CRITICAL findings

---
