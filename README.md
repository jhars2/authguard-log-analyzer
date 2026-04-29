# AuthGuard Log Analyzer

A cross-platform authentication log analysis tool and live SOC dashboard. Detects suspicious login behavior, privilege abuse, and brute-force patterns in system auth logs then displays findings in a real-time web dashboard served over hardened HTTPS.

---

## What It Does

AuthGuard has two components that work together:

**CLI Analyzer** (`log_analyzer.py`) - scans Linux auth logs or Windows Security Event Logs and outputs color-coded findings to the terminal, plus a structured `.txt` incident report.

**Web Dashboard** (`app.py`) - a Flask application that runs the analyzer continuously against the live systemd journal and displays findings in a browser-based SOC dashboard, served through a hardened Apache reverse proxy over HTTPS.

---

## Dashboard

![AuthGuard terminal output](screenshot.png)

The dashboard provides:

- Live findings feed with severity filtering
- Attack timeline chart (findings by hour)
- Detection type breakdown (donut chart)
- Top threat IP sources table
- User risk scoreboard (calculated risk score per account)
- Recent activity event log
- Auto-refresh every 60 seconds

---

## Detections

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

## Installation (Debian / Ubuntu)

The install script sets up the full stack automatically:

```bash
git clone https://github.com/jhars2/authguard-log-analyzer.git
cd authguard-log-analyzer
sudo bash install.sh
```

**What the installer does:**

- Installs Apache, Python, Gunicorn, ModSecurity, and dependencies
- Creates a dedicated low-privilege `authguard` system user
- Generates a self-signed SSL certificate
- Hardens Apache: version hiding, security headers, CSP, ModSecurity WAF with OWASP CRS
- Forces HTTP → HTTPS redirect
- Configures Apache as a reverse proxy to the Flask app via Unix socket
- Installs and enables a systemd service that starts on boot

After installation, the dashboard is available at `https://localhost/dashboard`.

---

## Architecture

```
Browser → Apache (HTTPS/443) → Unix Socket → Gunicorn → Flask → journalctl
```

- **Apache** handles TLS termination, security headers, ModSecurity WAF, and reverse proxying
- **Gunicorn** is the production WSGI server running the Flask app
- **Unix socket** - Flask never exposes a network port; all communication goes through a socket file
- **authguard system user** - the Flask process runs with minimal privileges, only needing read access to the systemd journal via group membership

---

## CLI Usage

```bash
# Run against your system logs (requires sudo on most Linux systems)
sudo python3 log_analyzer.py

# Run against the included sample log (no sudo needed, works on any OS)
python3 log_analyzer.py --sample
```

**Windows** - requires `pywin32`:
```bash
pip install pywin32
python log_analyzer.py
```

---

## Launch Script

Once installed, use the launch script to verify all services are running and open the dashboard:

```bash
bash /opt/authguard/launch.sh
```

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

The analyzer performs a single O(n) pass through the log source, running all regex patterns against each line simultaneously. Per-user state (failure timestamps, source IPs) is accumulated during the pass, and threshold-based detections like brute force use a sliding window evaluated after the full pass.

On modern Linux systems, logs are pulled directly from the systemd journal via `journalctl --grep`. On older systems or RHEL-based distros, it falls back to flat log files (`/var/log/auth.log`, `/var/log/secure`). Windows pulls from the Security Event Log via `pywin32`.

The web dashboard runs as a dedicated system user with no login shell, communicates with Apache through a Unix socket, and never requires root access at runtime.

---

## Sample Log

A realistic `sample_auth.log` is included for testing without elevated permissions:

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
- [ ] Let's Encrypt certificate support for public deployments

---
