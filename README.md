# AYNUO v4.0 — MikroTik Security Assessment Platform

AYNUO performs read-only MikroTik RouterOS security audits and NVD-backed CVE assessments. Live communication uses SSH exclusively. RouterOS API and API-SSL are not used or supported.

## Install and start on Windows

Install Python 3.11 or later, then run:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\run.ps1
```

The launcher creates or reuses `.venv`, installs `requirements.txt`, binds FastAPI to `127.0.0.1`, and opens the dashboard. Manual installation and testing:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m pytest -q
```

## SSH host-key enrollment

AYNUO never silently accepts an unknown SSH host key. In the dashboard, enter the target and click **Inspect key**. Independently verify the SHA-256 fingerprint against RouterOS or a trusted administrator, then click **Trust exact key**. AYNUO stores only public host keys in `data/known_hosts`.

CLI enrollment follows the same two-step workflow:

```powershell
.\.venv\Scripts\python.exe .\aynuo.py trust-host 192.0.2.1
```

If a router key changes, AYNUO fails closed. Remove or replace a key only after independently verifying why it changed.

## CLI

```powershell
# SSH security audit
.\.venv\Scripts\python.exe .\aynuo.py audit 192.0.2.1 sara

# Custom SSH port
.\.venv\Scripts\python.exe .\aynuo.py audit 192.0.2.1 sara --port 2222

# Offline CVE assessment
.\.venv\Scripts\python.exe .\aynuo.py cve --version 7.25.1

# Live CVE assessment (reads the installed version over SSH)
.\.venv\Scripts\python.exe .\aynuo.py cve 192.0.2.1 sara
```

Passwords are prompted without echo and are never stored.

## Dashboard workflows

The dashboard performs one unified SSH security scan. It collects the RouterOS snapshot and version once, then runs the existing audit and CVE engines independently. Missing or unsupported RouterOS menus are marked `not_evaluated`, never passed.

**CVE Assessment** supports live SSH version discovery and manual version entry. Results come from NVD. A CVE is marked confirmed only when NVD provides an exact RouterOS release or explicit version bounds matching the assessed version. Product-wide wildcard records and records without usable ranges are shown as unknown applicability. Data-source failures produce an explicit failed assessment rather than a misleading zero result.

The current unified result is persisted for report delivery. Plaintext passwords are never stored. Results export as JSON, HTML, CSV, or PDF.

## RouterOS account permissions

Use a dedicated RouterOS account that can log in through SSH and read the menus being assessed. AYNUO executes a fixed collection allowlist consisting only of `print` commands. It never runs `set`, `add`, `remove`, `enable`, `disable`, import, reboot, remediation, or user-supplied RouterOS commands.

## Network and application security

- Live targets default to RFC1918 and IPv6 ULA management networks. Override with comma-separated CIDRs in `AYNUO_SSH_NETWORKS`.
- Custom SSH ports from 1–65535 are supported; the peer must complete an SSH handshake and match an enrolled key.
- Concurrent SSH jobs are limited by `AYNUO_SSH_MAX_CONCURRENT` (default `2`).
- The web server binds to localhost. For intentional remote proxying, set `AYNUO_API_TOKEN` and send it in `X-AYNUO-Token`.
- Optionally set `NVD_API_KEY` for higher NVD request limits.
- Uploaded exports are limited to 5 MB and parsed only as text data.

## Architecture

- `app/services/live.py`: Paramiko SSH transport, target policy, host-key enrollment, read-only collection, RouterOS output normalization.
- `app/services/engine.py`: shared audit rules, scoring, coverage, and normalized audit results.
- `aynuomodules/cve.py`: shared NVD client, version-range evaluation, and normalized CVE results.
- `app/main.py`: FastAPI scan jobs, reports, and credential-safe endpoints.
- `frontend/`: unified Overview, Security Scan, Audit Findings, CVE Findings, and Reports dashboard.

## License and attribution

AYNUO preserves applicable code and project history from the original project by Ifrit. The MIT license and copyright attribution remain in `LICENSE`.

