# Sentinel Logger

A local web tool to analyze camera log files. Upload logs manually, download them from S3 or directly from a camera over SSH, and get automatic error detection and log visualization.

```bash
pip install git+https://github.com/alonmozesNexar/sentinel-logger.git
sentinel-logger
```

Opens at `http://localhost:9898`.

---

## What It Does

### Get Logs Into the Tool

| Feature | Description |
|---------|-------------|
| **Upload File** | Upload `.log`, `.txt`, `.csv`, `.db`, `.json`, `.xml`, `.zip`, `.gz` files (up to 500 MB). |
| **Paste Text** | Paste log content directly into the browser — no file needed. |
| **S3 Download** | Browse and download logs from the `sdk-logs-prod` S3 bucket by serial number and date. |
| **Camera Download (SSH)** | Connect to a camera over SSH, list log files, download them, and view device info (model, serial, firmware). |
| **Live Stream** | Tail `/var/log/messages` in real-time from a camera via SSH or Serial. |

### Analyze Logs

| Feature | Description |
|---------|-------------|
| **Log Viewer** | View parsed log entries with search (contains, regex, exact match), filter by severity, service, and component. |
| **DB Viewer** | Browse SQLite `.db` files — table browser with search, sort, and pagination. |
| **Error Detection** | Pattern-based detection of crashes, timeouts, memory issues, recording failures, thermal warnings, and more. |

### Other

| Feature | Description |
|---------|-------------|
| **Command Palette** | Press `Ctrl+K` / `Cmd+K` to quickly navigate to any page or action. |
| **Dark Mode** | Toggle between light and dark themes. |
| **System Stats** | Live CPU, memory, and network usage in the navbar. |

---

## Installation

### Requirements

- Python 3.9+
- pip

### Install

```bash
pip install git+https://github.com/alonmozesNexar/sentinel-logger.git
```

### Run

```bash
sentinel-logger
```

The browser opens automatically. To change port or host:

```bash
sentinel-logger --port 5000 --host 0.0.0.0
```

### Update

```bash
pip install --upgrade git+https://github.com/alonmozesNexar/sentinel-logger.git
```

### CLI Options

```
sentinel-logger [--port PORT] [--host HOST] [--no-browser] [--no-update-check] [--debug]
```

---

## Setting Up AWS SSO for S3 Log Downloads

To download logs from S3 (`sdk-logs-prod` bucket), you need AWS credentials. The recommended method is **AWS SSO**.

### Step 1: Configure SSO Profile

Run the AWS SSO configuration wizard:

```bash
aws configure sso
```

When prompted, enter:

| Prompt | Value |
|--------|-------|
| SSO session name | `nexar` (or any name) |
| SSO start URL | Your organization's SSO URL (e.g., `https://nexar.awsapps.com/start`) |
| SSO region | `us-east-1` |
| Account | Select the account that has access to `sdk-logs-prod` |
| Role | Select your role (e.g., `ReadOnlyAccess` or `PowerUserAccess`) |
| CLI default client Region | `us-east-1` |
| CLI default output format | `json` |
| CLI profile name | `nexar-sso` (or any name you prefer) |

This creates a profile in `~/.aws/config`.

### Step 2: Log In

```bash
aws sso login --profile nexar-sso
```

A browser window opens for authentication. After login, your credentials are cached locally.

### Step 3: Tell Sentinel Logger Which Profile to Use

Set the `AWS_PROFILE` environment variable before running:

```bash
export AWS_PROFILE=nexar-sso
sentinel-logger
```

Or add it to a `.env` file in your working directory:

```
AWS_PROFILE=nexar-sso
```

### Step 4: Verify

In Sentinel Logger, go to the **S3 Download** page. The status banner should show "Connected to S3 using profile: nexar-sso".

### Refreshing Expired Credentials

SSO tokens expire after a few hours. When they expire, the S3 page will show an error. Just re-run:

```bash
aws sso login --profile nexar-sso
```

Then refresh the S3 page in the browser.

---

## Optional: Camera SSH Connection

The tool connects to cameras at `192.168.50.1` by default (configurable). Authentication is automatic:

1. SSH key
2. AWS firmware password (from SSM Parameter Store, requires `fw-ops` AWS profile)
3. Empty password (none auth)
4. User-provided password

No setup needed if your SSH keys or AWS profiles are already configured.

To override defaults, set environment variables or use a `.env` file:

```
CAMERA_IP=192.168.50.1
CAMERA_USER=root
CAMERA_PASSWORD=root
CAMERA_SSH_PORT=22
```

---

## Development Setup

```bash
git clone https://github.com/alonmozesNexar/sentinel-logger.git
cd sentinel-logger
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python main.py
```

---

## License

MIT
