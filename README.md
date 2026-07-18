# HONEYPY

> A lightweight, Python-based honeypot toolkit featuring an emulated SSH jump-box with a fake interactive shell, a decoy WordPress login honeypot, and a unified command-line interface. Built to strengthen network programming fundamentals and demonstrate deception-engineering, protocol-emulation, and CLI-tooling capabilities.

## Badges

![Python](https://img.shields.io/badge/Python-3.11%2B-blue)
![Paramiko](https://img.shields.io/badge/Paramiko-SSH_Emulation-black)
![Flask](https://img.shields.io/badge/Flask-HTTP_Honeypot-000000)
![Sockets](https://img.shields.io/badge/Sockets-Multithreaded-informational)
![Logging](https://img.shields.io/badge/Logging-Rotating_Handlers-green)
![Security](https://img.shields.io/badge/Deception-Engineering-critical)

## Links

[GitHub Repository](https://github.com/harshitparpe/honeypy)

> Note: no public live demo is linked for this project — intentionally, since a honeypot's value comes from being deployed quietly on a private VPS rather than advertised publicly.

## Features

* Emulated SSH honeypot presenting a fake corporate jump-box (`corporate-jumbox2`) using `paramiko`.
* Interactive fake shell supporting `pwd`, `whoami`, `ls`, `cat jumpbox1.conf`, and `exit`, with all other input echoed back.
* Configurable credential enforcement — accept a specific username/password pair, or accept everything to maximize attacker capture.
* HTTP honeypot impersonating a WordPress admin login page (`/wp-admin-login`) using `flask`.
* Configurable decoy credentials, defaulting to the commonly brute-forced `admin` / `password123` pair.
* Multithreaded connection handling — each SSH client is served on its own thread.
* Rotating file-based logging for connection attempts, credentials, and executed commands.
* Unified CLI entry point built with `argparse` supporting both honeypot modes.
* Canary breadcrumb (`cat jumpbox1.conf`) designed to bait attackers toward a tracked follow-up destination.

## Project Metrics

| Metric                     | Value                     |
| -------------------------- | ------------------------- |
| Honeypot Services           | 2 (SSH + HTTP)            |
| Emulated Shell Commands     | 5                         |
| CLI Arguments               | 6                         |
| Log Files Generated         | 3                         |
| Log Rotation Size           | 2,000 bytes / 5 backups   |
| Concurrent Client Handling  | Multithreaded (unbounded) |
| Est. Monthly Hosting Cost   | < $5 (VPS)                |

## Tech Stack

| Category         | Technologies                                  |
| ----------------- | --------------------------------------------- |
| Core Language     | Python 3.11+                                  |
| SSH Emulation     | Paramiko, Socket, Threading                    |
| HTTP Emulation    | Flask                                          |
| CLI Tooling       | argparse                                       |
| Logging           | logging, RotatingFileHandler                   |
| Deployment        | Linux VPS (e.g. Hostinger), systemd / tmux     |

## Architecture

The platform separates concerns across connection handling, protocol emulation, credential capture, and command-line orchestration.

### SSH Emulation Layer

* Raw TCP socket listener bound to a configurable address/port
* Paramiko-based transport spoofing an SSH banner and RSA host key
* Per-connection threading for concurrent attacker sessions

### Shell Emulation Layer

* Character-by-character input capture with live echo
* Hardcoded responses for recon-style commands (`pwd`, `whoami`, `ls`)
* Canary file (`jumpbox1.conf`) used to bait and track follow-on attacker behavior

### HTTP Emulation Layer

* Flask application impersonating a WordPress admin login page
* Configurable decoy credentials with realistic success/failure responses
* Per-request IP and credential logging

### Credential Capture Layer

* Dual logging streams: connection-level (`funnel_logger`) and command/credential-level (`creds_logger`)
* Rotating log files to prevent unbounded disk growth

### CLI Orchestration Layer

* `argparse`-driven entry point (`honeypy.py`)
* Mode selection between SSH (`--ssh`) and HTTP (`--http`) honeypots
* Graceful exception handling on shutdown

## Core Modules

### SSH Honeypot Engine

Paramiko-based server built around:

* `Server` class — implements `paramiko.ServerInterface`, handles authentication and channel requests
* `emulated_shell()` — drives the fake interactive terminal
* `client_handle()` — manages per-connection transport setup and teardown
* `honeypot()` — binds the listening socket and dispatches client threads

### HTTP Honeypot Engine

Flask-based application built around:

* `web_honeypot()` — constructs the Flask app and registers routes
* `run_web_honeypot()` — launches the app on a configurable host/port
* Login route capturing and logging every submitted credential pair

### CLI Interface

`argparse`-based entry point supporting:

* Address and port configuration
* Optional decoy username/password
* Mutually exclusive honeypot mode selection (`--ssh` / `--http`)

## Log Files

#### `audits.log`: SSH connection attempts — source IP, username, and password for every login try.
#### `cmd_audits.log`: Commands executed by attackers inside the emulated shell, plus credential attempt records.
#### `http_audits.log`: HTTP login attempts against the fake WordPress page — timestamp, IP, username, and password.

## HTTP Endpoints

| Method | Endpoint             | Description                              |
| ------ | --------------------- | ----------------------------------------- |
| GET    | `/`                    | Serves the fake WordPress login page      |
| POST   | `/wp-admin-login`      | Captures and logs submitted credentials   |

## CLI Arguments

| Flag       | Description                                  |
| ---------- | --------------------------------------------- |
| `-a`       | Address/interface to bind to                  |
| `-p`       | Port to listen on                             |
| `-u`       | Optional decoy username                       |
| `-pw`      | Optional decoy password                       |
| `-s`       | Launch the SSH honeypot                       |
| `-w`       | Launch the HTTP (WordPress) honeypot          |

## Security Features

### Credential Capture

* Every authentication attempt is logged regardless of outcome
* Optional strict credential matching (SSH) vs. permissive capture-all mode

### Operational Safety

* Isolated deployment recommended (dedicated VPS, no shared credentials/data)
* Rotating logs to control disk usage over long-running deployments
* Debug mode disabled for any internet-facing HTTP honeypot instance

## Project Structure

```text
honeypy/
│
├── honeypy.py              # CLI entry point / argument parser
├── ssh_honeypot.py         # SSH honeypot server + emulated shell
├── web_honeypot.py         # Flask-based WordPress login honeypot
├── server.key              # RSA host key for the SSH honeypot
│
├── templates/
│   └── wp-admin.html       # Fake WordPress login page
│
├── audits.log              # SSH login attempts (auto-generated)
├── cmd_audits.log          # SSH commands executed by attackers (auto-generated)
└── http_audits.log         # HTTP login attempts (auto-generated)
```

## Quick Start

### Clone Repository

```bash
git clone https://github.com/YOUR_USERNAME/honeypy
cd honeypy
```

### Install Dependencies

```bash
pip install paramiko flask
```

### Generate SSH Host Key

```bash
ssh-keygen -t rsa -b 2048 -f server.key -N ""
```

### Run the SSH Honeypot

```bash
python honeypy.py -a 0.0.0.0 -p 2222 -s
```

### Run the HTTP Honeypot

```bash
python honeypy.py -a 0.0.0.0 -p 8080 -w
```

## Future Enhancements

* Real-time alerting (e.g., email/Slack notification on new login attempts)
* Expanded emulated shell command set for higher realism
* Centralized log shipping to a SIEM or log aggregator
* IP reputation lookups and automatic geolocation tagging
* Dockerized deployment for faster, repeatable provisioning
* Honeynet expansion — multiple coordinated decoy services

## Key Learnings

* Network socket programming and multithreaded connection handling
* Emulating a real protocol (SSH) at the application layer
* Building a minimal web app that mimics a real login flow
* Structured, rotating logging for security analysis
* Command-line tool design with `argparse`
* Safe deployment practices for internet-facing decoy services
