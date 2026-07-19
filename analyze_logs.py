"""
HONEYPY Threat Intel Report Generator (local run)
----------------------------------------------------
Parses audits.log, cmd_audits.log, and http_audits.log (including rotated
backups like audits.log.1, audits.log.2, etc.) and produces a Markdown
report summarizing activity captured by your locally-running honeypot(s):
unique IPs, credential attempts, commands executed, and a basic timeline.

Designed to run entirely on your own machine — point it at the same
folder honeypy.py is writing its logs to. No VPS or remote server needed.

Usage:
    python3 analyze_logs.py [log_directory]

If log_directory is omitted, the current directory is used.

Expects the log formats produced by ssh_honeypot.py / web_honeypot.py:
  audits.log       : "<timestamp> SSH login attempt from <ip> with username: <u> and password: <p>"
  cmd_audits.log    : "<timestamp> <ip> - <username>:<password>"
                       "<timestamp> Command <cmd> executed by <ip>"
  http_audits.log   : "<timestamp> Login attempt from <ip>\\nusername: <u> and password: <p>"

Note: this script assumes the timestamp-formatter fix (adding %(asctime)s
to the logging_format line in ssh_honeypot.py) has been applied. If
audits.log/cmd_audits.log lines have no leading timestamp, this script
still works — it just won't be able to build a time-based timeline for
SSH activity.

Reminder: if you're testing purely locally (not exposed to the internet),
this report will reflect only whatever traffic you generate yourself —
see the usage guide for how to simulate login attempts against your own
honeypot for testing purposes.
"""

import glob
import os
import re
import sys
from collections import Counter
from datetime import datetime

TIMESTAMP_RE = re.compile(r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3})\s+(.*)$')

SSH_LOGIN_RE = re.compile(
    r'SSH login attempt from (?P<ip>[\d.]+) with username: (?P<user>.*?) and password: (?P<pw>.*)$'
)
CREDS_RE = re.compile(r'^(?P<ip>[\d.]+) - (?P<user>.*?):(?P<pw>.*)$')
COMMAND_RE = re.compile(r"Command b?'(?P<cmd>.*?)(?:\\r)?' executed by (?P<ip>[\d.]+)")
HTTP_LOGIN_RE = re.compile(
    r'Login attempt from (?P<ip>[\d.]+)\s*(?:\r?\n|\\n)?username: (?P<user>.*?) and password: (?P<pw>.*)$'
)


def read_log_family(directory, base_name):
    """Read a base log file plus any rotated backups (base_name, base_name.1, ...)."""
    paths = sorted(glob.glob(os.path.join(directory, base_name + "*")))
    lines = []
    for path in paths:
        try:
            with open(path, "r", errors="replace") as f:
                lines.extend(f.read().splitlines())
        except FileNotFoundError:
            continue
    return lines


def strip_timestamp(line):
    m = TIMESTAMP_RE.match(line)
    if m:
        return m.group(1), m.group(2)
    return None, line


def parse_ssh_audits(lines):
    events = []
    for line in lines:
        ts, rest = strip_timestamp(line)
        m = SSH_LOGIN_RE.search(rest)
        if m:
            events.append({
                "ts": ts, "ip": m.group("ip"),
                "user": m.group("user"), "pw": m.group("pw"),
            })
    return events


def parse_cmd_audits(lines):
    creds, commands = [], []
    for line in lines:
        ts, rest = strip_timestamp(line)
        m = COMMAND_RE.search(rest)
        if m:
            commands.append({"ts": ts, "ip": m.group("ip"), "cmd": m.group("cmd")})
            continue
        m = CREDS_RE.search(rest)
        if m:
            creds.append({"ts": ts, "ip": m.group("ip"), "user": m.group("user"), "pw": m.group("pw")})
    return creds, commands


def parse_http_audits(lines):
    events = []
    buffer = ""
    for line in lines:
        ts, rest = strip_timestamp(line)
        buffer = rest if ts else (buffer + " " + rest)
        m = HTTP_LOGIN_RE.search(buffer)
        if m:
            events.append({
                "ts": ts, "ip": m.group("ip"),
                "user": m.group("user"), "pw": m.group("pw"),
            })
            buffer = ""
    return events


def top_n(counter, n=10):
    return counter.most_common(n)


def format_table(rows, headers):
    out = ["| " + " | ".join(headers) + " |", "| " + " | ".join(["---"] * len(headers)) + " |"]
    for row in rows:
        out.append("| " + " | ".join(str(c) for c in row) + " |")
    return "\n".join(out)


def main():
    directory = sys.argv[1] if len(sys.argv) > 1 else "."

    ssh_lines = read_log_family(directory, "audits.log")
    cmd_lines = read_log_family(directory, "cmd_audits.log")
    http_lines = read_log_family(directory, "http_audits.log")

    ssh_events = parse_ssh_audits(ssh_lines)
    creds_events, commands = parse_cmd_audits(cmd_lines)
    http_events = parse_http_audits(http_lines)

    all_ips = Counter()
    all_usernames = Counter()
    all_passwords = Counter()
    all_pairs = Counter()

    for e in ssh_events + http_events:
        all_ips[e["ip"]] += 1
        all_usernames[e["user"]] += 1
        all_passwords[e["pw"]] += 1
        all_pairs[f'{e["user"]}:{e["pw"]}'] += 1

    command_counter = Counter(c["cmd"] for c in commands)
    command_ips = Counter(c["ip"] for c in commands)

    total_attempts = len(ssh_events) + len(http_events)
    unique_ips = len(all_ips)

    timestamps = [e["ts"] for e in (ssh_events + http_events) if e["ts"]]
    time_range = None
    if timestamps:
        parsed = []
        for t in timestamps:
            try:
                parsed.append(datetime.strptime(t, "%Y-%m-%d %H:%M:%S,%f"))
            except ValueError:
                pass
        if parsed:
            time_range = (min(parsed), max(parsed))

    report = []
    report.append("# HONEYPY Threat Intel Report")
    report.append(f"\nGenerated: {datetime.now().isoformat(timespec='seconds')}\n")

    if time_range:
        duration = time_range[1] - time_range[0]
        report.append(f"**Observation window:** {time_range[0]} -> {time_range[1]} "
                       f"({duration})\n")
    else:
        report.append("**Observation window:** unknown (no parseable timestamps found — "
                       "apply the logging fix in DEPLOYMENT.md for future runs)\n")

    report.append("## Summary\n")
    report.append(f"- Total login attempts (SSH + HTTP): **{total_attempts}**")
    report.append(f"- Unique source IPs: **{unique_ips}**")
    report.append(f"- SSH login attempts: **{len(ssh_events)}**")
    report.append(f"- HTTP login attempts: **{len(http_events)}**")
    report.append(f"- Commands executed inside the fake shell: **{len(commands)}**")
    report.append("")

    report.append("## Top Source IPs\n")
    report.append(format_table(top_n(all_ips), ["IP", "Attempts"]))
    report.append("")

    report.append("## Top Usernames Attempted\n")
    report.append(format_table(top_n(all_usernames), ["Username", "Count"]))
    report.append("")

    report.append("## Top Passwords Attempted\n")
    report.append(format_table(top_n(all_passwords), ["Password", "Count"]))
    report.append("")

    report.append("## Top Username:Password Pairs\n")
    report.append(format_table(top_n(all_pairs), ["Pair", "Count"]))
    report.append("")

    if commands:
        report.append("## Commands Executed by Attackers\n")
        report.append(format_table(top_n(command_counter), ["Command", "Count"]))
        report.append("")
        report.append("## IPs That Executed Commands (i.e. got past auth)\n")
        report.append(format_table(top_n(command_ips), ["IP", "Commands Run"]))
        report.append("")
        canary_hits = sum(1 for c in commands if "jumpbox1.conf" in c["cmd"])
        report.append(f"- Attackers who read the canary file (`cat jumpbox1.conf`): **{canary_hits}**\n")
    else:
        report.append("## Commands Executed by Attackers\n")
        report.append("No commands captured in this window.\n")

    report.append("## Notes for the Write-Up\n")
    report.append(
        "- Cross-reference top IPs against an IP-reputation lookup (e.g. AbuseIPDB, "
        "Shodan) manually if you want attribution — this script stays offline by design.\n"
        "- A high ratio of unique IPs to total attempts suggests broad automated scanning; "
        "a low ratio suggests a smaller number of persistent/targeted sources.\n"
        "- Common username/password pairs matching known default-credential lists "
        "(e.g. admin/admin, root/123456) indicate credential-stuffing bots rather than "
        "targeted human attackers.\n"
    )

    output_path = os.path.join(directory, "threat_intel_report.md")
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(report))

    print(f"Report written to {output_path}")
    print(f"Total attempts: {total_attempts} | Unique IPs: {unique_ips} | "
          f"Commands captured: {len(commands)}")


if __name__ == "__main__":
    main()