"""
HONEYPY Live Dashboard Updater
-------------------------------
Parses audits.log, cmd_audits.log, and http_audits.log (plus rotated
backups) and regenerates dashboard.html with fresh stats baked in.

Usage:
    python3 update_dashboard.py [log_directory] [--watch] [--interval SECONDS]

  python3 update_dashboard.py .                  # run once
  python3 update_dashboard.py . --watch                 # regenerate every 30s
  python3 update_dashboard.py . --watch --interval 10    # every 10s

Then just open dashboard.html in a browser. The page auto-refreshes itself
every 30s to pick up whatever this script last wrote to disk, so leave it
open in a tab while the script runs on a loop (or via cron) on your VPS.

Expects the log formats produced by ssh_honeypot.py / web_honeypot.py, and
assumes the SSH loggers have the %(asctime)s timestamp fix applied (see
DEPLOYMENT.md). Falls back gracefully if timestamps are missing.
"""

import argparse
import glob
import html
import os
import re
import time
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


def read_log_family(directory, base_name, limit_raw=200):
    paths = sorted(glob.glob(os.path.join(directory, base_name + "*")))
    lines = []
    for path in paths:
        try:
            with open(path, "r", errors="replace") as f:
                lines.extend(f.read().splitlines())
        except FileNotFoundError:
            continue
    return lines[-limit_raw:] if limit_raw else lines


def strip_timestamp(line):
    m = TIMESTAMP_RE.match(line)
    return (m.group(1), m.group(2)) if m else (None, line)


def parse_ssh_audits(lines):
    events = []
    for line in lines:
        ts, rest = strip_timestamp(line)
        m = SSH_LOGIN_RE.search(rest)
        if m:
            events.append({"ts": ts, "ip": m.group("ip"), "user": m.group("user"), "pw": m.group("pw")})
    return events


def parse_cmd_audits(lines):
    commands = []
    for line in lines:
        ts, rest = strip_timestamp(line)
        m = COMMAND_RE.search(rest)
        if m:
            commands.append({"ts": ts, "ip": m.group("ip"), "cmd": m.group("cmd")})
    return commands


def parse_http_audits(lines):
    events = []
    buffer = ""
    for line in lines:
        ts, rest = strip_timestamp(line)
        buffer = rest if ts else (buffer + " " + rest)
        m = HTTP_LOGIN_RE.search(buffer)
        if m:
            events.append({"ts": ts, "ip": m.group("ip"), "user": m.group("user"), "pw": m.group("pw")})
            buffer = ""
    return events


def hourly_buckets(events):
    """Bucket events by hour for a simple timeline chart. Returns (labels, counts)."""
    buckets = Counter()
    for e in events:
        if not e["ts"]:
            continue
        try:
            dt = datetime.strptime(e["ts"], "%Y-%m-%d %H:%M:%S,%f")
            buckets[dt.strftime("%m-%d %Hh")] += 1
        except ValueError:
            continue
    labels = sorted(buckets.keys())
    return labels, [buckets[l] for l in labels]


def collect_stats(directory):
    ssh_lines = read_log_family(directory, "audits.log")
    cmd_lines = read_log_family(directory, "cmd_audits.log")
    http_lines = read_log_family(directory, "http_audits.log")

    ssh_events = parse_ssh_audits(ssh_lines)
    commands = parse_cmd_audits(cmd_lines)
    http_events = parse_http_audits(http_lines)

    all_events = ssh_events + http_events
    ips = Counter(e["ip"] for e in all_events)
    usernames = Counter(e["user"] for e in all_events)
    passwords = Counter(e["pw"] for e in all_events)
    pairs = Counter(f'{e["user"]}:{e["pw"]}' for e in all_events)
    command_counts = Counter(c["cmd"] for c in commands)
    canary_hits = sum(1 for c in commands if "jumpbox1.conf" in c["cmd"])

    timeline_labels, timeline_counts = hourly_buckets(all_events)

    # Raw tail feed: interleave the most recent raw lines across all three logs
    tail_raw = (ssh_lines[-15:] + cmd_lines[-15:] + http_lines[-15:])[-40:]

    return {
        "total_attempts": len(all_events),
        "unique_ips": len(ips),
        "ssh_attempts": len(ssh_events),
        "http_attempts": len(http_events),
        "commands_run": len(commands),
        "canary_hits": canary_hits,
        "top_ips": ips.most_common(8),
        "top_usernames": usernames.most_common(8),
        "top_passwords": passwords.most_common(8),
        "top_pairs": pairs.most_common(8),
        "top_commands": command_counts.most_common(8),
        "timeline_labels": timeline_labels,
        "timeline_counts": timeline_counts,
        "tail_raw": tail_raw,
    }


def rows_html(pairs, empty_label="No data yet"):
    if not pairs:
        return f'<tr><td colspan="2" class="empty">{empty_label}</td></tr>'
    return "".join(
        f'<tr><td>{html.escape(str(k))}</td><td class="num">{v}</td></tr>'
        for k, v in pairs
    )


def render_html(stats, directory):
    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    tail_html = "\n".join(
        f'<div class="line">{html.escape(l)}</div>' for l in stats["tail_raw"]
    ) or '<div class="line dim">-- waiting for traffic --</div>'

    template = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>HONEYPY // live console</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<style>
  :root {{
    --bg: #0a0f0d;
    --panel: #101613;
    --panel-line: #1d2622;
    --text: #d7ddd9;
    --text-dim: #6c7a73;
    --amber: #e8a33d;
    --teal: #4fd1a5;
    --red: #e2574c;
  }}
  * {{ box-sizing: border-box; }}
  html, body {{
    margin: 0; padding: 0;
    background: var(--bg);
    color: var(--text);
    font-family: 'JetBrains Mono', monospace;
  }}
  body {{ padding: 28px clamp(16px, 4vw, 48px) 60px; }}

  .topbar {{
    display: flex; align-items: center; justify-content: space-between;
    flex-wrap: wrap; gap: 12px;
    border-bottom: 1px solid var(--panel-line);
    padding-bottom: 18px; margin-bottom: 24px;
  }}
  .brand {{ display: flex; align-items: baseline; gap: 10px; }}
  .brand h1 {{
    font-size: 20px; letter-spacing: 0.06em; margin: 0;
    font-weight: 700; color: var(--text);
  }}
  .brand span {{ color: var(--text-dim); font-size: 13px; }}
  .status {{
    display: flex; align-items: center; gap: 8px;
    font-size: 12px; color: var(--text-dim);
  }}
  .dot {{
    width: 8px; height: 8px; border-radius: 50%;
    background: var(--teal);
    box-shadow: 0 0 0 0 rgba(79,209,165,0.6);
    animation: pulse 2s infinite;
  }}
  @keyframes pulse {{
    0% {{ box-shadow: 0 0 0 0 rgba(79,209,165,0.55); }}
    70% {{ box-shadow: 0 0 0 6px rgba(79,209,165,0); }}
    100% {{ box-shadow: 0 0 0 0 rgba(79,209,165,0); }}
  }}

  .stats-row {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 14px; margin-bottom: 24px;
  }}
  .stat {{
    background: var(--panel);
    border: 1px solid var(--panel-line);
    border-radius: 4px;
    padding: 16px 18px;
  }}
  .stat .num {{ font-size: 28px; font-weight: 700; line-height: 1; }}
  .stat .label {{
    margin-top: 8px; font-size: 11px; letter-spacing: 0.08em;
    text-transform: uppercase; color: var(--text-dim);
  }}
  .stat.amber .num {{ color: var(--amber); }}
  .stat.teal .num {{ color: var(--teal); }}
  .stat.red .num {{ color: var(--red); }}

  .grid {{
    display: grid;
    grid-template-columns: 1.3fr 1fr 1fr;
    gap: 16px; margin-bottom: 16px;
  }}
  @media (max-width: 900px) {{ .grid {{ grid-template-columns: 1fr; }} }}

  .panel {{
    background: var(--panel);
    border: 1px solid var(--panel-line);
    border-radius: 4px;
    padding: 16px 18px 18px;
  }}
  .panel h2 {{
    font-size: 11px; letter-spacing: 0.1em; text-transform: uppercase;
    color: var(--text-dim); margin: 0 0 12px;
    display: flex; align-items: center; gap: 8px;
  }}
  .panel h2::before {{ content: ''; width: 10px; height: 1px; background: var(--panel-line); }}

  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  td {{ padding: 6px 0; border-bottom: 1px solid var(--panel-line); }}
  td.num {{ text-align: right; color: var(--amber); font-weight: 600; }}
  td.empty {{ color: var(--text-dim); text-align: center; padding: 18px 0; }}
  tr:last-child td {{ border-bottom: none; }}

  .chart-wrap {{ height: 220px; }}

  .tail {{
    background: #070b09;
    border: 1px solid var(--panel-line);
    border-radius: 4px;
    padding: 14px 16px;
    height: 260px;
    overflow-y: auto;
    font-size: 12.5px;
    line-height: 1.7;
  }}
  .tail .line {{ white-space: pre-wrap; word-break: break-all; color: #9fb0a8; }}
  .tail .line.dim {{ color: var(--text-dim); }}
  .tail .line::before {{ content: '> '; color: var(--teal); }}
  .cursor {{
    display: inline-block; width: 7px; height: 13px;
    background: var(--teal); margin-left: 2px;
    animation: blink 1s steps(1) infinite; vertical-align: middle;
  }}
  @keyframes blink {{ 50% {{ opacity: 0; }} }}

  footer {{
    margin-top: 20px; font-size: 11px; color: var(--text-dim);
    text-align: center;
  }}
</style>
</head>
<body>

  <div class="topbar">
    <div class="brand">
      <h1>HONEYPY</h1>
      <span>// live threat console</span>
    </div>
    <div class="status">
      <span class="dot"></span>
      generated {generated} &nbsp;·&nbsp; refreshes every 30s
    </div>
  </div>

  <div class="stats-row">
    <div class="stat teal">
      <div class="num">{stats['total_attempts']}</div>
      <div class="label">Total attempts</div>
    </div>
    <div class="stat">
      <div class="num">{stats['unique_ips']}</div>
      <div class="label">Unique source IPs</div>
    </div>
    <div class="stat">
      <div class="num">{stats['ssh_attempts']}</div>
      <div class="label">SSH attempts</div>
    </div>
    <div class="stat">
      <div class="num">{stats['http_attempts']}</div>
      <div class="label">HTTP attempts</div>
    </div>
    <div class="stat amber">
      <div class="num">{stats['commands_run']}</div>
      <div class="label">Commands run</div>
    </div>
    <div class="stat red">
      <div class="num">{stats['canary_hits']}</div>
      <div class="label">Canary file reads</div>
    </div>
  </div>

  <div class="panel" style="margin-bottom:16px;">
    <h2>Attempts over time</h2>
    <div class="chart-wrap"><canvas id="timeline"></canvas></div>
  </div>

  <div class="grid">
    <div class="panel">
      <h2>Top source IPs</h2>
      <table><tbody>{rows_html(stats['top_ips'])}</tbody></table>
    </div>
    <div class="panel">
      <h2>Top usernames</h2>
      <table><tbody>{rows_html(stats['top_usernames'])}</tbody></table>
    </div>
    <div class="panel">
      <h2>Top passwords</h2>
      <table><tbody>{rows_html(stats['top_passwords'])}</tbody></table>
    </div>
  </div>

  <div class="grid">
    <div class="panel">
      <h2>Top credential pairs</h2>
      <table><tbody>{rows_html(stats['top_pairs'])}</tbody></table>
    </div>
    <div class="panel" style="grid-column: span 2;">
      <h2>Commands executed in fake shell</h2>
      <table><tbody>{rows_html(stats['top_commands'], "No commands captured yet")}</tbody></table>
    </div>
  </div>

  <div class="panel">
    <h2>Live log tail</h2>
    <div class="tail" id="tail">
      {tail_html}
      <span class="cursor"></span>
    </div>
  </div>

  <footer>reading from: {html.escape(os.path.abspath(directory))}</footer>

<script>
  // Auto-refresh the page so it picks up whatever update_dashboard.py
  // last wrote to disk. Run the script on a loop or via cron on the VPS.
  setTimeout(() => location.reload(), 30000);

  // Keep the log tail scrolled to the bottom on load
  const tail = document.getElementById('tail');
  tail.scrollTop = tail.scrollHeight;

  const ctx = document.getElementById('timeline');
  new Chart(ctx, {{
    type: 'line',
    data: {{
      labels: {stats['timeline_labels']!r},
      datasets: [{{
        label: 'Attempts',
        data: {stats['timeline_counts']!r},
        borderColor: '#4fd1a5',
        backgroundColor: 'rgba(79,209,165,0.12)',
        borderWidth: 2,
        pointRadius: 2,
        pointBackgroundColor: '#4fd1a5',
        fill: true,
        tension: 0.25,
      }}]
    }},
    options: {{
      responsive: true,
      maintainAspectRatio: false,
      plugins: {{ legend: {{ display: false }} }},
      scales: {{
        x: {{ ticks: {{ color: '#6c7a73', font: {{ family: 'JetBrains Mono', size: 10 }} }}, grid: {{ color: '#1d2622' }} }},
        y: {{ beginAtZero: true, ticks: {{ color: '#6c7a73', font: {{ family: 'JetBrains Mono', size: 10 }}, precision: 0 }}, grid: {{ color: '#1d2622' }} }},
      }}
    }}
  }});
</script>
</body>
</html>
"""
    return template


def main():
    parser = argparse.ArgumentParser(description="Regenerate the HONEYPY live dashboard from log files.")
    parser.add_argument("directory", nargs="?", default=".", help="Directory containing the log files")
    parser.add_argument("--watch", action="store_true", help="Keep regenerating on a loop")
    parser.add_argument("--interval", type=int, default=30, help="Seconds between regenerations in --watch mode")
    parser.add_argument("--out", default=None, help="Output HTML path (default: <directory>/dashboard.html)")
    args = parser.parse_args()

    out_path = args.out or os.path.join(args.directory, "dashboard.html")

    def run_once():
        stats = collect_stats(args.directory)
        with open(out_path, "w") as f:
            f.write(render_html(stats, args.directory))
        print(f"[{datetime.now().strftime('%H:%M:%S')}] wrote {out_path} "
              f"({stats['total_attempts']} attempts, {stats['unique_ips']} unique IPs)")

    run_once()
    if args.watch:
        try:
            while True:
                time.sleep(args.interval)
                run_once()
        except KeyboardInterrupt:
            print("\nStopped.")


if __name__ == "__main__":
    main()