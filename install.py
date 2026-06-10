#!/usr/bin/env python3
import os
import sys
import subprocess
import socket

print("[*] SIEM Tool Deployment Init...")
TELEGRAM_BOT_TOKEN = input("Telegram Bot Token : ").strip()
TELEGRAM_CHAT_ID = input("Notification ChatId : ").strip()
WEB_SERVER_TYPE = input("Server [nginx/apache] : ").strip().lower()

real_hostname = socket.gethostname()
custom_hostname = input(f"Server Hostname [Default: {real_hostname}]: ").strip()
if not custom_hostname:
    custom_hostname = real_hostname

if WEB_SERVER_TYPE not in ["nginx", "apache"]:
    print("[!] Warning: Invalid server selection. Defaulting background tracking to nginx.")
    WEB_SERVER_TYPE = "nginx"

TARGET_DIR = "/usr/local/bin"
TOOL_PATH = os.path.join(TARGET_DIR, "siem.py")

TOOL_CODE = r"""#!/usr/bin/env python3
import os
import re
import time
import queue
import threading
import click
import requests
from collections import defaultdict
from urllib.parse import unquote
from rich.console import Console
from rich.table import Table
from rich.live import Live

console = Console()

TELEGRAM_BOT_TOKEN = "___BOT_TOKEN___"
TELEGRAM_CHAT_ID = "___CHAT_ID___"
CONFIGURED_HOSTNAME = "___HOSTNAME___"

PATHS = {
    "nginx": "/var/log/nginx/access.log",
    "apache": "/var/log/apache2/access.log",
    "ssh": "/var/log/auth.log"
}

CACHE_FILES = {
    "web": "/tmp/wcheck_live.alerts",
    "ssh": "/tmp/shcheck_live.alerts"
}

WEB_SIGNATURES = {
    "SQLi": re.compile(r"(UNION[\s/\*]+SELECT|SELECT.+FROM|INSERT[\s/\*]+INTO|OR[\s/\*]+[\d\w]+[\s/\*]*=)", re.I),
    "XSS": re.compile(r"(<script>|javascript:|onerror\s*=|onload\s*=|alert\()", re.I),
    "Traversal": re.compile(r"(\.\.\/|\.\.\\|/etc/passwd|/windows/win\.ini)", re.I),
    "Log Injection": re.compile(r"(\r|\n|%0a|%0d)", re.I), 
    "Shellshock": re.compile(r"\(\)\s*\{\s*[:;]\s*\}\s*;", re.I),
    "Web Shell Probe": re.compile(r"(cmd\.php|shell\.php|exec\(|eval\(|passthru\()", re.I)
}

SSH_TRACKER = defaultdict(lambda: {"count": 0, "first_seen": 0.0, "reported": False})
SSH_THRESHOLD_LIMIT = 5
SSH_WINDOW_SECONDS = 30

def send_telegram_alert(log_type, alert):
    if TELEGRAM_BOT_TOKEN == "YOUR_BOT_TOKEN_HERE" or not TELEGRAM_BOT_TOKEN or "___" in TELEGRAM_BOT_TOKEN:
        return
    
    status_str = f" [Status: {alert['status']}]" if log_type == "web" else ""
    
    msg = (
        f"[{alert['severity']} RISK]\n"
        f"Traffic Detail: <code>{alert['ip']} -> {alert['info']}{status_str} ({alert['event']})</code>\n"
        f"Hostname: <code>{CONFIGURED_HOSTNAME}</code>"
    )
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    try:
        requests.post(url, data={"chat_id": TELEGRAM_CHAT_ID, "text": msg, "parse_mode": "HTML"}, timeout=5)
    except Exception:
        pass

def send_heartbeat_message():
    if TELEGRAM_BOT_TOKEN == "YOUR_BOT_TOKEN_HERE" or not TELEGRAM_BOT_TOKEN or "___" in TELEGRAM_BOT_TOKEN:
        return
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    msg = f"🟢 <b>[{CONFIGURED_HOSTNAME}]</b> : Active"
    try:
        requests.post(url, data={"chat_id": TELEGRAM_CHAT_ID, "text": msg, "parse_mode": "HTML"}, timeout=5)
    except Exception:
        pass

def heartbeat_loop():
    send_heartbeat_message()
    while True:
        time.sleep(86400)
        send_heartbeat_message()

def start_heartbeat_thread():
    t = threading.Thread(target=heartbeat_loop, daemon=True)
    t.start()

def analyze_web_line(line):
    match = re.match(r'(?P<ip>\S+) \S+ \S+ \[(?P<date>.*?)\] "(?P<method>\S+) (?P<url>\S+)\s?\S*" (?P<status>\d+) (?P<bytes>\S+)', line)
    if not match: return None

    data = match.groupdict()
    severity, event = "LOW", "Normal Web Traffic"

    decoded_url = unquote(data['url'])
    normalized_url = re.sub(r'/\*.*?\*/', ' ', decoded_url)

    for name, pattern in WEB_SIGNATURES.items():
        if pattern.search(normalized_url):
            severity = "HIGH"
            event = f"Attack Detection: {name}"
            break

    if severity == "LOW":
        if data['status'] == "404" and any(x in normalized_url.lower() for x in ['.env', '.git', 'wp-admin', 'config']):
            severity = "HIGH"
            event = "Critical Recon Probing"
        elif int(data['status']) >= 500:
            severity = "MEDIUM"
            event = "Internal Server Error"

    return {"time": data['date'].split()[0], "ip": data['ip'], "info": f"{data['method']} {data['url'][:40]}", "status": data['status'], "severity": severity, "event": event}

def analyze_ssh_line(line):
    timestamp_match = re.match(r"^(\S+)\s+", line)
    log_time = timestamp_match.group(1) if timestamp_match else "Unknown"
    if len(log_time) < 5:
        log_time = " ".join(line.split()[:3])

    failed_match = re.search(r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>\S+) port", line)
    accepted_match = re.search(r"Accepted password for (?P<user>\S+) from (?P<ip>\S+) port", line)
    
    if failed_match:
        ip = failed_match.group("ip")
        user = failed_match.group("user")
        current_time = time.time()
        
        tracker = SSH_TRACKER[ip]
        
        # Reset tracker window if the threshold time passed
        if current_time - tracker["first_seen"] > SSH_WINDOW_SECONDS:
            tracker["count"] = 1
            tracker["first_seen"] = current_time
            tracker["reported"] = False
        else:
            tracker["count"] += 1

        # Only trigger an alert line when it hits or surpasses the exact threshold boundary
        if tracker["count"] >= SSH_THRESHOLD_LIMIT and not tracker["reported"]:
            tracker["reported"] = True  # Stop repetitive logs from this IP until window resets
            return {
                "time": log_time, 
                "ip": ip, 
                "info": f"User: {user} (Failed {tracker['count']}x)", 
                "status": "-", 
                "severity": "HIGH", 
                "event": f"SSH Brute-Force: {tracker['count']} Failures in <{SSH_WINDOW_SECONDS}s"
            }
        
        # Drop the line completely if it's noise or intermediate aggregation steps
        return None

    elif accepted_match:
        ip = accepted_match.group("ip")
        if ip in SSH_TRACKER:
            del SSH_TRACKER[ip]
            
        severity = "HIGH" if "root" in accepted_match.group("user") else "LOW"
        return {"time": log_time, "ip": ip, "info": f"User: {accepted_match.group('user')}", "status": "-", "severity": severity, "event": "Successful SSH Authentication"}
        
    return None 

def daemon_engine(log_type, target):
    if log_type == "web":
        start_heartbeat_thread()

    path = PATHS[target] if log_type == "web" else PATHS["ssh"]
    cache_path = CACHE_FILES[log_type]
    
    with open(cache_path, "w") as c: c.write("")
    if not os.path.exists(path): return

    with open(path, "r") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue
            
            alert = analyze_web_line(line) if log_type == "web" else analyze_ssh_line(line)
            if alert:
                with open(cache_path, "a") as cache_f:
                    cache_f.write(f"{alert['time']}|{alert['ip']}|{alert['info']}|{alert['status']}|{alert['severity']}|{alert['event']}\n")
                if alert['severity'] == "HIGH":
                    threading.Thread(target=send_telegram_alert, args=(log_type, alert), daemon=True).start()

def run_interactive_ui(log_type, title, col_headers):
    cache_path = CACHE_FILES[log_type]
    if not os.path.exists(cache_path):
        with open(cache_path, "w") as f: pass

    table = Table(expand=True, title=title)
    for col in col_headers: table.add_column(col)
    console.print("[bold green]Entering Interactive View. Ctrl+C to exit dashboard (Daemon stays alive).[/]")
    
    with Live(table, refresh_per_second=4):
        with open(cache_path, "r") as f:
            f.seek(0, os.SEEK_END)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.2)
                    continue
                parts = line.strip().split("|")
                if len(parts) == 6:
                    time_val, ip, info, status, severity, event = parts
                    color = "red" if severity == "HIGH" else "yellow" if severity == "MEDIUM" else "blue"
                    if log_type == "web":
                        table.add_row(time_val, ip, info, status, f"[{color}]{severity}[/]", event)
                    else:
                        table.add_row(time_val, ip, info, f"[{color}]{severity}[/]", event)

@click.group()
def cli(): pass

@cli.command()
@click.argument('server', type=click.Choice(['nginx', 'apache'], case_sensitive=False))
@click.option('--daemon', is_flag=True)
def wcheck(server, daemon):
    if daemon: daemon_engine("web", server.lower())
    else: run_interactive_ui("web", f"Live Web Monitor ({server.upper()})", ["Timestamp", "Source IP", "Request", "Status", "Severity", "Event"])

@cli.command()
@click.option('--daemon', is_flag=True)
def shcheck(daemon):
    if daemon: daemon_engine("ssh", "ssh")
    else: run_interactive_ui("ssh", "Live SSH Monitor", ["Timestamp", "Source IP", "Identity Info", "Severity", "Event"])

if __name__ == "__main__":
    cli()
"""

TOOL_CODE = TOOL_CODE.replace("___BOT_TOKEN___", TELEGRAM_BOT_TOKEN)
TOOL_CODE = TOOL_CODE.replace("___CHAT_ID___", TELEGRAM_CHAT_ID)
TOOL_CODE = TOOL_CODE.replace("___HOSTNAME___", custom_hostname)

# --- SYSTEMD DAEMON GENERATION LAYOUTS ---
WCHECK_SERVICE = f"""[Unit]
Description=SIEM Engine - Web Monitoring Background Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 {TOOL_PATH} wcheck {WEB_SERVER_TYPE} --daemon
Restart=always

[Install]
WantedBy=multi-user.target
"""

SHCHECK_SERVICE = f"""[Unit]
Description=SIEM Engine - SSH Monitoring Background Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 {TOOL_PATH} shcheck --daemon
Restart=always

[Install]
WantedBy=multi-user.target
"""

def run_cmd(cmd):
    subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def main():
    if os.getuid() != 0:
        print("[!] Execution halted: This installation framework must be executed via sudo privileges.")
        sys.exit(1)

    print("[+] Step 1: Querying system requirements and package dependencies...")
    try:
        import click
        import rich
        import requests
    except ImportError:
        print("[*] Required packages missing. Deploying dependencies with system escape override...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--break-system-packages", "click", "rich", "requests"])

    print(f"[+] Step 2: Provisioning codebase directly into secure global path: {TOOL_PATH}")
    with open(TOOL_PATH, "w") as f:
        f.write(TOOL_CODE)
    run_cmd(f"chmod +x {TOOL_PATH}")

    print("[+] Step 3: Installing systemd daemon architecture dependencies...")
    with open("/etc/systemd/system/wcheck-daemon.service", "w") as f:
        f.write(WCHECK_SERVICE)
    with open("/etc/systemd/system/shcheck-daemon.service", "w") as f:
        f.write(SHCHECK_SERVICE)

    print("[+] Step 4: Activating systemd engine background loops...")
    run_cmd("systemctl daemon-reload")
    run_cmd("systemctl enable --now wcheck-daemon.service")
    run_cmd("systemctl enable --now shcheck-daemon.service")

    print("[+] Step 5: Forging clean command-wrapper executions for CLI routes...")
    wcheck_wrapper_path = os.path.join(TARGET_DIR, "wcheck")
    shcheck_wrapper_path = os.path.join(TARGET_DIR, "shcheck")

    for target_bin in [wcheck_wrapper_path, shcheck_wrapper_path]:
        if os.path.exists(target_bin) or os.path.islink(target_bin):
            os.remove(target_bin)

    wcheck_payload = f'#!/bin/bash\n/usr/bin/python3 {TOOL_PATH} wcheck "$@"\n'
    with open(wcheck_wrapper_path, "w") as f:
        f.write(wcheck_payload)
    run_cmd(f"chmod +x {wcheck_wrapper_path}")

    shcheck_payload = f'#!/bin/bash\n/usr/bin/python3 {TOOL_PATH} shcheck "$@"\n'
    with open(shcheck_wrapper_path, "w") as f:
        f.write(shcheck_payload)
    run_cmd(f"chmod +x {shcheck_wrapper_path}")

    print("\n[============= DEPLOYMENT COMPLETE =============]")
    print(f"[*] Configured Hostname: {custom_hostname}")
    print("[*] Background SIEM engines are running smoothly.")
    print("[*] Run interactively anytime via your shortcuts:")
    print(f"    ->  wcheck {WEB_SERVER_TYPE}")
    print("    ->  shcheck")
    print("[=================================================]\n")

if __name__ == "__main__":
    main()
