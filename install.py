#!/usr/bin/env python3
import os
import sys
import subprocess
import socket

# Ensure script runs as root right off the bat
if os.getuid() != 0:
    print("[!] Execution halted: This installation framework must be executed via sudo privileges.")
    sys.exit(1)

# HARDENING: Enforce strict file creation mask for the installation process (Owner Only)
os.umask(0o077)

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

# HARDENING: Shifted runtime variable flags out of the unsafe public shared /tmp folder 
RUN_DIR = "/var/run/siem"
VAR_LOG_DIR = "/var/log/siem"
os.makedirs(RUN_DIR, mode=0o700, exist_ok=True)
os.makedirs(VAR_LOG_DIR, mode=0o700, exist_ok=True)

TOOL_CODE = r"""#!/usr/bin/env python3
import os
import re
import time
import queue
import threading
import click
import requests
import html
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
    "web": "/var/run/siem/wcheck_live.alerts",
    "ssh": "/var/run/siem/shcheck_live.alerts"
}
STATUS_FILE = "/var/run/siem/.wcheck_active_view"
STAGING_DIR = "/var/log/siem/siem_stage"

os.makedirs(STAGING_DIR, mode=0o700, exist_ok=True)

WEB_SIGNATURES = {
    "SQLi": re.compile(r"(UNION[\s/\*]+SELECT|SELECT.+FROM|INSERT[\s/\*]+INTO|OR[\s/\*]+[\d\w]+[\s/\*]*=)", re.I),
    "XSS": re.compile(r"(<script>|javascript:|onerror\s*=|onload\s*=|alert\()", re.I),
    "Traversal": re.compile(r"(\.\.\/|\.\.\\|/etc/passwd|/windows/win\.ini)", re.I),
    "Log Injection": re.compile(r"(\r|\n|%0a|%0d)", re.I), 
    "Shellshock": re.compile(r"\(\)\s*\{\s*[:;]\s*\}\s*;", re.I),
    "Web Shell Probe": re.compile(r"(cmd\.php|shell\.php|exec\(|eval\(|passthru\()", re.I)
}

SSH_TRACKER = defaultdict(lambda: {"count": 0, "first_seen": 0.0, "reported": False})
SSH_THRESHOLD_LIMIT = 3
SSH_WINDOW_SECONDS = 60

DIGEST_QUEUE = queue.Queue()
DIGEST_INTERVAL_SECS = 14400 

def sanitize_log_field(value):
    return str(value).replace("\n", " ").replace("\r", " ").replace("|", "💳")

def send_telegram_raw(msg):
    if not TELEGRAM_BOT_TOKEN or "YOUR_BOT_TOKEN" in TELEGRAM_BOT_TOKEN or "___" in TELEGRAM_BOT_TOKEN:
        return
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    try:
        requests.post(url, data={"chat_id": TELEGRAM_CHAT_ID, "text": msg, "parse_mode": "HTML"}, timeout=8)
    except Exception:
        pass

def upload_telegram_file(file_path, caption):
    if not TELEGRAM_BOT_TOKEN or "YOUR_BOT_TOKEN" in TELEGRAM_BOT_TOKEN or "___" in TELEGRAM_BOT_TOKEN:
        return
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendDocument"
    try:
        with open(file_path, 'rb') as doc:
            files = {'document': doc}
            data = {'chat_id': TELEGRAM_CHAT_ID, 'caption': caption, 'parse_mode': 'HTML'}
            requests.post(url, data=data, files=files, timeout=15)
    except Exception:
        pass

def send_telegram_alert(log_type, alert):
    detail = f"{alert['ip']} -> {alert['info']}"
    if log_type == "web":
        detail += f" [Status: {alert['status']}]"

    msg = (
        f"🚨 <b>🔥 {html.escape(alert['severity'])} RISK ALERT</b>\n"
        f"<b>Host:</b> <code>{html.escape(CONFIGURED_HOSTNAME)}</code>\n"
        f"<b>Engine:</b> <code>{html.escape(log_type.upper())} Monitor</code>\n"
        f"<b>Event:</b> <code>{html.escape(alert['event'])}</code>\n"
        f"<b>Detail:</b> <code>{html.escape(detail)}</code>"
    )
    send_telegram_raw(msg)

def send_heartbeat_message():
    msg = f"🟢 <b>[{html.escape(CONFIGURED_HOSTNAME)}]</b> : Active"
    send_telegram_raw(msg)

def digest_flusher_loop():
    while True:
        time.sleep(DIGEST_INTERVAL_SECS)
        staged_alerts = []
        while not DIGEST_QUEUE.empty():
            try:
                staged_alerts.append(DIGEST_QUEUE.get_nowait())
            except queue.Empty:
                break
        
        if not staged_alerts:
            continue
            
        timestamp_prefix = time.strftime("%Y-%m-%d_%H-%M-%S")
        safe_host = "".join([c for c in CONFIGURED_HOSTNAME if c.isalnum() or c in ['.', '-', '_']])
        target_filename = f"{timestamp_prefix}_{safe_host}.log"
        full_log_path = os.path.join(STAGING_DIR, target_filename)
        
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
            fd = os.open(full_log_path, flags, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f_out:
                f_out.write(f"=== SIEM LOG BATCH FOR {CONFIGURED_HOSTNAME} ===\n")
                f_out.write(f"Generated at: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f_out.write(f"Total entries: {len(staged_alerts)}\n")
                f_out.write("="*50 + "\n\n")
                
                for item in staged_alerts:
                    log_type = item['log_type']
                    alert = item['data']
                    if log_type == "web":
                        f_out.write(f"[{alert['time']}] WEB_RECON | Severity: {alert['severity']} | IP: {alert['ip']} | Request: {alert['info']} | Status: {alert['status']} | Event: {alert['event']}\n")
                    else:
                        f_out.write(f"[{alert['time']}] SSH_BRUTE | Severity: {alert['severity']} | IP: {alert['ip']} | Detail: {alert['info']} | Event: {alert['event']}\n")
            
            caption_msg = f"📋 <b>4-Hour SIEM Log Delivery</b>\n<b>Host:</b> <code>{html.escape(CONFIGURED_HOSTNAME)}</code>\n<b>Compiled Events:</b> {len(staged_alerts)}"
            upload_telegram_file(full_log_path, caption_msg)
            
            if os.path.exists(full_log_path):
                os.remove(full_log_path)
        except Exception:
            pass

def heartbeat_loop():
    send_heartbeat_message()
    while True:
        time.sleep(86400)
        send_heartbeat_message()

def start_background_threads():
    threading.Thread(target=heartbeat_loop, daemon=True).start()
    threading.Thread(target=digest_flusher_loop, daemon=True).start()

def analyze_web_line(line):
    match = re.match(r'(?P<ip>\S+) \S+ \S+ \[(?P<date>.*?)\] "(?P<method>\S+) (?P<url>\S+)\s?\S*" (?P<status>\d+) (?P<bytes>\S+)', line)
    if not match: return None

    data = match.groupdict()
    severity, event = "LOW", "Normal Web Traffic"
    http_status = data['status']

    decoded_url = unquote(data['url'])
    normalized_url = re.sub(r'/\*.*?\*/', ' ', decoded_url)

    is_injection = False
    for name, pattern in WEB_SIGNATURES.items():
        if pattern.search(normalized_url):
            is_injection = True
            severity = "HIGH"
            event = f"Attack Detection: {name}"
            break

    if not is_injection:
        if any(x in normalized_url.lower() for x in ['.env', '.git', 'wp-admin', 'config', 'dashboard']):
            if http_status == "200":
                severity = "MEDIUM"
                event = "Asset Bruteforcing Detect"
            else:
                severity = "LOW"
                event = "Failed Recon Probing"
        elif int(http_status) >= 500:
            severity = "MEDIUM"
            event = "Internal Server Error"

    return {
        "time": sanitize_log_field(data['date'].split()[0]), 
        "ip": sanitize_log_field(data['ip']), 
        "info": sanitize_log_field(f"{data['method']} {data['url'][:40]}"), 
        "status": sanitize_log_field(http_status), 
        "severity": severity, 
        "event": event
    }

def analyze_ssh_line(line):
    parts = line.strip().split()
    if not parts: return None
    
    log_time = parts[0]
    if len(log_time) < 5 and len(parts) >= 3:
        log_time = f"{parts[0]} {parts[1]} {parts[2]}"

    failed_match = re.search(r"Failed password for (invalid user )?(\S+) from (\S+) port", line)
    accepted_match = re.search(r"Accepted password for (\S+) from (\S+) port", line)
    
    if failed_match:
        user = failed_match.group(2)
        ip = failed_match.group(3)
        current_time = time.time()
        tracker = SSH_TRACKER[ip]
        
        if tracker["first_seen"] == 0.0 or (current_time - tracker["first_seen"] > SSH_WINDOW_SECONDS):
            tracker["count"] = 1
            tracker["first_seen"] = current_time
            tracker["reported"] = False
        else:
            tracker["count"] += 1

        if tracker["count"] >= SSH_THRESHOLD_LIMIT:
            severity = "HIGH"
            event = f"SSH Brute-Force: {tracker['count']} Failures in <{SSH_WINDOW_SECONDS}s"
        else:
            severity = "LOW"
            event = f"Failed SSH Login Attempt (Count: {tracker['count']})"

        return {
            "time": sanitize_log_field(log_time.split("T")[-1].split(".")[0] if "T" in log_time else log_time), 
            "ip": sanitize_log_field(ip), 
            "info": sanitize_log_field(f"User: {user}"), 
            "status": "-", 
            "severity": severity, 
            "event": event
        }

    elif accepted_match:
        user = accepted_match.group(1)
        ip = accepted_match.group(2)
        if ip in SSH_TRACKER:
            del SSH_TRACKER[ip]
            
        severity = "HIGH" if "root" in user else "LOW"
        return {
            "time": sanitize_log_field(log_time.split("T")[-1].split(".")[0] if "T" in log_time else log_time), 
            "ip": sanitize_log_field(ip), 
            "info": sanitize_log_field(f"User: {user}"), 
            "status": "-", 
            "severity": severity, 
            "event": "Successful SSH Authentication"
        }
        
    return None 

def daemon_engine(log_type, target):
    if log_type == "web":
        start_background_threads()

    path = PATHS[target] if log_type == "web" else PATHS["ssh"]
    cache_path = CACHE_FILES[log_type]
    
    if not os.path.exists(path): return

    with open(path, "r", errors="ignore") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue
            
            alert = analyze_web_line(line) if log_type == "web" else analyze_ssh_line(line)
            if alert:
                if log_type == "web":
                    is_normal_web = (alert['severity'] == "LOW" and alert['event'] == "Normal Web Traffic")
                    is_view_active = os.path.exists(STATUS_FILE)
                    
                    if not is_normal_web or is_view_active:
                        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
                        fd = os.open(cache_path, flags, 0o600)
                        with os.fdopen(fd, "a") as cache_f:
                            cache_f.write(f"{alert['time']}|{alert['ip']}|{alert['info']}|{alert['status']}|{alert['severity']}|{alert['event']}\n")
                    
                    if alert['severity'] == "HIGH":
                        threading.Thread(target=send_telegram_alert, args=(log_type, alert), daemon=True).start()
                    elif alert['severity'] in ["LOW", "MEDIUM"] and not is_normal_web:
                        DIGEST_QUEUE.put({"log_type": "web", "data": alert})
                else:
                    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
                    fd = os.open(cache_path, flags, 0o600)
                    with os.fdopen(fd, "a") as cache_f:
                        cache_f.write(f"{alert['time']}|{alert['ip']}|{alert['info']}|{alert['status']}|{alert['severity']}|{alert['event']}\n")
                    
                    if alert['severity'] == "HIGH":
                        threading.Thread(target=send_telegram_alert, args=(log_type, alert), daemon=True).start()
                    else:
                        DIGEST_QUEUE.put({"log_type": "ssh", "data": alert})

def run_interactive_ui(log_type, title, col_headers):
    cache_path = CACHE_FILES[log_type]
    
    if log_type == "web":
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        fd = os.open(STATUS_FILE, flags, 0o600)
        with os.fdopen(fd, "w") as sf:
            sf.write("1")

    if not os.path.exists(cache_path):
        flags = os.O_WRONLY | os.O_CREAT
        fd = os.open(cache_path, flags, 0o600)
        with os.fdopen(fd, "w") as c_desc: pass

    table = Table(expand=True, title=title)
    for col in col_headers: table.add_column(col)
    console.print("[bold green]Entering Interactive View. Ctrl+C to exit dashboard (Daemon stays alive).[/]")
    
    try:
        with Live(table, refresh_per_second=4):
            with open(cache_path, "r", errors="ignore") as f:
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
    except KeyboardInterrupt:
        pass
    finally:
        if log_type == "web" and os.path.exists(STATUS_FILE):
            try: os.remove(STATUS_FILE)
            except Exception: pass

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

# Context Replacement Injection Processing
TOOL_CODE = TOOL_CODE.replace("___BOT_TOKEN___", TELEGRAM_BOT_TOKEN)
TOOL_CODE = TOOL_CODE.replace("___CHAT_ID___", TELEGRAM_CHAT_ID)
TOOL_CODE = TOOL_CODE.replace("___HOSTNAME___", custom_hostname)

# Systemd Layout Matrix Structure
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

def write_secured_file(path, payload, mode=0o600):
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(path, flags, mode)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(payload)

def run_cmd(cmd_list):
    subprocess.run(cmd_list, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def main():
    print("[+] Step 1: Querying system requirements and package dependencies...")
    try:
        import click
        import rich
        import requests
    except ImportError:
        print("[*] Required packages missing. Deploying dependencies...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--break-system-packages", "click", "rich", "requests"])

    print(f"[+] Step 2: Provisioning codebase directly into paths: {TOOL_PATH}")
    write_secured_file(TOOL_PATH, TOOL_CODE, mode=0o700)

    print("[+] Step 3: Installing systemd daemon architecture dependencies...")
    write_secured_file("/etc/systemd/system/wcheck-daemon.service", WCHECK_SERVICE)
    write_secured_file("/etc/systemd/system/shcheck-daemon.service", SHCHECK_SERVICE)

    print("[+] Step 4: Activating systemd engine background loops...")
    run_cmd(["systemctl", "daemon-reload"])
    run_cmd(["systemctl", "enable", "--now", "wcheck-daemon.service"])
    run_cmd(["systemctl", "enable", "--now", "shcheck-daemon.service"])

    print("[+] Step 5: Forging clean command-wrapper executions for CLI routes...")
    wcheck_wrapper_path = os.path.join(TARGET_DIR, "wcheck")
    shcheck_wrapper_path = os.path.join(TARGET_DIR, "shcheck")

    for target_bin in [wcheck_wrapper_path, shcheck_wrapper_path]:
        if os.path.exists(target_bin) or os.path.islink(target_bin):
            os.remove(target_bin)

    wcheck_payload = f'#!/bin/bash\nexec /usr/bin/python3 {TOOL_PATH} wcheck "$@"\n'
    write_secured_file(wcheck_wrapper_path, wcheck_payload, mode=0o755)

    shcheck_payload = f'#!/bin/bash\nexec /usr/bin/python3 {TOOL_PATH} shcheck "$@"\n'
    write_secured_file(shcheck_wrapper_path, shcheck_payload, mode=0o755)

    print("\n[============= DEPLOYMENT COMPLETE =============]")
    print(f"[*] Configured Hostname: {custom_hostname}")
    print("[*] Secure SIEM Engine configuration compiled successfully.")
    print("[=================================================]\n")

if __name__ == "__main__":
    main()
