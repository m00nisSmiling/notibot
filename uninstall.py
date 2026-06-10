#!/usr/bin/env python3
import os
import sys
import subprocess

TARGET_DIR = "/usr/local/bin"
TOOL_PATH = os.path.join(TARGET_DIR, "siem.py")
WCHECK_WRAPPER = os.path.join(TARGET_DIR, "wcheck")
SHCHECK_WRAPPER = os.path.join(TARGET_DIR, "shcheck")

SERVICES = ["wcheck-daemon.service", "shcheck-daemon.service"]
CACHE_FILES = ["/tmp/wcheck_live.alerts", "/tmp/shcheck_live.alerts"]

def run_cmd(cmd):
    """Utility to run shell commands cleanly and silently."""
    subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def main():
    if os.getuid() != 0:
        print("[!] Execution halted: This uninstaller must be executed via sudo privileges.")
        sys.exit(1)

    print("[+] Step 1: Stopping and disabling active SIEM background daemons...")
    for service in SERVICES:
        print(f"    -> Terminating service loop: {service}...")
        run_cmd(f"systemctl stop {service}")
        run_cmd(f"systemctl disable {service}")
        
        # Completely purge systemd configuration files
        service_path = f"/etc/systemd/system/{service}"
        if os.path.exists(service_path):
            os.remove(service_path)

    # Force systemd to refresh its directory trees and release broken links
    run_cmd("systemctl daemon-reload")
    run_cmd("systemctl reset-failed")

    print("[+] Step 2: Demolishing binary command wrappers and core engine source...")
    for path in [WCHECK_WRAPPER, SHCHECK_WRAPPER, TOOL_PATH]:
        if os.path.exists(path) or os.path.islink(path):
            os.remove(path)
            print(f"    -> Purged from environment: {path}")

    print("[+] Step 3: Clearing persistent live monitoring memory caches...")
    for cache in CACHE_FILES:
        if os.path.exists(cache):
            os.remove(cache)
            print(f"    -> Removed temporary alert file: {cache}")

    print("\n[============= UNINSTALL COMPLETE =============]")
    print("[*] All components of the custom SIEM have been safely purged.")
    print("[*] Background collection loops dropped and wrappers dismantled.")
    print("[================================================]\n")

if __name__ == "__main__":
    main()
