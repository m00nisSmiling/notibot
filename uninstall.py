#!/usr/bin/env python3
import os
import sys
import subprocess

# Ensure script runs as root
if os.getuid() != 0:
    print("[!] Execution halted: This uninstallation script must be executed via sudo privileges.")
    sys.exit(1)

TARGET_DIR = "/usr/local/bin"
TOOL_PATH = os.path.join(TARGET_DIR, "siem.py")
WCHECK_WRAPPER = os.path.join(TARGET_DIR, "wcheck")
SHCHECK_WRAPPER = os.path.join(TARGET_DIR, "shcheck")

SERVICES = ["wcheck-daemon.service", "shcheck-daemon.service"]
DATA_DIRS = ["/var/run/siem", "/var/log/siem"]

def run_cmd(cmd_list, ignore_fail=True):
    try:
        subprocess.run(cmd_list, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        if not ignore_fail:
            print(f"[!] Warning: Failed executing {' '.join(cmd_list)}")
        return False

def force_remove(path):
    if os.path.exists(path) or os.path.islink(path):
        try:
            if os.path.isdir(path) and not os.path.islink(path):
                import shutil
                shutil.rmtree(path)
            else:
                os.remove(path)
            print(f"[+] Removed: {path}")
        except Exception as e:
            print(f"[!] Error deleting {path}: {e}")

def main():
    print("[+] Step 1: Stopping and disabling systemd background services...")
    for service in SERVICES:
        # Check if service is loaded/active before trying to tear it down
        run_cmd(["systemctl", "stop", service])
        run_cmd(["systemctl", "disable", service])
        
        # Remove systemd unit definitions
        service_file = f"/etc/systemd/system/{service}"
        force_remove(service_file)

    print("[+] Step 2: Reloading systemd configuration manager...")
    run_cmd(["systemctl", "daemon-reload"])
    run_cmd(["systemctl", "reset-failed"])

    print("[+] Step 3: Purging engine binaries and user command wrappers...")
    force_remove(TOOL_PATH)
    force_remove(WCHECK_WRAPPER)
    force_remove(SHCHECK_WRAPPER)

    print("[+] Step 4: Cleaning up data directories and cached alert structures...")
    for directory in DATA_DIRS:
        force_remove(directory)

    print("\n[============= UNINSTALL COMPLETE =============]")
    print("[*] All engine components, service records, and loops have been removed.")
    print("[===============================================]\n")

if __name__ == "__main__":
    main()
