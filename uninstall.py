#!/usr/bin/env python3
import os
import sys
import subprocess

# Ensure script runs as root
if os.getuid() != 0:
    print("[!] Execution halted: This uninstallation framework must be executed via sudo privileges.")
    sys.exit(1)

TARGET_DIR = "/usr/local/bin"
TOOL_PATH = os.path.join(TARGET_DIR, "siem.py")
WCHECK_WRAPPER = os.path.join(TARGET_DIR, "wcheck")
SHCHECK_WRAPPER = os.path.join(TARGET_DIR, "shcheck")

SERVICES = ["wcheck-daemon.service", "shcheck-daemon.service"]
SYSTEMD_DIR = "/etc/systemd/system"

# Hardened storage runtime environments
RUN_DIR = "/var/run/siem"
VAR_LOG_DIR = "/var/log/siem"

def run_cmd(cmd_list):
    try:
        subprocess.run(cmd_list, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass

def main():
    print("[+] Step 1: Stopping and disabling systemd background engines...")
    for service in SERVICES:
        print(f" [*] Deactivating: {service}")
        run_cmd(["systemctl", "stop", service])
        run_cmd(["systemctl", "disable", service])
        
        # Remove definition matrix links
        service_path = os.path.join(SYSTEMD_DIR, service)
        if os.path.exists(service_path):
            os.remove(service_path)

    print("[+] Step 2: Reloading systemd daemon control configurations...")
    run_cmd(["systemctl", "daemon-reload"])
    run_cmd(["systemctl", "reset-failed"])

    print("[+] Step 3: Purging command wrappers and core engine binaries...")
    for binary in [TOOL_PATH, WCHECK_WRAPPER, SHCHECK_WRAPPER]:
        if os.path.exists(binary) or os.path.islink(binary):
            print(f" [*] Dropping entry: {binary}")
            try:
                os.remove(binary)
            except Exception as e:
                print(f" [!] Error removing {binary}: {e}")

    print("[+] Step 4: Erasing operational runtime volatile memory environments...")
    # Clean staging files, status controls, and alerts history
    for path in [RUN_DIR, VAR_LOG_DIR]:
        if os.path.exists(path):
            print(f" [*] Purging directory infrastructure: {path}")
            # Use standard recursive walking tools safely instead of shell matching vectors
            for root, dirs, files in os.walk(path, topdown=False):
                for name in files:
                    os.remove(os.path.join(root, name))
                for name in dirs:
                    os.rmdir(os.path.join(root, name))
            try:
                os.rmdir(path)
            except Exception:
                pass

    print("\n[============= UNINSTALLATION COMPLETE =============]")
    print("[*] Secure SIEM Engine structures dismantled successfully.")
    print("[===================================================]\n")

if __name__ == "__main__":
    main()
