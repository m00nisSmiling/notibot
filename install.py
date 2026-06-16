#!/usr/bin/env python3
import os
import sys
import subprocess

TARGET_DIR = "/usr/local/bin"
TOOL_PATH = os.path.join(TARGET_DIR, "siem.py")
WCHECK_WRAPPER = os.path.join(TARGET_DIR, "wcheck")
SHCHECK_WRAPPER = os.path.join(TARGET_DIR, "shcheck")

SERVICES = [
    "wcheck-daemon.service",
    "shcheck-daemon.service"
]

CACHE_FILES = [
    "/tmp/wcheck_live.alerts",
    "/tmp/shcheck_live.alerts",
    "/tmp/.wcheck_active_view"
]

def run_cmd(cmd):
    """Executes a system shell command silently."""
    try:
        subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        return False

def main():
    # Enforce root access privileges
    if os.getuid() != 0:
        print("[!] Execution halted: This uninstaller framework must be executed with sudo privileges.")
        sys.exit(1)

    print("[*] Initiating complete NotiBot SIEM Tool removal...")

    # Step 1: Terminate and disable systemd background services
    print("[+] Step 1: Stopping and disabling persistent systemd background engines...")
    for service in SERVICES:
        if os.path.exists(f"/etc/systemd/system/{service}"):
            print(f"    -> Managing background lifecycle for {service}")
            run_cmd(f"systemctl stop {service}")
            run_cmd(f"systemctl disable {service}")
            try:
                os.remove(f"/etc/systemd/system/{service}")
            except Exception as e:
                print(f"    [!] Failed to remove service definition file: {e}")
        else:
            print(f"    -> Service {service} not active or already absent.")

    # Reload systemd manager configuration profiles
    run_cmd("systemctl daemon-reload")

    # Step 2: Remove compiled bin wrappers and global binaries
    print("[+] Step 2: Purging global execution wrappers and core binaries...")
    targets_to_purge = [TOOL_PATH, WCHECK_WRAPPER, SHCHECK_WRAPPER]
    for target in targets_to_purge:
        if os.path.exists(target) or os.path.islink(target):
            try:
                os.remove(target)
                print(f"    -> Removed tracking path link: {target}")
            except Exception as e:
                print(f"    [!] Failed to strip target binary {target}: {e}")
        else:
            print(f"    -> Target entry path {target} already clear.")

    # Step 3: Clear transient volatile cache files
    print("[+] Step 3: Wiping volatile 2-hour staging files and tracking caches...")
    for cache in CACHE_FILES:
        if os.path.exists(cache):
            try:
                os.remove(cache)
                print(f"    -> Purged log cache state file: {cache}")
            except Exception as e:
                print(f"    [!] Failed to sweep volatile file {cache}: {e}")
        else:
            print(f"    -> File trace {cache} not present on filesystem.")

    print("\n[============= UNINSTALL COMPLETE =============]")
    print("[*] All systemic background hooks have been successfully stripped.")
    print("[*] NotiBot SIEM engine has been cleanly removed from the host environment.")
    print("[=================================================]\n")

if __name__ == "__main__":
    main()
