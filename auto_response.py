#!/usr/bin/env python3
"""CodeAlpha Task 4 - NIDS Auto-Response Script

Monitors Suricata's eve.json log in real time. When an alert from our
custom rules (or any high-severity alert) is seen from an IP, it is
automatically blocked with iptables and the action is logged.

Usage:
    sudo python3 auto_response.py
"""
import json
import subprocess
import time
from datetime import datetime

EVE_LOG = "/var/log/suricata/eve.json"
ACTION_LOG = "auto_response.log"

# IPs we must NEVER block (gateway, DNS, localhost, our own machine)
WHITELIST = {"10.0.2.2", "10.0.2.3", "10.0.2.15", "127.0.0.1"}

# Custom rule signature IDs we react to (from custom.rules)
REACT_SIDS = {1000002}  # Possible Port Scan

blocked_ips = set()


def log(msg):
    line = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line)
    with open(ACTION_LOG, "a") as f:
        f.write(line + "\n")


def block_ip(ip):
    if ip in WHITELIST:
        log(f"SKIPPED blocking {ip} (whitelisted)")
        return
    if ip in blocked_ips:
        return  # already blocked, avoid duplicate rules

    result = subprocess.run(
        ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        blocked_ips.add(ip)
        log(f"BLOCKED {ip} via iptables")
    else:
        log(f"FAILED to block {ip}: {result.stderr.strip()}")


def follow(path):
    """Yield new lines appended to a file, like `tail -f`."""
    with open(path, "r") as f:
        f.seek(0, 2)  # go to end of file
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line


def main():
    log("Auto-response engine started. Watching Suricata alerts...")
    for line in follow(EVE_LOG):
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue

        if event.get("event_type") != "alert":
            continue

        alert = event.get("alert", {})
        sid = alert.get("signature_id")
        signature = alert.get("signature", "")
        src_ip = event.get("src_ip")

        if sid in REACT_SIDS and src_ip:
            log(f"ALERT MATCHED: sid={sid} signature='{signature}' src_ip={src_ip}")
            block_ip(src_ip)


if __name__ == "__main__":
    main()
