# CodeAlpha_NIDS

Network Intrusion Detection System with automated response, built for the CodeAlpha Cyber Security Internship (Task 4).

## Overview
Uses Suricata as the detection engine with custom rules, paired with a Python
automation script that watches Suricata's alert log in real time and
automatically blocks malicious source IPs using iptables.

## Components
- **custom.rules** — custom Suricata detection rules:
  - `CUSTOM Ping Detected` (sid:1000001) — flags ICMP echo traffic
  - `CUSTOM Possible Port Scan - Multiple SYN` (sid:1000002) — flags 10+ SYN
    packets from one source within 5 seconds (threshold-based detection)
- **auto_response.py** — monitors `/var/log/suricata/eve.json` live, matches
  alerts against watched signature IDs, and auto-blocks the source IP with
  `iptables -A INPUT -s <ip> -j DROP`. Includes a whitelist to protect
  critical addresses (gateway, DNS, local machine) from being blocked.
- **auto_response.log** — action log of every alert match and block/skip
  decision made by the script.

## Setup
1. Install Suricata and update rules:
   sudo apt install -y suricata
   sudo suricata-update
2. Add custom.rules to /etc/suricata/suricata.yaml under rule-files, and
   copy it to /var/lib/suricata/rules/.
3. Run Suricata:
   sudo suricata -c /etc/suricata/suricata.yaml -i eth0
4. Run the automation script:
   sudo python3 auto_response.py

## Testing
- ping -c 4 8.8.8.8 → triggers the Ping rule
- sudo nmap -sS -p 1-50 scanme.nmap.org → triggers the Port Scan rule and
  the automation script logs the match (blocking is skipped for
  whitelisted/local addresses by design)
- Verified iptables blocking works independently:
  sudo iptables -A INPUT -s 203.0.113.99 -j DROP

## Screenshots
See the `screenshots/` folder for Suricata running, live alerts in eve.json,
and the automation script matching and responding to alerts.

## Disclaimer
For educational use on networks you own or are authorized to test.
