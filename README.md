# SOC Intrusion Detection Lab

> A hands-on SOC simulation environment built with Suricata IDS and Splunk SIEM, demonstrating real-time intrusion detection, custom rule authoring, and cross-machine log forwarding.

---

## Overview

This project simulates a Security Operations Center (SOC) detection pipeline using two virtual machines on VMware Fusion. Attack traffic is generated from a Kali Linux attacker VM, detected by Suricata IDS on an Ubuntu sensor VM, and forwarded in real time to Splunk Enterprise running on a separate machine over Wi-Fi.

The goal was to build a fully functional IDS → SIEM pipeline from scratch — including network segmentation, custom Suricata rules, and log forwarding across two physical machines.

---

## Architecture

![Architecture Diagram](docs/architecture.png)

> Full PDF version available in [`/docs/SOC_Lab_Architecture.pdf`](docs/SOC_Lab_Architecture.pdf)

---

## Environment

| Component | Details |
|---|---|
| Hypervisor | VMware Fusion (Intel MacBook Pro) |
| Sensor VM | Ubuntu 24.04 LTS |
| Attacker VM | Kali Linux (rolling) |
| IDS | Suricata 7.x |
| SIEM | Splunk Enterprise (M5 MacBook Pro) |
| Log Forwarder | Splunk Universal Forwarder 10.x |
| Network (internal) | VMware Host-Only (Private to my Mac) |
| Network (SIEM) | VMware Bridged Wi-Fi |

### Dual NIC Configuration (Ubuntu Sensor)

The Ubuntu VM was configured with two network adapters to isolate detection traffic from log forwarding traffic:

- **NIC1 (ens33)** — `192.168.115.132` — Private to my Mac — Suricata sniffs this interface for attack traffic from Kali
- **NIC2 (ens37)** — `192.168.1.200` — Bridged Wi-Fi — Splunk Universal Forwarder sends logs to Splunk Enterprise on a separate MacBook over the local network

---

## Detection Pipeline

```
Kali Linux (attacker)
    │
    │  nmap SYN scan / ICMP ping / malicious HTTP User-Agent
    ▼
Ubuntu ens33  ←── Suricata sniffs all inbound traffic
    │
    │  pattern match against custom rules + ET Open ruleset
    ▼
/var/log/suricata/eve.json  (structured JSON alerts)
    │
    │  Splunk Universal Forwarder monitors file
    ▼
Splunk Enterprise (192.168.1.105:9997)
    │
    │  index=main sourcetype=suricata
    ▼
Search, alerts, dashboards
```

---

## Custom Suricata Rules

Two custom rules were authored in `/etc/suricata/rules/local.rules`:

```
alert icmp any any -> $HOME_NET any (msg:"ICMP Ping detected"; sid:1000001; rev:1;)
alert tcp  any any -> $HOME_NET any (flags:S; msg:"port scan detected"; sid:1000002; rev:1;)
```

- **Rule 1** — Triggers on any inbound ICMP echo request, detecting basic ping reconnaissance
- **Rule 2** — Triggers on TCP SYN packets (flag `S`), catching port scan attempts including Nmap `-sS` stealth scans

`$HOME_NET` was verified to include `192.168.0.0/16`, `10.0.0.0/8`, and `172.16.0.0/12`, covering the entire private address space.

> Full rule file available in [`/rules/local.rules`](rules/local.rules)

---

## Attack Simulation

All attacks were launched from the Kali Linux VM (`192.168.115.130`) targeting the Ubuntu sensor (`192.168.115.132`):

### 1. ICMP Ping
```bash
ping 192.168.115.132
```
Triggers `ICMP Ping detected` (sid:1000001)

### 2. Nmap SYN Scan
```bash
nmap -sS 192.168.115.132
```
Triggers `port scan detected` (sid:1000002) — one alert per SYN packet across all scanned ports

### 3. Malicious HTTP User-Agent
```bash
curl -A "sqlmap/1.0" http://192.168.115.132/
```
Triggers ET Open ruleset signatures for known malicious scanners (sqlmap, Nikto, etc.)

---

## Results

### Suricata fast.log (real-time alerts)

```
03/21/2026-03:03:27  [**] [1:1000002:1] port scan detected [**] [Priority: 3] {TCP} 192.168.115.130 -> 192.168.115.132
03/21/2026-03:03:27  [**] [1:1000002:1] port scan detected [**] [Priority: 3] {TCP} 192.168.115.130 -> 192.168.115.132
03/21/2026-02:53:52  [**] [1:1000001:1] ICMP Ping detected [**] [Priority: 3] {ICMP} 192.168.115.130 -> 192.168.115.132
```

### Splunk SIEM

- **41,451 alert events** ingested (`index=main sourcetype=suricata event_type=alert`)
- Key fields parsed from `eve.json`: `src_ip`, `dest_ip`, `dest_port`, `alert.signature`, `alert.severity`, `proto`, `in_iface`, `timestamp`
- Example alert record:

```json
{
  "event_type": "alert",
  "src_ip": "192.168.115.130",
  "dest_ip": "192.168.115.132",
  "dest_port": 6566,
  "proto": "TCP",
  "in_iface": "ens33",
  "alert": {
    "signature": "port scan detected",
    "signature_id": 1000002,
    "severity": 3,
    "action": "allowed"
  }
}
```

---

## Key Technical Decisions

**Why dual NIC?**
Separating detection traffic (NIC1/Host-Only) from log forwarding traffic (NIC2/Bridged) mirrors a real SOC architecture where the sensor network is isolated from the management/reporting network. This prevents log traffic from appearing as suspicious activity on the monitored interface.

**Why Splunk Universal Forwarder instead of syslog?**
The Universal Forwarder provides reliable, encrypted forwarding with buffering — if the network drops, logs queue locally and are sent once connectivity resumes. It also preserves the structured JSON format of `eve.json`, enabling field-level SPL queries in Splunk.

**Why eve.json over fast.log?**
`fast.log` is human-readable but flat text. `eve.json` emits structured JSON with full flow metadata (flow_id, packet source, app_proto), making it suitable for SIEM ingestion and enabling precise SPL queries like `alert.signature_id=1000002`.

---

## SPL Queries Used

```spl
# All Suricata alerts in the last 30 minutes
index=main sourcetype=suricata event_type=alert

# Filter by attacker IP
index=main sourcetype=suricata src_ip="192.168.115.130"

# Count alerts by signature
index=main sourcetype=suricata event_type=alert
| stats count by alert.signature
| sort -count

# Port scan events only
index=main sourcetype=suricata event_type=alert alert.signature_id=1000002
```

> Full query file available in [`/splunk/queries.spl`](splunk/queries.spl)

---

## Screenshots

| # | Description |
|---|---|
| 1 | Ubuntu dual NIC configuration (`ifconfig`) |
| 2 | VMware NIC1 — Private to my Mac |
| 3 | VMware NIC2 — Bridged Wi-Fi |
| 4 | Custom Suricata rules (`local.rules`) |
| 5 | Kali Linux attacker — nmap, ping, curl |
| 6 | Suricata `fast.log` — Kali IP filtered alerts |
| 7 | Splunk — `eve.json` event detail |
| 8 | Splunk — 41,451 alert events ingested |
| 9 | Splunk — `alert.signature` field expanded |

*(Screenshots available in [`/screenshots/`](screenshots/))*

---

## Skills Demonstrated

- Network segmentation with VMware Fusion (Host-Only + Bridged)
- Suricata IDS deployment and custom rule authoring (ICMP, TCP SYN)
- ET Open ruleset integration and `$HOME_NET` variable configuration
- Structured log analysis with `eve.json`
- Splunk Universal Forwarder setup and cross-machine log forwarding
- SPL query authoring for alert triage and investigation
- Attack simulation with Nmap, ping, and curl (sqlmap UA)

---

## Author

**Hoyeon Kang** | Georgia Tech CS, GPA 3.8 | raykang20@gmail.com
