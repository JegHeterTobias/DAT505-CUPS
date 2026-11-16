# CUPS Printer Discovery Exploitation and Attack Detection

## Overview

This project investigates printer discovery vulnerabilities in CUPS using an isolated Docker lab based on CVE-2024-47177.

The project demonstrates how an attacker can advertise a controlled IPP printer to a vulnerable CUPS environment, causing the victim to discover the printer and request its IPP attributes.

It also implements a Python-based detection tool using Scapy to identify suspicious printer advertisements and unexpected IPP connections.

The final experiment investigates a mitigation by disabling remote printer discovery.

## Project objectives

- Understand CUPS printer discovery over UDP port 631.
- Create custom printer discovery packets using Scapy.
- Demonstrate unauthorized printer discovery.
- Test different advertisement variations.
- Develop a detector for suspicious CUPS traffic.
- Analyse PCAP files and export detection alerts.
- Implement and evaluate a mitigation.

## Technologies

- Python 3
- Scapy
- Docker and Docker Compose
- CUPS / cups-browsed
- IPP (Internet Printing Protocol)
- tcpdump
- Wireshark
- PCAP

## Lab environment

The lab consists of two Docker containers connected through an isolated Docker network.

| Component | IP address | Purpose |
|---|---|---|
| CUPS victim | 172.21.0.2 | Vulnerable printer discovery service |
| Attacker | 172.21.0.3 | Sends printer advertisements |
| Virtual IPP printer | 172.21.0.3:8631 | Controlled printer service |

The virtual printer uses `ippserver` in reject-only mode. No command execution or remote code execution is performed.

## Repository structure

```text
DAT505-CUPS/
├── scripts/
│   ├── cups_attack.py
│   └── cups_detector.py
├── pcap_files/
│   ├── cups_attack.pcap
│   ├── cups_baseline.pcap
│   ├── cups_different_port.pcap
│   ├── cups_different_queue.pcap
│   ├── cups_malformed.pcap
│   └── cups_after_mitigation.pcap
├── evidence/
│   ├── attack_alerts.csv
│   ├── attack_alerts.json
│   ├── baseline_alerts.csv
│   ├── baseline_alerts.json
│   ├── malformed_alerts.csv
│   ├── malformed_alerts.json
│   ├── trusted_test.csv
│   ├── trusted_test.json
│   ├── different_queue.log
│   ├── different_port.log
│   ├── malformed.log
│   ├── after_mitigation.log
│   └── successful_discovery.log
├── requirements.txt
└── README.md
```

## Installation

Create and activate a Python virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

The attacker container requires Scapy and tcpdump. The virtual IPP printer requires `ippserver`.

## Starting the lab

Clone Vulhub:

```bash
git clone https://github.com/vulhub/vulhub.git
```

Navigate to the CUPS vulnerability environment:

```bash
cd vulhub/cups-browsed/CVE-2024-47177
```

Start the environment:

```bash
docker compose up -d
```

Start the attacker container on the same Docker network:

```bash
docker run -it --rm \
  --name cups-attacker \
  --network cve-2024-47177_default \
  --cap-add NET_RAW \
  --cap-add NET_ADMIN \
  python:3.12-slim bash
```

Install the required packages inside the attacker container:

```bash
pip install scapy ippserver
apt-get update && apt-get install -y tcpdump
```

Start the controlled IPP printer:

```bash
python -m ippserver -v -H 0.0.0.0 -p 8631 reject
```

Keep the IPP server running while conducting the experiments.

## Attack experiments

The attack script sends custom CUPS printer advertisements using Scapy.

Copy the script into the attacker container:

```bash
docker cp ~/DAT505-CUPS/scripts/cups_attack.py cups-attacker:/tmp/cups_attack.py
```

### 1. Baseline advertisement

```bash
docker exec -it cups-attacker python /tmp/cups_attack.py \
  --variant baseline \
  --output /tmp/cups_baseline.pcap
```

### 2. Different queue name

```bash
docker exec -it cups-attacker python /tmp/cups_attack.py \
  --variant different-queue \
  --output /tmp/cups_different_queue.pcap
```

### 3. Different IPP port

```bash
docker exec -it cups-attacker python /tmp/cups_attack.py \
  --variant different-port \
  --output /tmp/cups_different_port.pcap
```

### 4. Malformed advertisement

```bash
docker exec -it cups-attacker python /tmp/cups_attack.py \
  --variant malformed \
  --output /tmp/cups_malformed.pcap
```

The script asks for confirmation before sending each advertisement.

## Attack detection

The detection script analyses PCAP files and identifies:

- Malformed CUPS printer advertisements.
- Printer advertisements from untrusted IP addresses.
- Advertised IPP printer URIs.
- New TCP connections to the configured IPP port.
- Repeated printer advertisements.

Example:

```bash
python scripts/cups_detector.py \
  --pcap pcap_files/cups_attack.pcap \
  --cups-ip 172.21.0.2 \
  --ipp-port 8631 \
  --trusted-sources 172.21.0.99 \
  --json evidence/attack_alerts.json \
  --csv evidence/attack_alerts.csv
```

The trusted-source argument accepts a comma-separated list of IP addresses.

### Allowlist test

The detector can also be tested with the attacker IP configured as trusted:

```bash
python scripts/cups_detector.py \
  --pcap pcap_files/cups_attack.pcap \
  --cups-ip 172.21.0.2 \
  --ipp-port 8631 \
  --trusted-sources 172.21.0.3 \
  --json evidence/trusted_test.json \
  --csv evidence/trusted_test.csv
```

### Normal traffic baseline

A 20-second idle capture was conducted using:

```bash
tcpdump -i eth0 -nn \
  -w /tmp/cups_normal.pcap \
  'udp port 631 or tcp port 8631'
```

No matching packets were captured during this interval. The detector consequently generated zero alerts.

This represents an idle baseline, not a test of normal printer discovery traffic.

## Mitigation

The mitigation tested was disabling remote printer discovery through the cups-browsed configuration.

The original configuration was backed up before modification.

The following setting was applied:

```text
BrowseRemoteProtocols none
```

The CUPS container was restarted:

```bash
docker compose restart cups
```

The logs confirmed that the new configuration was loaded:

```text
Reading config: BrowseRemoteProtocols none
```

The baseline advertisement was then transmitted again from the attacker container.

The attacker PCAP confirmed that the UDP packet was sent to the CUPS container. However, no new printer discovery processing or queue creation appeared in the CUPS logs.

This demonstrates that disabling remote printer browsing prevented the tested advertisement from being processed.

## Experimental results

| Experiment | Observation |
|---|---|
| Baseline advertisement | CUPS discovered the advertised printer |
| Different queue | CUPS discovered the alternative queue |
| Different IPP port | Advertisement received, but IPP connection failed |
| Malformed advertisement | CUPS rejected the packet format |
| Unauthorized advertisement detection | HIGH alert generated |
| Trusted-source test | HIGH alert disappeared |
| Malformed packet detection | WARNING alert generated |
| Idle baseline | Zero packets and zero alerts |
| After mitigation | No new discovery processing observed |

The original attack PCAP contained 29 packets. The detector generated four alerts: one HIGH alert and three informational alerts.

The malformed PCAP contained one packet and generated one WARNING alert.

## Limitations

- The experiments were performed in an isolated Docker network.
- The idle baseline contained zero matching packets and does not represent ordinary printer usage.
- The detector uses packet-level heuristics and does not perform full IPP protocol validation.
- The detector's repeated-advertisement threshold is based on more than three advertisements from one source.
- The mitigation was tested against the specific legacy browsing advertisement used in this lab.
- Remote code execution was not attempted or demonstrated.

## Safety

All experiments were conducted inside an isolated Docker environment under controlled conditions.

The virtual IPP printer was configured in reject-only mode. No real printers, external networks or production systems were targeted.

## Author

DAT505 – Cybersecurity Assignment

CUPS Printer Discovery Exploitation and Attack Detection Using Scapy
