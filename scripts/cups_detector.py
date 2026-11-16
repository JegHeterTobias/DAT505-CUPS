#!/usr/bin/env python3

import argparse
import csv
import json
import re
from collections import Counter
from pathlib import Path

from scapy.all import IP, UDP, TCP, Raw, rdpcap, sniff


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="CUPS printer discovery attack detector"
    )

    parser.add_argument("--pcap", help="PCAP file to analyse")
    parser.add_argument("--cups-ip", default=None)
    parser.add_argument("--ipp-port", type=int, default=8631)
    parser.add_argument("--trusted-sources", default="")
    parser.add_argument("--interface", default="eth0")
    parser.add_argument("--count", type=int, default=100)
    parser.add_argument("--json", dest="json_output")
    parser.add_argument("--csv", dest="csv_output")

    return parser.parse_args()


def get_payload(packet):
    if packet.haslayer(Raw):
        return packet[Raw].load.decode("utf-8", errors="replace").strip()
    return ""


def analyse_packets(packets, cups_ip, ipp_port, trusted_sources):
    alerts = []
    advertisements = Counter()

    for number, packet in enumerate(packets, start=1):

        if not packet.haslayer(IP):
            continue

        src = packet[IP].src
        dst = packet[IP].dst

        if (
            packet.haslayer(UDP)
            and packet[UDP].dport == 631
            and packet.haslayer(Raw)
        ):
            payload = get_payload(packet)
            advertisements[src] += 1

            valid_format = bool(
                re.match(r'^\d+\s+\d+\s+ipp://\S+', payload)
            )

            if not valid_format:
                alerts.append({
                    "packet": number,
                    "severity": "WARNING",
                    "type": "Malformed printer advertisement",
                    "source": src,
                    "destination": dst,
                    "details": "Unexpected CUPS browse packet format"
                })

            else:
                if trusted_sources and src not in trusted_sources:
                    alerts.append({
                        "packet": number,
                        "severity": "HIGH",
                        "type": "Unauthorized printer advertisement",
                        "source": src,
                        "destination": dst,
                        "details": "Source IP is not in the trusted-source list"
                    })

                elif not trusted_sources:
                    alerts.append({
                        "packet": number,
                        "severity": "INFO",
                        "type": "Printer advertisement",
                        "source": src,
                        "destination": dst,
                        "details": "Valid-looking printer advertisement detected"
                    })

                match = re.search(r'ipp://[^\s"]+', payload)

                if match:
                    alerts.append({
                        "packet": number,
                        "severity": "INFO",
                        "type": "Advertised IPP printer",
                        "source": src,
                        "destination": dst,
                        "details": f"Printer URI: {match.group(0)}"
                    })

        if packet.haslayer(TCP) and packet[TCP].dport == ipp_port:
            tcp_flags = int(packet[TCP].flags)

            if (tcp_flags & 0x02) and not (tcp_flags & 0x10):
                if cups_ip is None or src == cups_ip:
                    alerts.append({
                        "packet": number,
                        "severity": "INFO",
                        "type": "IPP connection attempt",
                        "source": src,
                        "destination": dst,
                        "details": f"New TCP connection attempt to IPP port {ipp_port}"
                    })

    for source, count in advertisements.items():
        if count > 3:
            alerts.append({
                "packet": None,
                "severity": "WARNING",
                "type": "Repeated printer advertisements",
                "source": source,
                "destination": "",
                "details": f"{count} advertisements detected from {source}"
            })

    return alerts


def save_json(alerts, filename):
    path = Path(filename)
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as file:
        json.dump(alerts, file, indent=4)

    print(f"[+] JSON saved: {path}")


def save_csv(alerts, filename):
    path = Path(filename)
    path.parent.mkdir(parents=True, exist_ok=True)

    fields = [
        "packet",
        "severity",
        "type",
        "source",
        "destination",
        "details"
    ]

    with path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()
        writer.writerows(alerts)

    print(f"[+] CSV saved: {path}")


def main():
    args = parse_arguments()

    trusted_sources = {
        address.strip()
        for address in args.trusted_sources.split(",")
        if address.strip()
    }

    print("=" * 60)
    print("CUPS PRINTER DISCOVERY ATTACK DETECTOR")
    print("=" * 60)

    if args.pcap:
        print(f"[*] Reading PCAP: {args.pcap}")
        packets = rdpcap(args.pcap)
    else:
        print(f"[*] Capturing on: {args.interface}")
        packets = sniff(
            iface=args.interface,
            count=args.count,
            filter=f"udp port 631 or tcp port {args.ipp_port}"
        )

    print(f"[*] Analysing {len(packets)} packets...")

    alerts = analyse_packets(
        packets,
        args.cups_ip,
        args.ipp_port,
        trusted_sources
    )

    print("\nDETECTION RESULTS")

    if not alerts:
        print("[+] No suspicious activity detected.")
    else:
        for alert in alerts:
            print(f"\n[{alert['severity']}] {alert['type']}")
            print(f"Packet:      {alert['packet']}")
            print(f"Source:      {alert['source']}")
            print(f"Destination: {alert['destination']}")
            print(f"Details:     {alert['details']}")

    high = sum(a["severity"] == "HIGH" for a in alerts)
    warnings = sum(a["severity"] == "WARNING" for a in alerts)
    info = sum(a["severity"] == "INFO" for a in alerts)

    print("\nSUMMARY")
    print(f"Packets analysed: {len(packets)}")
    print(f"Alerts generated: {len(alerts)}")
    print(f"High severity:    {high}")
    print(f"Warnings:         {warnings}")
    print(f"Informational:    {info}")

    if args.json_output:
        save_json(alerts, args.json_output)

    if args.csv_output:
        save_csv(alerts, args.csv_output)

    print("\n[*] Analysis complete.")


if __name__ == "__main__":
    main()
