
#!/usr/bin/env python3

import argparse
from datetime import datetime
from pathlib import Path

from scapy.all import IP, UDP, Raw, send, wrpcap


def build_advertisement(args):
    """Build a legacy CUPS printer browse advertisement."""

    printer_uri = (
        f"ipp://{args.printer_ip}:{args.ipp_port}"
        f"/printers/{args.queue}"
    )

    if args.variant == "malformed":
        payload = (
            f"INVALID-CUPS-ADVERTISEMENT {printer_uri}\n"
        )
    else:
        payload = (
            f"2 3 {printer_uri} "
            f'"{args.location}" '
            f'"{args.description}" '
            f'"{args.make_model}"\n'
        )

    return (
        IP(src=args.source_ip, dst=args.target_ip)
        / UDP(sport=631, dport=631)
        / Raw(load=payload.encode("utf-8"))
    )


def main():
    parser = argparse.ArgumentParser(
        description="Controlled CUPS printer discovery lab sender"
    )

    parser.add_argument("--target-ip", default="172.21.0.2")
    parser.add_argument("--source-ip", default="172.21.0.3")
    parser.add_argument("--printer-ip", default="172.21.0.3")
    parser.add_argument("--ipp-port", type=int, default=8631)
    parser.add_argument("--queue", default="lab")
    parser.add_argument("--location", default="Lab")
    parser.add_argument(
        "--description",
        default="Controlled Lab Printer"
    )
    parser.add_argument(
        "--make-model",
        default="Virtual IPP Printer"
    )
    parser.add_argument(
        "--variant",
        choices=["baseline", "different-queue", "different-port", "malformed"],
        default="baseline"
    )
    parser.add_argument(
        "--output",
        default="",
        help="Output PCAP path"
    )

    args = parser.parse_args()

    if not 1 <= args.ipp_port <= 65535:
        parser.error("IPP port must be between 1 and 65535")

    if args.variant == "different-queue":
        args.queue = args.queue + "_variant"

    if args.variant == "different-port" and args.ipp_port == 8631:
        args.ipp_port = 8632

    packet = build_advertisement(args)

    output = args.output or (
        f"cups_{args.variant}_"
        f"{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
    )

    output_path = Path(output).expanduser()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"Variant: {args.variant}")
    print(f"Target CUPS: {args.target_ip}")
    print(f"Advertised printer: {args.printer_ip}:{args.ipp_port}")
    print(f"Queue: {args.queue}")
    print(f"Payload: {bytes(packet[Raw].load).decode().strip()}")

    wrpcap(str(output_path), [packet])
    print(f"Saved packet to: {output_path}")

    confirm = input(
        "Send this advertisement to the isolated lab? [y/N]: "
    ).strip().lower()

    if confirm == "y":
        send(packet, verbose=False)
        print("Advertisement sent.")
    else:
        print("Sending cancelled. PCAP was still saved.")


if __name__ == "__main__":
    main()

