import argparse
import csv
import json
import logging
import re
from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path

# Регулярні вирази для валідації IP та MAC-адрес
IP_REGEX = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)
MAC_REGEX = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")


@dataclass
class ArpConflict:
    mac_address: str
    ip_addresses: list[str]


def setup_logging(log_file=None):
    """Налаштування логера для консолі та файлу."""
    logging.addLevelName(logging.WARNING, "ALERT")

    logger = logging.getLogger("ARPAuditor")
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter("[%(levelname)s] %(message)s")

    # Виведення в консоль
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # Запис у файл
    if log_file:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger


def parse_args():
    parser = argparse.ArgumentParser(
        description="Аудитор ARP-таблиць та виявлення ARP-Spoofing"
    )
    parser.add_argument(
        "--arp-file",
        type=str,
        required=True,
        help="Шлях до файлу ARP-таблиці (CSV/TXT)",
    )
    parser.add_argument(
        "--output-json", type=str, required=True, help="Шлях для збереження JSON-звіту"
    )
    parser.add_argument(
        "--detect-spoofing",
        action="store_true",
        help="Прапорець для пошуку ARP-Spoofing",
    )
    parser.add_argument("--log-file", type=str, help="Шлях до лог-файлу", default=None)
    return parser.parse_args()


def main():
    args = parse_args()
    logger = setup_logging(args.log_file)

    arp_path = Path(args.arp_file)
    json_out_path = Path(args.output_json)

    if not arp_path.exists() or not arp_path.is_file():
        logger.error(f"Файл {arp_path} не знайдено.")
        return

    logger.info(f"Parsing ARP table snapshot from {arp_path}...")

    valid_pairs = 0
    invalid_syntax = 0
    total_entries = 0
    mac_to_ips = defaultdict(list)

    with arp_path.open(mode="r", encoding="utf-8") as f:
        sample = f.read(2048)
        f.seek(0)
        dialect = csv.Sniffer().sniff(sample) if sample else csv.excel
        reader = csv.DictReader(f, dialect=dialect)

        for row_num, row in enumerate(reader, start=2):  # start=2 враховуючи заголовок
            total_entries += 1
            ip = row.get("IP Address", "").strip()
            mac = row.get("MAC Address", "").strip().lower()

            if not ip or not mac:
                invalid_syntax += 1
                logger.error(
                    f"Invalid syntax (missing data) at line {row_num}: IP='{ip}', MAC='{mac}'"
                )
                continue

            if IP_REGEX.match(ip) and MAC_REGEX.match(mac):
                valid_pairs += 1
                if ip not in mac_to_ips[mac]:
                    mac_to_ips[mac].append(ip)
            else:
                invalid_syntax += 1
                logger.error(
                    f"Invalid syntax (regex mismatch) at line {row_num}: IP='{ip}', MAC='{mac}'"
                )

    logger.info(f"Validated {total_entries} IP/MAC entries.\n")

    print("=== Validated Entries Summary ===")
    print(f"Valid IP/MAC Pairs\t: {valid_pairs}")
    print(f"Invalid Syntax\t\t: {invalid_syntax}\n")

    conflicts = []
    if args.detect_spoofing:
        for mac, ips in mac_to_ips.items():
            if len(ips) > 1:
                conflicts.append(ArpConflict(mac_address=mac, ip_addresses=ips))

        if conflicts:
            print("=== CRITICAL SECURITY ALERTS: ARP-SPOOFING DETECTED ===")
            for conflict in conflicts:
                logger.warning("MAC Address Duplicate Conflict!")
                print(
                    f"MAC Address: {conflict.mac_address} associated with MULTIPLE IP addresses:"
                )
                for ip in conflict.ip_addresses:
                    note = (
                        " (Default Gateway)"
                        if ip.endswith(".1")
                        else " (Suspicious Host)"
                    )
                    print(f"  {ip}{note}")
                print(
                    "-> POSSIBLE MAN-IN-THE-MIDDLE / ARP-SPOOFING ATTACK IN PROGRESS!\n"
                )

    json_out_path.parent.mkdir(parents=True, exist_ok=True)
    with json_out_path.open("w", encoding="utf-8") as f:
        json.dump([asdict(c) for c in conflicts], f, indent=4)

    if conflicts:
        logger.info(f"Critical conflict logged to {json_out_path}")
    else:
        logger.info(f"No conflicts found. Report saved to {json_out_path}")


if __name__ == "__main__":
    main()
