#!/usr/bin/env python3

import os
import time
import socket
import fcntl
import struct
import argparse
import signal
import sys
import logging
import csv
from typing import Dict, List, Optional, TypedDict


class InterfaceStats(TypedDict):
    operstate: str
    carrier: Optional[int]
    speed: Optional[int]
    duplex: Optional[str]
    mtu: Optional[int]
    mac: Optional[str]
    ipv4: Optional[str]
    ipv6: List[str]
    rx_bytes: int
    tx_bytes: int
    rx_packets: int
    tx_packets: int
    rx_errs: int
    tx_errs: int
    rx_drop: int
    tx_drop: int


running = True


def signal_handler(_sig, _frame) -> None:
    global running
    running = False


def read_text(path: str) -> Optional[str]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read().strip()
    except (FileNotFoundError, PermissionError, OSError):
        return None


def read_int(path: str) -> Optional[int]:
    value = read_text(path)
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def get_interfaces() -> List[str]:
    try:
        return sorted(
            name
            for name in os.listdir("/sys/class/net")
            if os.path.isdir(os.path.join("/sys/class/net", name))
        )
    except OSError:
        return []


def parse_proc_net_dev() -> Dict[str, Dict[str, int]]:
    data: Dict[str, Dict[str, int]] = {}
    try:
        with open("/proc/net/dev", "r", encoding="utf-8") as f:
            lines = f.readlines()
    except OSError:
        return data

    for line in lines[2:]:
        if ":" not in line:
            continue
        name, stats = line.split(":", 1)
        iface = name.strip()
        parts = stats.split()
        if len(parts) < 16:
            continue
        try:
            data[iface] = {
                "rx_bytes": int(parts[0]),
                "rx_packets": int(parts[1]),
                "rx_errs": int(parts[2]),
                "rx_drop": int(parts[3]),
                "tx_bytes": int(parts[8]),
                "tx_packets": int(parts[9]),
                "tx_errs": int(parts[10]),
                "tx_drop": int(parts[11]),
            }
        except ValueError:
            continue
    return data


def get_ipv4_address(ifname: str) -> Optional[str]:
    try:
        encoded = ifname.encode("utf-8")
        if len(encoded) > 15:
            logging.debug("Interface name too long for SIOCGIFADDR: %s", ifname)
            return None

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            result = fcntl.ioctl(
                s.fileno(),
                0x8915,
                struct.pack("256s", encoded)
            )
            return socket.inet_ntoa(result[20:24])
        except OSError as e:
            logging.debug("Failed to get IPv4 for %s: %s", ifname, e)
            return None
        finally:
            s.close()
    except OSError as e:
        logging.debug("Socket error for %s: %s", ifname, e)
        return None


def get_ipv6_addresses(ifname: str) -> List[str]:
    addresses: List[str] = []
    try:
        with open("/proc/net/if_inet6", "r", encoding="utf-8") as f:
            for line in f:
                parts = line.split()
                if len(parts) == 6 and parts[5] == ifname:
                    addr_hex = parts[0].zfill(32)
                    try:
                        addr_bytes = bytes.fromhex(addr_hex)
                        addresses.append(socket.inet_ntop(socket.AF_INET6, addr_bytes))
                    except (OSError, ValueError):
                        continue
    except OSError:
        pass
    return addresses


def get_operstate(ifname: str) -> str:
    return read_text(f"/sys/class/net/{ifname}/operstate") or "unknown"


def get_carrier(ifname: str) -> Optional[int]:
    return read_int(f"/sys/class/net/{ifname}/carrier")


def get_speed(ifname: str) -> Optional[int]:
    return read_int(f"/sys/class/net/{ifname}/speed")


def get_duplex(ifname: str) -> Optional[str]:
    return read_text(f"/sys/class/net/{ifname}/duplex")


def get_mtu(ifname: str) -> Optional[int]:
    return read_int(f"/sys/class/net/{ifname}/mtu")


def get_mac(ifname: str) -> Optional[str]:
    return read_text(f"/sys/class/net/{ifname}/address")


def format_rate(value: float) -> str:
    if value < 0:
        value = 0.0
    units = ["B/s", "KiB/s", "MiB/s", "GiB/s"]
    idx = 0
    while value >= 1024 and idx < len(units) - 1:
        value /= 1024.0
        idx += 1
    return f"{value:.2f} {units[idx]}"


def format_pps(value: float) -> str:
    if value < 0:
        value = 0.0
    if value >= 1_000_000:
        return f"{value / 1_000_000:.2f} Mpps"
    if value >= 1_000:
        return f"{value / 1_000:.2f} Kpps"
    return f"{value:.2f} pps"


def calculate_rates(
    current: InterfaceStats,
    previous: Optional[InterfaceStats],
    elapsed: float
) -> tuple[float, float, float, float]:
    if elapsed <= 0 or previous is None:
        return 0.0, 0.0, 0.0, 0.0

    rx_rate = (current["rx_bytes"] - previous["rx_bytes"]) / elapsed
    tx_rate = (current["tx_bytes"] - previous["tx_bytes"]) / elapsed
    rx_pps = (current["rx_packets"] - previous["rx_packets"]) / elapsed
    tx_pps = (current["tx_packets"] - previous["tx_packets"]) / elapsed

    return max(rx_rate, 0.0), max(tx_rate, 0.0), max(rx_pps, 0.0), max(tx_pps, 0.0)


def collect_snapshot(ifaces: List[str]) -> Dict[str, InterfaceStats]:
    proc_stats = parse_proc_net_dev()
    snapshot: Dict[str, InterfaceStats] = {}

    for ifname in ifaces:
        stats = proc_stats.get(ifname, {})
        snapshot[ifname] = {
            "operstate": get_operstate(ifname),
            "carrier": get_carrier(ifname),
            "speed": get_speed(ifname),
            "duplex": get_duplex(ifname),
            "mtu": get_mtu(ifname),
            "mac": get_mac(ifname),
            "ipv4": get_ipv4_address(ifname),
            "ipv6": get_ipv6_addresses(ifname),
            "rx_bytes": stats.get("rx_bytes", 0),
            "tx_bytes": stats.get("tx_bytes", 0),
            "rx_packets": stats.get("rx_packets", 0),
            "tx_packets": stats.get("tx_packets", 0),
            "rx_errs": stats.get("rx_errs", 0),
            "tx_errs": stats.get("tx_errs", 0),
            "rx_drop": stats.get("rx_drop", 0),
            "tx_drop": stats.get("tx_drop", 0),
        }
    return snapshot


def get_state_color(state: str) -> str:
    if not sys.stdout.isatty():
        return ""
    colors = {
        "up": "\033[92m",
        "down": "\033[91m",
        "unknown": "\033[93m",
        "dormant": "\033[93m",
        "lowerlayerdown": "\033[91m",
        "notpresent": "\033[91m",
        "testing": "\033[95m",
    }
    return colors.get(state, "\033[0m")


def get_status_bar_color(snapshot: Dict[str, InterfaceStats]) -> str:
    if not sys.stdout.isatty():
        return ""
    states = [info["operstate"] for info in snapshot.values()]
    if any(state in {"down", "lowerlayerdown", "notpresent"} for state in states):
        return "\033[91m"
    if any(state in {"unknown", "dormant", "testing"} for state in states):
        return "\033[93m"
    return "\033[92m"


def framed_line(width: int = 126) -> str:
    return "┌" + "─" * (width - 2) + "┐"


def framed_bottom(width: int = 126) -> str:
    return "└" + "─" * (width - 2) + "┘"


def framed_separator(width: int = 126) -> str:
    return "├" + "─" * (width - 2) + "┤"


def framed_text(text: str, width: int = 126) -> str:
    inner = width - 4
    if len(text) > inner:
        text = text[:inner]
    return f"│ {text.ljust(inner)} │"


def print_banner(snapshot: Dict[str, InterfaceStats], iteration: int, elapsed: float, width: int = 126) -> None:
    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    color = get_status_bar_color(snapshot)
    reset = "\033[0m" if color else ""
    title = f"NET MONITOR  time={ts}  iteration={iteration}  elapsed={elapsed:.3f}s  interfaces={len(snapshot)}"
    print(color + framed_line(width) + reset)
    print(color + framed_text(title, width) + reset)
    print(color + framed_separator(width) + reset)


def print_header(width: int = 126) -> None:
    header = (
        f"{'IFACE':<12} {'STATE':<14} {'IPv4':<16} "
        f"{'RX RATE':>12} {'TX RATE':>12} "
        f"{'RX PPS':>12} {'TX PPS':>12} "
        f"{'RX ERR':>8} {'TX ERR':>8} "
        f"{'RX DRP':>8} {'TX DRP':>8}"
    )
    print(framed_text(header, width))
    print(framed_separator(width))


def print_row(
    ifname: str,
    current: InterfaceStats,
    previous: Optional[InterfaceStats],
    elapsed: float,
    width: int = 126
) -> None:
    rx_rate, tx_rate, rx_pps, tx_pps = calculate_rates(current, previous, elapsed)
    ipv4 = current["ipv4"] or "-"
    state = current["operstate"]
    color = get_state_color(state)
    reset = "\033[0m" if color else ""

    state_field = f"{color}{state:<14}{reset}" if color else f"{state:<14}"

    row = (
        f"{ifname:<12} {state_field} {ipv4:<16} "
        f"{format_rate(rx_rate):>12} {format_rate(tx_rate):>12} "
        f"{format_pps(rx_pps):>12} {format_pps(tx_pps):>12} "
        f"{current['rx_errs']:>8} {current['tx_errs']:>8} "
        f"{current['rx_drop']:>8} {current['tx_drop']:>8}"
    )

    plain_prefix = f"{ifname:<12} "
    if color:
        visible_rest = (
            f"{ipv4:<16} "
            f"{format_rate(rx_rate):>12} {format_rate(tx_rate):>12} "
            f"{format_pps(rx_pps):>12} {format_pps(tx_pps):>12} "
            f"{current['rx_errs']:>8} {current['tx_errs']:>8} "
            f"{current['rx_drop']:>8} {current['tx_drop']:>8}"
        )
        text = plain_prefix + state_field + " " + visible_rest
    else:
        text = row

    print(framed_text(text, width))


def print_footer(width: int = 126) -> None:
    print(framed_bottom(width))


def print_details(snapshot: Dict[str, InterfaceStats], width: int = 90) -> None:
    print(framed_line(width))
    print(framed_text("INTERFACE DETAILS", width))
    print(framed_separator(width))

    for ifname, info in snapshot.items():
        print(framed_text(f"[{ifname}]", width))
        print(framed_text(f"state    : {info['operstate']}", width))
        print(framed_text(f"carrier  : {info['carrier'] if info['carrier'] is not None else 'N/A'}", width))
        print(framed_text(f"speed    : {str(info['speed']) + ' Mb/s' if info['speed'] is not None else 'N/A'}", width))
        print(framed_text(f"duplex   : {info['duplex'] if info['duplex'] is not None else 'N/A'}", width))
        print(framed_text(f"mtu      : {info['mtu'] if info['mtu'] is not None else 'N/A'}", width))
        print(framed_text(f"mac      : {info['mac'] if info['mac'] is not None else 'N/A'}", width))
        print(framed_text(f"ipv4     : {info['ipv4'] or '-'}", width))

        if info["ipv6"]:
            for idx, addr in enumerate(info["ipv6"], 1):
                print(framed_text(f"ipv6-{idx:<2}  : {addr}", width))
        else:
            print(framed_text("ipv6     : -", width))

        print(framed_text(f"rx_bytes : {info['rx_bytes']}", width))
        print(framed_text(f"tx_bytes : {info['tx_bytes']}", width))
        print(framed_text(f"rx_pkts  : {info['rx_packets']}", width))
        print(framed_text(f"tx_pkts  : {info['tx_packets']}", width))
        print(framed_text(f"rx_errs  : {info['rx_errs']}", width))
        print(framed_text(f"tx_errs  : {info['tx_errs']}", width))
        print(framed_text(f"rx_drop  : {info['rx_drop']}", width))
        print(framed_text(f"tx_drop  : {info['tx_drop']}", width))
        print(framed_separator(width))

    print(framed_bottom(width))


def print_once(snapshot: Dict[str, InterfaceStats], width: int = 126) -> None:
    print_banner(snapshot, iteration=0, elapsed=0.0, width=width)
    print_header(width)
    for ifname in snapshot:
        print_row(ifname, snapshot[ifname], None, 0.0, width)
    print_footer(width)


def write_csv_header(writer: csv.writer) -> None:
    writer.writerow([
        "timestamp",
        "iface",
        "state",
        "ipv4",
        "rx_rate_Bps",
        "tx_rate_Bps",
        "rx_pps",
        "tx_pps",
        "rx_errs",
        "tx_errs",
        "rx_drop",
        "tx_drop",
    ])


def write_csv_row(
    writer: csv.writer,
    timestamp: float,
    ifname: str,
    current: InterfaceStats,
    previous: Optional[InterfaceStats],
    elapsed: float
) -> None:
    rx_rate, tx_rate, rx_pps, tx_pps = calculate_rates(current, previous, elapsed)
    writer.writerow([
        f"{timestamp:.6f}",
        ifname,
        current["operstate"],
        current["ipv4"] or "-",
        f"{rx_rate:.2f}",
        f"{tx_rate:.2f}",
        f"{rx_pps:.2f}",
        f"{tx_pps:.2f}",
        current["rx_errs"],
        current["tx_errs"],
        current["rx_drop"],
        current["tx_drop"],
    ])


def main() -> None:
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    parser = argparse.ArgumentParser(description="Linux network interface monitor")
    parser.add_argument("-i", "--interval", type=float, default=2.0, help="refresh interval in seconds")
    parser.add_argument("-n", "--iterations", type=int, default=0, help="number of refresh cycles, 0 = infinite")
    parser.add_argument("--iface", action="append", help="monitor only selected interface(s)")
    parser.add_argument("--details", action="store_true", help="show detailed interface info before monitoring")
    parser.add_argument("--csv", action="store_true", help="output in CSV format")
    parser.add_argument("--debug", action="store_true", help="enable debug logging")
    parser.add_argument("--once", action="store_true", help="show one snapshot and exit")
    parser.add_argument("--no-header", action="store_true", help="suppress framed table headers in text mode")
    parser.add_argument("--header-every", type=int, default=15, help="repeat framed header every N iterations in text mode")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.WARNING,
        format="%(asctime)s %(levelname)s %(message)s"
    )

    min_interval = 0.1
    if args.interval < min_interval:
        print(f"Warning: Interval too small, setting to {min_interval}s", file=sys.stderr)
        args.interval = min_interval

    if args.header_every < 1:
        args.header_every = 1

    available = set(get_interfaces())
    if args.iface:
        invalid = [iface for iface in args.iface if iface not in available]
        if invalid:
            print(f"Unknown interface(s): {', '.join(invalid)}", file=sys.stderr)
            sys.exit(1)
        ifaces = args.iface
    else:
        ifaces = sorted(available)

    if not ifaces:
        print("No network interfaces found.")
        return

    previous = collect_snapshot(ifaces)
    previous_time = time.time()

    if args.details:
        print_details(previous)
        if not args.once and not args.csv:
            print()

    if args.once:
        if args.csv:
            writer = csv.writer(sys.stdout)
            write_csv_header(writer)
            timestamp = time.time()
            for ifname in ifaces:
                write_csv_row(writer, timestamp, ifname, previous[ifname], None, 0.0)
        else:
            print_once(previous)
        return

    csv_writer = csv.writer(sys.stdout) if args.csv else None
    count = 0

    while running:
        time.sleep(args.interval)

        if not running:
            break

        current_time = time.time()
        current = collect_snapshot(ifaces)
        elapsed = current_time - previous_time

        if args.csv:
            if count == 0:
                write_csv_header(csv_writer)
            for ifname in ifaces:
                write_csv_row(csv_writer, current_time, ifname, current[ifname], previous.get(ifname), elapsed)
        else:
            if not args.no_header and count % args.header_every == 0:
                print_banner(current, iteration=count + 1, elapsed=elapsed, width=126)
                print_header(126)
            for ifname in ifaces:
                print_row(ifname, current[ifname], previous.get(ifname), elapsed, 126)
            if not args.no_header:
                print_footer(126)
            else:
                print()

        previous = current
        previous_time = current_time
        count += 1

        if args.iterations > 0 and count >= args.iterations:
            break


if __name__ == "__main__":
    main()
