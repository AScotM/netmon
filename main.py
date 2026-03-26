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

def signal_handler(sig, frame):
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
            name for name in os.listdir("/sys/class/net")
            if os.path.isdir(os.path.join("/sys/class/net", name))
        )
    except OSError:
        return []

def parse_proc_net_dev() -> Dict[str, Dict[str, int]]:
    data = {}
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
    return data

def get_ipv4_address(ifname: str) -> Optional[str]:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            result = fcntl.ioctl(
                s.fileno(),
                0x8915,
                struct.pack("256s", ifname[:15].encode("utf-8"))
            )
            return socket.inet_ntoa(result[20:24])
        except OSError as e:
            logging.debug(f"Failed to get IPv4 for {ifname}: {e}")
            return None
        finally:
            s.close()
    except socket.error as e:
        logging.debug(f"Socket error for {ifname}: {e}")
        return None

def get_ipv6_addresses(ifname: str) -> List[str]:
    addresses = []
    try:
        with open("/proc/net/if_inet6", "r", encoding="utf-8") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 6 and parts[5] == ifname:
                    addr_hex = parts[0]
                    addr_hex = addr_hex.zfill(32)
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
    units = ["B/s", "KiB/s", "MiB/s", "GiB/s"]
    idx = 0
    while value >= 1024 and idx < len(units) - 1:
        value /= 1024.0
        idx += 1
    return f"{value:.2f} {units[idx]}"

def format_pps(value: float) -> str:
    if value >= 1_000_000:
        return f"{value / 1_000_000:.2f} Mpps"
    if value >= 1_000:
        return f"{value / 1_000:.2f} Kpps"
    return f"{value:.2f} pps"

def collect_snapshot(ifaces: List[str]) -> Dict[str, InterfaceStats]:
    proc_stats = parse_proc_net_dev()
    snapshot = {}

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

def print_header() -> None:
    print(
        f"{'IFACE':<12} {'STATE':<8} {'IPv4':<16} "
        f"{'RX RATE':>12} {'TX RATE':>12} "
        f"{'RX PPS':>12} {'TX PPS':>12} "
        f"{'RX ERR':>8} {'TX ERR':>8}"
    )

def get_state_color(state: str) -> str:
    if not sys.stdout.isatty():
        return ""
    colors = {
        "up": "\033[92m",
        "down": "\033[91m",
        "unknown": "\033[93m"
    }
    return colors.get(state, "\033[0m")

def print_row(
    ifname: str,
    current: InterfaceStats,
    previous: Optional[InterfaceStats],
    interval: float
) -> None:
    if interval <= 0 or previous is None:
        rx_rate = tx_rate = rx_pps = tx_pps = 0.0
    else:
        rx_rate = (int(current["rx_bytes"]) - int(previous["rx_bytes"])) / interval
        tx_rate = (int(current["tx_bytes"]) - int(previous["tx_bytes"])) / interval
        rx_pps = (int(current["rx_packets"]) - int(previous["rx_packets"])) / interval
        tx_pps = (int(current["tx_packets"]) - int(previous["tx_packets"])) / interval

    ipv4 = str(current["ipv4"] or "-")
    state = str(current["operstate"])
    color = get_state_color(state)
    reset = "\033[0m"

    print(
        f"{ifname:<12} {color}{state:<8}{reset} {ipv4:<16} "
        f"{format_rate(max(rx_rate, 0.0)):>12} {format_rate(max(tx_rate, 0.0)):>12} "
        f"{format_pps(max(rx_pps, 0.0)):>12} {format_pps(max(tx_pps, 0.0)):>12} "
        f"{int(current['rx_errs']):>8} {int(current['tx_errs']):>8}"
    )

def print_details(snapshot: Dict[str, InterfaceStats]) -> None:
    for ifname, info in snapshot.items():
        print(f"\n[{ifname}]")
        print(f"  state   : {info['operstate']}")
        print(f"  carrier : {info['carrier'] or 'N/A'}")
        speed = info['speed']
        if speed is not None:
            print(f"  speed   : {speed} Mb/s")
        else:
            print(f"  speed   : N/A")
        print(f"  duplex  : {info['duplex'] or 'N/A'}")
        print(f"  mtu     : {info['mtu'] or 'N/A'}")
        print(f"  mac     : {info['mac'] or 'N/A'}")
        print(f"  ipv4    : {info['ipv4'] or '-'}")
        ipv6 = info["ipv6"]
        if ipv6:
            for idx, addr in enumerate(ipv6, 1):
                print(f"  ipv6-{idx} : {addr}")
        else:
            print("  ipv6    : -")
        print(f"  rx_bytes: {info['rx_bytes']}")
        print(f"  tx_bytes: {info['tx_bytes']}")
        print(f"  rx_pkts : {info['rx_packets']}")
        print(f"  tx_pkts : {info['tx_packets']}")
        print(f"  rx_errs : {info['rx_errs']}")
        print(f"  tx_errs : {info['tx_errs']}")
        print(f"  rx_drop : {info['rx_drop']}")
        print(f"  tx_drop : {info['tx_drop']}")

def print_csv_header() -> None:
    print("timestamp,iface,state,ipv4,rx_rate_bps,tx_rate_bps,rx_pps,tx_pps,rx_errs,tx_errs")

def print_csv_row(
    timestamp: float,
    ifname: str,
    current: InterfaceStats,
    previous: Optional[InterfaceStats],
    interval: float
) -> None:
    if interval <= 0 or previous is None:
        rx_rate = tx_rate = rx_pps = tx_pps = 0.0
    else:
        rx_rate = (int(current["rx_bytes"]) - int(previous["rx_bytes"])) / interval
        tx_rate = (int(current["tx_bytes"]) - int(previous["tx_bytes"])) / interval
        rx_pps = (int(current["rx_packets"]) - int(previous["rx_packets"])) / interval
        tx_pps = (int(current["tx_packets"]) - int(previous["tx_packets"])) / interval

    ipv4 = str(current["ipv4"] or "-")
    state = str(current["operstate"])

    print(f"{timestamp},{ifname},{state},{ipv4},"
          f"{max(rx_rate, 0.0):.2f},{max(tx_rate, 0.0):.2f},"
          f"{max(rx_pps, 0.0):.2f},{max(tx_pps, 0.0):.2f},"
          f"{int(current['rx_errs'])},{int(current['tx_errs'])}")

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
    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)

    min_interval = 0.1
    if args.interval < min_interval:
        print(f"Warning: Interval too small, setting to {min_interval}s", file=sys.stderr)
        args.interval = min_interval

    ifaces = args.iface if args.iface else get_interfaces()
    if not ifaces:
        print("No network interfaces found.")
        return

    previous = collect_snapshot(ifaces)

    if args.details:
        print_details(previous)
        print()

    count = 0
    while running:
        time.sleep(args.interval)
        
        if not running:
            break
            
        current = collect_snapshot(ifaces)

        if args.csv:
            if count == 0:
                print_csv_header()
            timestamp = time.time()
            for ifname in ifaces:
                print_csv_row(timestamp, ifname, current[ifname], previous.get(ifname), args.interval)
        else:
            print_header()
            for ifname in ifaces:
                print_row(ifname, current[ifname], previous.get(ifname), args.interval)
            print()

        previous = current
        count += 1

        if args.iterations > 0 and count >= args.iterations:
            break

if __name__ == "__main__":
    main()
