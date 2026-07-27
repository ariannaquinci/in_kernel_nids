#!/usr/bin/env python3
import argparse
import socket
import statistics
import time


def percentile(values, pct):
    if not values:
        return 0
    ordered = sorted(values)
    idx = int((len(ordered) - 1) * pct / 100)
    return ordered[idx]


def main():
    parser = argparse.ArgumentParser(
        description="Send UDP packets to the receiver echo listener and print RTT statistics."
    )
    parser.add_argument("--target", required=True, help="Receiver IPv4 address")
    parser.add_argument("--port", type=int, default=9009, help="Receiver UDP port")
    parser.add_argument("--mode", choices=("deferred", "inline"), default="deferred")
    parser.add_argument("--count", type=int, default=10000, help="Packets to send")
    parser.add_argument("--duration", type=float, default=0, help="Optional duration limit in seconds")
    parser.add_argument("--payload-bytes", type=int, default=256, help="UDP payload size")
    parser.add_argument("--interval-us", type=float, default=0, help="Sleep between packets")
    parser.add_argument("--timeout", type=float, default=1.0, help="Echo timeout in seconds")
    args = parser.parse_args()

    payload_size = max(args.payload_bytes, 32)
    prefix = f"{args.mode}:".encode()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(args.timeout)

    rtts = []
    lost = 0
    sent = 0
    deadline = time.monotonic() + args.duration if args.duration > 0 else None

    for seq in range(args.count):
        if deadline is not None and time.monotonic() >= deadline:
            break

        stamp = time.perf_counter_ns()
        header = prefix + seq.to_bytes(8, "big") + stamp.to_bytes(8, "big")
        payload = header + bytes(max(0, payload_size - len(header)))

        sent += 1
        t0 = time.perf_counter_ns()
        sock.sendto(payload, (args.target, args.port))
        try:
            data, _ = sock.recvfrom(65535)
            t1 = time.perf_counter_ns()
        except socket.timeout:
            lost += 1
            continue

        if data[: len(header)] != header:
            lost += 1
            continue

        rtts.append(t1 - t0)
        if args.interval_us > 0:
            time.sleep(args.interval_us / 1_000_000)

    avg = int(statistics.mean(rtts)) if rtts else 0
    print(f"mode={args.mode}")
    print(f"target={args.target}:{args.port}")
    print(f"sent={sent}")
    print(f"echoed={len(rtts)}")
    print(f"lost={lost}")
    print(f"rtt_avg_ns={avg}")
    print(f"rtt_min_ns={min(rtts) if rtts else 0}")
    print(f"rtt_p50_ns={percentile(rtts, 50)}")
    print(f"rtt_p95_ns={percentile(rtts, 95)}")
    print(f"rtt_p99_ns={percentile(rtts, 99)}")
    print(f"rtt_max_ns={max(rtts) if rtts else 0}")


if __name__ == "__main__":
    main()
