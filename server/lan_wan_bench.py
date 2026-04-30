#!/usr/bin/env python3
"""
LAN vs WAN End-to-End Performance Benchmark (Online / Offline Analysis)

Uses Linux tc + netem on loopback to simulate different network environments
and drives the real Rust client binary through the full protocol flow.

Protocol phase breakdown:
   ONLINE  (server must be available)
    Phase 1 — Request JSON data from server (one RTT)                     
    Phase 3 — Submit commitment C + τ; server verifies C'==C and signs C  

   OFFLINE (no server needed, pure local CPU) 
    Phase 2 — Client samples z, computes τ=z·h, C=τ+Σ H(v_i)·g_i         
             (can be precomputed without network, independent of latency) 
  

Test scenarios:
  Baseline  — no extra delay (pure loopback)
  LAN       — one-way 0.5ms, 1 Gbps
  WiFi      — one-way 5ms,   100 Mbps
  WAN-near  — one-way 25ms,  20 Mbps
  WAN-far   — one-way 75ms,  5 Mbps
  WAN-poor  — one-way 150ms, 1 Mbps, 1% packet loss

Usage:
  # Ensure the server is running, then:
  sudo python3 lan_wan_bench.py [--iterations N] [--skip-wan]

Dependencies:
  sudo, tc (iproute2), matplotlib, python3
"""

import argparse
import os
import re
import signal
import socket
import statistics
import subprocess
import sys
import time

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

#  Configuration 

BASE_URL    = "http://127.0.0.1:8443"
IFACE       = "lo"
SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT   = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))

# Client binary candidates (highest priority first)
CLIENT_CANDIDATES = [
    os.path.join(REPO_ROOT, "target", "release", "client"),
    os.path.join(REPO_ROOT, "target", "debug",   "client"),
]

# Server binary candidates (highest priority first)
SERVER_CANDIDATES = [
    os.path.join(REPO_ROOT, "target", "release", "server"),
    os.path.join(REPO_ROOT, "target", "debug",   "server"),
]

# Network Scenarios

SCENARIOS = [
    {
        "name":     "Baseline",
        "label":    "Baseline\n(no extra delay)",
        "delay_ms": 0,
        "bw_mbit":  0,
        "loss_pct": 0,
    },
    {
        "name":     "LAN",
        "label":    "LAN\n(0.5ms, 1Gbps)",
        "delay_ms": 0.5,
        "bw_mbit":  1000,
        "loss_pct": 0,
    },
    {
        "name":     "WiFi",
        "label":    "WiFi\n(5ms, 100Mbps)",
        "delay_ms": 5,
        "bw_mbit":  100,
        "loss_pct": 0,
    },
    {
        "name":     "WAN-near",
        "label":    "WAN-near\n(25ms, 20Mbps)",
        "delay_ms": 25,
        "bw_mbit":  20,
        "loss_pct": 0,
    },
    {
        "name":     "WAN-far",
        "label":    "WAN-far\n(75ms, 5Mbps)",
        "delay_ms": 75,
        "bw_mbit":  5,
        "loss_pct": 0,
    },
    {
        "name":     "WAN-poor",
        "label":    "WAN-poor\n(150ms, 1Mbps, 1%loss)",
        "delay_ms": 150,
        "bw_mbit":  1,
        "loss_pct": 1,
    },
]

#  tc Control 

def tc_clear():
    """Remove all qdisc rules on loopback (silently ignore errors)."""
    subprocess.run(
        ["sudo", "tc", "qdisc", "del", "dev", IFACE, "root"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def tc_apply(delay_ms: float, bw_mbit: int, loss_pct: float):
    """Apply netem (delay + loss) + tbf (bandwidth limit) rules on loopback."""
    tc_clear()
    if delay_ms == 0 and bw_mbit == 0:
        return  # Baseline: no rules applied

    # 1. Root qdisc: netem (delay precision 0.1ms, one-way)
    delay_us = int(delay_ms * 1000)
    netem_cmd = [
        "sudo", "tc", "qdisc", "add", "dev", IFACE,
        "root", "handle", "1:", "netem",
        "delay", f"{delay_us}us",
    ]
    if loss_pct > 0:
        netem_cmd += ["loss", f"{loss_pct}%"]
    subprocess.run(netem_cmd, check=True, stdout=subprocess.DEVNULL)

    # 2. Child qdisc: tbf (token bucket filter for bandwidth limiting)
    if bw_mbit > 0:
        # burst must be at least one max TCP segment (~64KB) to avoid overly aggressive limiting
        burst_bytes = max(bw_mbit * 1_000_000 // 8 // 100, 65536)
        subprocess.run(
            [
                "sudo", "tc", "qdisc", "add", "dev", IFACE,
                "parent", "1:1", "handle", "10:", "tbf",
                "rate",    f"{bw_mbit}mbit",
                "burst",   str(burst_bytes),
                "latency", "500ms",
            ],
            check=True,
            stdout=subprocess.DEVNULL,
        )


# Client Execution 
# Regexes to parse key lines from Rust client output
_RE_PHASE1 = re.compile(r"Phase 1.*?:\s*(\d+)\s*ns")
_RE_PHASE2 = re.compile(r"Phase 2.*?:\s*(\d+)\s*ns")
_RE_PHASE3 = re.compile(r"Phase 3.*?:\s*(\d+)\s*ns")
_RE_TOTAL  = re.compile(r"Total Credential Issuance Time\s*:\s*(\d+)\s*ns")
_RE_JSIZE  = re.compile(r"JSON Payload.*?:\s*(\d+)\s*bytes")
_RE_CSIZE  = re.compile(r"Client Commitment\s*:\s*(\d+)\s*bytes")
_RE_JWSLEN = re.compile(r"JWS Size.*?:\s*(\d+)\s*bytes")
_RE_RFC    = re.compile(r"RFC9421 Headers Size\s*:\s*(\d+)\s*bytes")


def run_client(client_bin: str, iterations: int, timeout_s: int):
    """Run the Rust client binary, parse timing data (in ms), return None on failure."""
    try:
        result = subprocess.run(
            [client_bin, "--iterations", str(iterations)],
            capture_output=True,
            text=True,
            timeout=timeout_s,
        )
    except subprocess.TimeoutExpired:
        print(f"    ⚠ Client timed out (>{timeout_s}s), skipping scenario")
        return None
    except FileNotFoundError:
        print(f"    ✗ Client binary not found: {client_bin}")
        return None

    out = result.stdout + result.stderr

    def _ns(pat):
        m = pat.search(out)
        return int(m.group(1)) / 1e6 if m else None  # ns → ms

    def _bytes(pat):
        m = pat.search(out)
        return int(m.group(1)) if m else None

    p1 = _ns(_RE_PHASE1)
    p2 = _ns(_RE_PHASE2)
    p3 = _ns(_RE_PHASE3)
    total = _ns(_RE_TOTAL)

    if p1 is None or p3 is None or total is None:
        print(f"    ⚠ Failed to parse client output (returncode={result.returncode})")
        if result.returncode != 0:
            print(f"    stderr: {result.stderr[:300]}")
        return None

    return {
        "phase1_ms":    p1,
        "phase2_ms":    p2,
        "phase3_ms":    p3,
        "total_ms":     total,
        "json_bytes":   _bytes(_RE_JSIZE),
        "commit_bytes": _bytes(_RE_CSIZE),
        "jws_bytes":    _bytes(_RE_JWSLEN),
        "rfc_bytes":    _bytes(_RE_RFC),
    }


#  Main

def main():
    parser = argparse.ArgumentParser(description="LAN vs WAN end-to-end performance benchmark")
    parser.add_argument("--iterations", type=int, default=20,
                        help="Number of Rust client iterations per scenario (default: 20)")
    parser.add_argument("--skip-wan", action="store_true",
                        help="Skip WAN-far and WAN-poor scenarios to save time")
    args = parser.parse_args()

    # Locate client binary
    client_bin = next((p for p in CLIENT_CANDIDATES if os.path.isfile(p)), None)
    if client_bin is None:
        print("✗ Client binary not found. Please run: cargo build --release")
        sys.exit(1)

    # Start server silently if not already running
    server_proc = None
    if not _port_open(8443):
        server_bin = next((p for p in SERVER_CANDIDATES if os.path.isfile(p)), None)
        if server_bin is None:
            print("✗ Server binary not found. Please run: cargo build --release")
            sys.exit(1)
        server_proc = _start_server(server_bin)
        if server_proc is None:
            print("✗ Failed to start server")
            sys.exit(1)

    def _cleanup(signum=None, frame=None):
        tc_clear()
        _stop_server(server_proc)
        if signum is not None:
            sys.exit(0)

    signal.signal(signal.SIGINT,  _cleanup)
    signal.signal(signal.SIGTERM, _cleanup)

    # Check sudo / tc availability
    check = subprocess.run(["sudo", "-n", "tc", "qdisc", "show", "dev", IFACE],
                           capture_output=True)
    if check.returncode != 0:
        print("⚠ sudo privileges required to set tc rules. Run with sudo or configure NOPASSWD.")
        _cleanup()
        sys.exit(1)

    iterations  = args.iterations
    skip_wan    = args.skip_wan
    scenarios   = [s for s in SCENARIOS
                   if not (skip_wan and s["name"] in ("WAN-far", "WAN-poor"))]

    results: dict[str, dict] = {}

    print(f"\n{'═'*60}")
    print(f"  LAN vs WAN End-to-End Performance Benchmark")
    print(f"  Iterations per scenario: {iterations}")
    print(f"  Number of scenarios: {len(scenarios)}")
    print(f"{'═'*60}\n")

    for sc in scenarios:
        sc_name = sc["name"]
        print(f"{'─'*60}")
        print(f"Scenario: {sc_name:12s}  one-way delay={sc['delay_ms']}ms  "
              f"bandwidth={sc['bw_mbit']}Mbps  loss={sc['loss_pct']}%")

        # Estimate timeout: 3 RTTs x 2 directions x delay_ms + local computation margin
        per_iter_ms = (sc["delay_ms"] * 2 * 6) + 200  # 6 one-way delays + 200ms compute margin
        timeout_s   = max(60, int(iterations * per_iter_ms / 1000) + 30)

        try:
            tc_apply(sc["delay_ms"], sc["bw_mbit"], sc["loss_pct"])
        except subprocess.CalledProcessError as e:
            print(f"  ⚠ Failed to apply tc rules: {e}, running with Baseline settings")

        time.sleep(0.4)  # Wait for qdisc to take effect

        data = run_client(client_bin, iterations, timeout_s)

        tc_clear()
        time.sleep(0.2)

        if data:
            data["online_ms"]  = data["phase1_ms"] + data["phase3_ms"]
            data["offline_ms"] = data["phase2_ms"]
            results[sc_name] = data
            print(f"  [ONLINE]  Phase 1 (fetch JSON)      : {data['phase1_ms']:8.2f} ms  ← RTT")
            print(f"  [OFFLINE] Phase 2 (commit compute)  : {data['phase2_ms']:8.2f} ms  ← pure CPU")
            print(f"  [ONLINE]  Phase 3 (submit+sign)     : {data['phase3_ms']:8.2f} ms  ← RTT")
            print(f"  ─ Online  (Phase1+3)               : {data['online_ms']:8.2f} ms")
            print(f"  ─ Offline (Phase2)                 : {data['offline_ms']:8.2f} ms")
            print(f"  ─ Total                            : {data['total_ms']:8.2f} ms")
        else:
            print(f"  ✗ Data collection failed for this scenario")

    tc_clear()  # Ensure cleanup
    _stop_server(server_proc)

    if len(results) < 2:
        print("\n✗ Insufficient valid data to generate comparison chart.")
        sys.exit(1)

    # Print summary table 
    print(f"\n{'═'*80}")
    print(f"{'Scenario':<14} {'Online(ms)':>12} {'Offline(ms)':>12} {'Total(ms)':>12} {'Online%':>9} {'Speedup':>9}")
    print(f"  (Online = Phase1+3, needs server | Offline = Phase2, local CPU only)")
    print(f"{'─'*80}")
    baseline_total = results.get("Baseline", {}).get("total_ms", None)
    for sc in scenarios:
        n = sc["name"]
        if n not in results:
            continue
        d = results[n]
        online_pct = 100.0 * d["online_ms"] / d["total_ms"] if d["total_ms"] else 0
        slowdown = f"{d['total_ms']/baseline_total:.1f}x" if baseline_total else "-"
        print(f"{n:<14} {d['online_ms']:>12.2f} {d['offline_ms']:>12.2f} "
              f"{d['total_ms']:>12.2f} {online_pct:>8.1f}% {slowdown:>9}")

    # Print storage overhead (from Baseline scenario, network-independent)
    baseline = results.get("Baseline") or next(iter(results.values()))
    if baseline.get("json_bytes"):
        print(f"\n{'═'*40}")
        print("Storage Overhead (network-independent)")
        print("  JSON Payload (100 attrs)  : {json_bytes} bytes".format(**baseline))
        print("  Client Commitment         : {commit_bytes} bytes".format(**baseline))
        print("  JWS Size (in Header)      : {jws_bytes} bytes".format(**baseline))
        print("  RFC9421 Headers Size      : {rfc_bytes} bytes".format(**baseline))

    # Plot 
    sc_names  = [s["name"]  for s in scenarios if s["name"] in results]
    sc_labels = [s["label"] for s in scenarios if s["name"] in results]

    p1s      = [results[n]["phase1_ms"]  for n in sc_names]
    p2s      = [results[n]["phase2_ms"]  for n in sc_names]
    p3s      = [results[n]["phase3_ms"]  for n in sc_names]
    tots     = [results[n]["total_ms"]   for n in sc_names]
    onlines  = [results[n]["online_ms"]  for n in sc_names]   # phase1 + phase3
    offlines = [results[n]["offline_ms"] for n in sc_names]   # phase2

    x = list(range(len(sc_names)))

    fig, axes = plt.subplots(1, 2, figsize=(16, 6))

    # Left: Online vs Offline stacked bar chart 
    ax = axes[0]
    # Split Online into Phase1 + Phase3 layers for clarity
    bars_p1 = ax.bar(x, p1s, width=0.5,
                     label="Online: Phase 1 (fetch JSON, RTT)",
                     color="#1565C0", alpha=0.88)
    bars_p3 = ax.bar(x, p3s, width=0.5, bottom=p1s,
                     label="Online: Phase 3 (submit+sign, RTT)",
                     color="#42A5F5", alpha=0.88)
    bars_p2 = ax.bar(x, p2s, width=0.5,
                     bottom=[a + b for a, b in zip(p1s, p3s)],
                     label="Offline: Phase 2 (commit CPU, no network)",
                     color="#66BB6A", alpha=0.88, hatch="//")

    ax.set_xticks(x)
    ax.set_xticklabels(sc_labels, fontsize=8)
    ax.set_ylabel("Latency (ms)", fontsize=11)
    ax.set_title("Online vs Offline Cost by Network Scenario", fontsize=12)
    ax.legend(fontsize=8.5, loc="upper left")
    ax.grid(True, axis="y", alpha=0.35)

    # Annotate each bar with online_ms / offline_ms / total
    for i, (on, off, tot) in enumerate(zip(onlines, offlines, tots)):
        # Label in the middle of the online segment
        ax.text(i, on / 2,        f"Net\n{on:.1f}ms",
                ha="center", va="center", fontsize=6.5, color="white", fontweight="bold")
        # Label in the middle of the offline segment
        ax.text(i, on + off / 2,  f"CPU\n{off:.1f}ms",
                ha="center", va="center", fontsize=6.5, color="#1B5E20", fontweight="bold")
        # Total label at the top
        ax.text(i, tot + tot * 0.015, f"{tot:.1f}ms",
                ha="center", va="bottom", fontsize=7.5, fontweight="bold")

    # Right: Online and Offline trend line chart as network degrades 
    ax2 = axes[1]
    ax2.plot(sc_names, onlines,  "o-",  color="#1565C0", label="Online  (Phase1+3, needs server)", linewidth=2.2)
    ax2.plot(sc_names, offlines, "s--", color="#2E7D32", label="Offline (Phase2, local CPU only)",  linewidth=2.2)
    ax2.plot(sc_names, tots,     "D-",  color="#7B1FA2", label="Total",                             linewidth=1.8, alpha=0.75)

    # Annotate values on trend lines
    for i, (on, off, tot) in enumerate(zip(onlines, offlines, tots)):
        ax2.annotate(f"{on:.1f}",  (sc_names[i], on),  textcoords="offset points",
                     xytext=(0, 7),  ha="center", fontsize=7, color="#1565C0")
        ax2.annotate(f"{off:.1f}", (sc_names[i], off), textcoords="offset points",
                     xytext=(0, -13), ha="center", fontsize=7, color="#2E7D32")

    ax2.set_ylabel("Latency (ms)", fontsize=11)
    ax2.set_title("Online vs Offline Latency Trend", fontsize=12)
    ax2.legend(fontsize=8.5)
    ax2.grid(True, alpha=0.35)
    ax2.set_xticks(range(len(sc_names)))
    ax2.set_xticklabels(sc_labels, fontsize=8)

    plt.suptitle(
        f"LAN / WAN Online vs Offline Analysis  |  Ristretto255 JDC Protocol  |  {iterations}-iter avg\n"
        f"Online = network round-trips (Phase1+3)  |  Offline = local commitment computation (Phase2)",
        fontsize=10, y=1.02,
    )
    plt.tight_layout()

    out_path = os.path.join(REPO_ROOT, "json-commit", "lan_wan_bench.png")
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    print(f"\nChart saved: {out_path}")
    print("Benchmark complete ")


if __name__ == "__main__":
    main()
