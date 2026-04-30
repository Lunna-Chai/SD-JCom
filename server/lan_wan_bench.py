#!/usr/bin/env python3
"""
LAN vs WAN 端到端性能基准测试（Online / Offline 分析）
=====================================================
使用 Linux tc + netem 在 loopback 上模拟不同网络环境，
驱动真实 Rust 客户端二进制对服务端进行完整协议流程压测。

协议阶段划分：
  ┌─ ONLINE  (需要服务端在线) ─────────────────────────────────────────┐
  │  Phase 1 — 向服务端请求 JSON 数据（一次 RTT）                       │
  │  Phase 3 — 提交承诺 C + τ，服务端验证 C'==C 并对 C 签名（一次 RTT） │
  └────────────────────────────────────────────────────────────────────┘
  ┌─ OFFLINE (无需服务端，纯本地 CPU) ─────────────────────────────────┐
  │  Phase 2 — 客户端选取 z，计算 τ=h^z，C=τ+Σ H(v_i)·g_i             │
  │            （可在无网络环境下预计算，与网络延迟完全无关）             │
  └────────────────────────────────────────────────────────────────────┘

测试场景：
  Baseline  — 无额外延迟（纯本机回环）
  LAN       — 单向 0.5ms，1 Gbps
  WiFi      — 单向 5ms，  100 Mbps
  WAN-near  — 单向 25ms,  20 Mbps
  WAN-far   — 单向 75ms,  5 Mbps
  WAN-poor  — 单向 150ms, 1 Mbps，丢包 1%

用法：
  # 保证服务端在运行，然后：
  sudo python3 lan_wan_bench.py [--iterations N] [--skip-wan]

依赖：
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

# ── 配置 ──────────────────────────────────────────────────────────────────────

BASE_URL    = "http://127.0.0.1:8443"
IFACE       = "lo"
SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT   = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))

# 按优先级查找客户端二进制
CLIENT_CANDIDATES = [
    os.path.join(REPO_ROOT, "target", "release", "client"),
    os.path.join(REPO_ROOT, "target", "debug",   "client"),
]

# 按优先级查找服务端二进制
SERVER_CANDIDATES = [
    os.path.join(REPO_ROOT, "target", "release", "server"),
    os.path.join(REPO_ROOT, "target", "debug",   "server"),
]

# ── 网络场景 ──────────────────────────────────────────────────────────────────

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

# ── tc 控制 ───────────────────────────────────────────────────────────────────

def tc_clear():
    """清除 loopback 上的所有 qdisc 规则（静默失败）。"""
    subprocess.run(
        ["sudo", "tc", "qdisc", "del", "dev", IFACE, "root"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def tc_apply(delay_ms: float, bw_mbit: int, loss_pct: float):
    """在 loopback 上施加 netem（延迟 + 丢包）+ tbf（限速）规则。"""
    tc_clear()
    if delay_ms == 0 and bw_mbit == 0:
        return  # Baseline：不施加任何规则

    # 1. 根 qdisc：netem（延迟精度 0.1ms，单向）
    delay_us = int(delay_ms * 1000)
    netem_cmd = [
        "sudo", "tc", "qdisc", "add", "dev", IFACE,
        "root", "handle", "1:", "netem",
        "delay", f"{delay_us}us",
    ]
    if loss_pct > 0:
        netem_cmd += ["loss", f"{loss_pct}%"]
    subprocess.run(netem_cmd, check=True, stdout=subprocess.DEVNULL)

    # 2. 子节点：tbf（令牌桶限速）
    if bw_mbit > 0:
        # burst 至少为一个最大 TCP 段（约 64KB）以避免限速过于激进
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


# ── 客户端运行 ────────────────────────────────────────────────────────────────

# 匹配 Rust 客户端输出中的关键行
_RE_PHASE1 = re.compile(r"Phase 1.*?:\s*(\d+)\s*ns")
_RE_PHASE2 = re.compile(r"Phase 2.*?:\s*(\d+)\s*ns")
_RE_PHASE3 = re.compile(r"Phase 3.*?:\s*(\d+)\s*ns")
_RE_TOTAL  = re.compile(r"Total Credential Issuance Time\s*:\s*(\d+)\s*ns")
_RE_JSIZE  = re.compile(r"JSON Payload.*?:\s*(\d+)\s*bytes")
_RE_CSIZE  = re.compile(r"Client Commitment\s*:\s*(\d+)\s*bytes")
_RE_JWSLEN = re.compile(r"JWS Size.*?:\s*(\d+)\s*bytes")
_RE_RFC    = re.compile(r"RFC9421 Headers Size\s*:\s*(\d+)\s*bytes")


def run_client(client_bin: str, iterations: int, timeout_s: int):
    """运行 Rust 客户端二进制，解析并返回计时数据（单位：ms）；失败返回 None。"""
    try:
        result = subprocess.run(
            [client_bin, "--iterations", str(iterations)],
            capture_output=True,
            text=True,
            timeout=timeout_s,
        )
    except subprocess.TimeoutExpired:
        print(f"    ⚠ 客户端运行超时（>{timeout_s}s），跳过本场景")
        return None
    except FileNotFoundError:
        print(f"    ✗ 客户端二进制不存在：{client_bin}")
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
        print(f"    ⚠ 无法解析客户端输出（returncode={result.returncode}）")
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


# ── 主流程 ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="LAN vs WAN 端到端性能基准测试")
    parser.add_argument("--iterations", type=int, default=20,
                        help="每场景 Rust 客户端迭代次数（默认 20）")
    parser.add_argument("--skip-wan", action="store_true",
                        help="跳过 WAN-far 和 WAN-poor 场景（节省时间）")
    args = parser.parse_args()

    # 查找客户端二进制
    client_bin = next((p for p in CLIENT_CANDIDATES if os.path.isfile(p)), None)
    if client_bin is None:
        print("✗ 未找到客户端二进制，请先执行：cargo build --release")
        sys.exit(1)

    # 静默启动服务端（若已在运行则复用）
    server_proc = None
    if not _port_open(8443):
        server_bin = next((p for p in SERVER_CANDIDATES if os.path.isfile(p)), None)
        if server_bin is None:
            print("✗ 未找到服务端二进制，请先执行：cargo build --release")
            sys.exit(1)
        server_proc = _start_server(server_bin)
        if server_proc is None:
            print("✗ 服务端启动失败")
            sys.exit(1)

    def _cleanup(signum=None, frame=None):
        tc_clear()
        _stop_server(server_proc)
        if signum is not None:
            sys.exit(0)

    signal.signal(signal.SIGINT,  _cleanup)
    signal.signal(signal.SIGTERM, _cleanup)

    # 检查 sudo / tc
    check = subprocess.run(["sudo", "-n", "tc", "qdisc", "show", "dev", IFACE],
                           capture_output=True)
    if check.returncode != 0:
        print("⚠ 需要 sudo 权限来设置 tc 规则。请以 sudo 运行本脚本，或确保已配置 NOPASSWD。")
        _cleanup()
        sys.exit(1)

    iterations  = args.iterations
    skip_wan    = args.skip_wan
    scenarios   = [s for s in SCENARIOS
                   if not (skip_wan and s["name"] in ("WAN-far", "WAN-poor"))]

    results: dict[str, dict] = {}

    print(f"\n{'═'*60}")
    print(f"  LAN vs WAN 端到端性能基准测试")
    print(f"  每场景迭代次数: {iterations}")
    print(f"  场景数: {len(scenarios)}")
    print(f"{'═'*60}\n")

    for sc in scenarios:
        sc_name = sc["name"]
        print(f"{'─'*60}")
        print(f"场景: {sc_name:12s}  单向延迟={sc['delay_ms']}ms  "
              f"带宽={sc['bw_mbit']}Mbps  丢包={sc['loss_pct']}%")

        # 估算超时（每次迭代 3 个 RTT × 2 方向 × delay_ms + 本地计算余量）
        per_iter_ms = (sc["delay_ms"] * 2 * 6) + 200  # 6 个单向延迟 + 200ms 计算
        timeout_s   = max(60, int(iterations * per_iter_ms / 1000) + 30)

        try:
            tc_apply(sc["delay_ms"], sc["bw_mbit"], sc["loss_pct"])
        except subprocess.CalledProcessError as e:
            print(f"  ⚠ tc 规则设置失败: {e}，以 Baseline 规则运行")

        time.sleep(0.4)  # 等待 qdisc 生效

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
            print(f"  ✗ 本场景数据采集失败")

    tc_clear()  # 确保清理
    _stop_server(server_proc)

    if len(results) < 2:
        print("\n✗ 有效数据不足，无法生成对比图。")
        sys.exit(1)

    # ── 打印汇总表 ──────────────────────────────────────────────────────────────
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

    # 打印存储开销（来自 Baseline 场景，与网络无关）
    baseline = results.get("Baseline") or next(iter(results.values()))
    if baseline.get("json_bytes"):
        print(f"\n{'═'*40}")
        print("Storage Overhead (network-independent)")
        print("  JSON Payload (100 attrs)  : {json_bytes} bytes".format(**baseline))
        print("  Client Commitment         : {commit_bytes} bytes".format(**baseline))
        print("  JWS Size (in Header)      : {jws_bytes} bytes".format(**baseline))
        print("  RFC9421 Headers Size      : {rfc_bytes} bytes".format(**baseline))

    # ── 绘图 ────────────────────────────────────────────────────────────────────
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

    # ── 左图：Online vs Offline 堆叠柱状图 ──────────────────────────────────────
    ax = axes[0]
    # 将 Online 拆成 Phase1 + Phase3 两层以便观察
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

    # 在每个柱上标注 online_ms / offline_ms / total
    for i, (on, off, tot) in enumerate(zip(onlines, offlines, tots)):
        # online 段中间标注
        ax.text(i, on / 2,        f"Net\n{on:.1f}ms",
                ha="center", va="center", fontsize=6.5, color="white", fontweight="bold")
        # offline 段中间标注
        ax.text(i, on + off / 2,  f"CPU\n{off:.1f}ms",
                ha="center", va="center", fontsize=6.5, color="#1B5E20", fontweight="bold")
        # 顶部总计
        ax.text(i, tot + tot * 0.015, f"{tot:.1f}ms",
                ha="center", va="bottom", fontsize=7.5, fontweight="bold")

    # ── 右图：Online 和 Offline 随网络恶化的趋势折线图 ──────────────────────────
    ax2 = axes[1]
    ax2.plot(sc_names, onlines,  "o-",  color="#1565C0", label="Online  (Phase1+3, needs server)", linewidth=2.2)
    ax2.plot(sc_names, offlines, "s--", color="#2E7D32", label="Offline (Phase2, local CPU only)",  linewidth=2.2)
    ax2.plot(sc_names, tots,     "D-",  color="#7B1FA2", label="Total",                             linewidth=1.8, alpha=0.75)

    # 在折线上标注数值
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
    print(f"\n图表已保存: {out_path}")
    print("测试完成 ✅")


if __name__ == "__main__":
    main()
