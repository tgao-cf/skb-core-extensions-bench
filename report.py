#!/usr/bin/env python3
"""Tables and the figure from the raw files.

Usage: report.py <results-dir>

Prints the summary table of the cover letter, then one table per measurement
with every metric, baseline (store0) next to RX metadata (store1). Writes <results-dir>/bench.svg.

A measurement dir (<results-dir>/<measurement>/) holds state.txt and one dir
per test with these files per round:
  store<s>-r<n>.client     netperf, iperf3 (JSON) or pktgen output
  store<s>-r<n>.counters   XDP packet count, NIC and SNMP counters
  store<s>-r<n>.msr        perf stat: APERF, MPERF, TSC of the RX and cpumap CPU
  store<s>-r<n>.perf.txt   perf report by CPU and symbol, and the CPU totals

Cycle counts cover the perf window (WIN seconds). The counters cover a
slightly longer window, timed by the timestamps in .counters. Rates use each
one's own window, so cycles per packet is cycles/s divided by packets/s. Each
cell is the median over the rounds, with [min, max].
"""
import json
import re
import statistics
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

VARIANTS = {"0": "baseline", "1": "RX metadata"}
MEASUREMENTS = {"veth-checksum": "veth-tcp", "cpumap-rx-hash": "cpumap-tcp-16"}

# Software checksum work in the receive path
CSUM_SYMBOLS = {"csum_partial", "do_csum", "__skb_gro_checksum_complete",
                "__skb_checksum_complete", "__skb_checksum", "csum_partial_copy_generic"}


def is_store(sym):
    return sym.startswith("bpf_xdp_skb_ext_store") or sym == "xdp_skb_ext_add"


def is_to_skb(sym):
    return sym == "xdp_skb_ext_to_skb"


def read_msr(path):
    """{(cpu, "aperf" | "mperf" | "tsc"): (count, run time in ns)}"""
    msr = {}
    for line in path.read_text().splitlines():
        f = line.split(",")
        if len(f) > 4 and f[0].startswith("CPU"):
            msr[(int(f[0][3:]), f[3].split("/")[1])] = (int(f[1]), int(f[4]))
    return msr


def read_counters(path):
    """XDP stats before/after, NIC counters before/after, nstat deltas"""
    xdp, nic, snmp = {}, {}, {}
    for line in path.read_text().splitlines():
        f = line.split()
        if f[0] in ("time_before", "time_after"):
            xdp[f[0]] = int(f[1])
        elif f[0] in ("stats_before", "stats_after"):
            xdp[f[0]] = [int(x) for x in f[1:]]
        elif f[0] in ("nic_before", "nic_after"):
            nic[(f[0], f[1].rstrip(":"))] = int(f[2])
        elif f[0] == "nstat" and len(f) >= 3 and f[2].isdigit():
            snmp[f[1]] = int(f[2])
    return xdp, nic, snmp


def read_profile(path):
    """{cpu: {symbol: % of all samples}}, {cpu: % of all samples}"""
    symbols, totals = {}, {}
    for line in path.read_text().splitlines():
        m = re.match(r"cpu_total\s+([\d.]+)%\s+(\d+)", line)
        if m:
            totals[int(m[2])] = float(m[1])
            continue
        m = re.match(r"\s*([\d.]+)%\s+(\d+)\s+\[[kh.]\]\s+(\S+)", line)
        if m:
            symbols.setdefault(int(m[2]), {})[m[3]] = float(m[1])
    return symbols, totals


def cpu_share(profile, cpu, match):
    """% of one CPU's samples in the symbols that match"""
    symbols, totals = profile
    if not totals.get(cpu):
        return 0.0
    return 100 * sum(pct for sym, pct in symbols.get(cpu, {}).items() if match(sym)) / totals[cpu]


def throughput_gbps(test, client):
    """Gbps from the client output, None for pktgen. ValueError if the client failed."""
    if test == "veth-tcp":		# netperf -P 0: sizes, time, 10^6 bits/s
        return float(client.split()[4]) / 1000
    if test.startswith("cpumap-tcp"):
        return json.loads(client)["end"]["sum_received"]["bits_per_second"] / 1e9
    return None


def round_metrics(prefix, test, rx_cpu, map_cpu):
    msr = read_msr(Path(f"{prefix}.msr"))
    xdp, nic, snmp = read_counters(Path(f"{prefix}.counters"))
    profile = read_profile(Path(f"{prefix}.perf.txt"))

    tsc, perf_ns = msr[(rx_cpu, "tsc")]
    perf_win = perf_ns / 1e9
    tsc_hz = tsc / perf_win
    counter_win = (xdp["time_after"] - xdp["time_before"]) / 1e9
    pps = (xdp["stats_after"][0] - xdp["stats_before"][0]) / counter_win	# frames the XDP program handled
    skbs_ps = snmp.get("IpInDelivers", 0) / counter_win			# after GRO

    m = {
        "xdp_mpps": pps / 1e6,
        "delivered_mpps": skbs_ps / 1e6,
        "store_errors": xdp["stats_after"][1] - xdp["stats_before"][1],
        "nic_csum_bad": nic.get(("nic_after", "rx_csum_bad.nic"), 0)
                        - nic.get(("nic_before", "rx_csum_bad.nic"), 0),
        "in_csum_errors": snmp.get("TcpInCsumErrors", 0) + snmp.get("UdpInCsumErrors", 0),
    }
    gbps = throughput_gbps(test, Path(f"{prefix}.client").read_text())
    if gbps is not None:
        m["gbps"] = gbps

    cycles_ps = {}	# per second
    for name, cpu in (("rx", rx_cpu), ("map", map_cpu)):
        aperf, mperf = msr[(cpu, "aperf")][0], msr[(cpu, "mperf")][0]
        cycles_ps[cpu] = aperf / perf_win
        m[f"{name}_busy_pct"] = 100 * mperf / msr[(cpu, "tsc")][0]
        m[f"{name}_ghz"] = tsc_hz * aperf / mperf / 1e9 if mperf else 0.0
    m["rx_cycles_per_pkt"] = cycles_ps[rx_cpu] / pps

    # veth: the RX CPU also runs veth's NAPI, GRO and TCP. cpumap: the cpumap CPU does.
    stack_cpu = rx_cpu if test == "veth-tcp" else map_cpu
    stack = "rx" if test == "veth-tcp" else "map"
    m[f"{stack}_csum_pct"] = cpu_share(profile, stack_cpu, lambda s: s in CSUM_SYMBOLS)
    if test != "veth-tcp":
        m["map_cycles_per_skb"] = cycles_ps[map_cpu] / skbs_ps if skbs_ps else 0.0
        m["pkts_per_skb"] = pps / skbs_ps if skbs_ps else 0.0

    # Cost of the series per frame: the share of the CPU's samples in its
    # functions times the CPU's cycles per frame. Stores run on the RX CPU,
    # xdp_skb_ext_to_skb() where the skb is built.
    for name, cpu, match in (("store", rx_cpu, is_store), ("to_skb", stack_cpu, is_to_skb)):
        per_pkt = cpu_share(profile, cpu, match) / 100 * cycles_ps[cpu] / pps
        ghz = m["rx_ghz"] if cpu == rx_cpu else m["map_ghz"]
        m[f"{name}_cycles_per_pkt"] = per_pkt
        m[f"{name}_ns_per_pkt"] = per_pkt / ghz if ghz else 0.0
    return m


def load(run):
    """kernel release, {test: {store: [metrics of each round]}}, failed rounds"""
    state = Path(run, "state.txt").read_text()
    cpus = re.search(r"rx_cpu (\d+) cpumap_cpu (\d+)", state)
    rx_cpu, map_cpu = int(cpus[1]), int(cpus[2])
    tests, failed = {}, []
    for test_dir in sorted(p for p in Path(run).iterdir() if p.is_dir()):
        # perf.txt is written last in a round, so only finished rounds count
        for f in sorted(test_dir.glob("store*-r*.perf.txt")):
            store = re.match(r"store(\d)-r\d+", f.name)[1]
            prefix = str(f).removesuffix(".perf.txt")
            rounds = tests.setdefault(test_dir.name, {}).setdefault(store, [])
            try:
                rounds.append(round_metrics(prefix, test_dir.name, rx_cpu, map_cpu))
            except (ValueError, KeyError, json.JSONDecodeError):
                failed.append(f"{test_dir.name}/{f.name.removesuffix('.perf.txt')}")
    return state.splitlines()[1].split()[0], tests, failed


def cell(values):
    return f"{statistics.median(values):.4g} [{min(values):.4g}, {max(values):.4g}]"


def print_tables(run, kernel, tests, failed):
    print(f"\n# {run.name}: {kernel}")
    if failed:
        print("\nRounds left out, the client has no result: " + ", ".join(failed))
    for test, by_store in tests.items():
        stores = sorted(by_store)
        print(f"\n## {test}\n")
        print("| metric | " + " | ".join(f"{VARIANTS[s]} (n={len(by_store[s])})" for s in stores) + " |")
        print("|---|" + "---|" * len(stores))
        for key in by_store[stores[0]][0]:
            cells = [cell([r[key] for r in by_store[s]]) for s in stores]
            print(f"| {key} | " + " | ".join(cells) + " |")


def med(rows, key):
    return statistics.median(r[key] for r in rows)


def print_summary(veth, cpumap):
    rows = [("veth, 1 TCP flow", "RX CPU busy", veth, "rx_busy_pct", "{:.0f}%"),
            ("veth, 1 TCP flow", "RX cycles/pkt", veth, "rx_cycles_per_pkt", "{:.0f}"),
            ("veth, 1 TCP flow", "throughput", veth, "gbps", "{:.1f} Gbit/s"),
            ("cpumap, 16 TCP flows", "throughput", cpumap, "gbps", "{:.1f} Gbit/s"),
            ("cpumap, 16 TCP flows", "pkts/GRO skb", cpumap, "pkts_per_skb", "{:.1f}")]
    print("| test | metric | baseline | RX metadata |\n|---|---|---|---|")
    for test, metric, rows_by_store, key, fmt in rows:
        a, b = med(rows_by_store["0"], key), med(rows_by_store["1"], key)
        print(f"| {test} | {metric} | {fmt.format(a)} | {fmt.format(b)} ({100 * (b / a - 1):+.0f}%) |")
    print(f"\nStore kfuncs, ns per packet, RX metadata: veth {med(veth['1'], 'store_ns_per_pkt'):.1f},"
          f" cpumap {med(cpumap['1'], 'store_ns_per_pkt'):.1f}")


def bars(ax, rows, key, labels, notes):
    """One bar per variant: median, with min and max as error bars"""
    for i, s in enumerate(sorted(rows)):
        x = [r[key] for r in rows[s]]
        m = statistics.median(x)
        ax.bar(i, m, yerr=[[m - min(x)], [max(x) - m]], capsize=4, color=f"C{i}")
        ax.text(i, m / 2, notes(rows[s]), ha="center")
    ax.set_xticks(range(len(rows)), labels)


def plot(veth, cpumap, out):
    fig, (a, b) = plt.subplots(1, 2, figsize=(10, 4))
    bars(a, veth, "rx_cycles_per_pkt",
         ["baseline", "RX metadata:\nchecksum status"],
         lambda r: f"{med(r, 'gbps'):.1f} Gbps\nchecksum {med(r, 'rx_csum_pct'):.0f}%")
    a.set_ylabel("RX CPU cycles per packet")
    a.set_title("veth, one TCP flow")
    bars(b, cpumap, "gbps",
         ["baseline", "RX metadata:\nRX hash"],
         lambda r: f"{med(r, 'pkts_per_skb'):.1f} packets\nper GRO skb")
    b.set_ylabel("Gbps")
    b.set_title("cpumap, 16 TCP flows, one cpumap CPU")
    fig.tight_layout()
    fig.savefig(out, metadata={"Date": None})


def main():
    results = Path(sys.argv[1])
    runs = {name: load(results / name) for name in MEASUREMENTS}
    veth, cpumap = (runs[name][1][test] for name, test in MEASUREMENTS.items())
    print_summary(veth, cpumap)
    for name, (kernel, tests, failed) in runs.items():
        print_tables(results / name, kernel, tests, failed)
    plot(veth, cpumap, results / "bench.svg")


if __name__ == "__main__":
    main()
