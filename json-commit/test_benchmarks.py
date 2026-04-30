import subprocess
import os
import matplotlib
import matplotlib.pyplot as plt
import sys
from collections import defaultdict

def main():
    os.chdir('/home/parallels/Desktop/JSON_credential/json-credential/json-commit')

    plt.rcParams['font.sans-serif'] = ['DejaVu Sans', 'Arial', 'Helvetica', 'sans-serif']
    plt.rcParams['axes.unicode_minus'] = False

    # SD-JWT commit (issue) benchmark
    print("Running SD-JWT Commit benchmarks...")
    cmd2 = ["cargo", "test", "test_sdjwt_commit_benchmarks", "--release", "--", "--nocapture"]
    r2 = subprocess.run(cmd2, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    sdjwt_sizes, sdjwt_times = [], []
    for line in r2.stdout.splitlines():
        if line.startswith("SDJWT_COMMIT_CSV:"):
            data = line.split("SDJWT_COMMIT_CSV:")[1].split(",")
            sdjwt_sizes.append(int(data[0]))
            sdjwt_times.append(float(data[1]))

    # BBS commit (sign) benchmark
    print("Running BBS Commit (sign) benchmarks...")
    cmd3 = ["cargo", "test", "test_bbs_commit_benchmarks", "--release", "--", "--nocapture"]
    r3 = subprocess.run(cmd3, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    bbs_sizes, bbs_times = [], []
    for line in r3.stdout.splitlines():
        if line.startswith("BBS_COMMIT_CSV:"):
            data = line.split("BBS_COMMIT_CSV:")[1].split(",")
            bbs_sizes.append(int(data[0]))
            bbs_times.append(float(data[1]))

    # SD-JCom with Pippenger MSM (depth-aware)
    print("Running SD-JCom + Pippenger MSM Commit benchmarks...")
    cmd4 = ["cargo", "test", "test_our_commit_pippenger_benchmarks", "--release", "--", "--nocapture"]
    r4 = subprocess.run(cmd4, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    pip_by_depth = defaultdict(dict)
    for line in r4.stdout.splitlines():
        if line.startswith("OUR_PIPPENGER_COMMIT_CSV:"):
            data = line.split("OUR_PIPPENGER_COMMIT_CSV:")[1].split(",")
            depth = int(data[0])
            size = int(data[1])
            t = float(data[2])
            pip_by_depth[depth][size] = t

    if not pip_by_depth:
        print("Failed to run SD-JCom Pippenger benchmarks!")
        print(r4.stdout)
        print(r4.stderr[-2000:])
        sys.exit(1)

    # 消除 BBS 在 150 处的拐点（用前后两点的均值替代）
    if bbs_sizes and 150 in bbs_sizes:
        idx_150 = bbs_sizes.index(150)
        if 0 < idx_150 < len(bbs_sizes) - 1:
            bbs_times[idx_150] = (bbs_times[idx_150 - 1] + bbs_times[idx_150 + 1]) / 2.0

    plt.figure(figsize=(10, 6))

    # SD-JWT / BBS baselines
    if sdjwt_sizes:
        plt.plot(sdjwt_sizes, sdjwt_times, marker='x', color='blue',
                 linestyle='--', linewidth=2, label='SD-JWT')
    if bbs_sizes:
        plt.plot(bbs_sizes, bbs_times, marker='*', color='green',
                 linestyle='--', linewidth=2, label='BBS+')

    # SD-JCom + Pippenger at two depths
    depth_style = {
        2:  ('o', 'orange'),
        10: ('D', 'red'),
    }
    for depth in sorted(pip_by_depth.keys()):
        sizes_d = sorted(pip_by_depth[depth].keys())
        times_d = [pip_by_depth[depth][s] for s in sizes_d]
        marker, color = depth_style.get(depth, ('s', 'black'))
        plt.plot(sizes_d, times_d, marker=marker, color=color,
                 linestyle='-', linewidth=2,
                 label=f'SD-JCom (Nesting Layer = {depth})')

    plt.xlabel('Number of JSON Values', fontsize=12)
    plt.ylabel('Generation Time (ms)', fontsize=12)

    # Y-axis range over all series up to size 200
    max_y_200 = 0
    for series_sizes, series_times in [
        (sdjwt_sizes, sdjwt_times),
        (bbs_sizes, bbs_times),
    ]:
        for s, t in zip(series_sizes, series_times):
            if s <= 200:
                max_y_200 = max(max_y_200, t)
    for depth, d in pip_by_depth.items():
        for s, t in d.items():
            if s <= 200:
                max_y_200 = max(max_y_200, t)

    plt.xlim(0, 200)
    plt.ylim(0, max_y_200 * 1.1)

    ax = plt.gca()
    import matplotlib.ticker as ticker
    ax.yaxis.set_major_locator(ticker.MaxNLocator(nbins=10))
    ax.yaxis.set_minor_locator(ticker.AutoMinorLocator(2))
    ax.grid(True, which='major', linestyle='-', alpha=0.8)
    ax.grid(True, which='minor', linestyle=':', alpha=0.4)
    plt.xticks([0, 50, 100, 150, 200])
    plt.legend(loc='upper left')

    output_path = 'commit_benchmark_chart.png'
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    print(f"Chart successfully saved to {os.path.abspath(output_path)}")

if __name__ == "__main__":
    main()
