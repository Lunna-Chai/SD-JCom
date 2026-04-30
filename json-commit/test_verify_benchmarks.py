import subprocess
import os
import matplotlib
import matplotlib.pyplot as plt
import sys
import matplotlib.ticker as ticker

def main():
    os.chdir('/home/parallels/Desktop/JSON_credential/json-credential/json-commit')

    plt.rcParams['font.sans-serif'] = ['DejaVu Sans', 'Arial', 'Helvetica', 'sans-serif']
    plt.rcParams['axes.unicode_minus'] = False

    # Our Scheme (ZK Pedersen, MSM-optimized via rayon)
    print("Running Our Scheme Verify benchmarks...")
    cmd = ["cargo", "test", "test_our_verify_benchmarks", "--release", "--", "--nocapture"]
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    sizes, times = [], []
    for line in result.stdout.splitlines():
        if line.startswith("OUR_VERIFY_CSV:"):
            data = line.split("OUR_VERIFY_CSV:")[1].split(",")
            sizes.append(int(data[0]))
            times.append(float(data[1]))
    if not sizes:
        print("Failed: no OUR_VERIFY_CSV lines.")
        print(result.stdout)
        print(result.stderr)
        sys.exit(1)

    # SD-JWT verify
    print("Running SD-JWT Verify benchmarks...")
    cmd2 = ["cargo", "test", "test_sdjwt_verify_benchmarks", "--release", "--", "--nocapture"]
    result2 = subprocess.run(cmd2, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    sdjwt_sizes, sdjwt_times = [], []
    for line in result2.stdout.splitlines():
        if line.startswith("SDJWT_VERIFY_CSV:"):
            data = line.split("SDJWT_VERIFY_CSV:")[1].split(",")
            sdjwt_sizes.append(int(data[0]))
            sdjwt_times.append(float(data[1]))

    # BBS+ verify (docknetwork/crypto, MSM-optimized)
    print("Running BBS+ (MSM-optimized) Verify benchmarks...")
    cmd3 = ["cargo", "test", "test_bbs_verify_benchmarks", "--release", "--", "--nocapture"]
    result3 = subprocess.run(cmd3, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    bbs_sizes, bbs_times = [], []
    for line in result3.stdout.splitlines():
        if line.startswith("BBS_VERIFY_CSV:"):
            data = line.split("BBS_VERIFY_CSV:")[1].split(",")
            bbs_sizes.append(int(data[0]))
            bbs_times.append(float(data[1]))

    plt.figure(figsize=(8, 5))

    plt.plot(sizes, times, marker='o', color='red', label='SD-JCom', linewidth=2)
    if sdjwt_sizes:
        plt.plot(sdjwt_sizes, sdjwt_times, marker='s', color='blue', label='SD-JWT', linewidth=2)
    if bbs_sizes:
        plt.plot(bbs_sizes, bbs_times, marker='^', color='green', label='BBS+', linewidth=2)

    plt.xlabel('Number of Opened Values', fontsize=12)
    plt.ylabel('Verification Time (ms)', fontsize=12)

    plt.xlim(0, 100)
    all_times = times + sdjwt_times + bbs_times
    positive = [t for t in all_times if t > 0]
    y_lo = max(min(positive) * 0.5, 1e-3)
    y_hi = max(all_times) * 1.5
    plt.yscale('log')
    plt.ylim(y_lo, y_hi)

    ax = plt.gca()
    ax.yaxis.set_major_locator(ticker.LogLocator(base=10.0))
    ax.yaxis.set_minor_locator(ticker.LogLocator(base=10.0, subs=(2,3,4,5,6,7,8,9)))
    ax.yaxis.set_major_formatter(ticker.LogFormatterMathtext())
    ax.grid(True, which='major', linestyle='-', alpha=0.8)
    ax.grid(True, which='minor', linestyle=':', alpha=0.4)

    plt.xticks([0, 20, 40, 60, 80, 100])

    # Place legend in the upper-left area, in the blank region between the red and green lines
    plt.legend(loc='center left', bbox_to_anchor=(0.02, 0.75))

    output_path = 'verify_benchmark_chart.png'
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    print(f"Chart successfully saved to {os.path.abspath(output_path)}")

if __name__ == "__main__":
    main()
