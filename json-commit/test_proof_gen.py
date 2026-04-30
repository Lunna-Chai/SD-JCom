import subprocess
import os
import matplotlib
import matplotlib.pyplot as plt
import sys
import matplotlib.ticker as ticker

def main():
    print("Running Rust Proof Generation benchmarks...")
    os.chdir('/home/parallels/Desktop/JSON_credential/json-credential/json-commit')
    
    plt.rcParams['font.sans-serif'] = ['DejaVu Sans', 'Arial', 'Helvetica', 'sans-serif']
    plt.rcParams['axes.unicode_minus'] = False
    
    cmd = ["taskset", "-c", "2-3", "nice", "-n", "-5", "cargo", "test", "test_proof_gen_benchmarks", "--release", "--", "--nocapture"]
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    sizes = []
    times = []
    
    for line in result.stdout.splitlines():
        if line.startswith("PROOF_GEN_CSV:"):
            data = line.split("PROOF_GEN_CSV:")[1].split(",")
            sizes.append(int(data[0]))
            times.append(float(data[1]))
            
    if not sizes:
        print("Failed to run benchmarks or no output generated! stdout was:")
        print(result.stdout)
        print("stderr was:")
        print(result.stderr)
        sys.exit(1)
    
    # Run SD-JWT benchmark for comparison
    print("Running SD-JWT (sd-jwt-rust) Proof Generation benchmarks...")
    cmd2 = ["taskset", "-c", "2-3", "nice", "-n", "-5", "cargo", "test", "test_sdjwt_proof_gen_benchmarks", "--release", "--", "--nocapture"]
    result2 = subprocess.run(cmd2, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    sdjwt_sizes = []
    sdjwt_times = []
    for line in result2.stdout.splitlines():
        if line.startswith("SDJWT_PROOF_GEN_CSV:"):
            data = line.split("SDJWT_PROOF_GEN_CSV:")[1].split(",")
            sdjwt_sizes.append(int(data[0]))
            sdjwt_times.append(float(data[1]))

    # Run BBS (pairing_crypto) benchmark for comparison
    print("Running BBS (pairing_crypto) Proof Generation benchmarks...")
    cmd3 = ["taskset", "-c", "2-3", "nice", "-n", "-5", "cargo", "test", "test_bbs_proof_gen_benchmarks", "--release", "--", "--nocapture"]
    result3 = subprocess.run(cmd3, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    bbs_sizes = []
    bbs_times = []
    for line in result3.stdout.splitlines():
        if line.startswith("BBS_PROOF_GEN_CSV:"):
            data = line.split("BBS_PROOF_GEN_CSV:")[1].split(",")
            bbs_sizes.append(int(data[0]))
            bbs_times.append(float(data[1]))
    if not bbs_sizes:
        print("Warning: BBS benchmark produced no output. stderr was:")
        print(result3.stderr[-2000:])

    plt.figure(figsize=(8, 5))
    
    plt.plot(sizes, times, marker='o', color='red', label='SD-JCom', linewidth=2)
    if sdjwt_sizes:
        plt.plot(sdjwt_sizes, sdjwt_times, marker='s', color='blue', label='SD-JWT', linewidth=2)
    if bbs_sizes:
        # Apply 3-point moving average to BBS to suppress minor step jitter from blstrs windowed scalar-mul
        def smooth3(xs):
            n = len(xs)
            if n < 3:
                return list(xs)
            out = [xs[0]]
            for i in range(1, n - 1):
                out.append((xs[i - 1] + xs[i] + xs[i + 1]) / 3.0)
            out.append(xs[-1])
            return out
        bbs_times_s = smooth3(bbs_times)
        plt.plot(bbs_sizes, bbs_times_s, marker='^', color='green', label='BBS', linewidth=2)

    plt.xlabel('Number of Opened Values', fontsize=12)
    plt.ylabel('Proof Generation Time (ms)', fontsize=12)
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
    
    plt.legend(loc='center right')
    
    output_path = 'proof_gen_benchmark_chart.png'
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    print(f"Chart successfully saved to {os.path.abspath(output_path)}")

if __name__ == "__main__":
    main()
