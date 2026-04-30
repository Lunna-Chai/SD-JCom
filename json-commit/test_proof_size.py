import subprocess
import os
import matplotlib
import matplotlib.pyplot as plt
import sys
from collections import defaultdict

def main():
    print("Running Proof Size Benchmarks...")
    os.chdir('/home/parallels/Desktop/JSON_credential/json-credential/json-commit')
    
    plt.rcParams['font.sans-serif'] = ['DejaVu Sans', 'Arial', 'Helvetica', 'sans-serif']
    plt.rcParams['axes.unicode_minus'] = False

    # SD-JCom proof size 
    print("Running SD-JCom proof size benchmarks...")
    cmd = ["cargo", "test", "test_proof_size_benchmarks", "--release", "--", "--nocapture"]
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    data_by_depth = defaultdict(dict)
    
    for line in result.stdout.splitlines():
        if line.startswith("PROOF_SIZE_CSV:"):
            data = line.split("PROOF_SIZE_CSV:")[1].split(",")
            depth = int(data[0])
            size = int(data[1])
            proof_size = int(data[2])
            
            if depth in [3, 5]:
                continue
            
            if size <= 100:
                data_by_depth[depth][size] = proof_size
            
    if not data_by_depth:
        print("Failed to run SD-JCom benchmarks!")
        print(result.stdout)
        sys.exit(1)

    # SD-JWT proof size
    print("Running SD-JWT proof size benchmarks...")
    cmd2 = ["cargo", "test", "test_sdjwt_proof_gen_benchmarks", "--release", "--", "--nocapture"]
    result2 = subprocess.run(cmd2, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    sdjwt_x, sdjwt_raw = [], []
    for line in result2.stdout.splitlines():
        if line.startswith("SDJWT_PROOF_SIZE_CSV:"):
            data = line.split("SDJWT_PROOF_SIZE_CSV:")[1].split(",")
            sdjwt_x.append(int(data[0]))
            sdjwt_raw.append(int(data[1]))
    sdjwt_y = [v / 1024.0 for v in sdjwt_raw]

    # BBS+ proof size
    print("Running BBS+ proof size benchmarks...")
    cmd3 = ["cargo", "test", "test_bbs_proof_gen_benchmarks", "--release", "--", "--nocapture"]
    result3 = subprocess.run(cmd3, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    bbs_x, bbs_raw = [], []
    for line in result3.stdout.splitlines():
        if line.startswith("BBS_PROOF_SIZE_CSV:"):
            data = line.split("BBS_PROOF_SIZE_CSV:")[1].split(",")
            bbs_x.append(int(data[0]))
            bbs_raw.append(int(data[1]))
    bbs_y = [v / 1024.0 for v in bbs_raw]

    plt.figure(figsize=(10, 6))
    
    colors = {2: 'orange', 10: 'red'}
    markers = {2: 'o', 10: 'D'}
    
    max_y = 0
    for depth, sizes_dict in sorted(data_by_depth.items()):
        sizes = sorted(sizes_dict.keys())
        sizes_kb = [sizes_dict[s] / 1024.0 for s in sizes]
        max_y = max(max_y, max(sizes_kb))
        
        c = colors.get(depth, 'black')
        m = markers.get(depth, 'x')
    
        label = f'SD-JCom (Nesting Layer = {depth})'
        plt.plot(sizes, sizes_kb, marker=m, color=c, label=label)

    if sdjwt_x:
        plt.plot(sdjwt_x, sdjwt_y, marker='s', color='blue', linestyle='--', label='SD-JWT', linewidth=2)
    if bbs_x:
        plt.plot(bbs_x, bbs_y, marker='*', color='green', linestyle='--', label='BBS+', linewidth=2)

    if sdjwt_y:
        max_y = max(max_y, max(sdjwt_y))
    if bbs_y:
        max_y = max(max_y, max(bbs_y))
    plt.xlabel('Number of Opened Values', fontsize=12)
    plt.ylabel('Proof Size (KB)', fontsize=12)
    plt.xlim(0, 100)
    plt.xticks([0, 20, 40, 60, 80, 100])
    plt.ylim(0, max_y * 1.1)
    
    # Optional: ensure nice round ticks for Y axis
    import matplotlib.ticker as ticker
    plt.gca().yaxis.set_major_locator(ticker.MaxNLocator(nbins=6, integer=False))
    
    plt.grid(True, linestyle='--', alpha=0.7)
    plt.legend(loc='upper left')
    
    output_path = 'proof_size_benchmark_chart.png'
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    print(f"Chart successfully saved to {os.path.abspath(output_path)}")

if __name__ == "__main__":
    main()
