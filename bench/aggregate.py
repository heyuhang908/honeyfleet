#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
honeyfleet bench aggregator — 把 collector.sh 产出的 JSONL 采样聚合成
telemetry.json 中"待采集"部分（reliability/resource/timeline），然后重跑 charts.py。

用法（在装有 matplotlib 的机器上，data/ 与 charts.py 同目录）：
    python bench/aggregate.py  <JSONL 目录或文件>...
示例：python bench/aggregate.py  /var/lib/honeyfleet/bench/main-vps-202609*.jsonl
"""
import glob
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
DATA_PATH = HERE / "data" / "telemetry.json"
REPORT_PATH = HERE / "report"

AGG_FIELDS = {
    "load1": "load1",
    "mem_used_pct": "mem_used_pct",
    "disk_used_pct": "disk_used_pct",
    "fork_since_boot": "fork_since_boot",
}


def main(files):
    samples = []
    bad = 0
    bad_samples = []
    for pattern in files:
        for f in glob.glob(pattern):
            for lineno, line in enumerate(Path(f).read_text(encoding="utf-8").splitlines(), 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    samples.append(json.loads(line))
                except json.JSONDecodeError:
                    bad += 1
                    if len(bad_samples) < 10:
                        bad_samples.append(f"{f}:{lineno}")
    if not samples:
        print("未找到有效采样数据。请先运行 bench/collector.sh 采集。")
        return 1
    if bad:
        print(f"[WARN] {bad} 条坏行被跳过（覆盖 {len(samples)}/{len(samples)+bad}）— 请检查 collector 日志：")
        for s in bad_samples:
            print(f"       {s}")
        # fail-closed：数据不完整时不自动刷新图表（避免把采集故障伪装成正常）
        print("[FAIL] 存在坏行，跳过图表自动刷新。修复采集后重跑。")
        return 2

    samples.sort(key=lambda s: s.get("ts", 0))
    start, end = samples[0].get("utc"), samples[-1].get("utc")
    nodes = sorted({s.get("node", "?") for s in samples})

    # 系统指标：取中位数（抗毛刺）
    def median(key):
        vals = sorted(float(s.get(key) or 0) for s in samples)
        n = len(vals)
        return vals[n // 2] if n else None

    # fail2ban jail 封禁数（最后一条快照）
    jails = samples[-1].get("fail2ban_jails", {}) or {}
    # 蜜罐日志增量：仅在同 inode（未轮转）的相邻采样间累计；轮转即重置基线
    hp_delta = 0
    prev_inode, prev_size = None, None
    for s in samples:
        inode = s.get("honeypot_log_inode")
        size = s.get("honeypot_log_size", 0)
        if inode and inode == prev_inode and size >= prev_size:
            hp_delta += size - prev_size
        prev_inode, prev_size = inode, size

    telemetry = json.loads(DATA_PATH.read_text(encoding="utf-8"))
    telemetry["reliability_resource"] = {
        "status": "已采集（实时）",
        "placeholder": False,
        "collected": {"start": start, "end": end, "nodes": nodes, "samples": len(samples)},
        "metrics": {
            "load1_median": median("load1"),
            "mem_used_pct_median": median("mem_used_pct"),
            "disk_used_pct_median": median("disk_used_pct"),
            "fork_since_boot_median": median("fork_since_boot"),
            "honeypot_log_bytes_delta": hp_delta,
        },
        "fail2ban_banned_snapshot": jails,
        "unit_active_snapshot": samples[-1].get("units", {}),
    }

    DATA_PATH.write_text(json.dumps(telemetry, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"已聚合 {len(samples)} 条采样 → {DATA_PATH}")
    print("重跑 charts.py 刷新图表…")
    import subprocess
    subprocess.run([sys.executable, str(HERE / "charts.py")], check=True)
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    sys.exit(main(sys.argv[1:]))
