#!/usr/bin/env bash
# honeyfleet bench collector — 在 VPS 上持续采集运行时指标（30 天数据管道）
# 用法：以 root 在 honeyfleet 节点上执行；cron 建议每 10 分钟一次：
#   */10 * * * * /usr/local/lib/honeyfleet/bench/collector.sh >> /var/log/honeyfleet/bench-collector.log 2>&1
# 输出：/var/lib/honeyfleet/bench/<hostname>-<YYYYMMDD>.jsonl（每行一个采样 JSON，python3 结构化生成）
# 聚合：bench/aggregate.py 读取后合并进 bench/data/telemetry.json → 重跑 charts.py 刷新图表
# 依赖：python3（honeyfleet 运行时必备）、flock（util-linux）
set -uo pipefail

STORE_DIR=/var/lib/honeyfleet/bench
mkdir -p "$STORE_DIR"

# 并发锁：同一节点同一时刻只允许一个采集器
exec 9>"$STORE_DIR/.lock"
flock -n 9 || { echo "bench: another collector is running — skip"; exit 0; }

OUT="$STORE_DIR/$(hostname)-$(date -u +%Y%m%d).jsonl"
now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
ts=$(date +%s)

# ── fail2ban 各 jail 当前封禁数（结构化 python 解析，健壮处理 jail 名）────
F2B_TMP=$(mktemp)
if command -v fail2ban-client >/dev/null 2>&1; then
    fail2ban-client status 2>/dev/null | sed -n 's/^Jail list:[[:space:]]*//p' | tr ',' '\n' | sed 's/[[:space:]]//g' | grep -v '^$' > "$F2B_TMP"
fi
f2b=$(python3 -c '
import json, subprocess, sys
jails = [l.strip() for l in sys.stdin if l.strip()]
out = {}
for j in jails:
    try:
        r = subprocess.run(["fail2ban-client", "status", j],
                           capture_output=True, text=True, timeout=10)
        banned = None
        for line in r.stdout.splitlines():
            if "Currently banned:" in line:
                banned = int(line.split(":", 1)[1].strip()); break
        out[j] = banned
    except Exception:
        out[j] = None
print(json.dumps(out, sort_keys=True))
' < "$F2B_TMP") || { echo "bench: fail2ban json build failed" >&2; rm -f "$F2B_TMP"; exit 1; }
rm -f "$F2B_TMP"

# ── sshesame 蜜罐日志（记录字节数，窗口增量由 aggregate 按"同文件"计算）──
hp_log=""
for f in /var/log/honeyfleet/sshesame.log /var/log/honeyfleet/sshesame.json /var/log/sshesame/*; do
    [ -f "$f" ] && hp_log="$f" && break
done
hp_size=0; hp_inode=""
if [ -n "$hp_log" ]; then
    hp_size=$(wc -c <"$hp_log" 2>/dev/null || echo 0)
    hp_inode=$(stat -c %i "$hp_log" 2>/dev/null || echo "")
fi

# ── systemd 记账（结构化 python 生成，杜绝手工拼 JSON）─────────────
UNITS_TMP=$(mktemp)
for unit in ssh-hardening.service firewall-baseline.service fail2ban-stack.service \
            honeypot-ssh.service file-integrity.service waterline-alerts.service \
            honeyfleet-sshesame.service honeyfleet-sshesame-health.timer \
            file-integrity.timer waterline-alerts.timer; do
    if systemctl list-unit-files "$unit" >/dev/null 2>&1; then
        # is-active 对 inactive 单元可能输出多行（inactive/unknown）——只取首行
        active=$(systemctl is-active "$unit" 2>/dev/null | head -n1)
        active=${active:-unknown}
        m=$(systemctl show "$unit" -p MemoryCurrent --value 2>/dev/null | head -n1)
        c=$(systemctl show "$unit" -p CPUUsageNSec --value 2>/dev/null | head -n1)
        printf '%s\t%s\t%s\t%s\n' "$unit" "$active" "${m:-0}" "${c:-0}" >> "$UNITS_TMP"
    fi
done
units=$(python3 -c '
import json, sys
out = {}
for line in sys.stdin:
    line = line.rstrip("\n")
    if not line:
        continue
    unit, active, m, c = line.split("\t")
    def _int(v):
        try:
            return int(v)
        except (TypeError, ValueError):
            return 0
    out[unit] = {"active": active, "rss_bytes": _int(m), "cpu_ns": _int(c)}
print(json.dumps(out, sort_keys=True))
' < "$UNITS_TMP") || { echo "bench: units json build failed" >&2; rm -f "$UNITS_TMP"; exit 1; }
rm -f "$UNITS_TMP"

# ── 系统级 ─────────────────────────────────────────────────────
load=$(awk '{print $1}' /proc/loadavg 2>/dev/null || echo 0)
meminfo=$(awk '/MemTotal/{t=$2} /MemAvailable/{a=$2} END{printf "%.1f", (1-a/t)*100}' /proc/meminfo 2>/dev/null || echo 0)
disk=$(df -P / 2>/dev/null | awk 'NR==2{print $5}' | tr -d '%' || echo 0)
fork_since_boot=$(awk '/^processes /{print $2}' /proc/stat 2>/dev/null || echo 0)
boot_id=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || echo unknown)

# ── 组装（单行 JSON，python3 保证合法）──────────────────────────
python3 -c '
import json, sys
row = {
  "schema": 1, "collector_ver": "2",
  "ts": sys.argv[1], "utc": sys.argv[2], "node": sys.argv[3], "boot_id": sys.argv[4],
  "load1": float(sys.argv[5]), "mem_used_pct": float(sys.argv[6]),
  "disk_used_pct": float(sys.argv[7]), "fork_since_boot": int(sys.argv[8]),
  "honeypot_log_size": int(sys.argv[9]), "honeypot_log_inode": sys.argv[10],
  "fail2ban_jails": json.loads(sys.argv[11]), "units": json.loads(sys.argv[12]),
}
print(json.dumps(row, ensure_ascii=True, sort_keys=True))
' "$ts" "$now" "$(hostname)" "$boot_id" "$load" "$meminfo" "$disk" "$fork_since_boot" \
    "$hp_size" "$hp_inode" "$f2b" "$units" >> "$OUT" || { echo "bench: row assembly failed" >&2; exit 1; }

echo "bench: sampled $(date -u +%H:%M:%SZ) -> $OUT"
