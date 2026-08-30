# honeyfleet（多节点服务器蜜罐防御与联邦监控系统）

> **本项目仅含防御功能，不包含任何网络代理、隧道与流量混淆类组件，亦不涉及任何网络访问规避用途。** 只做蜜罐、封禁、加固与自监控；任何代理、隧道规避、流量混淆类代码均不在范围内，也不会被接受。

**Honeypot-fronted SSH defense with a three-tier enforcement funnel, fleet-wide self-monitoring, and a consistency gate that keeps the monitoring itself honest — one config, N servers, pluggable alerting.**
（蜜罐前置的 SSH 纵深防御：三级封禁漏斗、全队自监控、以及让监控自身保持诚实的一致性闸门 —— 一份配置，N 台服务器，可插拔告警。）

honeyfleet 把一台原装 Ubuntu/Debian 服务器变成硬目标：真实 sshd 迁到随机高位端口，防火墙默认 DROP；22 端口由假 SSH（蜜罐）接手并喂给逐级升级的 fail2ban 漏斗；每个节点持续自监控自身防御，把状态推送到中心节点 —— 监控一旦被"噤声"，噤声本身就是一条告警。

---

## ⚠️ 安装前必读（防自锁）

honeyfleet 会刻意让你的服务器**难以连入** —— 包括你自己。密码登录被关闭、真实 SSH 端口迁移、防火墙默认 DROP。运行安装器之前：

1. **保持第二个终端在线。** 当前会话是第一恢复通道。
2. **先让密钥登录可用。** 只能用密码登录的，先配好密钥再安装 —— 安装器会禁用密码认证。
3. **记下云商控制台（VNC）地址。** 这是网络路径彻底断掉时的带外恢复通道。
4. **来源白名单默认关闭，是故意的**（动态 IP 自锁教训）。若显式开启 `HF_SSH_SOURCE_RESTRICT=true`，60 秒看门狗会在你未及时确认时自动回滚；确认命令：`sudo /usr/local/lib/honeyfleet/ssh-hardening.sh confirm`。完整手册见 [`docs/hardening-guide.md`](docs/hardening-guide.md)。

所有触碰 sshd 或防火墙的变更都走同一级阶梯：先校验候选配置（`sshd -t` / `iptables-restore --test`）→ 在新端口上拉起独立测试 sshd 并**实测一次真实密钥登录** → 每个被触碰的文件都留时间戳备份 → 任一步失败自动回滚。失败时恢复到之前可用状态，运行中的 sshd 绝不会留下坏配置。

## 快速开始

```bash
# 0. 把仓库放到服务器上（root 或 sudo）

# 1. 复制配置 —— 唯一配置源
sudo mkdir -p /etc/honeyfleet
sudo cp config/honeyfleet.conf.example /etc/honeyfleet/honeyfleet.conf
sudoedit /etc/honeyfleet/honeyfleet.conf      # 设定 HF_ROLE 与需要调整的键

# 2. 安装（--role 必须与配置中的 HF_ROLE 一致）
sudo ./install.sh install --role agent        # 或：--role central

# 3. 校验 —— 一致性闸门 + 端到端检查；非零退出说明有问题，先修再走开
sudo ./install.sh verify

# 日常：每个模块一行健康状态
sudo ./install.sh status
```

安装器只做分发：所有参数来自唯一配置文件；模块幂等（一致系统上重复 install 是 NO-OP）；依赖自动声明、自动排序（`./install.sh plan` 只打印计划不做变更）。

## 三级封禁漏斗

| 层级 | 谁在应答 | 发生什么 |
|---|---|---|
| 1. 蜜罐（22 端口） | 假 SSH（`sshesame`，SHA256 钉死版本） | 任何触碰都是证据；10 分钟内 3 次 = 封禁 30 天；横幅从真实 sshd 逐字节校准，假的看起来是真的 |
| 2. 真实 sshd（迁移后端口） | 加固后的真 sshd（密码认证关闭） | 对真口的爆破：5 次失败 = 递增封禁（倍增器最高 3650 天） |
| 3. recidive（累犯） | fail2ban recidive jail | 30 天内反复被封者，**全端口**封禁最高 10 年 |

22 端口**有意**保持开放 —— 它是蜜罐喂食口。连进来的不是攻击者就是配错的客户端，两者都是有价值的信号。

## 模块（8 个）

| 模块 | 一句话 |
|---|---|
| `ssh-hardening` | 真实 sshd 迁到随机（或指定）高位端口，四阶梯防自锁；关闭密码认证；在服务器上落一份运维 README；可选白名单置于 60 秒自动回滚看门狗之下。 |
| `firewall-baseline` | INPUT 默认 DROP 基线 + 按端口放行 + 带出处注释的封禁源（`banned-<reason>`）+ 可选出站挖矿端口封锁；60 秒看门狗；持久化不含 f2b 动态链的 rules.v4，开机由 fail2ban 自行重挂。 |
| `fail2ban-stack` | 三个 jail（sshd / sshesame / recidive）由一份受管文件部署；verify 闸门把**每个**已部署参数从运行中的 fail2ban 读回并与配置比对 —— 参数一致性事故类的消费端闸门。 |
| `honeypot-ssh` | 22 端口假 SSH：上游二进制钉死版本且 SHA256 fail-closed 校验；专用蜜罐主机密钥（连 22 时 known-hosts 不匹配是绊线，不是事故）；横幅从真 sshd 逐字节校准；systemd 沙箱（User=nobody、NoNewPrivileges、ProtectSystem=full）；每 3 分钟健康探针，僵死自动重启。 |
| `file-integrity` | 分钟级 SHA256 监控安全关键文件，**计数诚实**：`files_tracked` 恒等于真实基线规模；悬空目标显式告警、绝不静默跳过；verify 闸门将计数与基线本身交叉核对。 |
| `waterline-alerts` | 磁盘/内存/swap 水位告警，阈值从配置渲染进检查脚本并带冷却；verify 闸门把渲染值与实时配置比对。 |
| `notifiers` | 可插拔告警通道 —— `telegram` \| `wecom` \| `dingtalk` \| `smtp` —— 统一走 `hf_notify` 接口，"未配置 ≠ 故障"；以共享库形态部署，端点绝不写死。 |
| `federation` | 全队自监控：agent 每 60 秒经 SSH 推送状态快照到中心接收器（校验 schema + 时间戳，防重放），每 agent 一份 JSON 存储 + 去重后的全队摘要推送；超过 10 倍推送间隔未上报的 agent 被标记 **stale —— 滞后绝不无声**，恢复时同样通告。 |

每个模块遵循 [`docs/MODULE-CONTRACT.md`](docs/MODULE-CONTRACT.md)：单一配置源（`hf_conf`）、幂等安装、验行为而非验文件存在的 verify 闸门、显式依赖声明、任何写操作前先备份（每文件家族保留最近 2 份）。

## 一致性闸门：让监控自身保持诚实

一个会对自身状态说谎的安全工具比没有更糟。honeyfleet 的对策：

- **每个模块自带 verify 闸门。** `install.sh verify` 从配置重新推导期望状态，并与**已部署、运行中**的实际状态比对：fail2ban 参数用 `fail2ban-client get` 读回、告警阈值与渲染进脚本里的值比对、完整性计数与基线本身交叉核对。
- **计数必须诚实。** "监控 N 项"就是 N 个受保护对象，不是 N 行配置。
- **同一参数的所有消费方必须同改。** 若两个组件校验同一个值，变更必须同一提交内两处都改 —— 契约第 4 条强制执行，跨模块闸门兜底（如蜜罐闸门复核 fail2ban jail 端口）。
- **每次 install 结束**，分发器执行全队校验（`verify/consistency-gate.sh`），配置与实际运行之间的漂移在部署时暴露，而不是在事故时。

三个真实事故如何变成上述机制，见 [`docs/design-rationale.md`](docs/design-rationale.md)。

## 威胁模型摘要

大规模扫描器撞 22 端口、喂蜜罐、在构成威胁前就被封禁。定向攻击者面对默认 DROP、已迁移且加固的 sshd、按白名单收紧的服务端口 —— 同时必须承认：蜜罐的 accept-all 行为**可以**被坚定攻击者指纹探测；它的价值是预警与封禁数据源，不是完美欺骗。最现实的"攻击者"是你自己：白名单敲错一个 IP、家庭宽带换了出口，就把自己锁在门外 —— 所以才有上面的防自锁阶梯。root 一旦沦陷，主机侧检测（完整性检查、定时器、日志）都可被攻击者关闭；剩余信号在舰队层面：停止推送的节点会在 10 分钟内被中心标记 stale，且联邦设计假设中心与 agent **不会同时**沦陷。完整模型见 [`docs/threat-model.md`](docs/threat-model.md)。

## 文档

| 文档 | 内容 |
|---|---|
| [`docs/user-manual.md`](docs/user-manual.md) | 用户手册（中文）：安装、全部配置键、运维命令、告警处理、卸载、故障排查 |
| [`docs/hardening-guide.md`](docs/hardening-guide.md) | 防自锁手册：改端口四级阶梯、白名单、看门狗、云商控制台兜底 |
| [`docs/threat-model.md`](docs/threat-model.md) | 资产、攻击者画像、信任边界、控制映射、已知边界 |
| [`docs/design-rationale.md`](docs/design-rationale.md) | 三个生产事故与其产品化机制 |
| [`docs/MODULE-CONTRACT.md`](docs/MODULE-CONTRACT.md) | 每个模块必须满足的契约 |
| [`CHANGELOG.md`](CHANGELOG.md) | 版本历史 |
| [`SECURITY.md`](SECURITY.md) | 漏洞报告方式 |

## 支持矩阵与许可

- **支持平台：** Ubuntu 20.04+、Debian 11+（systemd、bash、python3、curl、iptables）。其他发行版可能可用（fail2ban-stack 会回退 dnf/yum），但未经测试。
- **许可：** GPL-3.0，见 [`LICENSE`](LICENSE)。
- **不提供任何担保。** 本程序按"有用"的期望分发，但不附带任何担保；不附带适销性或特定用途适用性的默示担保。详见 GNU 通用公共许可证第 3 版第 15/16 条。跳过上述警告导致防火墙把自己挡在门外是真实可能 —— honeyfleet 自动化安全阶梯，但不能消除风险。

本仓库所有示例值一律使用 RFC 5737 文档地址段（`192.0.2.0/24`、`198.51.100.0/24`、`203.0.113.0/24`）与 `example.com`；契约第 7 条禁止出现任何真实 IP、域名、密钥与令牌。
