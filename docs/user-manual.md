# 多节点服务器蜜罐防御与联邦监控系统 用户手册

**软件全称：** 多节点服务器蜜罐防御与联邦监控系统
**软件简称：** honeyfleet
**版本：** V1.0
**适用平台：** Ubuntu 20.04+ / Debian 11+

---

## 1. 软件概述

本软件用于 Linux 服务器的 SSH 蜜罐防御与多节点自监控：真实 SSH 服务迁移至随机高位端口并关闭密码认证；22 端口由蜜罐（假 SSH 服务）接手，所有连入行为被记录并喂给三级封禁漏斗（蜜罐封禁 → 真实端口爆破封禁 → 累犯全端口封禁）；防火墙默认拒绝入站，仅放行显式声明的服务端口；每个节点以分钟级周期自检关键文件完整性、资源水位与自身防御组件的健康状态，并按角色将状态快照推送至中心节点汇总。软件内置一致性闸门：每次安装结束时将"配置声明的状态"与"实际运行状态"逐项比对，防止监控自身失真。

本软件仅含防御功能，不包含任何网络代理、隧道与流量混淆类组件，亦不涉及任何网络访问规避用途。

### 1.1 系统组成

| 组成部分 | 说明 |
|---|---|
| `install.sh` | 安装器/分发器。支持 install（安装）、verify（校验）、status（状态）、uninstall（卸载）、plan（打印计划）五种模式；模块依赖自动排序；安装结束自动执行全队一致性校验 |
| `lib/common.sh` | 公共库：配置读取（hf_conf）、备份（hf_backup）、systemd 单元写入、依赖与注册表 |
| `modules/` | 8 个功能模块（见第 5 章） |
| `notifiers/` | 可插拔告警通道库：telegram / wecom（企业微信）/ dingtalk（钉钉）/ smtp |
| `config/honeyfleet.conf.example` | 配置样例（唯一配置源，复制为 `/etc/honeyfleet/honeyfleet.conf` 后编辑） |
| `verify/` | 一致性闸门脚本目录；`install.sh install` 结束时若存在 `verify/consistency-gate.sh` 则自动执行 |

### 1.2 部署目录约定

| 路径 | 用途 |
|---|---|
| `/etc/honeyfleet/` | 配置文件、完整性监控目标清单与基线、各模块落盘的运维说明 |
| `/usr/local/lib/honeyfleet/` | 部署后的检查脚本、联邦推送/接收脚本、通知通道库 |
| `/var/lib/honeyfleet/` | 模块注册表、模块状态 JSON、防火墙快照、备份（每文件家族保留最近 2 份） |
| `/var/log/honeyfleet/` | 水位告警日志、蜜罐 JSON 日志、联邦校验日志 |

## 2. 运行环境

| 项目 | 要求 |
|---|---|
| 操作系统 | Ubuntu 20.04+ 或 Debian 11+ |
| 系统组件 | systemd（服务与定时器）、bash、python3、curl |
| 防火墙 | iptables（建议安装 iptables-persistent 以持久化） |
| 自动安装的依赖 | fail2ban（由 fail2ban-stack 模块在缺失时自动安装） |
| 账户权限 | root 或具备 sudo 权限 |
| 网络 | agent 角色需可 SSH 连接中心节点；告警通道需可达对应服务地址 |

## 3. 安装与初始部署

### 3.1 安装前必读（防自锁警告）

本软件会刻意提高服务器的接入门槛：密码登录被禁用、真实 SSH 端口迁移、防火墙默认拒绝入站。安装前请务必：

1. **保持第二个终端在线**——当前会话是第一恢复通道；
2. **先确认密钥登录可用**——仅有密码登录时，先配置好密钥再安装；
3. **记下云服务商控制台（VNC）地址**——这是网络中断时的带外恢复通道；
4. **来源白名单默认关闭是刻意设计**（防止动态 IP 自锁）；如确需开启，启用后 60 秒内未确认将自动回滚（见 4.2 与 `docs/hardening-guide.md`）。

### 3.2 安装步骤

```bash
# 1. 复制并编辑配置（唯一配置源）
sudo mkdir -p /etc/honeyfleet
sudo cp config/honeyfleet.conf.example /etc/honeyfleet/honeyfleet.conf
sudoedit /etc/honeyfleet/honeyfleet.conf

# 2. 执行安装（--role 必须与配置中 HF_ROLE 一致）
sudo ./install.sh install --role agent      # 中心节点使用 --role central

# 3. 一致性校验（非零退出表示存在不一致，须修复后再投入使用）
sudo ./install.sh verify

# 4. 查看各模块一行式健康状态
sudo ./install.sh status
```

安装器特性：

- **幂等**：系统已一致时重复执行 install 为空操作（NO-OP）；
- **依赖自动排序**：`./install.sh plan` 可在不做任何变更的前提下打印模块执行顺序；
- **单模块安装**：`--only 模块名`（如 `--only ssh-hardening`）；
- **指定配置**：`--config FILE` 可临时使用其他配置文件。

agent 角色需额外完成推送密钥授权（见 5.8）。

## 4. 配置详解

配置文件为 `/etc/honeyfleet/honeyfleet.conf`，是全部模块的唯一配置源。每个模块只通过 `hf_conf` 读取自己的键；代码中不硬编码任何端口、路径、阈值或地址。修改配置后重跑 `install.sh install` 即可生效（模块幂等，只重渲染实际变化的部分）。

### 4.1 核心配置键

| 配置键 | 默认值 | 说明 |
|---|---|---|
| HF_ROLE | agent | 节点角色。central=中心节点（接收全队快照并汇总告警）；agent=代理节点（推送状态快照）。安装器会校验 `--role` 与此值一致 |
| HF_SSH_REAL_PORT | random | 真实 sshd 端口。`random` 表示安装时自动在 10000–65535 中选取空闲端口并**回写**到本配置；也可直接填 1024–65535 的数字。不得与蜜罐端口相同 |
| HF_SSH_HONEYPOT | true | 是否在蜜罐端口部署假 SSH。为 false 时 honeypot-ssh 模块自动跳过 |
| HF_SSH_MAXAUTHTRIES | 3 | sshd 最大认证尝试次数（同时用于蜜罐） |
| HF_SSH_MANAGEMENT_SOURCES | （空/示例值） | 运维来源列表（空格分隔，支持 CIDR）。始终作为 fail2ban ignoreip；开启来源白名单时必填 |
| HF_F2B_FINDTIME_SSH | 600 | sshd jail 计时窗口（秒） |
| HF_F2B_MAXRETRY_SSH | 5 | sshd jail 触发封禁的失败次数 |
| HF_F2B_BANTIME_SSH | 10m | sshd jail 基础封禁时长（支持 s/m/h/d/w 组合或纯秒数） |
| HF_F2B_INCREMENT | true | 是否启用递增封禁（屡犯翻倍） |
| HF_F2B_INCREMENT_MAXTIME | 3650d | 递增封禁上限 |
| HF_HP_FINDTIME | 600 | 蜜罐 jail 计时窗口（秒） |
| HF_HP_MAXRETRY | 3 | 蜜罐 jail 触发封禁的触碰次数（蜜罐任何认证行为都计入失败） |
| HF_HP_BANTIME | 30d | 蜜罐封禁时长 |
| HF_RECIDIVE_FINDTIME | 30d | 累犯判定窗口 |
| HF_RECIDIVE_BANTIME | 3650d | 累犯全端口封禁时长 |
| HF_FW_SERVICES | 443/tcp | 对外服务端口列表（`端口/协议`，空格分隔；协议缺省 tcp） |
| HF_FW_SOURCE_WHITELIST_<端口> | "" | 对应端口的来源白名单（如 HF_FW_SOURCE_WHITELIST_443）。留空=全球可达；设置后仅白名单来源可达该端口 |
| HF_FW_BLOCKED_SOURCES | "" | 显式封禁源，格式 `地址#原因`（如 `203.0.113.7#scanner 198.51.100.0/24#abuse`）。每条规则带 `banned-原因` 注释并由 verify 逐一核验 |
| HF_FW_MINING_PORT_BLOCK | true | 封锁出站挖矿/矿池常用端口 |
| HF_FI_TARGETS | /etc/ssh/sshd_config /etc/fail2ban /etc/systemd/system | 完整性监控目标（空格分隔；目录展开其下两层内的全部常规文件）。建议将 /etc/honeyfleet 与 /usr/local/lib/honeyfleet 一并纳入 |
| HF_WATERLINE_DISK | 80 | 磁盘使用率告警阈值（百分比，达到即告警） |
| HF_WATERLINE_MEM | 20 | 可用内存占比告警阈值（百分比，低于即告警） |
| HF_WATERLINE_SWAP | 50 | swap 使用率告警阈值（百分比，高于即告警） |
| HF_NOTIFIER | wecom | 告警通道：wecom / telegram / dingtalk / smtp（默认 wecom） |
| HF_TG_BOT_TOKEN | "" | Telegram 机器人令牌 |
| HF_TG_CHAT_ID | "" | Telegram 会话 ID |
| HF_WECOM_WEBHOOK | "" | 企业微信群机器人 Webhook 地址 |
| HF_DINGTALK_WEBHOOK | "" | 钉钉群机器人 Webhook 地址 |
| HF_SMTP_TO | "" | SMTP 收件人地址 |
| HF_SMTP_RELAY | "" | SMTP 中继（必填，如 relay.example.com:25；本通道不直接投递 MX） |
| HF_CENTRAL_HOST | "" | 中心节点主机名/IP（仅 agent 角色需要，必填） |
| HF_CENTRAL_PORT | 22 | 中心节点 SSH 端口 |
| HF_CENTRAL_USER | honeyfleet | 中心节点推送账户 |
| HF_PUSH_INTERVAL | 60 | 状态快照推送间隔（秒） |

### 4.2 可选/高级配置键（未列出时使用内置默认值）

| 配置键 | 默认值 | 说明 |
|---|---|---|
| HF_SSH_SOURCE_RESTRICT | false | SSH 来源白名单开关。true 时仅 HF_SSH_MANAGEMENT_SOURCES 可达真实端口，且置于 60 秒自动回滚看门狗之下（见 4.3） |
| HF_FW_MINING_PORTS | 3333 4444 5555 7777 8048 14444 | 出站封锁的矿池端口列表 |
| HF_WATERLINE_COOLDOWN_S | 3600 | 同一指标两条告警的最小间隔（秒），防止 5 分钟周期刷屏 |
| HF_DINGTALK_SECRET | "" | 钉钉机器人加签密钥（启用加签安全设置时填写） |
| HF_FLEET_SUMMARY_DEDUPE | 1 | 全队摘要去重：1=内容未变化且心跳未到（1 小时）则抑制；0=每次接收都通知 |
| HF_F2B_SSHD_BACKEND | systemd | sshd jail 日志后端：systemd（journald，无 logpath）或 auto（/var/log/auth.log） |
| HF_F2B_INCREMENT_MULTIPLIERS | 1 525600 | 递增封禁倍增器列表 |
| HF_F2B_DBPURGEAGE | 3650d | fail2ban 封禁数据库保留期（须不小于累犯窗口） |
| HF_RECIDIVE_MAXRETRY | 2 | 累犯触发阈值 |
| HF_RECIDIVE_LOGPATH | /var/log/fail2ban.log | 累犯 jail 读取的日志路径 |
| HF_HP_PORT | 22 | 蜜罐监听端口 |
| HF_HP_LISTEN | 0.0.0.0 | 蜜罐监听地址 |
| HF_HP_LOGPATH | /var/log/honeyfleet/sshesame/sshesame.json | 蜜罐 JSON 日志路径（自动按周+10M 轮转，保留 8 份） |
| HF_HP_BANNER | （自动校准） | 蜜罐 SSH 横幅。缺省时从真实 sshd 逐字节抓取校准；含 YAML 不安全字符时拒绝并要求手工指定 |
| HF_HP_TCPIP_SERVICES | 25:SMTP 80:HTTP 110:POP3 587:SMTP 8080:HTTP | 蜜罐提供的诱饵端口转发服务（`端口:服务名` 列表） |
| HF_HP_HEALTH_INTERVAL | 180 | 蜜罐健康探针运行间隔（秒） |
| HF_HP_HEALTH_THRESHOLD | 2 | 连续失败多少次后自动重启蜜罐 |
| HF_HP_HEALTH_COOLDOWN | 900 | 两次自动重启之间的最小间隔（秒） |
| HF_HP_SSHESAME_SHA256 | （模块内置钉死值） | 蜜罐二进制 SHA256 钉死值覆盖。校验失败（fail-closed）时按提示三选一：按钉死 tag 自行构建、审查官方发布物后设置本键、或在受审版本升级中更新模块常量 |

### 4.3 SSH 来源白名单与 60 秒看门狗

`HF_SSH_SOURCE_RESTRICT=true` 时，模块在应用白名单前会先保存当前防火墙快照并武装 60 秒看门狗；应用后须在 60 秒内执行确认命令解除：

```bash
sudo /usr/local/lib/honeyfleet/ssh-hardening.sh confirm
```

超时未确认，看门狗自动回滚内存与磁盘上的规则集并记录日志（`source whitelist ROLLED BACK`）。该开关默认关闭的原因：运维来源（如家庭宽带 IP）动态变化，白名单极易造成自锁——详细论证与操作阶梯见 `docs/hardening-guide.md`。

## 5. 模块与运维命令

### 5.1 总控命令

```bash
sudo ./install.sh install   [--role central|agent] [--only 模块] [--config FILE]  # 安装（幂等）
sudo ./install.sh verify    [--only 模块]                                            # 一致性闸门 + 端到端校验
sudo ./install.sh status    [--only 模块]                                            # 每模块一行健康状态
sudo ./install.sh uninstall [--only 模块]                                            # 卸载（保留状态文件供取证）
sudo ./install.sh plan      [--only 模块]                                            # 打印模块执行顺序（不改动）
```

模块执行顺序（依赖优先）：ssh-hardening → firewall-baseline → fail2ban-stack → honeypot-ssh → file-integrity → waterline-alerts → notifiers → federation。

### 5.2 ssh-hardening（SSH 加固与端口迁移）

- 功能：真实 sshd 迁移至高位端口（四级防自锁阶梯：第二终端警告 → `sshd -t` 预检 → 新端口独立测试 sshd 实测密钥登录 → 自动回滚）；关闭密码认证；可选来源白名单（60 秒看门狗）；在服务器上生成运维说明 `/etc/honeyfleet/README-ssh-hardening.txt`。
- 特有子命令：`confirm`（解除白名单看门狗）。
- 直调示例：`sudo ./modules/ssh-hardening.sh install|verify|status|confirm|remove`。

### 5.3 firewall-baseline（防火墙基线）

- 功能：INPUT 链默认 DROP；按 HF_FW_SERVICES 放行；按端口来源白名单收紧；显式封禁源（带 `banned-原因` 出处注释）；出站矿池端口封锁；应用前快照 + 60 秒看门狗 + `iptables-restore --test` 预检 + 应用后逐条自检；持久化到 `/etc/iptables/rules.v4`（剥离 fail2ban 动态链，开机由 fail2ban 自行重建）。
- 直调示例：`sudo ./modules/firewall-baseline.sh install|verify|status|remove`。
- 注意：FORWARD 链与 OUTPUT 默认策略不受影响；IPv6（ip6tables）不在本模块范围内。

### 5.4 fail2ban-stack（三级封禁漏斗）

- 功能：以单一受管文件 `/etc/fail2ban/jail.d/honeyfleet.local` 部署三个 jail——sshd（真实端口爆破）、sshesame（蜜罐触碰）、recidive（累犯全端口升级）；ignoreip 恒含回环与运维来源；数据库保留期与累犯窗口对齐。
- verify 闸门：将**运行中** fail2ban 的每个 jail 参数经 `fail2ban-client get` 读回并与配置逐一比对。
- 直调示例：`sudo ./modules/fail2ban-stack.sh install|verify|status|remove`。
- 注意：fail2ban reload 会清零进行中的失败计数，属预期行为。

### 5.5 honeypot-ssh（蜜罐）

- 功能：在 HF_HP_PORT（默认 22）部署假 SSH（sshesame，版本与 SHA256 钉死、fail-closed 校验）；横幅从真实 sshd 逐字节校准；使用独立蜜罐主机密钥——连接 22 端口时本地 known_hosts 报 HOST KEY MISMATCH 属**预期绊线信号**；服务以 nobody 用户运行于 systemd 沙箱（NoNewPrivileges、ProtectSystem=full）；健康探针每 3 分钟检查"服务活跃 + 回环 TCP 可接受 + 横幅正常"，连续 2 次失败自动重启（900 秒冷却）；日志按周/10MB 轮转保留 8 份。
- 直调示例：`sudo ./modules/honeypot-ssh.sh install|verify|status|remove`。

### 5.6 file-integrity（文件完整性）

- 功能：按分钟级定时器对 HF_FI_TARGETS 内目标做 SHA256 校验；首次安装自动建立基线；状态写入 `/var/lib/honeyfleet/file-integrity-state.json`（files_tracked 恒等于真实基线规模——悬空目标显式告警并排除，绝不静默计入）。
- 特有子命令：`rebase`（核实漂移后接受当前状态为新基线；悬空条目会列出）。
- 直调示例：`sudo ./modules/file-integrity.sh install|verify|status|rebase|remove`。

### 5.7 waterline-alerts（水位告警）

- 功能：每 5 分钟检查磁盘/内存/swap 水位，越线即经 hf_notify 告警（默认冷却 3600 秒）；阈值在安装时渲染进检查脚本，verify 闸门将渲染值与配置比对——修改 HF_WATERLINE_* 后须重跑 install 重新渲染。
- 直调示例：`sudo ./modules/waterline-alerts.sh install|verify|status|remove`。

### 5.8 federation（联邦监控）

- agent 角色：每 HF_PUSH_INTERVAL 秒将本机状态快照（fail2ban 各 jail 实时封禁计数、文件完整性状态、水位、主机名与时间戳）经 SSH 推送至中心节点。
- 推送密钥配置（首次）：
  1. agent 上生成专用密钥：`ssh-keygen -t ed25519 -N '' -f ~/.ssh/id_ed25519_fleetpush`；
  2. 中心节点创建推送用户（HF_CENTRAL_USER，默认 honeyfleet），在 `~<user>/.ssh/authorized_keys` 中以强制命令锁定该公钥（最小权限，禁端口转发/X11/agent 转发/PTY）：
     `command="/usr/local/lib/honeyfleet/receive-fleet.py",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty ssh-ed25519 AAAA... agent@192.0.2.10`；
  3. agent 配置 HF_CENTRAL_HOST/PORT/USER 后执行 `sudo ./install.sh install --only federation`。
- central 角色：接收器（python3 标准库实现）校验快照 schema 与时间戳（防重放：拒绝早于已存时间戳、拒绝超前 120 秒以上的时钟）；每 agent 一份 JSON 原子化存储于 `/var/lib/honeyfleet/fleet/`；回执 `OK <agent> age=0 entries=N`；随后推送去重的全队摘要（内容不变且 1 小时心跳未到则抑制；HF_FLEET_SUMMARY_DEDUPE=0 关闭去重）；另有扫描定时器标记超过 10×推送间隔未上报的 agent 为 stale 并告警——滞后绝不无声，恢复时同样通告。
- 实用命令：`sudo /usr/local/lib/honeyfleet/fleet-push.sh`（手动推送一次）；`sudo /usr/local/lib/honeyfleet/receive-fleet.py --scan`（手动执行滞后扫描）；`--selftest`（自检）。
- 直调示例：`sudo ./modules/federation.sh install|verify|status|remove`。

### 5.9 notifiers（告警通道库）

- 统一接口 `hf_notify "标题" "正文"`；通道由 HF_NOTIFIER 选择，凭据全部来自配置文件。
- 失败语义：通道未配置 → 警告并视为成功（未配置≠故障）；发送失败 → 警告并返回非零；绝不中断调用方主流程。
- 手工测试：`sudo /usr/local/lib/honeyfleet/notifiers/dispatch.sh "测试标题" "测试正文"`。

## 6. 告警处理

| 告警 | 含义 | 处置 |
|---|---|---|
| 水位 disk | 根分区使用率 ≥ HF_WATERLINE_DISK% | 清理大文件/日志；核对轮转策略；长期逼近应扩容 |
| 水位 mem | 可用内存 < HF_WATERLINE_MEM% | 定位内存占用进程；关注是否触发 OOM；必要时调低常驻服务的内存上限 |
| 水位 swap | swap 使用率 > HF_WATERLINE_SWAP% | 与 mem 告警联动分析；小内存机器属常见现象，重点是增速 |
| 蜜罐告警/摘要中蜜罐封禁数 | 22 端口出现触碰并被封禁 | 例行安全事件；封禁由漏斗自动执行，无需人工干预；数量突增可结合封禁来源核对 |
| fleet agent stale | 某 agent 超过 10×推送间隔（默认 600 秒）未上报 | 按 8.2 排查推送链路；恢复后会自动收到 recovered 通告 |
| fleet agent recovered | 此前 stale 的 agent 恢复推送 | 无需处置；确认期间无变更即可 |
| honeyfleet fleet summary | 全队状态摘要（每 agent 一行） | 例行浏览；内容不变时按 1 小时心跳节流 |
| 文件完整性 drift | 受监控文件与基线不一致 | 逐项核实：本人变更 → `rebase` 接受；非本人变更 → 立即按安全事件处置 |

## 7. 卸载

```bash
sudo ./install.sh uninstall            # 全部模块
sudo ./install.sh uninstall --only 模块 # 单个模块
```

各模块卸载行为：

| 模块 | 卸载行为 |
|---|---|
| ssh-hardening | 删除托管 drop-in、移除白名单/迁移防火墙规则；sshd 回退到发行版默认配置并 reload；备份与运维说明保留 |
| firewall-baseline | 逐条移除带 honeyfleet 注释的规则；INPUT 默认策略若为 DROP 将**重置为 ACCEPT 并显式警告**（节点不再受基线保护）；重新持久化 rules.v4；f2b 链不受影响 |
| fail2ban-stack | 从备份恢复安装前的 jail 策略（无备份则删除受管文件）；删除蜜罐过滤器；封禁数据库保留供取证 |
| honeypot-ssh | 停止并禁用服务与健康探针；备份并删除配置、密钥、二进制与轮转配置；日志与健康状态保留；若 fail2ban 中 sshesame jail 仍在会给出提示（用 HF_SSH_HONEYPOT=false 重装 fail2ban-stack，或重装蜜罐） |
| file-integrity | 停止定时器、删除检查脚本与单元；状态 JSON 保留供取证 |
| waterline-alerts | 停止定时器、删除检查脚本与单元；状态与日志保留 |
| federation | 停止推送/扫描定时器并删除脚本与单元；全队数据目录与推送状态保留；通知通道库保留（其他模块可能仍在使用） |

如需彻底清除残留目录，在卸载后手工删除 `/etc/honeyfleet/`、`/usr/local/lib/honeyfleet/`、`/var/lib/honeyfleet/`、`/var/log/honeyfleet/`（取证需要时请先归档）。

## 8. 故障排查

### 8.1 「蜜罐防御行显示数据缺失」

**现象：** 中心节点全队摘要中，某 agent 的蜜罐字段显示"数据缺失"（无封禁数/来源数）。

**原因：** 该 agent 上不存在 sshesame jail——通常为该节点 `HF_SSH_HONEYPOT=false`，或 honeypot-ssh 模块未安装/服务未运行。

**处置：** 确认该节点预期是否启用蜜罐；预期启用则在该节点执行 `sudo ./install.sh install --only fail2ban-stack && sudo ./install.sh install --only honeypot-ssh`，并检查 `honeyfleet-sshesame.service` 状态；预期不启用则属正常显示，无需处理。

### 8.2 「fleet agent stale」

**现象：** 告警 `fleet agent stale: agent <主机名> has not pushed for Ns`。

**排查顺序：**

1. agent 上 `systemctl status honeyfleet-push.timer` 是否 active；`systemctl list-timers | grep push` 是否在正常调度；
2. 查看推送状态 `/var/lib/honeyfleet/fleet-push-state.json` 中的 last_push_rc / error / central_reply；
3. 手动推送一次并观察输出：`sudo /usr/local/lib/honeyfleet/fleet-push.sh`；
4. 检查 agent → 中心节点的 SSH 密钥授权是否仍然有效（authorized_keys 是否被改动）、HF_CENTRAL_HOST/PORT 是否正确、中心节点 SSH 服务是否可达；
5. 检查 agent 与中心节点的系统时间（快照时间戳超前 120 秒以上会被拒收，需校时）。

恢复推送后中心自动发送 `fleet agent recovered` 通告，无需手工清除状态。

### 8.3 全新安装报 "module 'notifiers' is required but not installed"

**原因：** waterline-alerts 与 federation 依赖通知通道库的注册标记；全新节点首次全量安装时该标记尚未生成。

**处置：** 先单独安装联邦模块（其会部署通知通道库并注册依赖），再全量安装：

```bash
sudo ./install.sh install --only federation
sudo ./install.sh install
```

（模块幂等，重复执行安全。）

### 8.4 verify 报 port-unresolved（HF_SSH_REAL_PORT=random:install-never-ran）

**原因：** 配置仍为 `random` 且安装尚未解析回写过具体端口。

**处置：** 执行 `sudo ./install.sh install`，安装器会随机选口并回写配置；回写失败（如配置文件不可写）会拒绝迁移而非静默继续。

### 8.5 连接 22 端口报 HOST KEY MISMATCH

**预期行为：** 蜜罐使用独立主机密钥。该警告即绊线信号——应答 22 端口的是蜜罐（或冒充者），不是真实 sshd。请使用真实端口连接；并按运维说明固定真实主机密钥指纹。

### 8.6 密码登录被拒绝

**预期行为：** ssh-hardening 已将 PasswordAuthentication 置为 no。请使用密钥登录。

### 8.7 安装/改口后连不上（疑似自锁)

**处置：** 按 `docs/hardening-guide.md` 第 1 节阶梯处理——不要断开当前会话；用第二终端实测；必要时经云商控制台按 `/etc/honeyfleet/README-ssh-hardening.txt` 的回滚配方，用 `/var/lib/honeyfleet/backups/` 中带时间戳的备份恢复。白名单场景下，60 秒看门狗会自动回滚，等待即可。

### 8.8 waterline verify 报 script-disk(x)!=config(y) 一类

**原因：** 修改了 HF_WATERLINE_* 阈值但未重新渲染部署脚本。

**处置：** `sudo ./install.sh install --only waterline-alerts` 重新渲染。

### 8.9 file-integrity verify FAIL（drift / tracked 与基线不一致）

**处置：** `sudo ./modules/file-integrity.sh status` 查看 drift_files；逐项核实变更来源；确认为本人有意变更后 `sudo ./modules/file-integrity.sh rebase`。verify 闸门同时核对 files_tracked 与基线键数一致——若二者不符，说明目标清单与基线不同步，重跑 `install --only file-integrity` 重建目标清单并 rebase。

### 8.10 蜜罐安装报 SHA256 mismatch

**原因：** 二进制钉死校验为 fail-closed 设计：钉死值记录的是受审生产构建的哈希，上游官方发布物因构建工具链不同不会匹配。

**处置：** 按报错提示三选一——①以钉死 tag 自行构建；②审查官方发布物后将审查过的 SHA256 写入 `HF_HP_SSHESAME_SHA256`；③在受审版本升级流程中更新模块常量。**不要**为图省事直接关闭该校验。

### 8.11 防火墙操作后 fail2ban 封禁"消失"

**原因：** 重放/重载防火墙持久化规则会连同 fail2ban 动态链一起清掉（封禁仍在数据库中）。

**处置：** 任何涉及 `iptables-restore`/`netfilter-persistent reload` 的操作后，执行 `sudo systemctl restart fail2ban` 重建动态链；封禁记录会从数据库恢复。honeyfleet 持久化的 rules.v4 已剥离 f2b 动态链，正常开机流程不受此影响。

### 8.12 蜜罐服务 active 但无连接记录

**原因：** 历史事故形态：accept 循环僵死（进程在、backlog 积压、零日志）。

**处置：** 健康探针（3 分钟周期）会检测"服务活跃但不可接受连接/无横幅"并自动重启（连续 2 次失败触发，900 秒冷却）；如需立即恢复可手工 `sudo systemctl restart honeyfleet-sshesame.service`，并检查 `/var/lib/honeyfleet/sshesame-health/state.json` 中的 last_restart 记录。

## 9. 已知边界

- 蜜罐 accept-all 行为可被坚定攻击者指纹探测；其价值在预警与封禁数据源，而非完美欺骗（详见 `docs/threat-model.md` §5.1）。
- root 沦陷后主机侧检测可被攻击者关闭；剩余信号在舰队层面（节点停推 → 中心 stale 告警），联邦设计假设中心与 agent 不同时沦陷（§3 信任边界、§5.2）。
- firewall-baseline 仅管理 IPv4；IPv6 需另行评估与处理（§5.4）。
- 内存紧张时系统按"自愈最快的组件优先献祭"设计（蜜罐 Restart=always + 探针自愈，§5.3）。

## 10. 技术支持与许可

- 文档：`README.md` / `README.zh-CN.md` / `docs/`（威胁模型、设计论证、防自锁手册、模块契约）。
- 漏洞报告：见 `SECURITY.md`（勿以公开 issue 提交安全漏洞）。
- 许可：GPL-3.0；本软件按现状提供，不附带任何明示或默示担保（详见 LICENSE）。
