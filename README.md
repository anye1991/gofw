# 🛡️ gofw · 纯 Go 网络层防火墙

<p align="center">
  <img src="https://img.shields.io/badge/Go-1.23%2B-00ADD8?logo=go&logoColor=white" alt="Go">
  <img src="https://img.shields.io/badge/CGO-0-success" alt="CGO disabled">
  <img src="https://img.shields.io/badge/打包-单二进制-blueviolet" alt="single binary">
  <img src="https://img.shields.io/badge/Python-0-orange" alt="no python">
  <img src="https://img.shields.io/badge/GeoIP-1411297%20CIDR-informational" alt="GeoIP">
  <img src="https://img.shields.io/badge/Platform-Linux-2ea44f?logo=linux&logoColor=white" alt="Platform">
  <img src="https://img.shields.io/badge/License-MIT-blue" alt="License">
</p>

> **一个二进制 = 引擎 + 规则 + Web 管理界面 + 图标**。纯 Go 实现，`CGO_ENABLED=0`，运行时零 Python、零外部依赖（仅 `gopkg.in/yaml.v3`）。
> 支持两种执行后端：**用户态监控（monitor）** 与 **内核 nftables 真实丢包**。启动时由 `--monitor` 决定，运行中可在「系统增强」页一键切换（带护栏自检 + 30 秒自动回滚），无需改 systemd 或重启。

> 📌 **当前线上快照（2026-11-06 实测，对应提交 `a6c13be`）**
> `http://192.168.58.128:18081/` · systemd 托管开机自启 · **monitor 模式** · 规则 27 条 · 地理围栏未启用
> GeoIP 库 **1,411,297** 条（IPv4 597,286 / IPv6 814,011，250 个国家/地区，外部 DBIP CSV）
> 本地与线上二进制哈希一致，页面 / favicon 200，常驻内存约 330–410 MB，负载正常。
> ⚠️ **这一版跑的是监控挡位：只记录、统计、决策，不真实丢包。** 真实内核拦截的代码已就绪但未启用，见 [能力挡位](#-能力挡位速览)。

---

## 📑 目录

- [🎚️ 能力挡位速览](#-能力挡位速览)
- [🚦 两种运行挡位：monitor vs kernel](#-两种运行挡位monitor-vs-kernel)
- [✨ 功能清单](#-功能清单)
- [🏗️ 架构](#️-架构)
- [🌍 GeoIP 与地理围栏](#-geoip-与地理围栏)
- [🧑‍💻 小白四步：按国家放行 / 断网](#-小白四步按国家放行--断网)
- [🖥️ Web 管理界面与 API](#️-web-管理界面与-api)
- [📦 当前部署与回滚](#-当前部署与回滚)
- [🔧 构建、运行与参数](#-构建运行与参数)
- [✅ 验证与测试](#-验证与测试)
- [⚠️ 已知边界与未做事项](#️-已知边界与未做事项)
- [📚 文档索引](#-文档索引)
- [📄 许可证与数据来源](#-许可证与数据来源)

---

## 🎚️ 能力挡位速览

用户最关心的一句话：**现在到底有哪些功能，各做到什么程度？** 下面按真实代码与线上实测逐项标注，不夸大、不把"代码里有"写成"已经生效"。

**挡位定义**

| 挡位 | 含义 |
| :--- | :--- |
| 🟢 **L3 生产可用** | 已在 128 上稳定运行，页面 / API / 日志可验证 |
| 🟡 **L2 监控试跑** | 逻辑全跑（决策、统计、规则生成），但当前 `--monitor` 下不真实丢包 |
| 🔵 **L1 运行时可切换** | 代码 + 测试 + 语法校验完成，页面一键启用，默认未长期开启、需二次确认 |
| ⚪ **L0 未实现** | 明确没做，不臆造 |

| 能力 | 挡位 | 实现位置 / 验证方式 | 线上状态 |
| :--- | :---: | :--- | :--- |
| 多维规则匹配（IP/MAC/端口/协议/TCP flags/VLAN/时间段/方向/状态） | 🟢 L3 | `rules/`、`engine/`；Web 规则页 27 条 | 生效（用户态决策） |
| DPI 应用层协议识别（HTTP / TLS / SSH / DNS / MySQL / FTP / SMTP 等） | 🟢 L3 | `dpi/`；能力中心显示已加载 | 生效（用户态识别） |
| 连接跟踪、TCP 状态机、IP 分片重组 | 🟢 L3 | `engine/`；连接跟踪页 | 生效 |
| AF_PACKET 抓包、网关模式 | 🟢 L3 | `capture/`、`--gateway` | 可用，未开启网关模式 |
| 限速 / 带宽 / 并发连接限制、NAT、VRRP 高可用 | 🟢 L3 | `enforce/`、`ha/`；单元测试 + 目标机 `nft -c -f` 全量校验 | 规则在线上 27 条里已配置；monitor 下只在用户态决策，切 kernel 后由 nft meter / `ct count` 下发 |
| Web 管理界面（9 个页面）+ 盾牌 favicon + 能力中心 | 🟢 L3 | `webui/`，`//go:embed` 编入二进制 | 200 可访问，能力中心有真实数据 |
| 规则 / 地址簿增删改 + YAML 持久化 + 注释保留 | 🟢 L3 | `webui/webui.go`、`config/comments.go` | 生效，注释锚点迁移已测 |
| 告警（Webhook / SMTP） | 🟢 L3 | `alert/`；`--alert /opt/gofw/alert.yaml` | 已配置 |
| **全球 GeoIP 库**（141 万 CIDR、v4 + v6、250 国家/地区） | 🟢 L3 | `geoip/`；流式加载 + 最长前缀二分索引 | `/api/geofence` 返回 `loaded:true` |
| GeoIP 定时热加载 + 手动重载 + 统计缓存 | 🟢 L3 | `--geoip-reload-interval 60`、`/api/geoip/reload` | 生效，内存无增长 |
| 来源国实时排行、决策统计、拦截流 | 🟡 L2 | `geoctl/tracker.go`、`/api/geoip/stats` | 数据真实，但"丢弃"=引擎判定，非内核真丢 |
| 阈值自动封禁、手动封禁 / 解封、安全网段豁免 | 🟡 L2 | `geoctl/`、`/api/bans` | 判定生效；管理机 / 回环 / LAN 三层豁免已实测 |
| 一键地理围栏（黑名单 / 白名单 / 端口 / 清空） | 🟡 L2 | `webui/geofence.go`，护栏强制前置 | 规则可生成、顺序可核对、可一键清空；**未真实断网** |
| 中文国家选择 + 基于真实流量的策略预演 | 🟢 L3 | `webui/index.html`（`Intl.DisplayNames` + 来源国统计） | 页面可用，Ctrl+F5 后可见 |
| **运行时后端切换**（monitor ↔ nftables kernel） | 🟢 L3 | `enforce/switchable.go`；页面「系统增强」→ 装护栏 → 预检 → 切换 | 一键可用；切 kernel 需二次确认，切换后 30 秒未确认自动回滚 |
| **nftables 内核真实丢包**（`table inet gofw`） | 🔵 L1 | `enforce/`；全量规则集 `nft -c -f` 语法校验通过（nft v1.0.2，31 条含护栏）、护栏顺序测试通过 | 能力已可启用，线上默认仍 monitor，需人工确认后切 |
| GeoIP v4/v6 命名集合 + 动态封禁集下发内核 | 🔵 L1 | `enforce/enforce.go`（`ip6 saddr`、`gofw_ban_v6`） | 随 kernel 切换自动下发 |
| 地理围栏真实封锁（国家级断网） | 🔵 L1 | 切换到 kernel 后围栏规则真实 DROP | 可启用，未长期开启 |
| 仅安装护栏预设（不生成 DROP） | 🟢 L3 | `POST /api/geofence/apply` 的 `preset=guard` | 幂等，4 条 ACCEPT 置顶，单测覆盖 |
| **审计日志留存**（JSONL 轮转 + 查询） | 🟢 L3 | `audit/`；8 MiB × 5 份，只记管理动作 | 启用，记录规则/围栏/封禁/登录/后端切换/策略导入 |
| **Web 登录保护**（页面启用 / 修改 / 停用，密码落盘 0600） | 🟢 L3 | `webui/extensions.go`；启用时自动建立当前会话 | 可一键启用，默认关闭（不擅自锁死） |
| **城市 / ASN 级策略**（`geo_city` / `geo_asn` 规则字段） | 🟢 L3 | `rules/`、`config/`、`engine/`；`LookupFull` | 字段可用；当前库为国家/地区级，无扩展列时不会误命中 |
| **多机策略同步**（HMAC-SHA256 签名导出 / 导入） | 🟢 L3 | `webui/extensions.go`；`--sync-secret` | 签名不符一律拒绝，需两端同密钥 |
| eBPF / XDP 线速数据面 | ⚪ L0 | — | **明确不做**，见下方「已知边界」说明 |

> 一句话总结当前级别：**L3「看得清、配得动、数据真实、可追溯、可集群同步」+ L2「决策与围栏全程试跑」+ L1「真丢包一键可切、带自动回滚」**。
> 仍刻意保留 monitor 为默认挡：内网低配 VM 上先试跑、看清影响，再切内核；但切换本身已经不再需要改配置或重启。

---

## 🚦 两种运行挡位：monitor vs kernel

| 对比项 | 🟡 monitor（**当前线上默认**） | 🟢 nftables kernel（页面一键切换） |
| :--- | :--- | :--- |
| 抓包 / 规则匹配 / 决策 | ✅ 全跑 | ✅ 全跑 |
| 统计、日志、来源国排行、拦截流 | ✅ 真实 | ✅ 真实 |
| 地理围栏规则生成、护栏、清空 | ✅ 可用 | ✅ 可用 |
| 是否真的丢包 | ❌ **不丢包，流量照常通过** | ✅ 内核 `table inet gofw` 真实 DROP |
| 自动封禁是否生效 | 记录判定、写入封禁表 | 额外下发 `@gofw_ban_v4/v6` 集合 |
| Web 顶部横幅 | 黄色「旁路监控模式」 | 绿色「内核生效模式（nftables）」 |
| 风险 | 无锁死风险 | 护栏缺失会锁死 SSH / Web；切换前强制预检，切换后 30 秒自动回滚兜底 |

> 页面横幅由 `/api/system` 的 `backend` 字段驱动，**取运行时真实后端**（`Switchable.Mode()`），不会把监控冒充成内核模式。切换入口在「系统增强」页：① 仅安装护栏 → ② 预检（nft 命令 / CAP_NET_ADMIN 权限 / `nft -c -f` 语法 / 护栏数量与顺序）→ ③ 二次确认切换 → ④ 验证 SSH 与面板可达后点「确认保留」。未确认则自动切回 monitor 并清空内核表。

---

## ✨ 功能清单

| 模块 | 能力 | 说明 |
| :--- | :--- | :--- |
| `rules/` `engine/` | 规则引擎 | `accept / drop / reject / log`，多字段组合匹配，连接状态与时间段的匹配，方向规则已修复（用户态不再跳过 `direction:in/out`） |
| `dpi/` | 深度包检测 | HTTP / TLS / SSH / DNS / MySQL / FTP / SMTP 等协议识别 |
| `capture/` | 抓包 | `AF_PACKET` raw socket，单网卡 / 多网卡，混杂模式 |
| `geoip/` | GeoIP | 流式 CSV 加载、原子替换、v4/v6 分族最长前缀索引、国家/统计预计算、城市与 ASN 扩展列可选、`LookupFull` |
| `geoctl/` | 地理围栏控制 | 来源国计数、阈值封禁、手动封禁、版本变化触发重下发、三层安全网段豁免 |
| `enforce/` | 双后端 | `MonitorEnforcer`（只记录）与 `NftablesEnforcer`（编译 limit / ct count / meter / TCP flags / GeoIP set / ban set） |
| `webui/` | Web 管理 | 单页应用 + REST API，`//go:embed index.html` 与 `favicon.ico` 编入二进制 |
| `config/` | 配置 | YAML 读写、注释锚点迁移（Save 不再抹掉手工分段注释）、并发安全 |
| `audit/` | 审计日志 | 纯标准库 JSONL 轮转（8 MiB × 5），只记管理动作，不随包量增长 |
| `enforce/switchable.go` | 运行时后端切换 | atomic 指针热路径无锁；预检 → 清旧表 → 下发 → 原子替换；失败保持原后端 |
| `alert/` `ha/` | 告警 / 高可用 | Webhook（generic/slack/dingtalk）与 SMTP；VRRPv2 主备选举与 VIP 漂移，无权限回退 TCP 探测 |

---

## 🏗️ 架构

```mermaid
flowchart TB
    P[入站 / 出站 / 转发流量] --> C[capture: AF_PACKET 抓包]
    C --> E[engine: 规则匹配 · DPI · 连接跟踪]
    E --> G[geoctl: 来源国统计 · 封禁判定]
    G --> B{执行后端 BuildEnforcer}
    B -->|--monitor 当前| M[MonitorEnforcer<br/>只记录 / 统计 / 决策<br/>不真实丢包]
    B -->|运行时切换（护栏自检+自动回滚）| N[NftablesEnforcer<br/>table inet gofw<br/>真实 DROP]
    N --> K[(Linux 内核 nftables<br/>@geoip_XX · @gofw_ban_v4/v6)]
    D[(GeoIP CSV<br/>1,411,297 CIDR)] -->|流式加载 + 热更新| E
    D -->|国家集合| N
    W[Web UI :18081<br/>8 个页面 · 能力中心 · 地理围栏] -->|REST API| CF[(rules.yaml)]
    CF -->|热应用| B
    W -->|状态 / 统计 / 封禁| G
```

- **控制面**：Web 改规则 → `config` 持久化 → `apply` 互斥锁串行化 → 后端重编译；库文件 mtime 变化触发版本变化重下发。
- **数据面**：monitor 下走用户态决策；kernel 下由 nftables 集合匹配真实丢包。
- **运维面**：全部逻辑在一个 Go 进程里，`systemd` 托管，**没有 Python 助手、没有代理脚本**。

---

## 🌍 GeoIP 与地理围栏

### 真实库，不再是"代表性网段"

旧文档写的是内置 16 国 / 1589 条精简库，那已经过时。当前线上加载的是**外部 DBIP Country Lite 全量库**（`rules.yaml.geoip`）：

| 指标 | 数值 |
| :--- | ---: |
| 总 CIDR | **1,411,297** |
| IPv4 段 | 597,286 |
| IPv6 段 | **814,011** |
| 国家 / 地区 | 250 |
| 加载方式 | 流式 `csv.Reader` + 原子替换，启动约几十秒 |
| 查询 | 按 v4/v6 + 前缀长度分族二分，**最长前缀匹配** |
| 热加载 | `--geoip-reload-interval 60`（mtime 检测）+ `POST /api/geoip/reload` |

IPv6 段由起止区间拆分为最少 CIDR 并做同国相邻合并，抽样 244 万点校验零失配。数据来源 **DBIP / CC BY 4.0**，精度为国家/地区级，不能当司法级归属证据；库文件旁的 `rules.yaml.geoip.LICENSE` 记录署名与限制。

### 一键地理围栏

| 预设 | 语义 | 典型用途 |
| :--- | :--- | :--- |
| `blacklist` | 只拦选中国家，其它照常 | 阻断某国访问 |
| `whitelist` | 只放选中国家，其余全断 | 国家级地理围栏 / 仅本国访问 |
| `ports` | 只在指定端口上限制 | 只保护 SSH / RDP |
| `clear` | 只删 `[gofw-*]` 托管规则 | 一键回到原规则集 |

**防锁死护栏（不可关闭，强制置顶）**：已建立连接、loopback、管理端口 `22,888,18706,18081`、LAN 网段。规则顺序固定为 `护栏 → 围栏 → 保留的业务规则`，避免业务里的 `accept 80,443` 抢先命中；清空操作只移除托管标记规则，不碰手工规则。顺序由 `webui/geofence_test.go` 锁定。

---

## 🧑‍💻 小白四步：按国家放行 / 断网

1. **选国家**：进「地理围栏」页，从中文下拉里选（中国 / 美国 / 俄罗斯…），或点常用国家按钮，不用记 `RU` / `US`。下拉里每个国家都标了网段数。
2. **看预演**：页面用本次启动以来的**真实来源国流量**算出：选中这些国家有多少包、其它来源有多少包，并写明黑名单拦谁、白名单拦谁。
3. **应用**：点「禁止这些国家访问」或「只允许这些国家访问」，规则列表里可逐条核对护栏是否排在最前；不满意点「清空，恢复原状」。
4. **真正断网**：进「系统增强」页 → ① 仅安装护栏 → ② 预检 → ③ 切到内核真实拦截（二次确认）→ 验证 SSH / 面板可达后点「确认保留」。横幅由黄变绿，此时规则才会真实丢包；30 秒内没确认会自动回滚，不会把自己锁在外面。

> 前三步在 monitor 下就能做、能看到结果；第 4 步是唯一会改变真实流量的动作，**必须先确认护栏放行了管理通道与内网**，否则可能把自己锁在服务器外面。

---

## 🖥️ Web 管理界面与 API

**页面**：概览、规则管理、地址簿、实时拦截、连接跟踪、能力中心、地理围栏、配置源、**系统增强（后端切换 / 登录保护 / 审计 / 精度 / 策略同步）**。盾牌 favicon 与页面一起 `//go:embed` 编入二进制，无外部静态文件。

全局挡位条常驻所有页面：monitor 黄色（只记录不丢包）、kernel 绿色（真实生效），避免把「拦截数」误读成实际丢包；概览卡片、图表与来源国排行统一使用「判定拦截」措辞。

| Method | Path | 说明 |
| :--- | :--- | :--- |
| GET | `/api/stats` `/api/events` | 实时统计 / 事件流 |
| GET/POST | `/api/rules`、`/api/rules/{index}` | 规则增删改查 |
| GET/POST | `/api/ipgroups`、`/api/ipgroups/{name}` | 地址簿 |
| GET | `/api/conns` `/api/config` `/api/system` | 连接表 / 配置 / 能力中心 |
| POST | `/api/reload` | 热重载规则 |
| GET | `/api/geofence` | 库统计、v4/v6、护栏与围栏规则、`mode` |
| POST | `/api/geofence/apply` | 应用黑名单 / 白名单 / 端口预设 |
| POST | `/api/geofence/clear` | 清空托管规则 |
| GET | `/api/geoip/countries` `/api/geoip/stats` | 国家列表 / 来源国排行与封禁配置 |
| POST | `/api/geoip/reload` | 手动热加载 GeoIP 库 |
| GET/POST/DELETE | `/api/bans`、`/api/bans/{ip}` | 封禁列表 / 手动封禁 / 解封 |
| GET | `/api/backend` | 运行时后端、护栏数、自动回滚剩余秒数 |
| POST | `/api/backend/preflight` `/switch` `/confirm` `/rollback` | 切换前预检 / 二次确认切换 / 确认保留 / 立即回滚 |
| GET | `/api/audit?limit=&kind=` | 审计日志查询（倒序、类型过滤） |
| GET/POST | `/api/auth` | 登录保护状态 / 启用、改密、停用 |
| GET/POST | `/api/sync` | HMAC-SHA256 签名策略包导出 / 导入并热应用 |
| GET | `/api/geoip/meta` `/api/geoip/lookup?ip=` | 库精度（国家 / 城市 / ASN）与单 IP 归属查询 |
| GET | `/favicon.ico` | 内嵌盾牌图标 |

> 未设置密码时 API 放行；设置密码后 `/api/*` 走会话 cookie 校验。能力中心上排全部取自 `/api/system` 运行实例真实字段（`backend`、`geofence`、`autoban`、GeoIP v4/v6/国家数、DPI 协议、连接跟踪、引擎统计），其中「执行后端」卡片直接标明是否真实丢包；下排为按当前规则集字段推导的防护能力，并标注「不等于内核已生效」。不用占位假数据。

---

## 📦 当前部署与回滚

```ini
# /etc/systemd/system/gofw.service（线上 ExecStart，保持 monitor）
ExecStart=/opt/gofw/gofw start -r /opt/gofw/rules.yaml -i ens32 --web :18081 --monitor \
  --stats-interval 15 --log-file /opt/gofw/gofw.log --alert /opt/gofw/alert.yaml \
  --geoip-reload-interval 60 --auto-ban --ban-threshold 30 --ban-window 10 --ban-ttl 300 \
  --ban-safe-cidr 192.168.58.0/24,127.0.0.0/8,10.0.0.0/8
```

- 访问：`http://192.168.58.128:18081/`（**不是 80 / 8981 / 8080**）。
- 产物：`GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o gofw.linux .`，单文件约 11 MB，scp 覆盖 `/opt/gofw/gofw` 后重启即可。
- 备份：`gofw.bak.*`、`gofw.service.bak.*`、`rules.yaml.geoip.bak.*`；规则文件 `rules.yaml` 保持原始 27 条。
- 回滚：代码回退到 `dba12b2`（本次增强前），或用备份二进制替换后 `systemctl restart gofw`。

---

## 🔧 构建、运行与参数

```bash
# Linux 目标（推荐，仓库内 capture/ha 含 Linux 专用 syscall）
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 GOFLAGS=-mod=mod go build -o gofw.linux .

# 启动：监控挡位（当前线上）
sudo ./gofw.linux start -r rules.yaml -i ens32 --web :18081 --monitor

# 启动：内核真实拦截（需先确认护栏）
sudo ./gofw.linux start -r rules.yaml -i ens32 --web :18081
```

| 参数 | 默认 | 说明 |
| :--- | :--- | :--- |
| `-r, --rules` | 必填 | 规则文件 |
| `-i, --interface` | `eth0` | 监听网卡 |
| `--monitor` | `false` | **只记录决策 / 统计 / 日志，不真实丢包** |
| `--web` | — | Web 监听地址，如 `:18081` |
| `--workers` | CPU 核数 | 工作线程数 |
| `--stats-interval` | `0` | 统计输出间隔（秒） |
| `--ctl-sock` | `/tmp/gofw.sock` | 控制套接字 |
| `--gateway` | `false` | 网关模式（IP 转发 + 多网卡抓包） |
| `--ha` / `--alert` / `--log-file` | — | 高可用配置 / 告警配置 / 日志文件 |
| `--geoip-reload-interval` | `0`（关闭） | GeoIP 库 mtime 热加载检查间隔（秒） |
| `--auto-ban` | `false` | 启用阈值自动封禁 |
| `--ban-threshold` | `20` | 窗口内 DROP 次数阈值 |
| `--ban-window` | `10` | 统计窗口（秒） |
| `--ban-ttl` | `300` | 封禁时长（秒） |
| `--ban-safe-cidr` | 空 | 永不封禁的额外网段（逗号分隔） |
| `--audit-file` | `rules.yaml.audit.jsonl` | 审计日志文件（8 MiB × 5 轮转） |
| `--web-auth-file` | `rules.yaml.webauth` | Web 登录密码持久化文件（0600） |
| `--sync-secret` | 空（`GOFW_SYNC_SECRET`） | 多机策略同步 HMAC 密钥，空则导入禁用 |

子命令：`start`、`rules list|stats|add|del`、`conns list`、`reload`、`test`（详见 `main.go`）。

---

## ✅ 验证与测试

```bash
# Linux 全量编译（Windows 本机请带 GOOS=linux，capture/ha 是 Linux 专用代码）
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build ./...

# 本次增强相关包测试（跨平台可跑）
go test ./config ./enforce ./engine ./geoctl ./geoip ./webui

# 页面 JS 语法（抽取 <script> 内容后校验，临时文件随即删除）
node -e "const fs=require('fs');const h=fs.readFileSync('webui/index.html','utf8');const m=[...h.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)];fs.writeFileSync('ui-check.js',m.map(x=>x[1]).join('\n'))" && node --check ui-check.js && rm ui-check.js
```

回归测试覆盖：注释锚点迁移、GeoIP 最长前缀 / v4 / v6 / 热加载、自动封禁安全网段豁免、围栏规则顺序、nftables IPv6 集合、城市/ASN 匹配、审计轮转、护栏预设、meter 语法（唯一集合名 + `drop` 在花括号外）。线上已验证：白名单 CN 生成 32 条规则且护栏置顶、Web/SSH 可达，`clear` 回 27 条无残留、4 段手工注释仍在，手动热加载与公网 IP 封禁/解封正常，装护栏后全量规则集 `nft -c -f` 预检通过（nft v1.0.2）。

---

## ⚠️ 已知边界与未做事项

- **当前线上默认仍是 monitor**：页面上的"丢弃 / 拦截"是引擎决策计数，**不等于内核真丢包**。切换能力已完全可用（页面一键、护栏预检、30 秒自动回滚），但真实下发到生产流量仍需人工确认后执行；未做「线上长期开启 kernel」的实证。
- **GeoIP 精度**：线上库为国家/地区级，存在 `??`（无归属，含内网）与边界误差；IPv6 由区间拆分合并而来，非运营商原始宣告。`geo_city` / `geo_asn` 规则字段已可用，但只有导入 `CIDR,country,city,asn` 三/四列库才会命中，两列库下不误命中。
- **城市 / ASN 规则与内核**：nftables 无法表达城市/ASN 匹配，带这两个条件的规则整条跳过内核下发，只在用户态决策层生效（避免退化成裸 drop 误伤全网）。
- **per-src 并发连接限制在内核侧降级**：目标机 nftables v1.0.2 内核不支持动态集 / meter 与 `ct count over N` 组合（`nft -c -f` 报 `Operation not supported`）。因此 `per_src: true` 的并发连接限制下发内核时降级为**全局** `ct state new ct count over N drop`，预检结果会以 `!` 明确列出，不会把「每源 N」悄悄冒充成原语义。速率 / 带宽限制的 per-src 仍由 nft meter 动态集实现真实的每源独立计数；meter 语法（必须带集合名、`drop` 必须在花括号外）已在目标机实测并全量校验通过。
- **DPI 在用户态**：用于识别与统计，不是内核线速过滤。
- **Web 认证默认关闭**：可一键启用并持久化，但不会擅自强制开启——否则现有自动化脚本与未登录页面会被立刻挡住。
- **eBPF / XDP 明确不做**：本项目硬约束是纯 Go、零 CGO、仅 `yaml.v3` 依赖、单二进制、`AF_PACKET` 用户态抓包。XDP 需要 `github.com/cilium/ebpf` 依赖、内核 BTF、clang 生成的 BPF 字节码或特权加载器，等于重写整个数据面，也会破坏低配 VM 上「一个二进制跑起来」的前提。这不是遗漏，是不在架构目标内；真要线速过滤的正确路径是直接用 nftables 内核后端（已具备）。

---

## 📚 文档索引

- [功能说明（docs/FEATURES.md）](docs/FEATURES.md) — GeoIP 库、Web API、地理围栏、自动封禁、VRRP 细节
- [部署与运维（deploy/README.md）](deploy/README.md) — systemd、严格模式、真下发流程（注意线上目前是 monitor）

---

## 📄 许可证与数据来源

- 代码：**MIT**，见 [LICENSE](LICENSE)。
- GeoIP 数据：DBIP Country Lite，**CC BY 4.0**，需保留署名；国家/地区级精度，详见库文件旁 `rules.yaml.geoip.LICENSE`。

---

## 👤 作者

- **署名**：暗夜铭少 · **邮箱**：azgq@foxmail.com
- 仓库：https://gitee.com/nights-shadow/gofw.git

欢迎提交 Issue 和 Pull Request。
