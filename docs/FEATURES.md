# 🧩 gofw 功能说明文档

> 更新至 **2026-11-06**（提交 `a6c13be`）。本文按**真实代码 + 线上实测**描述，不把"代码已就绪"写成"已生效"。
> 当前线上默认挡位为 **monitor（旁路监控）**：决策、统计、规则生成全部在跑，但**不真实丢包**。真实内核拦截现在可在 Web「系统增强」页运行时一键切换（装护栏 → 预检 → 二次确认 → 30 秒自动回滚保护），无需改 systemd 或重启；启动时仍可用 `--monitor` 指定初始后端。完整挡位矩阵见 [README 能力挡位速览](../README.md#-能力挡位速览)。

---

## 📑 目录

- [一、GeoIP 国家库](#一geoip-国家库)
- [二、一键地理围栏](#二一键地理围栏)
- [三、来源国统计与自动封禁](#三来源国统计与自动封禁)
- [四、Web UI 规则增删改 API](#四web-ui-规则增删改-api)
- [五、地理围栏 / GeoIP / 封禁 API](#五地理围栏--geoip--封禁-api)
- [六、HA 高可用（VRRPv2）](#六ha-高可用vrrpv2)
- [七、配置注释保留](#七配置注释保留)

---

## 一、GeoIP 国家库

### 📌 现状

旧版本文档描述的"内置 16 国 / 1589 条代表性网段"**只是无外部文件时的兜底**。当前生产部署加载的是**外部全量库**，数字来自线上 `/api/geofence` 实测：

| 指标 | 数值 |
| :--- | ---: |
| 总 CIDR | **1,411,297** |
| IPv4 段 | 597,286 |
| IPv6 段 | **814,011** |
| 国家 / 地区 | 250 |
| 库文件 | `/opt/gofw/rules.yaml.geoip`（`CIDR,国家码`，可选城市 / ASN 扩展列） |
| 数据来源 | DBIP Country Lite，**CC BY 4.0**（需署名，国家/地区级精度） |

加载优先级：**外部 CSV → 代码内置精简库兜底**。内置库覆盖有限，仅用于没有外部文件时的开箱即用，不能当全球库使用。

### ⚙️ 实现要点

- **流式加载**：`csv.Reader.Read()` 逐行解析，避免一次性把 140 万行读进内存；解析完成后 `db.loadEntries()` 原子替换，热加载期间查询不中断。
- **最长前缀索引**：按 `IPv4 / IPv6` 分族 + 前缀长度建索引，`lookupEntry()` 二分查找最长匹配前缀，取代旧版线性扫描。
- **预计算缓存**：国家列表与统计在加载时算好，`Stats()` / `Countries()` 不再遍历全库。
- **IPv6**：由 DBIP 起止区间拆成最少 CIDR、同国相邻合并；抽样 244 万点校验零失配。
- **热加载**：`--geoip-reload-interval 60` 按 mtime 检测变化；也可 `POST /api/geoip/reload` 手动触发；库版本变化会触发 enforcer 重下发。
- **扩展列**：CSV 可选城市 / ASN 列，通过 `LookupFull` 返回完整元数据。

### 🧱 规则中使用

```yaml
# 默认 deny 语义：放行俄罗斯、阻断其余
- action: drop
  geoip: RU
  direction: in

# allow 语义：阻断中国、放行其余
- action: drop
  geoip: allow:CN
  direction: in
```

内核后端会把每个引用的国家码编译成命名集合 `@geoip_XX`（v4 用 `ipv4_addr`、v6 用 `ipv6_addr`），入站/转发按源地址、出站按目标地址匹配。**库里没有任何网段的国家码会被跳过并告警**，避免空集合导致误杀全网。

> ⚠️ 语义提醒：`geoip: RU` 是"**放行**俄罗斯、阻断其余"，不是"阻断俄罗斯"。要按国家断网，请用下一节的地理围栏预设，语义更直白。

---

## 二、一键地理围栏

面向不熟悉国家码与 nftables 的使用者，把"按国家放行 / 断网"做成四步：`选国家 → 看预演 → 应用 → 切内核`。

### 🎯 预设（`POST /api/geofence/apply`）

| preset | 语义 | 生成规则标记 |
| :--- | :--- | :--- |
| `blacklist` | 只拦选中国家，其它照常 | `[gofw-geo] blacklist RU,US` |
| `whitelist` | 只放选中国家，其余全断 | `[gofw-geo] whitelist only CN` |
| `ports` | 仅在指定目的端口上限制 | `[gofw-geo] ports ...` |
| `clear` | 清空全部托管规则 | 只删 `[gofw-guard]` / `[gofw-geo]` |

### 🛡️ 防锁死护栏（不可关闭）

固定 4 条 ACCEPT，标记 `[gofw-guard]`：

1. 已建立连接（`established`）
2. loopback
3. 管理端口 `22,888,18706,18081`
4. LAN 网段（默认 `192.168.58.0/24`，前端可覆盖）

### 📐 规则顺序

强制 `护栏 → 围栏 → 保留的业务规则`。业务规则里若有 `accept 80,443` 之类，会被排到围栏之后，否则白名单/黑名单会被抢先命中而失效。顺序由 `webui/geofence_test.go` 锁定；`clear` 只移除托管标记规则，手工规则一条不动。

### 🧑‍💻 页面辅助

- **中文国家选择**：`Intl.DisplayNames('zh-CN')` 生成 250 个国家中文名下拉，附该国网段数；常用国家一键加/删，不用记代码。
- **策略预演**：用 `/api/geoip/stats` 的真实来源国流量，算出"选中这些国家 X 个包 / 其它来源 Y 个包"，并写明黑名单拦谁、白名单拦谁。
- **真实后端标识**：黄色横幅 = monitor（预演），绿色横幅 = nftables（真实生效），由 `/api/geofence` 的 `mode` 驱动，不冒充。

> 线上实测：白名单 CN 生成 32 条规则、护栏置顶、Web/SSH 仍可达；`clear` 后回到 27 条原始规则、无托管残留。`nft -c -f` 语法校验通过。**真实内核封锁未启用**（当前 monitor）。

---

## 三、来源国统计与自动封禁

`geoctl.Tracker` 在 `engine.Decide` 的决策前检查封禁、决策后累计观察：

- **来源国排行**：按包量 / 判定丢弃数统计，`??` 表示库中无归属（含内网）。
- **自动封禁**：窗口内连续丢弃超阈值即临时封禁，参数 `--auto-ban --ban-threshold 30 --ban-window 10 --ban-ttl 300`。
- **手动封禁 / 解封**：`/api/bans` 增删，带原因与到期时间。
- **三层豁免**：回环、`--ban-safe-cidr` 指定网段、管理机网段在 `BanManual / IsBanned / ActiveBansSplit` 三处都过滤，**管理机与内网不会被封**。已实测 `192.168.58.1` 返回 400 拒绝、公网 `203.0.113.9` 正常封禁与解封。
- **内核联动**：切到 nftables 后端时，活跃封禁会下发到 `@gofw_ban_v4` / `@gofw_ban_v6` 动态集合（当前 monitor 下只记录判定）。

---

## 四、Web UI 规则增删改 API

| Method | Path | 功能 |
| :--- | :--- | :--- |
| GET | `/api/rules` | 列出全部规则 |
| POST | `/api/rules` | 新增规则 |
| PUT | `/api/rules/{index}` | 替换指定索引规则 |
| DELETE | `/api/rules/{index}` | 删除指定索引规则 |

写操作经互斥锁串行化，自动持久化到 YAML 并热应用；索引边界检查在锁内执行，消除 TOCTOU 竞态。支持字段：`action`、`src_ip`、`dst_ip`、`src_mac`、`dst_mac`、`protocol`、`src_port`、`dst_port`、`tcp_flags`、`direction`、`state`、`vlan`、`time`、`rate_limit`、`burst`、`per_src`、`bandwidth`、`burst_bytes`、`conn_limit`、`geoip`、`app_proto`、`ip_group`、`nat`、`comment`、`name`。

错误码：`400` 参数/索引非法、`404` 索引越界、`500` 持久化失败。

---

## 五、地理围栏 / GeoIP / 封禁 API

| Method | Path | 说明 |
| :--- | :--- | :--- |
| GET | `/api/geofence` | 库统计（count / v4 / v6 / countries / loaded / path / source）、护栏与围栏规则、`mode` |
| POST | `/api/geofence/apply` | `{preset, countries:[], ports, guard:{mgmt_ports, lan_cidr}}` |
| POST | `/api/geofence/clear` | 清空托管规则，返回剩余规则数 |
| GET | `/api/geoip/countries` | 250 个国家/地区及各自 CIDR 数 |
| GET | `/api/geoip/stats` | 来源国排行、封禁列表、自动封禁配置 |
| POST | `/api/geoip/reload` | 手动热加载，返回新条目数 |
| GET | `/api/bans` | 活跃封禁列表 |
| POST | `/api/bans` | `{action:"add"|"unban"|"config", ip, ...}` |
| DELETE | `/api/bans/{ip}` | 解封 |
| GET | `/favicon.ico` | 内嵌盾牌图标 |

`/api/geofence` 返回示例（节选）：

```json
{
  "active": false,
  "mode": "monitor",
  "db": { "count": 1411297, "v4": 597286, "v6": 814011, "loaded": true,
          "path": "/opt/gofw/rules.yaml.geoip", "source": "external" },
  "guards": null,
  "fences": null
}
```

---

## 六、HA 高可用（VRRPv2）

VRRPv2（RFC 3768）组播通告实现主备选举，兼容标准 VRRP；无 `CAP_NET_RAW` 权限时自动回退 TCP 探测。

| 参数 | 值 |
| :--- | :--- |
| IP 协议号 / 组播 | 112 / `224.0.0.18` |
| TTL / 认证 | 255 / 0（无认证） |
| VRID / Priority | 1–255 / 1–254（255=VIP 拥有者） |

选举规则：Priority=255 直接为 Master → 收到更高优先级降级 → 收到 priority=0 提升 → 同优先级比源 IP → Master 超时（`3*Advert_Int + ((256-Priority)*Advert_Int)/256`）提升。VIP 通过 `ip addr add/del <vip>/32 dev <iface>` 漂移，支持 `onPromote` / `onDemote` 回调。

```yaml
enabled: true
mode: backup
vrid: 1
priority: 100
advert_int: 1
vip: 192.168.1.254
interface: eth0
peer_ip: 192.168.1.2
```

启动：`gofw start -r rules.yaml --ha ha.yaml`。VRRP 需 `CAP_NET_RAW`（`sudo setcap cap_net_raw+ep ./gofw` 或 root）。

---

## 七、配置注释保留

`config.Save` 规范化 YAML 时会抹掉手工写的 `# ===== ... =====` 分段注释。新增**注释锚点迁移**（`config/comments.go`）：保存前提取原文件注释块，写回时按锚点还原。已通过 `config/comments_test.go`，线上 `apply` / `clear` 后原始 4 段注释完好。

---

## 📌 相关文档

- [README · 能力挡位速览与部署现状](../README.md)
- [deploy/README.md · systemd 与严格模式](../deploy/README.md)
