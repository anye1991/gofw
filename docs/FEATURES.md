# 🧩 gofw 功能说明文档

本文档详细说明 gofw 防火墙的三项核心能力：**内置 GeoIP 国家库**、**Web UI 规则增删改 API**、**HA 升级为 VRRP 协议**。

---

## 📑 目录

- [一、内置 GeoIP 国家库](#一内置-geoip-国家库)
- [二、Web UI 规则增删改 API](#二web-ui-规则增删改-api)
- [三、HA 升级为 VRRP 协议](#三ha-升级为-vrrp-协议)

---

## 一、内置 GeoIP 国家库

### 📌 功能说明

无需外部 CSV 文件，内置常见国家 / 地区的 CIDR 网段数据，启动时自动加载，支持按国家码匹配流量。

- 内置覆盖 15 个国家 / 地区：`CN`、`US`、`JP`、`KR`、`GB`、`DE`、`FR`、`RU`、`SG`、`IN`、`BR`、`AU`、`CA`、`NL`、`HK`、`TW`
- 共 **1589 条** CIDR 记录
- 按 CIDR 前缀长度降序稳定排序，更具体的网段优先匹配
- 优先加载外部 CSV（`rules.yaml.geoip`），不存在时回退内置库

### 🚀 使用方法

无需额外配置，启动时自动加载：

```bash
gofw start -r rules.yaml
```

启动日志会显示：

```
geoip builtin loaded: 1589 entries
```

如需使用更精确的 GeoIP 数据，将 CSV 文件命名为 `rules.yaml.geoip` 放在规则文件同目录，格式为 `CIDR,country_code`：

```
1.0.1.0/24,CN
8.8.8.0/24,US
```

### 🧱 规则中使用

在规则的 `geoip` 字段指定国家码（逗号分隔多个）：

```yaml
rules:
  - action: DROP
    geoip: CN,RU
    comment: 阻止来自中国和俄罗斯的流量
  - action: ACCEPT
    geoip: US
    comment: 仅允许美国 IP
```

### ✅ 验证 IP

| IP | 国家 |
|----|------|
| 114.114.114.114 | CN |
| 223.5.5.5 | CN |
| 8.8.8.8 | US |
| 9.9.9.9 | US |
| 133.0.0.1 | JP |
| 255.255.255.255 | unknown（未匹配） |

---

## 二、Web UI 规则增删改 API

### 📌 功能说明

在原只读 Web 管理界面基础上，新增规则的增删改 REST API，支持运行时动态修改规则并自动持久化到 YAML 文件、热应用到引擎。

### 🔌 API 端点

| Method | Path | 功能 |
|--------|------|------|
| GET | `/api/rules` | 列出所有规则 |
| POST | `/api/rules` | 新增规则 |
| PUT | `/api/rules/{index}` | 替换指定索引的规则 |
| DELETE | `/api/rules/{index}` | 删除指定索引的规则 |

### 🚀 启动 Web UI

```bash
gofw start -r rules.yaml --web :8080
```

### 📨 请求示例

**新增规则（POST /api/rules）**

```bash
curl -X POST http://localhost:8080/api/rules \
  -H "Content-Type: application/json" \
  -d '{
    "action": "drop",
    "protocol": "tcp",
    "dst_port": 3306,
    "app_proto": "mysql",
    "comment": "block mysql"
  }'
```

响应：

```json
{"index": 17, "rule": "DROP tcp any:any -> any:3306 app=mysql # block mysql", "status": "added"}
```

**更新规则（PUT /api/rules/17）**

```bash
curl -X PUT http://localhost:8080/api/rules/17 \
  -H "Content-Type: application/json" \
  -d '{"action": "reject", "protocol": "tcp", "dst_port": 3306, "comment": "reject mysql"}'
```

**删除规则（DELETE /api/rules/17）**

```bash
curl -X DELETE http://localhost:8080/api/rules/17
```

响应：

```json
{"index": 17, "status": "deleted"}
```

### 🧾 支持的 JSON 字段

与 YAML 配置字段一致：`action`、`src_ip`、`dst_ip`、`src_mac`、`dst_mac`、`protocol`、`src_port`、`dst_port`、`tcp_flags`、`direction`、`state`、`vlan`、`time`、`rate_limit`、`burst`、`per_src`、`bandwidth`、`burst_bytes`、`conn_limit`、`geoip`、`app_proto`、`ip_group`、`nat`、`comment`、`name`。

### ⚠️ 错误响应

| HTTP 状态码 | 场景 |
|------------|------|
| 400 | JSON 格式错误、非法 action、非法索引格式 |
| 404 | 规则索引超出范围 |
| 500 | 规则持久化失败 |

### 🔒 并发安全

写操作（POST / PUT / DELETE）通过互斥锁串行化，防止并发修改导致规则丢失更新；索引边界检查在锁内执行，消除 TOCTOU 竞态。

---

## 三、HA 升级为 VRRP 协议

### 📌 功能说明

将原 TCP 探测主备切换升级为 VRRPv2（RFC 3768）协议，通过组播通告实现主备选举，兼容标准 VRRP 路由器。无 `CAP_NET_RAW` 权限时自动回退到 TCP 探测模式。

### 📐 协议参数

| 参数 | 值 |
|------|-----|
| IP 协议号 | 112 |
| 组播地址 | 224.0.0.18 |
| TTL | 255（VRRP 要求） |
| 认证类型 | 0（无认证） |
| VRID | 1-255 |
| Priority | 1-254（255=VIP 拥有者，0=Master 释放） |

### ⚙️ 配置示例

`ha.yaml`：

```yaml
enabled: true
mode: backup          # master / backup / auto
vrid: 1               # 虚拟路由器 ID（1-255），>0 启用 VRRP
priority: 100         # 优先级（1-254，255=VIP 拥有者）
advert_int: 1         # 通告间隔（秒，默认 1）
vip: 192.168.1.254    # 虚拟 IP
interface: eth0       # VIP 绑定的网卡
peer_ip: 192.168.1.2  # 对端 IP（VRRP 下作为本地发送源 IP）
```

启动：

```bash
gofw start -r rules.yaml --ha ha.yaml
```

### 🗳️ 主备选举规则

1. **Priority=255（VIP 拥有者）**：启动时直接成为 Master
2. **收到更高优先级通告**：降级为 Backup
3. **收到 priority=0 通告**（对端 Master 主动释放）：提升为 Master
4. **同优先级**：比较源 IP，IP 大的优先
5. **Master 超时**：`Master_Down_Interval = 3 * Advert_Int + ((256 - Priority) * Advert_Int) / 256`，超时未收到通告则提升为 Master

### 🔁 TCP 探测回退

当 VRRP 套接字初始化失败（无 `CAP_NET_RAW`）时，自动回退到 TCP 探测模式，使用原有的 `peer_port`、`check_port`、`interval`、`fail_count` 参数。

### 🌐 VIP 管理

- 提升为 Master 时：`ip addr add <vip>/32 dev <interface>`
- 降级为 Backup 时：`ip addr del <vip>/32 dev <interface>`
- 支持主备切换回调：`onPromote` / `onDemote`

### 🔐 权限要求

VRRP 模式需要 `CAP_NET_RAW` 权限（原始套接字）：

```bash
sudo setcap cap_net_raw+ep /path/to/gofw
# 或直接以 root 运行
```
