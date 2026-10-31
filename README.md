# gofw - Go 网络层防火墙

基于 Go 实现的网络层防火墙，支持规则匹配、DPI 深度包检测、GeoIP 地理位置、带宽限速、并发连接限制、NAT、高可用（VRRP）等能力。

## 快速开始

```bash
# 构建
go build -o gofw .

# 启动
./gofw start -r rules.yaml --web :8080
```

## 核心功能

### 规则匹配
支持多维度包过滤：
- **网络层**：IP 地址、MAC 地址
- **传输层**：端口、协议（TCP/UDP/ICMP）
- **应用层**：TCP 标志位（SYN/ACK/FIN/RST/PSH/URG）
- **流量方向**：入站（In）、出站（Out）、双向（Any）
- **连接状态**：NEW、ESTABLISHED、RELATED、INVALID
- **VLAN**：支持 VLAN ID 匹配
- **时间控制**：基于时间段的规则生效控制

### DPI 深度包检测
应用层协议识别，支持：
- HTTP：检测请求方法和 URI
- TLS：识别客户端 Hello 和服务器证书信息
- SSH：协议版本协商检测
- DNS：查询类型识别（A、AAAA、CNAME 等）
- MySQL：客户端认证和服务器问候包检测
- FTP、SMTP 等常用协议

### GeoIP 地理位置
内置 15 国 CIDR 数据，无需外部文件：
- 中国、美国、日本、韩国、德国、英国、法国、俄罗斯、加拿大、澳大利亚、印度、巴西、新加坡、韩国、香港

### 流量控制
- **速率限制**：基于令牌桶算法的请求速率控制
- **带宽限速**：按源 IP 或全局的流量带宽限制
- **并发连接限制**：限制单个源 IP 的并发连接数

### NAT 网络地址转换
- SNAT：源地址转换
- DNAT：目的地址转换
- Masquerade：动态地址伪装

### 高可用（VRRP）
- 实现 VRRPv2 协议（RFC 3768）
- 主备自动选举，优先级高者为主
- 支持 TCP 探测作为健康检查回退
- VIP 自动漂移

### Web UI 管理界面
- 规则增删改查 REST API
- 实时流量统计面板
- 连接状态查看

## 项目结构

```
gofw/
├── alert/          # 告警管理（Webhook、邮件通知）
├── capture/        # 数据包捕获（原始套接字）
├── cmd/verify/     # 功能验证测试
├── config/         # 配置加载（YAML 解析）
├── dpi/            # 深度包检测
├── enforce/        # 规则执行（nftables/监控模式）
├── engine/         # 核心引擎（连接追踪、碎片重组）
├── geoip/          # GeoIP 地理位置库
├── ha/             # 高可用（VRRP 协议实现）
├── packet/         # 数据包解析
├── rules/          # 规则定义与匹配
├── webui/          # Web 管理界面
├── main.go         # 主程序入口
└── rules.yaml      # 规则配置文件
```

## 安装

### 前置要求
- Go 1.21+
- Linux 内核（推荐 5.x）
- root 权限或 CAP_NET_RAW 能力

### 构建

```bash
# 克隆项目
git clone https://gitee.com/nights-shadow/fhq.git
cd fhq

# 构建
go build -o gofw .

# 或使用 Go 模块
go build -o gofw ./main.go
```

## 配置说明

### 规则配置 (rules.yaml)

```yaml
rules:
  - action: drop
    src: 192.168.1.100
    dst: 10.0.0.1
    proto: tcp
    dport: 80
    direction: in
    state: new
    
  - action: accept
    src: 10.0.0.0/8
    proto: tcp
    dport: 443
    state: established
    
  - action: accept
    geoip: CN,US
    proto: tcp
    dport: 22
    
  - action: drop
    rate_limit:
      rate: 100
      burst: 50
      per_src: true
      
  - action: accept
    conn_limit:
      max: 100
      per_src: true

nat:
  - type: snat
    src: 192.168.0.0/16
    to_src: 203.0.113.1
    
  - type: dnat
    dst: 203.0.113.2
    dport: 8080
    to_dst: 192.168.1.100:80
```

### 完整启动命令

```bash
# 基本启动
./gofw start -r rules.yaml

# 启动并开启 Web UI
./gofw start -r rules.yaml --web :8080

# 启用高可用
./gofw start -r rules.yaml --ha --ha-iface eth0 --ha-vip 192.168.1.254

# 监控模式（不实际拦截，仅记录）
./gofw start -r rules.yaml --monitor
```

## 验证

```bash
# 构建测试
go build ./...

# 代码检查
go vet ./...

# 单元测试（带竞态检测）
go test -race -count=1 ./...

# 功能验证
go run ./cmd/verify
```

## 文档

详细功能说明请参阅：
- [功能说明文档](docs/FEATURES.md) — 三项新增能力的详细说明

## 许可证

本项目采用 MIT 许可证，详见 LICENSE 文件。

## 作者

- **署名**：暗夜铭少
- **官网**：https://waf.duduziy.com
- **邮件**：azgq@foxmail.com

## 贡献

欢迎提交 Issue 和 Pull Request！