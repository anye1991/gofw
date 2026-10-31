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

- 规则匹配：IP/MAC/端口/协议/TCP 标志位/方向/状态/VLAN/时间段
- DPI 应用层检测：HTTP、TLS、SSH、DNS、MySQL 等
- GeoIP 国家库：内置 15 国 CIDR，无需外部文件
- 流量控制：速率限制、带宽限速、并发连接限制
- NAT：SNAT / DNAT / Masquerade
- 高可用：VRRPv2 主备选举（RFC 3768），自动回退 TCP 探测
- Web UI：规则增删改 REST API + 实时统计面板

## 文档

- [功能说明文档](docs/FEATURES.md) — 三项新增能力的详细说明

## 验证

```bash
go build ./...
go vet ./...
go test -race -count=1 ./...
go run ./cmd/verify
```

## 作者

- **署名**：暗夜铭少
- **官网**：[https://waf.duduziy.com](https://waf.duduziy.com)
- **邮件**：[azgq@foxmail.com](mailto:azgq@foxmail.com)
