# gofw Web 管理面板 · 公网部署指南

本目录提供将 gofw Web 管理面板部署到 Linux 服务器的生产产物。
**所有文件均在本地准备好，服务端步骤由你（或在你明确授权后）在目标机上执行。**

## 目录内容

| 文件 | 作用 |
|------|------|
| `gofw-webui.service` | systemd 单元，开机自启、崩溃重启、读取 `GOFW_WEB_PASSWORD` |
| `nginx-gofw.conf`    | nginx 反代配置，置于 EdgeOne/CDN 之后，仅绑回环 |
| `deploy.sh`          | 一键推送二进制+规则、安装服务、启用 nginx（需 ssh 可达） |

## 一、本地生成二进制

```bash
# 交叉编译 Linux amd64 静态二进制
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o gofw-webui ./cmd/uilaunch
```

> Web 前端已通过 `//go:embed index.html` 打进二进制，无需额外拷贝前端文件。

## 二、服务端部署

```bash
# 把二进制放到 deploy/ 或指定路径，然后执行：
chmod +x deploy.sh
./deploy.sh root@<服务器IP> ./gofw-webui
```

脚本会：建 `/opt/gofw` → 推送二进制与 `rules.yaml` → 安装 systemd 服务 →
启用 nginx 反代 → 输出运行状态。

## 三、上线与安全（重要）

1. **设置登录密码**：编辑 `/etc/systemd/system/gofw-webui.service`，
   把 `GOFW_WEB_PASSWORD` 改为强密码，然后 `systemctl daemon-reload && systemctl restart gofw-webui`。
   不设置则面板**无鉴权**，公网环境绝对禁止留空。

2. **走 CDN/EdgeOne**：面板域名（如 `fw.example.com`）解析到 EdgeOne，
   由 EdgeOne 终结 TLS 并回源到源站 80/443。源站不直接暴露给公网。

3. **源站防火墙白名单**：源站 `iptables/ipset`（集合 `ysl_admin4`）仅放行
   **EdgeOne 回源段 + 你的管理员 IP**，80/443 不要对全网开放。
   若你的宽带为公网 IP 动态（会漂移），新增 IP 时用 `ipset add ysl_admin4 <新IP>` 加白。

4. **权限**：真正下发规则到 nftables 需 `CAP_NET_ADMIN`/root。
   单元默认以 `root` 运行以保证规则可下发；如仅作只读展示可降权。

5. **关闭演示流量**：上线用 `-demo=false`（单元已默认），避免假数据污染统计。

## 四、验证

```bash
ssh root@<服务器IP> 'systemctl status gofw-webui'
curl -sk https://<你的域名>/api/system   # 应返回能力中心 JSON
```

浏览器访问 `https://<你的域名>/`，用设置的密码登录即可看到完整管理面板。
