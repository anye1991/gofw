# 🖥️ gofw 网络层防火墙 · 公网部署与运维指南

本目录提供将 **gofw 规则下发引擎**（`gofw start`，仓库根 `main.go`）部署到
Linux 服务器并下发到内核 nftables 的生产产物。所有文件均在本地准备好，
服务端步骤在目标机上执行。

> 📌 **当前实际部署状态（2026-11-06，务必先读）**
> 本文档描述的是 **kernel 真下发**方案，属于「运行时可切换 / 默认未长期开启」挡位：`nft -c -f` 语法校验与规则顺序测试已通过，**当前线上默认仍是 monitor**。
> 线上实际运行：`192.168.58.128:18081`，systemd 托管（User=root，具备 CAP_NET_ADMIN），`/opt/gofw/gofw`，启动参数带 **`--monitor`** —— 只记录决策 / 统计 / 日志，**不真实丢包**；规则 27 条，地理围栏未启用，GeoIP 库 1,411,297 条（v4 597,286 / v6 814,011）。
> 要真正按国家断网：进 Web「系统增强」页 → ① 仅安装护栏（4 条 ACCEPT 置顶）→ ② 预检（nft 权限 / 语法 / 护栏顺序）→ ③ 二次确认切到内核 → 验证 SSH 与面板可达后点「确认保留」。未确认会在 30 秒内自动回滚到 monitor 并清空内核表，无需改 systemd 或重启，也不会锁死 SSH。启动时不带 `--monitor` 则直接以 kernel 启动，效果相同。
> 完整能力挡位与线上快照见 [README](../README.md#-能力挡位速览)。

> ⚠️ 注意：切到 kernel 后，这不是只读「管理面板」，而是会**真正改写内核 nftables** 的引擎。
> 切换规则（尤其切到 `default: drop` 严格模式）前务必确认白名单完整，避免锁死服务器。

---

## 📑 目录

- [📦 目录内容](#目录内容)
- [一、本地生成二进制](#一本地生成二进制)
- [二、服务端部署](#二服务端部署)
- [三、上线与安全](#三上线与安全)
- [四、运维操作](#四运维操作)
- [五、验证](#五验证)

---

## 📦 目录内容

| 文件 | 作用 |
|------|------|
| `gofw.service`        | systemd 单元：真引擎开机自启 / 崩溃重启，密码经 `Environment` 注入（不入库） |
| `start-gofw.sh`       | 启动包装：确保 PATH 含 nft，调 `gofw start -r rules.yaml -i eth0 --web :18081` |
| `rules-prod.yaml`     | 生产规则（**默认 accept 增强层**：只做精确阻断 + 显式放行，叠加在现有 UFW 之上） |
| `rules-prod-strict.yaml` | 生产规则（**默认 drop 严格模式**：未显式放行一律拒绝，含入站 + 出方向全量白名单） |
| `nginx-gofw.conf`     | nginx 反代 `gofw.<域名>` → `127.0.0.1:18081`，置于 EdgeOne 之后；同时监听 `80` 与 `443`（自签证书） |
| `deploy.sh`           | 一键推送二进制 + 规则 + 单元、安装服务、启用 nginx（需 ssh 可达） |

---

## 一、本地生成二进制

```bash
# 真正的引擎是仓库根 main.go 的 `gofw start`（不是 cmd/uilaunch 假面板）
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o gofw .
```

---

## 二、服务端部署

```bash
chmod +x deploy.sh
./deploy.sh root@<服务器IP> ./gofw
```

脚本会：建 `/opt/gofw` → 推送二进制、生产规则、启动脚本、systemd 单元 →
启用 nginx 反代 → 输出运行状态。默认部署的是 `rules-prod.yaml`（默认 accept）。

---

## 三、上线与安全

1. **设置登录密码**：编辑 `/etc/systemd/system/gofw.service`，把
   `Environment=GOFW_WEB_PASSWORD=...` 改为强密码，再
   `systemctl daemon-reload && systemctl restart gofw`。不设置则面板**无鉴权**。
2. **走 CDN / EdgeOne**：面板域名解析到 EdgeOne，由 EdgeOne 终结 TLS 回源到源站 `80`（推荐），
   源站不直接暴露。面板经 nginx 反代到 `127.0.0.1:18081`（外部直接访问 18081 会被防火墙挡掉）。
3. **源站防火墙白名单**：源站 `ipset ysl_admin4` 仅放行 EdgeOne 回源段 + 管理员 IP，
   80 / 443 不对全网开放。宽带公网 IP 漂移时用 `ipset add ysl_admin4 <新IP>` 加白。
4. **权限**：真正下发 nftables 需 root。单元默认 `root` 运行；若 `NoNewPrivileges` /
   `CapabilityBoundingSet` 裁剪了 `CAP_NET_ADMIN`，引擎会 fallback 成只监控不下发的
   Monitor 模式（日志里会写 `nftables unavailable ... falling back to monitor mode`）——务必确认
   日志出现 `enforcement backend: nftables` 才是真下发。
5. **nginx 443**：`nginx-gofw.conf` 已同时 `listen 80` 与 `listen 443 ssl`（自签证书，
   CN / SAN = `gofw.<域名>`）。EdgeOne 回源到 `:80` 即出面板；若后续 DNS 直连源站（绕过 EdgeOne），
   走 `:443` 会提示自签证书、手动信任即可。
6. **可选告警**：如需拦截 / 异常告警，准备 `alert.yaml`（Webhook 或 SMTP 邮件，字段见主文档「告警通知」），
   在 `start-gofw.sh` 的启动命令追加 `--alert /opt/gofw/alert.yaml`，再 `systemctl restart gofw` 即可生效。

---

## 四、运维操作

### 1) 改规则
- **方式 A（即时真下发）**：Web 面板「规则」页直接增删，引擎 apply 会调用 `enf.Apply` 真改内核。
- **方式 B（改文件）**：编辑 `/opt/gofw/rules.yaml` 后 `systemctl restart gofw`
  （服务启动即 `enf.Apply`，整表幂等刷新）。

### 2) 改密码
编辑 `/etc/systemd/system/gofw.service` 的 `GOFW_WEB_PASSWORD`，再
`systemctl daemon-reload && systemctl restart gofw`。

### 3) 切「默认拒绝」严格模式
⚠️ 本引擎的 `default` 动作会**同时套用到 input / output / forward 三条链**。
所以 `default: drop` 不仅把入站默认拒绝，**出方向也会被默认拒绝**（会掐断 DNS 上游、
NTP、apt、云厂商内部通信）。切之前必须把所有**对外端口 + 必要出方向**补进白名单。

已就绪的 `rules-prod-strict.yaml` 已包含：
- 入站白名单：SSH(22,带限速) / Web(80, 443 tcp+udp) / 宝塔(888, 18706) / MySQL(3306) / ICMP
- 出方向白名单：DNS(53) / NTP(123) / HTTP-HTTPS(80, 443) / 阿里云内部(100.100.0.0/16)
- 通用首行：established / related + 回环 全链放行；末端：恶意网段 / Xmas 扫描 / Web 并发限制

切换（先在服务器备份，建议带 10 分钟自动回退兜底）：
```bash
ssh root@<服务器IP> '
  cp /opt/gofw/rules.yaml /opt/gofw/rules.yaml.bak
  # 10 分钟兜底：恢复安全规则并重启（setsid 脱离会话，SSH 断开也执行）
  cat > /tmp/rb.sh <<EOF
  #!/bin/bash
  sleep 600; cp /opt/gofw/rules.yaml.bak /opt/gofw/rules.yaml; systemctl restart gofw
  echo rollback at $(date) >> /root/gofw-rollback.log
  EOF
  setsid bash /tmp/rb.sh >/dev/null 2>&1 &
  cp /opt/gofw/rules-prod-strict.yaml /opt/gofw/rules.yaml
  systemctl restart gofw'
# 验证：服务 active、三链 policy drop、Web/MySQL/宝塔/DNS 均正常，再取消兜底
#   pkill -f rb.sh   # 注意别用 pkill -f 匹配到当前命令自身
```
回退：`cp /opt/gofw/rules.yaml.bak /opt/gofw/rules.yaml && systemctl restart gofw`
（或等待兜底自动恢复）。

---

## 五、验证

```bash
ssh root@<服务器IP> 'systemctl status gofw'
ssh root@<服务器IP> 'nft list table inet gofw'   # 应见 table inet gofw 及三条链规则
ssh root@<服务器IP> '/opt/gofw/gofw rules list -r /opt/gofw/rules.yaml'  # 仅解析不应用
```
浏览器访问 `https://gofw.<域名>/`，用密码登录可看到完整管理面板与能力中心。
