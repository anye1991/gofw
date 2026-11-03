#!/usr/bin/env bash
# gofw 真·规则下发引擎 一键部署脚本
# 在本地(ssh/scp 可达目标服务器)执行。需 nginx、systemd、nftables 已装。
#
# 用法:
#   ./deploy.sh user@服务器IP [本地二进制路径]
# 例:
#   ./deploy.sh root@47.113.145.207
#   ./deploy.sh root@47.113.145.207 ./gofw
#
# 前置:
#   - 本地已生成二进制:
#       go build -o gofw .                         # 本机编译
#       或交叉编译: GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o gofw .
#     (真正的引擎是仓库根 main.go 的 `gofw start`，不是 cmd/uilaunch)
#   - 服务器监听网卡名(默认 eth0，可用 -i 改，见 start-gofw.sh)
set -euo pipefail

SERVER="${1:?用法: deploy.sh user@服务器IP [本地二进制]}"
LOCAL_BIN="${2:-./gofw}"                 # 本地真实引擎二进制
HERE="$(cd "$(dirname "$0")" && pwd)"
REMOTE_DIR="/opt/gofw"

echo "==> 目标服务器: $SERVER"
echo "==> 本地二进制: $LOCAL_BIN"

# 0) 交叉编译校验提醒（若未提供二进制）
if [ ! -f "$LOCAL_BIN" ]; then
  echo "!! 未找到本地二进制 $LOCAL_BIN，请先编译: GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o gofw ."
  exit 1
fi

# 1) 建目录
ssh "$SERVER" "mkdir -p $REMOTE_DIR && echo dir-ok"

# 2) 推送二进制 + 生产规则(默认增强层) + 严格模式规则 + 启动脚本
scp "$LOCAL_BIN"                 "$SERVER:/tmp/gofw"
scp "$HERE/rules-prod.yaml"      "$SERVER:$REMOTE_DIR/rules.yaml"
scp "$HERE/rules-prod-strict.yaml" "$SERVER:$REMOTE_DIR/rules-prod-strict.yaml"
scp "$HERE/start-gofw.sh"        "$SERVER:$REMOTE_DIR/start-gofw.sh"

# 3) 放置二进制并授权
ssh "$SERVER" "mv /tmp/gofw $REMOTE_DIR/gofw \
  && chmod +x $REMOTE_DIR/gofw $REMOTE_DIR/start-gofw.sh \
  && chown -R root:root $REMOTE_DIR"

# 4) 安装 systemd 单元并启动（密码在 gofw.service 的 Environment 注入）
scp "$HERE/gofw.service" "$SERVER:/tmp/gofw.service"
ssh "$SERVER" "mv /tmp/gofw.service /etc/systemd/system/ \
  && systemctl daemon-reload \
  && systemctl enable --now gofw"

# 5) 安装 nginx 反代(若目标机已装 nginx)
if ssh "$SERVER" "command -v nginx >/dev/null 2>&1"; then
  scp "$HERE/nginx-gofw.conf" "$SERVER:/tmp/nginx-gofw.conf"
  ssh "$SERVER" "mv /tmp/nginx-gofw.conf /www/server/panel/vhost/nginx/gofw.conf \
    && nginx -t && systemctl reload nginx" \
    && echo "  nginx 反代已启用(/www/server/panel/vhost/nginx/gofw.conf)" \
    || echo "  nginx 配置需手动检查"
fi

echo "==> 部署完成。检查状态:"
ssh "$SERVER" "systemctl status gofw --no-pager | head -n 8"
echo "==> 必做: 改 /etc/systemd/system/gofw.service 的 GOFW_WEB_PASSWORD 后 daemon-reload+restart"
echo "==> 切严格模式: 把 /opt/gofw/rules-prod-strict.yaml 覆盖 /opt/gofw/rules.yaml 再 restart gofw"
echo "==> 外部: DNS 把 gofw.<域名> 指到 EdgeOne 回源; 源站 ipset ysl_admin4 放行回源段+管理员IP"
