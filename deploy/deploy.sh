#!/usr/bin/env bash
# gofw Web 管理面板一键部署脚本
# 在本地(有网络可达目标服务器)执行。需 ssh/scp 可达目标 Linux 服务器。
#
# 用法:
#   ./deploy.sh user@服务器IP
# 例:
#   ./deploy.sh root@47.113.145.207
#
# 前置:
#   - 本地已生成二进制: go build -o gofw-webui ./cmd/uilaunch
#     (或交叉编译: GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o gofw-webui ./cmd/uilaunch)
#   - 服务器已安装 nginx、systemd、nftables
set -euo pipefail

SERVER="${1:?用法: deploy.sh user@服务器IP}"
REMOTE_DIR="/opt/gofw"
LOCAL_BIN="${2:-./gofw-webui}"          # 本地二进制路径(默认当前目录)
HERE="$(cd "$(dirname "$0")" && pwd)"

echo "==> 目标服务器: $SERVER"
echo "==> 本地二进制: $LOCAL_BIN"

# 1) 建目录与专用用户
ssh "$SERVER" "sudo mkdir -p $REMOTE_DIR && sudo useradd -r -s /usr/sbin/nologin gofw 2>/dev/null || true"

# 2) 推送二进制与规则
scp "$LOCAL_BIN"        "$SERVER:/tmp/gofw-webui"
scp "$HERE/../rules.yaml" "$SERVER:$REMOTE_DIR/rules.yaml" 2>/dev/null || echo "  (跳过 rules.yaml: 服务器端已有则保留)"

# 3) 放置二进制并授权
ssh "$SERVER" "sudo mv /tmp/gofw-webui $REMOTE_DIR/gofw-webui \
  && sudo chmod +x $REMOTE_DIR/gofw-webui \
  && sudo chown -R root:root $REMOTE_DIR"

# 4) 安装 systemd 单元并启动
scp "$HERE/gofw-webui.service" "$SERVER:/tmp/gofw-webui.service"
ssh "$SERVER" "sudo mv /tmp/gofw-webui.service /etc/systemd/system/ \
  && sudo systemctl daemon-reload \
  && sudo systemctl enable --now gofw-webui"

# 5) 可选: 安装 nginx 反代(需目标机 nginx 已装)
if ssh "$SERVER" "command -v nginx >/dev/null 2>&1"; then
  scp "$HERE/nginx-gofw.conf" "$SERVER:/tmp/nginx-gofw.conf"
  ssh "$SERVER" "sudo mv /tmp/nginx-gofw.conf /etc/nginx/sites-enabled/gofw.conf \
    && sudo nginx -t && sudo systemctl reload nginx" \
    && echo "  nginx 反代已启用" || echo "  nginx 配置需手动检查"
fi

echo "==> 部署完成。检查状态:"
ssh "$SERVER" "sudo systemctl status gofw-webui --no-pager | head -n 8"
echo "==> 别忘了: 设置 GOFW_WEB_PASSWORD 强密码、在源站防火墙放行 EdgeOne 回源段+管理员IP"
