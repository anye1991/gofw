#!/bin/bash
# gofw 启动后自动恢复 autoban（自动拦截）配置
# autoban 为运行时状态、不持久化，gofw 重启会静默回到 enabled:false
# 故每次启动后需调用引擎 API 恢复，避免"重启即失效"
PW="${GOFW_WEB_PASSWORD:?需从服务器 systemd 环境变量注入}"
for i in $(seq 1 60); do
  curl -s -o /dev/null --max-time 2 http://127.0.0.1:18082/ && break
  sleep 1
done
curl -s -c /tmp/gofw_ab_cj.txt -X POST http://127.0.0.1:18082/api/login \
  -H "Content-Type: application/json" -d "{\"password\":\"$PW\"}" >/dev/null 2>&1
curl -s -b /tmp/gofw_ab_cj.txt -X POST http://127.0.0.1:18082/api/bans \
  -H "Content-Type: application/json" \
  -d '{"action":"config","config":{"enabled":true,"threshold":50,"window_sec":10,"ban_sec":600}}' >/dev/null 2>&1
rm -f /tmp/gofw_ab_cj.txt
