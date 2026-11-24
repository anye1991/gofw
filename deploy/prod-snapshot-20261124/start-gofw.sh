#!/bin/bash
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
# 启动后自动恢复 autoban（自动拦截）：autoban 为运行时状态、不持久化，
# gofw 重启会静默回到 enabled:false，故每次启动由后台脚本调 API 恢复
nohup /opt/gofw/enable-autoban.sh >/var/log/gofw-autoban.log 2>&1 &
exec /opt/gofw/gofw start -r /opt/gofw/rules.yaml -i eth0 --web 127.0.0.1:18082 --stats-interval 30 --ban-safe-cidr 127.0.0.1/32,ADMIN-CIDR
