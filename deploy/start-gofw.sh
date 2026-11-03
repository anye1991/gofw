#!/bin/bash
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
exec /opt/gofw/gofw start -r /opt/gofw/rules.yaml -i eth0 --web :18081 --stats-interval 5
