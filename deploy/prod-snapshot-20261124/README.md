# 生产机配置快照（PROD-HOST-IP · 2026-11-24）

服务器 /opt/gofw 与 /etc/systemd/system/gofw.service 的实机配置原样备份。
与 deploy/ 模板的差异（生产特化，均为有意为之）：

| 项 | deploy/ 模板 | 生产实机 |
|---|---|---|
| 启动 | gofw start -r rules.yaml -i eth0 --web :18081 | 经 start-gofw.sh 包装：web 绑 127.0.0.1:18082、--ban-safe-cidr、启动时自动恢复 autoban |
| rules.yaml admin_cidrs | 127.0.0.1/32 | 127.0.0.1/32,ADMIN-CIDR（管理网段数据面白名单，11-12 根治自锁） |
| rules.yaml 其余 | 基础模板 | 增补宝塔端口、conn_limit、扫描特征、bogon、GeoIP-RU、出站 DNS 放行（11-24 修监视器误判） |
| gofw.service | 直启 gofw | start-gofw.sh 包装 + GOFW_WEB_PASSWORD 环境变量 + MemoryMax=256M |

注意：服务器上运行的两个二进制（gofw、gofw-webui）均构建自本仓库
commit 53297e4（2026-11-06T01:35:45Z, vcs.modified=false），与仓库源码完全同源；
服务器文件体积更小是因为构建时加了 -ldflags "-s -w" 去符号。
