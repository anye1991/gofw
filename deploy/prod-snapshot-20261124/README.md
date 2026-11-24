# 生产机配置快照（PROD-HOST-IP · 2026-11-24）

服务器 /opt/gofw 与 /etc/systemd/system/gofw.service 的实机配置原样备份。
与 deploy/ 模板的差异（生产特化，均为有意为之）：

| 项 | deploy/ 模板 | 生产实机 |
|---|---|---|
| 启动 | gofw start -r rules.yaml -i eth0 --web :18081 | 经 start-gofw.sh 包装：web 绑 127.0.0.1:18082、--ban-safe-cidr、启动时自动恢复 autoban |
| rules.yaml admin_cidrs | 127.0.0.1/32 | 127.0.0.1/32,ADMIN-CIDR（管理网段数据面白名单，11-12 根治自锁） |
| rules.yaml 其余 | 基础模板 | 增补宝塔端口、conn_limit、扫描特征、bogon、GeoIP-RU、出站 DNS 放行（11-24 修监视器误判）、**EdgeOne 回源节点放行 164 段 + 非 EdgeOne Web 连接限制**（11-24 源站回源加固） |
| gofw.service | 直启 gofw | start-gofw.sh 包装 + GOFW_WEB_PASSWORD 环境变量 + MemoryMax=256M |

## EdgeOne 回源网段维护说明（2026-11-24 起生效）

- 网段来源：雷池 WAF 的 EdgeOne IP 库（2025-09 快照，153 段）+ 本站 30 天日志观测扩容段（11 段，43.146/43.168/43.139/43.144/120.226.146 等腾讯国际段）。
- 背景：官方 `api.edgeone.ai/ips` 已于 2026-07-31 停服，免费版套餐不支持源站防护（无法从控制台获取权威网段）。EdgeOne 网段变更前 3-6 个月一次，留意腾讯云站内信通知后需人工更新本快照与实机 rules.yaml。
- 实现约束（源自 gofw 内核编译器）：① 多网段 src_ip 会生成非法 nft 语句（引擎退出），必须每段一条规则；② ip_group 仅用户态识别、内核不编译，禁止用于影响数据面的规则；③ autoban 封禁集位于链首，白名单规则无法绕过封禁。
- 非 EdgeOne 来源的 80/443 受每源并发 200 限制（内核强制），缓解绕过 CDN 直打源站；完整白名单拦截需升级 EdgeOne 付费套餐启用源站防护后实施。

注意：服务器上运行的两个二进制（gofw、gofw-webui）均构建自本仓库
commit 53297e4（2026-11-06T01:35:45Z, vcs.modified=false），与仓库源码完全同源；
服务器文件体积更小是因为构建时加了 -ldflags "-s -w" 去符号。
