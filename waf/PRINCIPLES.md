# kejilion.sh / KPanel 通用 WAF 原则

本规范约束共享 WAF 实现、试点和公共模板交付。正式服是生态发布前的试点生产环境，公共默认值须同时通过独立通用场景验证。

1. 面向 kejilion.sh、KPanel 的所有用户；域名、地址、凭据、白名单和业务例外属于部署配置，不进入公共默认值。
2. 两端复用由 kejilion.sh 声明的同一份配置来源、管理入口和资源布局，不维护平行规则或影子状态。
3. 同时支持直连、Cloudflare、明确配置的其他 CDN/可信反代及混合部署。
4. 覆盖静态站、CMS/WordPress、论坛、REST API、鉴权、Webhook、上传下载、WebSocket/SSE、多站点和共享 NAT；应用专属例外必须精确且可审计。
5. 逐环节查阅实际版本的组件及依赖官方文档：CDN、真实 IP、Nginx、TLS/OpenSSL、ModSecurity、OWASP CRS、Fail2Ban、日志和封禁后端。核对默认值、版本兼容、上游限制及弃用项；验证组件组合后的行为。
6. 重要调优项保留官方来源、适用版本、选择理由、余量依据及原始验证结果。当前配置和第三方教程不能替代官方依据。
7. 根据正常业务、实测峰值和机器容量保留请求突发、连接、请求体、上传、超时及资源余量；所有配额有边界、可观测、可调整。攻击评分采用经验证的安全基线，误报以精确排除处理。
8. 客户端身份只接受明确可信代理提供的来源信息；直连伪造头无效；不自动信任整个私网、Docker 地址段或任意来源。
9. 限流、异常累计和封禁按站点与真实客户端隔离，防止跨站及共享出口误伤。
10. 单次请求拦截与持续滥用封禁分离。普通业务 401/403/404/429 不作为独立封禁依据；只消费明确、可信的防御事件。
11. 封禁有范围、上限、有效期、记录和解封入口；保护代理节点及本机基础设施，避免账号范围的默认 CDN 封禁。
12. 通用基线与业务配置档分离。例外限定到站点、路径、参数和规则；检测模式和灰度是可管理状态，不能冒充已经阻断。
13. 安装、检测、启停、状态诊断、策略调整、封禁管理、更新、回滚和卸载形成闭环；两端回读真实资源状态。
14. 变更保留基线，原子写入、语法检查、应用、回读；失败保留或恢复上一份有效配置，升级和卸载保护用户自定义内容。
15. 日志、封禁、状态、临时文件及刷新频率有界；验证 CPU、内存、磁盘和延迟影响，不以增加配额掩盖无界资源问题。
16. 使用通用矩阵与试点生产验证：正常业务、恶意请求、伪造 IP、CDN/直连、多站点隔离、失败注入、重启、升级和回滚。攻击、压力和故障注入使用隔离环境，避免再次封禁办公出口或影响真实用户。
17. 验证通过后才更新公共默认模板；同步同一套已验证版本、摘要、兼容条件、迁移和回滚方式。
18. 核对原生脚本入口、下载来源、KPanel 共享适配及受管脚本依赖；只有生态消费链路有证据，才宣告生态交付完成。
19. 区分已验证、未验证、检测中、待发布及受限制状态；不以正式服正常代替全部验收，不声称 WAF 配置等于 ASVS 整体符合性。
20. 历史整站关闭 WAF 视为待迁移兼容问题，不复制为公共永久豁免；逐项定位误报，形成业务配置档和精确排除，以正常业务通过且攻击反例仍阻断作为开启拦截的条件。检测模式是过渡状态，不能替代精细调优。
21. 优先沿用现有 Cloudflare、Nginx、ModSecurity/CRS、Fail2Ban 组件和链路；新增常驻服务、替换封禁后端等架构变更单独评估，经明确确认后才能实施或纳入公共默认方案。

## 官方依据

- [Nginx realip](https://nginx.org/en/docs/http/ngx_http_realip_module.html)：信任明确的代理；保留原始连接地址。
- [Nginx 请求限流](https://nginx.org/en/docs/http/ngx_http_limit_req_module.html)：按 key 计数、突发、检测模式和明确的拒绝状态。
- [Nginx 连接限制](https://nginx.org/en/docs/http/ngx_http_limit_conn_module.html)：并发与 HTTP/2、HTTP/3 的计数语义。
- [ModSecurity v3](https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v3.x))：规则阶段、请求体限额、检测模式、审计及事务控制。
- [OWASP CRS 异常评分](https://coreruleset.org/docs/2-how-crs-works/2-1-anomaly_scoring/)：PL 与阈值独立，目标入站阈值 5、出站阈值 4；通过精确排除处理误报。
- [OWASP CRS 误报调优](https://coreruleset.org/docs/2-how-crs-works/2-3-false-positives-and-tuning/)：优先应用排除包与精确运行期排除，保留其他规则；避免误报日志泄露合法业务敏感输入。
- [Nginx 代理头继承](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_set_header)及[子请求访问检查](https://nginx.org/en/docs/http/ngx_http_auth_request_module.html)：按完整有效作用域迁移代理头，组合访问控制；已有自定义认证不可静默覆盖。
- [Cloudflare 来源恢复](https://developers.cloudflare.com/support/troubleshooting/restoring-visitor-ips/restoring-original-visitor-ips/)及[官方地址 API](https://developers.cloudflare.com/api/resources/ips/methods/list/)：CIDR 与客户端头的信任边界。
- [Fail2Ban](https://github.com/fail2ban/fail2ban/wiki)：基于可信日志的过滤、动作、计数和封禁生命周期。

WAF 不替代应用鉴权、授权、漏洞修复和上游容量防御。具体默认值、适配版本及验证结果随实现记录，不把尚未验证的设计写为通过。
