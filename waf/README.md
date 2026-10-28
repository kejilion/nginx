# 共享 WAF 配置

本目录管理现有 Docker Nginx + ModSecurity v3 + OWASP CRS 的配置。1.1.0 新增显式安装的 Fail2Ban 统一事件封禁及可选 CF 同步，延续 1.0.5 的请求检查、限流和性能基线。旧版正式服试点记录保留在下文；新封禁链路的隔离验证与生产边界见“统一事件封禁”。KPanel 镜像发行仍独立进行。

后续性能、安全、官方新特性和依赖迭代统一遵循 [通用 Nginx 性能与安全规范](PRINCIPLES.md)。以官方 Nginx 为共同基线，WAF 按需扩展；按“官方核对→隔离比较→独立复核→正式服试点→同一产物发布→公开与消费回读”推进。已启用、仅版本支持和待评估的特性分别记录，未验证收益不计入完成项。

## 架构边界

沿用已有 CDN、Nginx、ModSecurity/CRS 和 Fail2Ban 链路。配置工具使用 Python 3.11+ 标准库，不安装 WAF 常驻服务，不新增 HTTP/Unix Socket 检查服务，不自动替换封禁后端。新增后端须另行评估。

`banBackend: existing` 使用按站点 IP map 接口，既有未声明此字段的试点策略保持原语义。新部署示例仍为 `none`：只检查、拦截及限流。普通 WAF 开关/刷新不安装封禁组件；用户明确选择防护安装或 CF 模式后，才安装统一 Fail2Ban jail、动作及每分钟到期/CF 同步任务，并接通该 map。自定义封禁集成不自动覆盖。

## 使用前提与入口

需要 root、Docker 中名为 `nginx` 的现有容器、`/home/web` 原生布局，以及兼容的 ModSecurity/CRS 镜像。当前实测版本为 Nginx 1.31.7 / 1.31.8、ModSecurity 3.0.17、连接器 1.0.4、CRS 4.30.0；其他组合不能直接视为已验证。先备份并在隔离环境验证。

日常仍使用原生环境防护菜单中的 WAF 开关。接入后可使用 `k web waf status`、`k web waf doctor` 诊断。原生脚本固定共享提交及七文件摘要（新增 `ban.py`）；下列 Python 入口用于已经取得并核验完整配置包后的高级设置：

原生开关保留一键自动迁移：官方 `nginx` 镜像开启或检测 WAF 时，先检查日志轮转依赖，再备份当前 Compose 和配置、隔离预检兼容镜像、切换并应用共享策略。只修改生效的 Nginx 镜像声明，保留其他服务、端口、挂载、环境变量、CF 模式及自定义项，不重新下载覆盖整份 `nginx.conf`。首次没有策略文件时，轮转预检使用固定包的示例策略。普通镜像执行关闭为幂等操作，不为关闭 WAF 更换镜像。

自动迁移覆盖 `/home/web` 下可备份的 Compose YAML/JSON 及覆盖文件；自定义构建/非官方镜像、目录外配置或无法确认的复杂声明会明确中止。拉取、预检、切换或策略配置失败按恢复点回退；旧镜像回切前须能解析恢复后的配置。策略恢复失败或执行中断导致结果不确定时，保留兼容镜像与恢复点供检查。菜单只在成功时显示“已开启/已关闭”，失败不再显示“操作完成”。已有 WAF 镜像继续沿用原配置事务，不重复换镜像。

原生脚本发布与 KPanel 发行包分别核对。现有面板镜像固定的内置脚本不会因脚本仓库更新而自动更换；不得以原生入口验证代替已安装面板的发行与迁移验证。

2026-10-24，原生修复提交 `7277679bc25c2ce7461174added658d17cb2ac62` 保持脚本版本号不变。Linux 47 项更新器测试、10 项配置包引导测试、原生菜单/共享 WAF/KPanel LDNMP 入口及根/CN 同步检查通过；隔离真实 Docker 验证覆盖直连和 CF 模式的普通镜像自动迁移、拉取/切换/策略语法失败恢复与重试、重复开启、检测/关闭/再开启、完整 Compose 参数及有效来源恢复。策略输出混入过滤器 JSON、回滚失败和信号中断另有回归检查；未在生产执行失败注入，也未因此重发面板或镜像。

```sh
python3 -B configure.py configure --mode detect
python3 -B configure.py doctor
python3 -B configure.py configure --site example.com --profile wordpress --mode on
python3 -B configure.py configure --site api.example.com --profile api --mode on
python3 -B configure.py configure --site proxy.example.com --profile artifact-proxy --mode on
python3 -B configure.py configure --site panel.example.com --profile kpanel --mode on
python3 -B configure.py configure --site forum.example.com --profile flarum --mode on
python3 -B configure.py status
```

不带 `--site` 的 `configure --mode` 会统一全部站点模式并清除模式覆盖；已有业务配置档及精确排除仍保留。`off` 关闭规则引擎检查，Nginx 的独立限流仍有效。历史整站 Off 自动迁移到检测模式，须完成业务验证后再开启拦截；位置级自定义关闭保持原状并由管理员继续盘点。

站点中重复的 `modsecurity on` 统一继承 HTTP 全局开关；嵌套 Off→On、外部 include 中的独立开启需明确整合，自动迁移会拒绝处理。历史原生开关仍有效，普通刷新与 CF 信任更新尊重实际开关状态；显式 `configure --mode` 才改变目标模式。

兼容镜像只提供容器内部的规则基线与请求解析余量，不改宿主挂载、CF 模式或封禁动作。完整站点策略、受信代理、日志轮转与可回滚升级由同源固定版本配置包接入；不应把单独更新镜像解释为已完成所有宿主配置迁移。旧规则的评分阈值与审计开关由镜像兼容层保留，启用完整配置包后才使用本方案的阈值和审计策略。用户日常仍通过原生 WAF 开关操作。

`--profile` 必须同时指定 `--site`。`wordpress` 使用已有官方排除插件及受限文章路径兼容；`flarum` 仅对 JSON:API 发帖正文和登录密码作精确例外；`artifact-proxy` 限定下载路径与 Git 协议；`kpanel` 限定方法、API 路径和已知业务参数，其他查询及用户名仍接受检查。WebSocket/SSE、上传等配置档不替代应用鉴权、代理超时或上传容量配置。

`artifact-proxy` 对 GitHub 原始文件及 OCI manifest 的规范只读路径兼容 CRS 932260：仅 GET/HEAD、无方法覆盖头、路径为有界的字面安全字符且没有百分号或双点时，排除该规则的 `REQUEST_FILENAME` 目标；查询参数及其他规则仍检查。支持常规 tag 和 `sha256:<64位小写十六进制>` manifest 引用。这个配置档要求代理后端将路径作为数据处理而非交给 shell；其他源、编码路径和不符合格式的请求仍按原规则检查。仅有某条记录被拦截并不代表该请求一定正常，需结合后端行为判断。

站点 `exclusions` 支持 Unicode 字面路径，例如 `{"ruleId":932260,"path":"/category/docker-项目/","target":"REQUEST_FILENAME"}`。路径填写解码后的文字，不接受百分号编码、通配符或正则表达式。`REQUEST_FILENAME` 例外只适用于 GET/HEAD 且无方法覆盖头的精确路径；仅移除指定规则的路径目标，查询、正文和其他规则保持检查。既有 `ARGS:参数名` 例外行为不变。部署域名及具体业务路径留在用户策略内，不进入公共默认值。这遵循 [CRS 精确排除建议](https://coreruleset.org/docs/2-how-crs-works/2-3-false-positives-and-tuning/)；CRS 4.30 加入路径命令注入检查后，[官方要求关注路径误报](https://coreruleset.org/20261002/crs-versions-4.30.0-and-4.25.2-lts-released/)，不能为兼容而整体关闭 RCE 路径检测。

## 通用请求语义兼容

共享修复 `eb58fe4` 将方法覆盖按协议行为统一处理，不绑定 Flarum、域名或 `/api` 路径。仅原始 POST、单个 `X-HTTP-Method-Override` / `X-HTTP-Method` / `X-Method-Override` 头、明确的 PUT/PATCH/DELETE 且完整匹配既有允许方法时，才可进入兼容处理。请求方法及正文不改写，SQLi/XSS 等攻击检查继续执行；重复、冲突、危险值、覆盖头与顶层 query/body `_method` 混用仍由协议守卫按原评分基线拦截。参数 `_method` 单独使用仍遵循原有 PL1/PL2 行为，此开关不替代框架授权或 CSRF 防护。

默认策略为 `methodOverride: guarded`，但只有管理工具核对完整 `nginx -T` 能力图后才激活。遇到 `limit_except`、按原始方法派生的权限条件、认证子请求、脚本认证或方法头改写等不确定语义时，对相应作用域保持 strict。覆盖请求不继承 WordPress、KPanel、Git 及自定义参数的业务排除，避免把原 POST 的特例错误用于另一种方法。也可明确设置全局或站点 `methodOverride: strict`；原有 WAF Off/Detect/On 和 CDN 模式独立保留。

```sh
python3 -B configure.py configure --method-override guarded
python3 -B configure.py configure --site example.com --method-override strict
python3 -B configure.py doctor
```

`status` 的 `methodOverride.synchronized` 核对当前能力与实际受管规则是否一致；`doctor` 在漂移时失败。手工调整 ACL、认证或代理头后，先 `apply` / 原生刷新再重载并检查；已有原生受管重载入口会刷新配置。普通 `nginx -s reload` 本身不会重新生成管理策略。仅更新镜像且未刷新受管配置的旧链路保持严格行为，不宣称自动获得这一兼容功能。本轮不更改版本号或重建镜像，配置包按提交及摘要分发。

该实现保留 CRS 完整 `rules/*.conf` 装载，仅从 920450 的头名目标中排除三个规范名字，由自有 phase 2 守卫承担其严格校验并保留 949 评分/审计事件；其他受限头仍由原规则处理。ModSecurity 3.0.17 的动态单目标控制存在大小写边界，因此采用经真实引擎验证的配置期正则目标。隔离验证通过 Linux 70 项单测与 147 项真实 Nginx/ModSecurity 集成，含 Express `method-override@3.0.0` 组件 9 项有效方法检查、SQLi/XSS、ACL、多站点、可信代理、业务排除、Off/Detect、日志和恢复。其他框架为行为分析及请求形状覆盖，未宣称都做过完整登录业务测试。

依据：[CRS 4.30 协议规则](https://raw.githubusercontent.com/coreruleset/coreruleset/v4.30.0/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf)、[ModSecurity 目标更新](https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v3.x)#secruleupdatetargetbyid)、[Express 方法覆盖组件](https://github.com/expressjs/method-override)、[Nginx 方法权限](https://nginx.org/en/docs/http/ngx_http_core_module.html#limit_except)。

## 来源地址与 CDN

```sh
python3 -B configure.py configure --site direct.example.com --cdn direct
python3 -B configure.py configure --site cdn.example.com --cdn cloudflare
python3 -B configure.py trust-cloudflare
python3 -B configure.py refresh-ips
```

直连不信任客户端自带的转发头。Cloudflare 模式仅信任官方 IPv4/IPv6 CIDR；`mixed` 同时允许直连与 Cloudflare，直连伪造头仍无效。其他代理须在策略 JSON 中明确声明 `trustedProxies` 和 `proxyHeader`，多级代理必须实际清洗并维护可信转发链，不能自动信任整个 Docker/私网。

`trust-cloudflare` 只调整来源信任，不启用 WAF、不替换 Fail2Ban 动作、不需要 Cloudflare API 凭据。官方地址刷新失败保留旧快照，不使用任意地址作为降级信任。

## 日志、Fail2Ban 与恢复

### 统一事件封禁（1.1.0）

原生防护菜单 `1` 安装统一链路，`21` 开启 CF 封禁，`23` 关闭 CF 封禁；`6` 查看新 jail 与同步状态，`11` 调整两个受管 jail 的重试次数、计数窗口和封禁秒数，`12` 清空封禁。无共享策略时首次安装从 WAF 检测模式开始；已有 WAF 模式、站点例外、SSH 和自定义 jail 保留。管理员确认业务兼容后再开启 WAF 拦截。

```sh
k web waf ban-install  # 已安装 Fail2Ban、运行中的 cron 与共享 WAF 策略
k web waf ban-status
k web waf cf-off
k web waf ban-clear
k web waf ban-remove
```

调用 `cf-on` 时从标准输入传入 `{"email":"邮箱或空字符串","key":"Global API Key 或 API Token"}`，不要把凭据写到命令参数或共享日志。Token 需能读取目标 Zone 并编辑 Zone WAF 自定义规则；不要求账号级 IP 黑名单权限。凭据、owner 与 TTL 状态均由 root 以 0600 保存；缺少 owner 时拒绝假装完成远端清理，须恢复 `bans.json`。

统一链路只累计真实 WAF 入站阻断（949110/949111、既有秘密路径规则 1110/1111）与 Nginx 明确限流拒绝事件。检测模式命中、业务 403/404/429、解析失败 400 和限流 dry-run 不独立触发封禁。原脚本九个按普通业务状态计数的 jail 在明确安装时停用，避免重复累计；原始文件保留，SSH/自定义 jail 不变。

Fail2Ban 按 `站点|真实IP` 隔离计数。攻击默认 300 秒内 20 次、限流 120 次，封禁 600 秒；支持 60–3600 秒，不启用递增。攻击与限流保留独立到期时间，解掉一个来源不误解另一个来源。数据库重放使用原始 ticket 时间，避免重启延长封禁。IPv4/IPv6、本机接口地址、可信代理和 `banIgnore` CIDR 保护名单在动作端再次核验；管理员共享公网出口或 NAT 外部地址应在策略中明确加入 `banIgnore`。

源站 map 立即执行。CF 模式作为附加边缘同步，每分钟按当前有效记录批量更新；接口故障、配额不足时源站继续拦截，状态报告未就绪。每个 Zone 只管理带有本机唯一 ref/description 的一条 custom rule，表达式同时限定 `lower(http.host)` 和 IP，不创建账号/整 Zone 的 IP Access Rules；保留其他用户规则，使用规则级新增/更新/删除接口。开启时以 `false` 规则预检写权限与额度。最多管理 20 个历史 Zone，表达式上限 4096 字节；超限 Zone 清空本方案边缘投影并报告降级，避免过期记录永远无法清理。

只支持可明确映射到 CF Zone 的字面域名及别名；通配域名、别名冲突、缺失权限明确拒绝，不扩大到整个 Zone。`direct`/其他代理站点只在源站封禁。站点清单变化时先清理旧投影，再提示重新配置 CF；历史 Zone 单独保留用于清理。API 有请求及总同步时间预算，多 Zone 超时按分钟轮转优先次序重试。持续接口故障仍可能延迟远端解封，不能保证 CF 侧严格按秒到期；保留凭据、owner 和健康状态，恢复 API 后补偿。

CF 关闭先清除本方案远端规则，保留源站有效封禁；失败显示清理待重试并保留凭据。卸载、整环境卸载和备份还原在替换资源前清理当前联动，恢复的备份也需清理其中历史状态，随后重新显式安装/开启。自定义/其他机器的 CF 规则及未知旧账号黑名单不擅自删除。重复安装保留受管 jail 参数、其他 cron；定时任务以固定标记去重。配置锁忙时先持久化事件，由配置事务后/下次同步补偿。升级与封禁重载共用锁，避免载入半份候选配置。

隔离验证使用真实 Nginx/ModSecurity 与私有 Fail2Ban 配置、套接字、数据库及 crontab shim，所有攻击只到无网络容器的 Unix socket；身份注入仅用于隔离动作测试，不声称是生产 CF 回源实测。CF 接口生命周期和失败通过模拟客户端验证，未对真实 CF 账号写入，也未在生产执行攻击/失败注入。实际 cron 服务仍须在安装机器运行；`ban-status` 以真实 jail 运行状态和最近成功同步时间核验健康，pending 不会掩盖旧错误。

2026-10-28，本轮 Linux 单测 119 项全部通过，隔离真实 Nginx 1.31.8 / ModSecurity / Fail2Ban 1.0.2 联动 54 项通过，覆盖正常业务 403 不封禁、WAF 日志到封禁、限流事件回放、跨站隔离、手动解封、安装失败恢复、多 ticket 清理、参数保留及卸载重装不恢复已清票据。原有 WAF 真实引擎集成 181 项通过；脚本另通过 10 项下载完整性检查和共享/CF/协议 smoke。发现并补偿 Fail2Ban 首次 actionban 尚未返回就执行 unbanip 时跳过 actionunban 的竞态：定时同步在锁外取得两个 jail 的完整票据快照，仅当 generation 未改变时按来源清除残留；快照失败或过时则不修剪。真实联动实际执行了保存的 cron 命令来验证补偿，不将 crontab shim 宣称为系统 cron 调度实测。

依据：[CF 自定义规则 API](https://developers.cloudflare.com/waf/custom-rules/create-api/)、[规则级新增接口](https://developers.cloudflare.com/ruleset-engine/rulesets-api/add-rule/)、[Fail2Ban 动作及票据生命周期](https://github.com/fail2ban/fail2ban/blob/master/fail2ban/server/actions.py)。

`existing-filters` 仅更新带有共享方案管理标记的既有 Fail2Ban 过滤器，不创建 jail 或动作。`retire-jails` 是显式迁移动作：只停用旧脚本按普通业务状态计数的九个网站 jail，保留 SSH 和自定义 jail；执行前应确认替代的受信事件链路已可用。不要把该动作当作新用户完整安装流程。公共旧网站 jail 模板默认关闭，不自动改变已安装的 jail；旧版原生入口重装或重新配置 CF/Fail2Ban 会重新下载传统模板，升级前须回读其启用状态。本版改走上述统一安装；CF 切换不重置现有参数，配置成功仍须结合运行状态核验。

审计使用 ModSecurity JSON 的 AHZ 部分，省略原始请求头、请求体和响应体；URI 与规则匹配信息仍可能敏感，日志权限为 0640。不要公开原始审计日志。请求体解析失败仍在 WAF 返回 400，由访问日志保留请求与状态，`nolog` 减少重复审计，其他攻击规则继续审计。当前 1.0.4 连接器仍强制写入拦截错误，不能将 `nolog` 宣称为完全抑制错误日志，见[连接器源码](https://github.com/owasp-modsecurity/ModSecurity-nginx/blob/v1.0.4/src/ngx_http_modsecurity_module.c)。

高频上报等单一业务可在管理员确认后，针对精确 `location` 使用 `error_log /var/log/nginx/error.log crit` 和 `access_log /var/log/nginx/waf-protocol.log waf_protocol`，同时保留现有 WAF 限流访问日志。该可选策略保留每次请求的状态、上游状态、耗时及请求编号，减少重复的拦截错误；正文校验、400 拒绝和 403 攻击审计保持开启。它也会减少该位置其他非致命错误细节，因此不能自动推广到所有业务位置。共享轮转同时覆盖 `waf-protocol.log`。

安装系统已有的 `logrotate`、`cron` 并启用 cron 后，可显式运行 `python3 -B configure.py rotation`。它按分钟检查 WAF 专用日志和普通访问、错误日志，分别以 10 MiB、50 MiB 为轮转阈值，各保留四份；普通日志立即压缩，WAF 专用日志沿用延迟压缩。只移除包内已知的旧容器轮转任务，保留其他 cron 项。阈值不是硬磁盘配额，高流量下一分钟内仍可超出；`copytruncate` 保留在用文件描述符，但有标准的短暂日志丢失窗口，不用于声称无损取证，见 [logrotate 官方手册](https://github.com/logrotate/logrotate/blob/main/logrotate.8.in)。

配置应用先校验完整 include/代理头继承图，保存精确原件，再检查候选语法、重载并观察新的工作进程；失败恢复原件。重复应用不增加相同配置备份。受管备份上限 128 份、64 MiB，达到限额会要求管理员归档，不静默删除恢复点。

```sh
python3 -B configure.py rollback --backup /home/web/backups/waf-managed/具体备份目录
```

后续人工改动发生冲突时回滚会拒绝覆盖，须先核对差异。停用请使用 `configure --mode off`；原生整个环境卸载会清理本包带标记的轮转任务，保留其他 Cron；备份、停容器或清理失败会中止。该入口不自动拆除管理员原有 Fail2Ban 动作或迁移封禁后端，本包也没有独立的自动卸载命令。

## 通用 Nginx 响应缓冲调优

原生安装实际下载根目录的 `nginx10.conf`，普通模式使用官方 `nginx:alpine`，WAF 模式使用在官方镜像上构建的兼容镜像；两者挂载同一份宿主配置。本次共同基线只调整响应缓冲，不提高攻击阈值、关闭正文检查或改变 CF 信任及站点开关。

| 参数 | 原公共模板 | 本版值 | 官方依据与余量 |
| --- | --- | --- | --- |
| `gzip_buffers` | `8 256k`，池上限 2 MiB | `16 32k`，512 KiB | [官方默认](https://nginx.org/en/docs/http/ngx_http_gzip_module.html#gzip_buffers)总量约 128 KiB；保留四倍总量，压缩等级仍为 3 |
| `output_buffers` | `8 1024k`，池上限 8 MiB | `2 128k`，256 KiB | [官方默认](https://nginx.org/en/docs/http/ngx_http_core_module.html#output_buffers)为 `2 32k`；保留四倍总量，兼容线程读取及 TLS/压缩输出 |

这些数值是按需使用的缓冲池上限，不是每个连接必定分配的内存，也不是上传或响应大小限制。`ssl_buffer_size` 保留原有 32 KiB；[官方默认](https://nginx.org/en/docs/http/ngx_http_ssl_module.html#ssl_buffer_size)为 16 KiB，本轮较小值在大响应中没有体现足够收益，因此未采用。代理/FastCGI 响应头缓冲、上传容量、HTTP/2/3 连接参数、缓存和超时保持原值。

通用比较入口如下；测试使用实际完整模板、20 个独立虚拟主机（10 个轮流发压）、PHP-FPM、反向代理、Range、gzip、SSE 及慢读大响应，分别运行官方镜像、WAF Off 和 WAF On。`--cpus 1` 用于控制单 worker 比较，`--cpus 2` 可验证多 worker；少量持久连接在 worker 间的分布会影响双核吞吐，不能直接当作参数收益。

```sh
python3 tests/nginx_performance.py --official-image <已核验的官方镜像> \
  --waf-image <同版本已核验WAF镜像> --baseline <原nginx10.conf> \
  --work-dir /root/nginx-perf-run --cpus 1 --seconds 8
```

所有流量仅在隔离容器间产生；前端限制 512 MiB，客户端和轻量源站各限制 256 MiB，禁止额外 swap。门禁检查正常状态、协议、完整响应字节数、前后正文摘要、gzip 解压内容、OOM、日志预算及剩余磁盘。100 ms 内存采样是观测峰值；延迟包含整个响应下载，不是 TTFB。该工具不衡量 HTTP/3、新 TLS 握手、大客户应用或真实 CDN 的容量。

2026-10-24，Nginx 1.31.8 的官方镜像及正式 WAF 镜像，在单核 / 512 MiB 下完成 42 组负载、48 项功能预检；完整大响应、协议、资源预算均通过。官方镜像大静态响应的匿名内存采样峰值为 15.85→7.85 MiB，gzip 为 24.85→10.99 MiB，慢读静态响应为 35.71→11.57 MiB。WAF On 慢读静态响应为 172.29→157.41 MiB。各模式大响应吞吐变化约为 -5.4% 至 +1.5%；这是以较小缓冲降低内存占用的折中，不宣称普遍提速。小静态响应 100 次/秒及 PHP 50 次/秒均完整完成，无网络错误、跳过或 OOM；它们是验证档位，不是整机上限。

正式服原先已使用 gzip 512 KiB 和输出缓冲 `8 16k`，因此另做了 16 组负载、32 项预检，避免混用基线。输出改为 `2 128k` 后，隔离夹具的官方镜像大静态响应约 165.9→259.5 MiB/s，匿名内存约 6.73→7.79 MiB；WAF On 为 93.9→122.9 MiB/s，约 106.79→106.89 MiB。这里是增大单块和总池上限换取输出效率，不是正式服实流量提速承诺。生产环境仅做分步更新、语法检查、重载和 20 站点源站/CDN 各一项普通 GET 比较，每步状态和选定安全头无差异；不在生产压测或发攻击样本。

新安装通过公共模板取得参数；原生脚本的三方配置更新固定本版模板及摘要，保留旧基线和管理员自定义项。仅更新镜像不会覆盖宿主配置；不满足受管基线的自定义缓冲保持原值，管理员可备份后精确调整，再检查语法、重载和验证业务。不要用完整模板覆盖用户已有的站点、认证、代理头或安全策略。试点生产保持现有压缩配置，仅对齐输出缓冲；公共模板的收益须以通用矩阵为依据。

## 1.0.5 WAF 性能调整

沿用现有组件及开关，启用 CRS 的 `tx.early_blocking=1`。仅当请求头阶段已经达到原有拦截分数时，才提前拒绝，避免继续读取、解析和检查正文；正常请求仍执行原有规则。完整配置维持 PL1、入站 5 / 出站 4，检测模式仍检查正文。镜像兼容层增加同一开关，保留旧配置的阈值及审计设置，供仍使用旧共享包的环境在升级镜像后获得此项改进。

[CRS 官方说明](https://coreruleset.org/docs/2-how-crs-works/2-1-anomaly_scoring/#early-blocking)指出，提前阻断会减少被拒请求的后续正文告警；这不等于漏过了该请求，但排查误报时应使用检测模式取得完整信息。本版已验证 949111 审计事件继续匹配现有受信过滤器，检测模式保留扫描器与正文 SQLi 告警，Off 仍由原开关控制。

2026-10-24，在同一 amd64 虚拟机上对正式 Nginx 1.31.8 / ModSecurity 3.0.17 / CRS 4.30.0 镜像做隔离比较：分别分配 1 CPU / 512 MiB / 20 站点、2 CPU / 1024 MiB / 200 站点。WAF Off、1.0.4 和 1.0.5 共 108 组矩阵；另做 12 组反向顺序复测、120 秒小 JSON、120 秒 1 MiB 上传及负载后恢复检查。普通异常状态、未发出的请求、网络错误及 OOM 会使验证失败；只有明确的单站共享出口限流工况允许 429，429 不计入业务成功吞吐量。

下表为 1.0.5 在本轮夹具上的观测值，CPU 百分比按该档分配的总核数归一化。各行是独立负载，不应相加；上游为轻量测试服务，不能代替客户应用的容量测试。

| CPU / 站点 | 请求形态 | 有效请求/秒 | 观测 P99 | CPU 利用率 |
| --- | --- | ---: | ---: | ---: |
| 1 / 20 | 小静态响应 | 150 | 5.0 ms | 43.3% |
| 1 / 20 | 约 1 KiB JSON，持续 120 秒 | 50 | 14.8 ms | 33.2% |
| 1 / 20 | 64 KiB JSON | 2 | 120.4 ms | 21.5% |
| 1 / 20 | 1 MiB multipart 上传，持续 120 秒 | 5 | 117.4 ms | 51.9% |
| 2 / 200 | 小静态响应 | 300 | 37.0 ms | 46.4% |
| 2 / 200 | 约 1 KiB JSON | 100 | 23.7 ms | 29.1% |

三轮比较中，对请求头已命中拦截阈值的扫描器请求，开启提前阻断后 CPU 利用率下降约 97%–98%；这不是所有攻击或所有请求的提速比例。正常业务没有获得同量级加速，不以短窗口波动宣称提速。单核持续负载的匿名内存约 43 MiB，上传时短暂上升约 51 MiB，结束后回落约 43 MiB；该观察窗口不能证明长期无泄漏。

按正常业务峰值实测后，至少预留 40% CPU 容量，同机应用、TLS 新建连接和磁盘写入另计；每 IP 限流值不是整机承载量。64 KiB JSON 的成本明显高于小 JSON，1 GiB 解析上限也不等于已验证 1 GiB 并发上传：本轮性能上传体为 1 MiB，更大文件须单独验证内存、临时磁盘及并发预算。不要通过关闭正文检查或提高攻击阈值来满足吞吐指标。

可复现入口（Linux、Docker、Go、openssl，使用新的短目录）：

```sh
python3 waf/tests/performance.py --image <已核验的本地镜像> \
  --baseline <1.0.4源码的waf目录> --work-dir /root/waf-perf-run \
  --suite matrix --cpus 1 --sites 20 --seconds 8
```

测试容器无公网端口、无外网，CPU 绑定且内存禁用额外 swap。覆盖 Unix HTTP/1.1、回环 TLS HTTP/2、可信代理身份模拟、直连、64 个并发 SSE、多站点及共享出口；身份模拟不是真实 CDN 压测。Off 闭环部分受发压器限制，少量长连接的闭环也不代表整机极限；小样本的 P99 不作为稳定尾延迟承诺。

每轮保留镜像、源文件和工具摘要、原始响应计数、有效吞吐、调度延迟、CPU、内存及日志数据。日志按 250 ms 检查预算，默认阈值 128 MiB；超限停止本任务发压容器，保留证据。`--suite guard --variants off --log-budget-mib 1` 用于验证此失败路径，预期非零退出。源码策略与工具验证不替代新镜像的正式双架构构建和公开产物核验。

## 2026-10-25 配置与遥测维护发布

共享配置代码固定为 [`1662016`](https://github.com/kejilion/nginx/commit/16620161a319443747ac0fc89242cbf510e89716)，原生脚本固定为 [`5edce6d`](https://github.com/kejilion/sh/commit/5edce6da87fef5f203efcc9dee98dc244eabf0c2)。本轮发布配置包和脚本维护修复，不重建或替换 WAF 镜像；旧客户端需要更新脚本后才能获得 JSON 转义、网络超时及单进程发送频率限制。

精确候选通过 74 项 Linux 单测、147 项真实 Nginx/ModSecurity 隔离检查、5 项遥测编码与预算测试、10 项固定包引导测试、47 项配置更新/失败恢复测试及 3 项备份测试。源站约 12 分钟观察中正常上报成功、旧格式请求仍返回 400，错误及审计日志增长约下降 99%；这是本轮观察事实，不代表所有部署的长期性能。中文文件名例外保持精确站点、路径、CRS 规则和 GET/HEAD 范围，其他参数攻击仍受检查。高频接口的专用日志等级属于部署配置，不进入所有站点的公共默认值。

固定包六个文件按公开提交地址逐项校验 SHA256；回退代码基线分别为共享仓库 `3c69706`、脚本仓库 `805c5f0`。公开回退应形成聚焦的恢复提交，保留固定源码身份及管理员定制。已安装 KPanel 镜像内的固定脚本仍按 KPanel 发行流程更新，本次原生脚本发布不代表面板发行或升级已完成。

## 验证与依据

2026-10-24 的 [1.0.5 正式构建](https://github.com/kejilion/docker/actions/runs/40041358151)完成 amd64 / arm64 各 36 项兼容检查，组件仍为 Nginx 1.31.8 / ModSecurity 3.0.17 / CRS 4.30.0。该批产物在隔离环境完成新共享包 73 项和旧共享包 71 项通用检查、56 组站点模板及 67 项核心 Linux 单测。原生脚本模板更新器完成 42 项 Linux 测试、10 项固定包引导测试，官方及 WAF 镜像各完成一次真实 Docker 更新与失败恢复验证；未在生产执行数据库更新或故障注入。

```sh
python3 -m unittest discover -s waf/tests -p 'test_*.py'
```

2026-10-23 的正式 Nginx 1.31.8 镜像完成 amd64 / arm64 各 36 项镜像检查；完整配置完成 71 项通用场景、15 项真实 KPanel、18 项原生升级回滚和 56 项模板组合检查，核心 Linux 单测 62 项通过。正式服镜像与配置试点为 20 站点拦截模式，40 项正常访问检查无差异。KPanel 适配候选的完整 L2 通过，包含 314 个前端测试文件、3115 项通过和 6 项跳过，以及固定脚本来源的实际镜像构建。

上一版 1.0.4 的[正式构建](https://github.com/kejilion/docker/actions/runs/39971721735)与[已验证产物发布](https://github.com/kejilion/docker/actions/runs/39974763991)使用同一批产物。发布标签为 `kjlion/nginx:alpine`、`kjlion/nginx:1.31.8-alpine`；该回滚版本的不可变镜像为 `kjlion/nginx@sha256:7827d4c2e19bfce579f6fb4ce94884a126b5ab8ea74943e5448fa4c2b3d7f894`。源码固定、CI 产物和公开镜像摘要均已核验。

生产副本迁移及真实 KPanel 用例位于 `tests/pilot_config.py`、`tests/kpanel_profile.py`。它们使用无外网、无公开端口的隔离容器；KPanel 用例不挂载 Agent，因此文件内容测试只验证请求通过 WAF 到达 Agent 边界，不代表实际写文件功能通过。

持续迭代规范、当前特性状态、后续评估队列和组件官方依据见 [PRINCIPLES.md](PRINCIPLES.md)。限流余量不能代替精确误报排除，WAF 配置通过也不等于 OWASP ASVS 整体符合性。

## 2026-10-26 公共应用兼容发布

本轮修改共享配置包，不修改 KPanel 程序、不重建镜像、不提升版本号。通用反代模板生成的混合大小写 upstream 现可正确匹配 KPanel 容器端点；混合后端、未知业务 include 或脚本转发不能自动获得 KPanel 例外。已有显式 profile 优先。Flarum 自动识别同时要求项目及安装包元数据，遇到其他反代、不同 root、未知 include 或无法证明的 PHP 脚本路径时保持默认配置档。

首次授权生产试点发现打包图标 `/desktop-icons/` 的普通文件名仍触发 `932260`，已在发布前精确回滚。补充配置档内 `assets` / `desktop-icons` 的 GET/HEAD 静态文件语法：限定目录深度、文件名与扩展名，拒绝双点及 shell 字符，仅排除该规则的路径目标；查询、正文及其他规则继续扫描。新增 12 项真实引擎正反例和真实 KPanel WebP 文件内容检查通过，公共矩阵增为 135 项、真实应用检查增为 22 项。该回退与补齐不能省略为“首次试点全部正常”。

同一试点还确认既有反代把未登录图标的 404 缓存了 10 分钟，带入口 Cookie 的后续请求仍命中该结果。KPanel 共享配置档的 server hook 增加 `proxy_cache_bypass $http_authorization $http_cookie` 与 `proxy_no_cache $http_authorization $http_cookie`，同时避免已认证内容进入共享缓存；generic 默认及管理员位置级显式覆盖保持原样。真实缓存的匿名 MISS/HIT、两个 Cookie 独立内容、Authorization BYPASS 及匿名结果保持共 6 项通过，公共矩阵增为 141 项，Linux 单测增为 78 项。此保守选择会减少带 Cookie 的静态请求缓存命中；浏览器缓存与 CDN 策略独立，不声称没有性能代价。依据：[Nginx 缓存读取条件](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_cache_bypass)及[写入条件](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_no_cache)。

缓存谓词按两个指令各自的有效继承图处理：server 已有条件时同层追加认证条件；原无条件时复制有效 HTTP 条件后追加，避免改变原有 `$arg_nocache`、自定义开关或始终绕过策略。只忽略本包已生成的 server hook 以保证重复应用和 HTTP 条件后续变更可重新计算；位置级显式列表仍由管理员决定。补充 HTTP 继承、server 自定义及替代 HTTP、location 自定义及替代 server 的 5 项真实缓存检查通过，最终公共矩阵 146 项、Linux 单测 79 项。初版 server hook 未保留 HTTP 继承的缺陷在隔离复核中发现，未部署该中间版本。

同域多个物理 server 若需要不同的继承列表，KPanel 配置档会明确中止本次应用并保留旧配置，要求管理员先统一条件，避免按文件顺序静默选择；generic 站点不受此应用配置档约束。合法引号写法及管理员自定义 include 的缓存条件也参与识别。

- KPanel：桌面窗口路径、快捷命令/链接、文件路径及操作、Compose/环境变量、终端历史、交互输入和联合通信按明确方法、端点和字段兼容。Base64 终端输入及 Noise 消息仅排除 SQLi 字段目标，不把元数据一并放行。JSON 例外拒绝同名 `json.*` 查询参数和方法覆盖头；其他字段、Cookie、头和请求解析检查保留。
- 二进制上传：仅已知文件上传/分片接口的 `application/octet-stream` 及快捷图标接口的 PNG/JPEG/WebP，调整 `920420` 与注入规则的 `REQUEST_BODY` 目标。查询参数继续检查；JSON、其他媒体类型、其他路径及其他站点不借用例外。`SecRequestBodyAccess` 保持 On；ModSecurity 3.0.17 在 Off 时会跳过 phase 2，不能用它实现“只跳过文件内容”。应用仍负责会话、CSRF、文件类型、目录权限和大小校验；WAF 不是病毒扫描器。
- WordPress：仅 GET/HEAD 的标准分类/标签/作者路径、受限含连字符的文章路径移除 `932260` 的 `REQUEST_FILENAME` 目标。其他 RCE 规则、查询和正文继续检查；不接受 shell 分隔符或编码绕过作为路径语法。
- Flarum：JSON/JSON:API 的指定发帖/编辑字段可包含代码示例，标题和其他字段继续扫描。应用鉴权、CSRF 和内容渲染安全仍由论坛负责；不将这类源码字段例外推广到所有 REST API。

KPanel 站点解析上限为 8192，默认请求达到 2048 参数仍拒绝；仅 PUT 桌面 workspace 的 JSON 正文允许至 8192 的专用预算（达到上限拒绝，防止解析截断后遗漏尾部字段）。其他站点解析上限保持 2048。该余量覆盖桌面 512 位置、512 标签及 512 隐藏项等合法结构；不提高全局正文容量或攻击评分阈值。

隔离验证使用实际 ARM64 Nginx 1.31.8 / ModSecurity 3.0.17 / CRS 4.30.0，固定本地镜像，不连接生产应用数据、Agent 或 Docker socket：79 项 Linux 单测、146 项公共应用请求形状及缓存语义、22 项真实 KPanel 鉴权/保存读回及 147 项原有真实引擎集成通过。覆盖查询与元数据攻击反例、畸形/超深 JSON、多站点、2048/8192 参数边界及超限尾部字段、9 MiB 原始文件正文、multipart、WebSocket/SSE、CDN 信任、Off/Detect/On 和重载恢复。Windows 单测 75 通过、4 项平台跳过；Linux 须使用受信私有 `TMPDIR`，不能以全局 `/tmp` 作为管理配置根目录。

失败尝试保留在隔离证据中：初版遇到 Java 原始 JSON 重复扫描、桌面参数不足、为不存在的数组项添加大量动态例外导致超时，均先复现后调整；新增例外仅对实际存在字段添加，规则列表按配置档共享编译。单 CPU ARM64 隔离样本的 32 帧输入约 246 ms，最大桌面元数据约 1 s、64 个代码快捷方式约 3.6 s、8191 个普通叶子约 6.4 s；这些是边界单次样本，不代表所有用户性能或长时间稳定性。512 MiB 旧式单体上传、所有扩展/第三方应用及真实用户终端执行未全部验证；实际应用测试只做到保存、鉴权和 Agent 边界。

最终共享配置固定为 [993ab1d](https://github.com/kejilion/nginx/commit/993ab1d89c2b19abbb89205ddc936c5962ad6828)，根/CN 脚本入口为 [d9ee024](https://github.com/kejilion/sh/commit/d9ee024ceed6b3057edad4caa3bb526e186e9cd4)，版本仍为配置包 1.0.5 / 脚本 4.5.14，不重建镜像。授权 EU 试点保持 mixed 来源信任并开启 WAF；重载/doctor、10 项正常生产请求、真实 Docker/终端 WebP、应用会话拒绝及重复计划零漂移通过。原有镜像身份不变。公开六文件与两脚本字节校验一致，生产机器已通过发布脚本实际下载、校验和幂等应用；本机两份旧入口仅对齐 WAF 固定来源与摘要，其他内容保留，恢复点分别保留。真实账户的 Docker 操作与终端执行仍需按用户实际业务复验，生产 401 只证明到达应用鉴权，不代表执行成功。

其他用户需更新脚本并通过现有 WAF 开关/共享刷新入口取得新配置；只拉取 WAF 镜像不会自动替换旧的宿主策略。已安装面板若固化旧脚本，仍需核对或更新其实际调用来源，不宣称所有旧发行包已自动升级。

依据：[CRS 精确排除](https://coreruleset.org/docs/2-how-crs-works/2-3-false-positives-and-tuning/)、[CRS 4.30 路径检查变更](https://coreruleset.org/20261002/crs-versions-4.30.0-and-4.25.2-lts-released/)、[ModSecurity v3 指令及 ctl 限制](https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-%28v3.x%29)、[3.0.17 正文处理实现](https://github.com/owasp-modsecurity/ModSecurity/blob/v3.0.17/src/transaction.cc)、[Flarum JSON:API](https://docs.flarum.org/extend/api/)。本轮仍沿用六文件固定配置包，直连/CDN 信任和现有 WAF 开关独立保留。

## 2026-10-26 公共例外执行性能与上游升级

本次候选针对 ModSecurity 3.0.17 在运行期目标排除中反复展开不相关静态标签的成本，不减少检测规则、不提高评分阈值、不扩大业务豁免。静态标签先比较字段目标，再判断标签；只要规则包含动态宏标签，就保留原有标签优先顺序及求值副作用。空排除表不额外遍历标签。依据为实际固定的[官方执行实现](https://github.com/owasp-modsecurity/ModSecurity/blob/1925753989ccce977cdaae417b55c9726c7cf02c/src/rule_with_operator.cc)及标签实现，而非将该局部补丁视为上游已发布修复。

首份镜像源码为 docker 仓库 `de1303ae5396208ca2eacb16d43d828677056f31`，补丁仅验证 ModSecurity 3.0.17 和源码提交 `1925753989ccce977cdaae417b55c9726c7cf02c`，没有增加对象成员或虚函数。该初版曾把优化适用条件作为强制构建条件；用户要求平滑跟随上游后，已调整为下述可选优化机制，不再以此阻止新引擎构建。原型阶段在原生产镜像根文件系统上替换候选库，镜像 ID 为 `sha256:84345c8095256a13dadbdd4ca776d7ef9d42d76cdd5fd47a3c7cf96aeddefda7`，库 SHA256 为 `84e6952c162275e867abe0335f239bd6528acb8333b981b85eaf5dab9f436616`。私有原型的编译前缀与正式流程不同，不作为正式发布产物。

公平比较使用相同 8511 字节脱敏 JSON，50 个位置、20 个快捷方式，正文 SHA256 为 `a97c9dfe276eee9f6618050c27b49b1307fece369e60de2243cf9802b877cef4`。各组限制 1 CPU / 768 MiB、无外网、同一轻量上游，profile/generic/Off 交错执行，每种模式 10 次，去掉前两次预热后取 8 次中位数。另用同一工具链和依赖重编原执行顺序作为对照，排除编译环境变化造成的主要收益。

| 隔离样本处理耗时 P50 | 原生产镜像 | 同工具链原顺序对照 | 候选原型 |
| --- | ---: | ---: | ---: |
| KPanel profile | 1475.49 ms | 1471.12 ms | 98.67 ms |
| generic | 113.42 ms | 113.55 ms | 93.97 ms |
| WAF Off | 2.25 ms | 2.11 ms | 2.14 ms |

该 profile 样本处理耗时下降约 93.3%，不包含公网、CDN、浏览器 debounce 或实际业务执行时间，也不是所有请求的提速或长期吞吐承诺。原始结果位于试验机私有目录 `/root/waf-perf-guard26/summary.json` 及各组 `results.json`；未公布原始桌面数据或凭据。尚未完成并发容量、长期 CPU/内存趋势及 amd64 性能比较，不能据此提高公共容量参数或减少既有余量。

原型通过完整镜像门禁、36 项镜像兼容、16 项目标排除语义对照（含动态标签、大小写、整集合、错误标签及空标签配置拒绝，逐项比较状态、规则 ID 和评分），以及现行共享包的 146 项公共应用/缓存、147 项既有引擎集成和 22 项真实 KPanel 鉴权/保存读回检查。独立复核已完成。失败尝试保留：最初测试目录只读导致 Unix socket 无法建立，修正隔离夹具写权限后通过；空字面标签本来就被 3.0.17 拒绝，改为显式验证候选和基线均拒绝，未为测试放宽解析器。

422 单独处理：KPanel 源码候选 `362e1feb17762aa3274d01cc14e0775659dc25c8` 仅补齐既有前端使用的 `/virtual-machines` 与 `/sites/monitor` 窗口路径校验，并验证相似前缀、额外路径和越界路径仍拒绝。Linux 官方变更门禁、store 竞态测试及独立安全盲审通过。生产失败请求的原始正文未记录，因此该缺口已确认，但不能断言历史每一次 422 均由它引起；不通过放宽 WAF 来处理应用校验错误。

422 按用户选择只合入源码，留待下一次 KPanel 发行，不覆盖已经发布的 rc.7 或部署新面板程序。功能提交 `362e1feb` 后补充现有扫描范围的源文件身份，集成提交为 `af2c6fbcce34d3ffe2c1b19b14a89ec656f7f051`；候选和主线 Linux CI 均通过。首次候选 CI 因第一方源码身份未重新绑定失败，修正身份后重跑，没有增加例外、变更现有扫描结论或延长到期日。已保留原任务分支精确 tip 到 `archive/fix/preferences-route-validation-20261026`。

镜像平滑升级候选 `aa9f40e` 取消强制版本锁：未知上游版本、不同源码或补丁预检不适用时，自动保留官方源码继续构建；只有精确满足已验证条件且实际打补丁成功才记录 `optimized`，其他情况记录 `upstream`。记录随镜像位于 `/usr/share/doc/kejilion-waf/modsecurity-optimization.json`，并由正式镜像读出写入构建产物 `components.json` 与 Actions 摘要。六项已验证/次版本/主版本/源码改变/补丁不适用/非法版本检查及独立复核通过；正式双架构构建与同批产物发布另按实际结果登记。退回上游可能失去本轮加速，不改变正常保护逻辑；真正的编译或业务兼容失败仍会中止发布，不能保证任何未知未来版本无条件通过。

未采用的纯规则替代也保留证据：将标签排除展开为当前 CRS 规则编号后，同一桌面样本约 409 ms，但配置从约 0.5 MiB 增至约 9 MiB，64 个代码快捷方式仍约 850 ms，因此未进入公共默认。此试验只在固定源码与隔离夹具上执行，不能宣称该转换已实现可通用维护的解析器。

共享包继续加载镜像内的官方 CRS 规则；显式正文解析、参数预算、审计和精确排除会覆盖相应默认，官方新增配置不会因此自动启用。日常规则调整不需重编镜像；引擎与 CRS 的升级仍按现有兼容门禁验证，但可选性能优化不成为其必需依赖。共享六文件 `993ab1d`、原生脚本 `d9ee024`、CDN 信任及原开关在本轮均保持原样。

最终源码为 [`aa9f40e`](https://github.com/kejilion/docker/commit/aa9f40e818629122fccce33ee722620fc2a8b427)，[正式构建 40284738493](https://github.com/kejilion/docker/actions/runs/40284738493) 完成 amd64 / arm64 原生编译，各通过 36 项兼容、16 项目标语义检查和 6 项可选优化回退检查。ARM 正式产物另通过 146 项公共应用/缓存、147 项原有引擎集成、22 项真实 KPanel 及与原镜像的 16 项语义对照。独立复核未发现可信阻断问题；未知未来引擎未实际编译，次/主版本用例验证的是准入回退流程，不冒充未来版本兼容实测。

新正式产物在同一 8511 字节脱敏请求上完成 39 项有界比较，去掉每组两次预热后的 8 次中位数为：原镜像 profile 1538.27 ms、新产物 96.57 ms；generic 119.20→91.70 ms，Off 1.88→1.90 ms。64 个代码快捷方式的三次样本中位数为 3735.63→90.53 ms；最大桌面结构约 1057→878 ms，8191 个普通参数约 6462→5601 ms，后者仍是明显成本，不能宣传已消除所有大 JSON 开销。新结果位于试验机私有 `/root/waf-engine-upstream-20261026/performance/`；所有请求只到隔离轻量上游，未在生产发攻击样本或执行用户命令，不把处理耗时当作网络或 UI 端到端收益。

EU 先后使用正式产物试点，语法、就绪、普通源站/公网请求及复查各 10 项无差异，实际 Docker WebP 内容一致，受保护接口仍由应用拒绝未登录访问；KPanel 容器、宿主策略、CF/mixed 信任及持久 Compose 保持原样。改进后镜像实际记录 `optimized / verified-source`。生产观察是本轮短窗口事实，未做长期内存或并发容量承诺。恢复顺序及原始证据分别保留在 `/root/waf-engine-upstream-20261026/previous-compose.json`（退回首份性能镜像）和 `/root/waf-engine-formal-20261026/previous-compose.json`（再退回本轮前镜像）；涉及宿主配置恢复时仍遵循更早共享包备份顺序。

[同批产物发布 40285955080](https://github.com/kejilion/docker/actions/runs/40285955080) 已完成，未重建验证后的镜像。公开 `kjlion/nginx:alpine` / `1.31.8-alpine` 同指向 `sha256:065a40f37e508787769513aca655fc541acf687afffd57b25241b1a6bac53ef8`；amd64 配置 ID 为 `sha256:2a2a84d16b8f7ed8604e378dc6a39b0b716d3a7a9723b7648f66333d888a22b4`，arm64 为 `sha256:1a31e330f71409f19042cdbc78b5bc9d423d9eab47a33b8dbc15586b156bb323`。两个架构的公开配置和 RootFS 逐项匹配各自 CI 产物；EU 实际拉取不可变公开 digest 后与试点镜像一致。首份强制源码条件产物 `sha256:c64fd9585362f51a38d5716bc961b183d3a10789e4b8849b03e6427ffc8fefb3` 已由本版公共标签替代，不再作为后续升级方案。

本轮不改版本号。现有用户通过原 Nginx 镜像更新入口取得本版即可，无须调整 CF 模式、重开 WAF 或手工维护补丁；仅更新镜像仍不会替换旧宿主规则包，也不会自动安装 KPanel 的 422 修复。镜像目录中的状态文件和正式构建报告用于核对当前是否启用可选加速，不能以版本号相同推断已取得同一产物。
