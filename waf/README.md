# 共享 WAF 配置

本目录管理现有 Docker Nginx + ModSecurity v3 + OWASP CRS 的配置。1.0.5 包含通用 Nginx 响应缓冲和 CRS 提前阻断调优，已在正式服 20 个站点完成分步试点。既有 KPanel 同源适配分支已通过完整 L2，面板版本发行另行进行。

后续性能、安全、官方新特性和依赖迭代统一遵循 [通用 Nginx 性能与安全规范](PRINCIPLES.md)。以官方 Nginx 为共同基线，WAF 按需扩展；按“官方核对→隔离比较→独立复核→正式服试点→同一产物发布→公开与消费回读”推进。已启用、仅版本支持和待评估的特性分别记录，未验证收益不计入完成项。

## 架构边界

沿用已有 CDN、Nginx、ModSecurity/CRS 和 Fail2Ban 链路。配置工具使用 Python 3.11+ 标准库，不安装 WAF 常驻服务，不新增 HTTP/Unix Socket 检查服务，不自动替换封禁后端。新增后端须另行评估。

`banBackend: existing` 仅保留试点既有的按站点 IP map 接口；它要求安装环境已具备受信事件消费、到期及解封机制，不会凭空安装这些组件。新部署示例为 `none`：仍执行请求拦截及限流，但不宣称具备累计自动封禁能力。既有未声明此字段的试点策略保持原有 map 语义。公共默认提供请求拦截和限流；累计封禁继续使用管理员已有的受信机制，不自动新增封禁后台服务。

## 使用前提与入口

需要 root、Docker 中名为 `nginx` 的现有容器、`/home/web` 原生布局，以及兼容的 ModSecurity/CRS 镜像。当前实测版本为 Nginx 1.31.7 / 1.31.8、ModSecurity 3.0.17、连接器 1.0.4、CRS 4.30.0；其他组合不能直接视为已验证。先备份并在隔离环境验证。

日常仍使用原生环境防护菜单中的 WAF 开关。接入后可使用 `k web waf status`、`k web waf doctor` 诊断。原生脚本固定共享提交及六文件摘要；下列 Python 入口用于已经取得并核验完整配置包后的高级设置：

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
python3 -B configure.py status
```

不带 `--site` 的 `configure --mode` 会统一全部站点模式并清除模式覆盖；已有业务配置档及精确排除仍保留。`off` 关闭规则引擎检查，Nginx 的独立限流仍有效。历史整站 Off 自动迁移到检测模式，须完成业务验证后再开启拦截；位置级自定义关闭保持原状并由管理员继续盘点。

站点中重复的 `modsecurity on` 统一继承 HTTP 全局开关；嵌套 Off→On、外部 include 中的独立开启需明确整合，自动迁移会拒绝处理。历史原生开关仍有效，普通刷新与 CF 信任更新尊重实际开关状态；显式 `configure --mode` 才改变目标模式。

兼容镜像只提供容器内部的规则基线与请求解析余量，不改宿主挂载、CF 模式或封禁动作。完整站点策略、受信代理、日志轮转与可回滚升级由同源固定版本配置包接入；不应把单独更新镜像解释为已完成所有宿主配置迁移。旧规则的评分阈值与审计开关由镜像兼容层保留，启用完整配置包后才使用本方案的阈值和审计策略。用户日常仍通过原生 WAF 开关操作。

`--profile` 必须同时指定 `--site`。`wordpress` 使用已有官方排除插件；`artifact-proxy` 限定下载路径与 Git 协议；`kpanel` 限定方法、API 路径和密码/代码参数，其他查询及用户名仍接受检查。WebSocket/SSE、上传等配置档不替代应用鉴权、代理超时或上传容量配置。

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

`existing-filters` 仅更新带有共享方案管理标记的既有 Fail2Ban 过滤器，不创建 jail 或动作。`retire-jails` 是显式迁移动作：只停用旧脚本按普通业务状态计数的九个网站 jail，保留 SSH 和自定义 jail；执行前应确认替代的受信事件链路已可用。不要把该动作当作新用户完整安装流程。公共旧网站 jail 模板默认关闭，不自动改变已安装的 jail；原生重装或重新配置 CF/Fail2Ban 会重新下载模板，须回读传统 jail 的启用状态，不能把配置成功等同于累计封禁已经生效。

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
