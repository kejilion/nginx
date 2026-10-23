# 共享 WAF 配置

本目录管理现有 Docker Nginx + ModSecurity v3 + OWASP CRS 的配置。共享配置 1.0.4、原生脚本和兼容镜像已发布；KPanel 同源适配分支已通过完整 L2，面板版本发行另行进行。

## 架构边界

沿用已有 CDN、Nginx、ModSecurity/CRS 和 Fail2Ban 链路。配置工具使用 Python 3.11+ 标准库，不安装 WAF 常驻服务，不新增 HTTP/Unix Socket 检查服务，不自动替换封禁后端。新增后端须另行评估。

`banBackend: existing` 仅保留试点既有的按站点 IP map 接口；它要求安装环境已具备受信事件消费、到期及解封机制，不会凭空安装这些组件。新部署示例为 `none`：仍执行请求拦截及限流，但不宣称具备累计自动封禁能力。既有未声明此字段的试点策略保持原有 map 语义。公共默认提供请求拦截和限流；累计封禁继续使用管理员已有的受信机制，不自动新增封禁后台服务。

## 使用前提与入口

需要 root、Docker 中名为 `nginx` 的现有容器、`/home/web` 原生布局，以及兼容的 ModSecurity/CRS 镜像。当前实测版本为 Nginx 1.31.7 / 1.31.8、ModSecurity 3.0.17、连接器 1.0.4、CRS 4.30.0；其他组合不能直接视为已验证。先备份并在隔离环境验证。

日常仍使用原生环境防护菜单中的 WAF 开关。接入后可使用 `k web waf status`、`k web waf doctor` 诊断。原生脚本固定共享提交及六文件摘要；下列 Python 入口用于已经取得并核验完整配置包后的高级设置：

```sh
python3 configure.py configure --mode detect
python3 configure.py doctor
python3 configure.py configure --site example.com --profile wordpress --mode on
python3 configure.py configure --site api.example.com --profile api --mode on
python3 configure.py configure --site proxy.example.com --profile artifact-proxy --mode on
python3 configure.py configure --site panel.example.com --profile kpanel --mode on
python3 configure.py status
```

不带 `--site` 的 `configure --mode` 会统一全部站点模式并清除模式覆盖；已有业务配置档及精确排除仍保留。`off` 关闭规则引擎检查，Nginx 的独立限流仍有效。历史整站 Off 自动迁移到检测模式，须完成业务验证后再开启拦截；位置级自定义关闭保持原状并由管理员继续盘点。

站点中重复的 `modsecurity on` 统一继承 HTTP 全局开关；嵌套 Off→On、外部 include 中的独立开启需明确整合，自动迁移会拒绝处理。历史原生开关仍有效，普通刷新与 CF 信任更新尊重实际开关状态；显式 `configure --mode` 才改变目标模式。

兼容镜像只提供容器内部的规则基线与请求解析余量，不改宿主挂载、CF 模式或封禁动作。完整站点策略、受信代理、日志轮转与可回滚升级由同源固定版本配置包接入；不应把单独更新镜像解释为已完成所有宿主配置迁移。旧规则的评分阈值与审计开关由镜像兼容层保留，启用完整配置包后才使用本方案的阈值和审计策略。用户日常仍通过原生 WAF 开关操作。

`--profile` 必须同时指定 `--site`。`wordpress` 使用已有官方排除插件；`artifact-proxy` 限定下载路径与 Git 协议；`kpanel` 限定方法、API 路径和密码/代码参数，其他查询及用户名仍接受检查。WebSocket/SSE、上传等配置档不替代应用鉴权、代理超时或上传容量配置。

## 来源地址与 CDN

```sh
python3 configure.py configure --site direct.example.com --cdn direct
python3 configure.py configure --site cdn.example.com --cdn cloudflare
python3 configure.py trust-cloudflare
python3 configure.py refresh-ips
```

直连不信任客户端自带的转发头。Cloudflare 模式仅信任官方 IPv4/IPv6 CIDR；`mixed` 同时允许直连与 Cloudflare，直连伪造头仍无效。其他代理须在策略 JSON 中明确声明 `trustedProxies` 和 `proxyHeader`，多级代理必须实际清洗并维护可信转发链，不能自动信任整个 Docker/私网。

`trust-cloudflare` 只调整来源信任，不启用 WAF、不替换 Fail2Ban 动作、不需要 Cloudflare API 凭据。官方地址刷新失败保留旧快照，不使用任意地址作为降级信任。

## 日志、Fail2Ban 与恢复

`existing-filters` 仅更新带有共享方案管理标记的既有 Fail2Ban 过滤器，不创建 jail 或动作。`retire-jails` 是显式迁移动作：只停用旧脚本按普通业务状态计数的九个网站 jail，保留 SSH 和自定义 jail；执行前应确认替代的受信事件链路已可用。不要把该动作当作新用户完整安装流程。公共旧网站 jail 模板默认关闭，不自动改变已安装的 jail；原生重装或重新配置 CF/Fail2Ban 会重新下载模板，须回读传统 jail 的启用状态，不能把配置成功等同于累计封禁已经生效。

审计使用 ModSecurity JSON 的 AHZ 部分，省略原始请求头、请求体和响应体；URI 与规则匹配信息仍可能敏感，日志权限为 0640。不要公开原始审计日志。

安装系统已有的 `logrotate`、`cron` 并启用 cron 后，可显式运行 `python3 configure.py rotation`。它保留其他 cron 项，按分钟检查两个 WAF 日志，单文件超过 10 MiB 或到每日轮转时切分，保留四份并压缩。高流量下一分钟内仍可能超过 10 MiB；`copytruncate` 有标准的短暂日志丢失窗口，不用于声称无损取证。

配置应用先校验完整 include/代理头继承图，保存精确原件，再检查候选语法、重载并观察新的工作进程；失败恢复原件。重复应用不增加相同配置备份。受管备份上限 128 份、64 MiB，达到限额会要求管理员归档，不静默删除恢复点。

```sh
python3 configure.py rollback --backup /home/web/backups/waf-managed/具体备份目录
```

后续人工改动发生冲突时回滚会拒绝覆盖，须先核对差异。停用请使用 `configure --mode off`；原生整个环境卸载会清理本包带标记的轮转任务，保留其他 Cron；备份、停容器或清理失败会中止。该入口不自动拆除管理员原有 Fail2Ban 动作或迁移封禁后端，本包也没有独立的自动卸载命令。

## 验证与依据

```sh
python3 -m unittest discover -s waf/tests -p 'test_*.py'
```

2026-10-23 的正式 Nginx 1.31.8 镜像完成 amd64 / arm64 各 36 项镜像检查；完整配置完成 71 项通用场景、15 项真实 KPanel、18 项原生升级回滚和 56 项模板组合检查，核心 Linux 单测 62 项通过。正式服镜像与配置试点为 20 站点拦截模式，40 项正常访问检查无差异。KPanel 适配候选的完整 L2 通过，包含 314 个前端测试文件、3115 项通过和 6 项跳过，以及固定脚本来源的实际镜像构建。

[正式构建](https://github.com/kejilion/docker/actions/runs/39971721735)与[已验证产物发布](https://github.com/kejilion/docker/actions/runs/39974763991)使用同一批产物。发布标签为 `kjlion/nginx:alpine`、`kjlion/nginx:1.31.8-alpine`；本次不可变镜像为 `kjlion/nginx@sha256:7827d4c2e19bfce579f6fb4ce94884a126b5ab8ea74943e5448fa4c2b3d7f894`。源码固定、CI 产物和公开镜像摘要均已核验。

生产副本迁移及真实 KPanel 用例位于 `tests/pilot_config.py`、`tests/kpanel_profile.py`。它们使用无外网、无公开端口的隔离容器；KPanel 用例不挂载 Agent，因此文件内容测试只验证请求通过 WAF 到达 Agent 边界，不代表实际写文件功能通过。

原则和组件官方依据见 [PRINCIPLES.md](PRINCIPLES.md)。限流余量不能代替精确误报排除，WAF 配置通过也不等于 OWASP ASVS 整体符合性。
