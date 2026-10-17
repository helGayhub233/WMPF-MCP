# 08 · 执行流手册（任意 MCP 客户端通用）

> v0.1.0 · 2026-10-17。动态目标按 P0–P7 推进，每阶段核对成功判据；已有健康资源从首个未满足条件续接。源码／二进制静态问题可独立执行。
> MCP 初始化 instructions 摘要、资源 wmpf://manual/execution-flow、提示词 wechat_workflow 与本文件同步；安装 wheel 的客户端也能读取完整手册。
> 当前 13 个工具：保留原 12 个，新增明确修改应用的 manage_wechat。只记住方法链，不维护版本兼容表或现场身份、证据模型。备份中的文件校验值仅用于还原完整性。

## 执行总览

| 阶段 | 工具／操作 | 成功判据 |
| --- | --- | --- |
| P0 环境 | check_environment(goal="automation") | 所需包可导入，实际模块／ISA 可检查；版本未知允许继续分析 |
| P1 准备微信 | manage_wechat(action="prepare") → 登录 Q&A → 用户确认后重做 P0 | 完整 .bak 已校验；仅强停配置应用目录内的进程；实际签名已验证；微信主程序拉起并交给用户手动登录，确认不替代实际运行体检 |
| P2 参数 | check_offsets；未就绪才 prepare_offsets | 当前实际模块静态角色与调试链复核通过；不按版本猜偏移 |
| P3 监听与 Hook | start_runtime(component="all")；必要时 probe_runtime(layer="hooks") | 先监听、后挂钩；各准备 PID 完整安装并最终 armed，任一失败阻断重开提示；awaiting_miniapp 是正常阶段 |
| P4 用户打开 | 执行交互中的 MCP Q&A 提示完整重开小程序；确认继续后 probe_runtime(layer="reconnect") | 当前 socket 与 setupContext；这只是传输就绪 |
| P5 命令 | probe_runtime(layer="raw") | 固定 1+1 返回 2；之后仍须 frame／事件／客户端验收 |
| P6 Portal 与业务 | start_runtime(component="portal") → probe_runtime(layer="portal") → probe_runtime(layer="page", ready_selector=...) | browser/session/frame/context 正常，并等到具体业务就绪条件；随后执行真实客户端动作 |
| P7 流量与收尾 | query_traffic；按需 clear_traffic；stop_runtime(component="all") | 对照实际请求验证事件／body；释放本进程资源 |

失败停在当前条件，按结构化错误与 next_actions 分支分析；没有变化时不重复等待。协议成功和客户端／业务成功分别报告。

## P0 · 环境与进程

~~~python
check_environment(goal="automation", scope="all")
~~~

environment_ready 只表示预检。包需实际可导入；scope=packages/system/wechat 不宣称整体就绪。macOS 签名检查覆盖实际发现的主程序及 helper，逐项报告 ad-hoc／hardened runtime；签名状态是权限线索，实际 attach 才是验证。SIP 开启不意味着每台机器都须相同处理。

端口 9421 是私有回连，10000 是单 runtime 裸 CDP，20000 是 browser-level Portal。外部占用不自动接管。Linux／Ubuntu／Windows 的格式查询或模拟测试不等于已实现原生 Hook 后端。

### 路径配置与未实现分支

应用安装、radium 包缓存、本地参数／备份和源码工作目录分别读取 WMPF_MCP_WECHAT_APP、WMPF_MCP_RADIUM_DIR、WMPF_MCP_HOME、WMPF_MCP_WORKSPACE，不用项目启动目录代替安装目录。四个键及显式 module/config/backup 路径统一展开 ~、$VAR、${VAR}，不执行 shell；相对路径以服务当前目录为基准，符号链接归一为绝对目标。变量未定义／为空／循环或路径语法错误时先修正客户端 env；path_configuration 失败不进入文件写入、监听或微信维护。默认根目录、来源及告警见 check_environment.config/path_warnings。uv --directory 由客户端在启动前处理，填写真实绝对项目路径。

macOS framework 优先跟随实际 executable／Versions/Current 和 bundle 元数据；没有选择器时仅接受唯一候选。缺失模块、多个未选择版本、坏链接及越界不猜路径，先修复安装／配置再继续。当前原生验收只覆盖 macOS arm64。

| 方法缺口 | 下次在对应环境执行的工作 | 当前状态 |
| --- | --- | --- |
| Windows PATH-04 | 应用与数据根分开定位；用真实 executable 路径核对进程范围，替换仅按名称 tasklist | 未实现、未做 Windows 真机验收 |
| Windows PATH-05 | 将实际 flue.dll 传入体检及默认分析，不能用插件目录充当模块 | 未实现、未做 Windows 真机验收 |
| Linux／Ubuntu PATH-06 | 接入配置的安装根、离线模块发现，核对运行 executable／module 范围；Ubuntu 属于发行版维度 | 未实现、未做 Linux 真机验收 |
| Windows／Linux PATH-09 | 实现各自的端口和系统代理诊断；当前明确返回 unknown，不能推导端口空闲或代理关闭 | 未实现、待对应系统开发及验收 |
| Windows／Linux PATH-07、PATH-08 | 用实际缓存布局、宿主环境继承及原生路径形态验收共享解析器；Windows 盘符／UNC 尚未实测 | 共享实现存在，待本系统原生验收 |
| 非 Mach-O arm64 动态链 | 分析当前格式／ISA／ABI 并实现 Hook／提取后端；Windows／Linux 还缺应用维护后端，之后分别做原生验收 | 未实现；PE／ELF／共享解析器样本不替代原生支持 |

check_environment.implementation_gaps 随当前平台返回上述方法缺口编号。只记住缺失的方法分支，不保存版本表、机器身份或长期现场证据；后续运行不可把本机回归记录当成其他系统的通过结论。

## P1 · 解签名、精确强停、重新拉起与 .bak 还原

~~~python
manage_wechat(action="prepare", dry_run=True)  # 可先查看实际范围
manage_wechat(action="prepare")                # 执行准备；会中断当前微信及小程序
~~~

执行 prepare 时先释放本 MCP 的资源，复制并校验完整 WeChatAppEx.app.bak，保存目录到 backup_path。备份包含整个 runtime bundle，使用 ditto 保留资源叉、扩展属性和 ACL。校验完成后，按内核实际 executable 路径选择配置的 WeChat.app 目录内进程，使用临时父子关系优先停止父进程；每次 SIGKILL 前重新核对路径、先订阅退出事件。退出事件到达后重新检查并收束期间新生的应用内进程，整个强停共用 10 秒截止，不 sleep 轮询，也不把新子进程直接当作维护失败。持续再生或无法退出才报超时，文件操作不会继续。

之后将实际发现的主程序／helper 改为 ad-hoc，显式去掉 hardened runtime，保留 identifier、entitlements、requirements。默认复用已经符合条件的单元；需要实际重新签名时，可显式使用 manage_wechat(action="prepare", force_resign=True)，该参数只适用于 prepare。signed_binaries 列出本次签名命令实际完成的单元，dry_run 或全部复用时为空。逐项核验后只拉起微信主程序，由用户在“进入微信”界面手动登录；不自动点击登录，不单独 open 嵌套的 WeChatAppEx.app。嵌套 runtime 可能需要从微信继承 sandbox，独立启动已有初始化崩溃实测。

prepare／restart／restore／launch 完成后，复用 MCP Form Elicitation 请求登录 Q&A，选项为“已登录，继续／取消”。确认后才建议 check_environment，之后按实际条件进入 P2/P3；选择取消／decline／cancel 结束后续流程，已完成的备份、签名或还原保留。维护执行中的取消仍按回滚规则处理，两者不混淆。Q&A 等待在生命周期锁外；新协议续接校验原工具、参数和 request_state，不重复备份、签名、强停或拉起。stop_runtime 或新维护使旧提问失效。dry_run 不提问；不支持 form 的客户端返回 awaiting_login 和明确手动登录提示，不自动推进后续工具。

launch.requested 和用户确认登录都不等于 runtime、Hook 或业务页面就绪。登录后仍需实际 P0；runtime 应由微信正常创建，再按 P2/P3 准备监听与 Hook。当前维护验收以拉起主程序、停在登录界面并交接 Q&A 为终点，不要求自动登录。

~~~python
manage_wechat(action="restart")                  # 精确强停并拉起；不签名
manage_wechat(action="launch")                   # 仅请求拉起
manage_wechat(action="restore", backup_path="prepare 返回的备份目录")
~~~

restore 核对备份校验值、原安装位置及当前 before/after 文件状态；拒绝覆盖微信更新后或不匹配的安装。还原通过同目录临时 bundle 切换，保留原 .bak。部分签名失败时先回滚，再拉起原文件。取消要等子进程、回滚和拉起收束后才释放操作锁。

当前账户必须具备应用写权限及目标进程操作权限；失败返回 E_PERMISSION，不自动 sudo、修改权限或安装依赖。prepare/restart/restore 为明确有副作用的动作，AI 应在用户授权的维护范围内调用。备份仅保证还原 prepare 前的文件状态；若当时已是 ad-hoc，不能据此恢复腾讯原始签名。

## P2 · 参数准备与方法链

~~~python
check_offsets()
prepare_offsets(source="extract")  # 只在当前参数未通过时
prepare_offsets(source="import", candidate_path="/path/to/checked.json")
~~~

沿实际格式／ISA → 字符串 → xref／数据流 → Hook 角色 → 当前模块复核推进。版本号仅是可选标签，未知不阻塞分析。提取失败读 methodology／branch_guidance；无法证明的字段不猜测。缺少完整必需角色时不进入动态注入。

## P3–P4 · 就绪后提示用户打开

~~~python
start_runtime(component="all")                     # 新会话默认在执行交互中请求 Q&A
probe_runtime(layer="hooks", timeout_s=10)          # 仅在需要等待 armed 时
probe_runtime(layer="reconnect", timeout_s=10)      # 完整打开一次后有界等待
~~~

`script.load()` 返回不证明 Hook 初始化成功。模板完成所有配置项的 attach／flush 后才发送最终 armed；每个 PID 按初始化事件等待最多 5 秒，包含在原生阶段总计 30 秒截止内。安装异常按角色、偏移、地址和实际指令报告，回滚已装 Hook，失败 PID 不提交；部分 PID 成功仍使本次准备失败，成功会话继续归本 MCP 所有。`inspect_runtime` 提供会话 initialization／installed_hooks、last_start_failures；后者是最近一次准备的失败，不是当前进程存活证明，下一次准备按真实 PID 重新核对。停止会清除此准备失败状态，错误摘要仍保留。纯事件等待可被取消唤醒，不要求 sleep 轮询。

DebugStartBlOffset 保留为静态调用关系及返回地址参照，不直接在 BL 指令挂钩。ARM64 该位置的在线重定位只能使用 4 字节近跳转，合法指令／静态检查通过仍可能缺少附近跳板；从 DebugConnectOffset 的函数入口观察，并用 returnAddress=BL+4 核对发起方。遇到 unable to intercept function，先区分具体角色和 Frida 错误语义，再查实际指令／已有插桩／重定位条件，不默认重签、不强制寄存器／分支或忽略重定位检查。历史进程已退出时，明确不能复查当时的地址布局。

小程序重开 Q&A 只在监听运行、所有本次准备 PID 完整 armed 且没有准备失败、正在等待回连时通过 MCP Form Elicitation 请求，由客户端在执行交互中呈现，同一准备周期只问一次。选项为“打开后继续／取消”；两个选项的含义如下：

- 打开后继续：用户确认已先关闭再重新打开目标小程序；后续建议回连探针验证 socket／setupContext，不代表连接或业务已就绪。
- 取消：结束流程，依次停止本 MCP 的 Portal、监听和 Hook，清理完成后才返回 status=cancelled、cleanup_complete=true、awaiting_miniapp=false。不会继续回连或业务检查。停止对象包括当前流程复用的自有资源，不操作外部监听或其他进程。

拒绝或关闭问答按取消处理，同样停止自有调试资源。清理期间重复取消请求不会提前释放生命周期锁。某一组件停止失败时仍尝试停止其余组件，返回 cleanup_failed 与各组件停止结果；检查剩余资源后可用 stop_runtime 重试。失败或超时未取得用户确认，不自动推进后续检查，也不宣称资源已释放。

不启动系统原生弹窗，不打开外部网页或 iframe。prompt_user=False 跳过提问；客户端未声明 form elicitation 能力时返回 notification.status=unsupported 和操作提示，由客户端自己的 Q&A 取得用户确认后再探测。工具无法强制决定客户端的选项外观。

旧协议在工具调用中发送 elicitation/create（最多等待 120 秒），停止或完整回连会结束自有等待；新协议返回 InputRequiredResult，客户端把 input_responses 与原 request_state 带回相同工具和参数完成续接。续接不重复启动、挂钩或 armed 等待，停止／重启后的旧答案被拒绝。Q&A 等待不持有生命周期锁，也不消耗 hooks 探针的超时额度。协议依据见 [MCP Elicitation](https://modelcontextprotocol.io/specification/2025-11-25/client/elicitation) 与 [Python SDK 多轮交互](https://py.sdk.modelcontextprotocol.io/handlers/multi-round-trip/)。

start_runtime 不负责签名、强停或提取；这些分别由 manage_wechat、prepare_offsets 承担。不要在监听和 hooks 就绪前打开目标。每次完整重新打开后，只做一次有界回连等待。

## P5–P6 · 命令、Portal 与业务资源加载

~~~python
probe_runtime(layer="raw", timeout_s=5)
start_runtime(component="portal")
probe_runtime(layer="portal", timeout_s=20)
probe_runtime(layer="page", ready_selector=".business-content[data-loaded='true']",
              frame_name="实际观察到的渲染帧名称")
~~~

ready_selector 是示例，必须换成该小程序实际业务就绪元素或加载状态属性。不得以 body、导航栏、DOM 节点数、setupContext 或截图文件存在代替业务加载完成。frame_name 可省略，由探针观察实际 DOM/eval default contexts；需要限定页面时传真实 frame 名称。

page 层通过 MutationObserver、尺寸／DOM 事件和独立 CDP binding 等待 CSS 条件可见，并直接监听业务区域内可见图片的 load/error、等待字体就绪。page 只设固定 60 秒这一档，就绪事件到达即可提前结束，不传 timeout_s；其他探针默认 10 秒、最多 30 秒；不固定 sleep，也不靠重复 inspect_runtime。纯业务等待不占住一条长期未回包的 CDP 命令。超时 E_PAGE_NOT_READY；先核对业务条件、当前帧及加载状态。结束清理自有 observer、图片监听、binding、session 和 socket，远端清理最多另用 2 秒。图片加载失败单独警告；该条件不保证全部后台资源成功。客户端需给长等待配置足够的请求超时。

业务条件通过后，再连接 agent-browser／Playwright，在实际渲染帧定位、快照、截图、点击，并验证可见结果。frame 名称只用于选择，不按虚拟 target 名称断言业务隔离。业务条件可见只证明该条件，不代表所有后台资源、原生网络或业务流程都完成。

~~~javascript
const browser = await chromium.connectOverCDP("http://127.0.0.1:20000");
const page = browser.contexts().flatMap(c => c.pages())[0];
const frame = page.frames().find(f => f.name() === observedFrameName);
await frame.locator(actualBusinessSelector).waitFor({ state: "visible", timeout: 60000 });
await page.screenshot({ path: "loaded-page.png" });
~~~

Portal 探针覆盖 discovery（含 /json/version/）、Target/session、Page.getFrameTree、execution-context 事件与能力；真实客户端还需覆盖求值、可访问性、大截图等消息结构。1+1 或 Portal 探针通过不能替代这些操作。外层微信壳可能禁用 eval，按实际上下文能力选择渲染帧。

## P7 · 流量与收尾

~~~python
query_traffic(view="list", filter="实际 URL 片段", method="POST", limit=50)
query_traffic(view="body", request_id="列表中的当前 id", which="both")
query_traffic(view="har", filter="实际 URL 片段", limit=50, content="all")
clear_traffic()                           # 仅在确实要清空时
stop_runtime(component="all")
~~~

Portal 启动后尝试启用 Network 域，失败单独报告。ledger 只覆盖实际发出的 CDP Network 事件；body 每侧最多 256 KiB，分别报告失败和截断。原生 CBOR 单条 16 MiB 上限与 body 展示上限不同。

HAR 通过现有 `query_traffic` 返回结构化对象，由调用方按需保存 `data.har`，工具不写文件。`content=none/text/all` 控制正文；每份最多保留 2 MiB 正文、4 MiB 条目，单次导出 deadline 为 20 秒。每个重定向跳次有独立 `id`，`runtime_request_id` 可相同；取正文必须使用列表给出的该跳 `id`。首跳正文已被 runtime 丢弃时明确报不可取，不能用末跳正文顶替。ExtraInfo 按协议标志与跳次关联；等待中的头、队列溢出、缓存／失败、未知大小和截断均须看具体字段。`response.bodySize` 是编码实体大小，`content.size` 是解码后大小，`_transferSize` 包含响应头；未知保持 -1。二进制正文保留 base64。Cookie／Set-Cookie 头保留，cookie 数组未解析；这不是字节级 HTTP 报文。

WebView fetch 已有真机验收；wx.request／mmtls／ilink 原生通道需独立证明，invalid url 不能当成捕获成功或捕获失败。要核对实际接收端、事件、请求体和响应体。本机历史结果及当前未覆盖项见仓库 docs/审查清单.md。

## 执行纪律与客户端接入

- 不猜偏移、不移植未经验证的 ISA／ABI；不做 tag 0→6 放行。
- 不重叠注入实验；需要干净基线时显式 manage_wechat(restart/prepare)。
- 等待依赖事件或明确业务条件；deadline 定时器用于结束等待。
- 受控回归、真实微信验收、真实客户端业务操作分别记录。
- MCP initialize instructions、资源和 prompt 提供流程；工具校验参数和各自前提。AI 客户端仍须消费失败分支并执行真实客户端验收。
- 安装后刷新 tools/list，应见 13 个工具、完整参数说明、output schema 和行为注解。未支持资源／prompt 的客户端仍可从 initialize instructions 与 next_actions 推进。
- Portal 只有现有 runtime 的兼容视图。`Target.createTarget` 明确报不支持独立新页；失败后继续使用原 target/session；runtime 替换时从新 discovery 选择新 ID，旧会话和账本已失效。未知根方法返回协议错误；`Browser.setDownloadBehavior` 转发实际 runtime 的确认或错误，不表示下载整链已经验收。
- agent-browser 每次显式指定 `--cdp`，按命令核对 iframe 的实际上下文；客户端 HAR 与 MCP HAR 分开核对，不能只凭文件导出成功判断重定向、头部和大小完整。

## runtime 替换后续接

1. 保持 browser/CDP 连接，观察旧 target 销毁、新 target/session 出现；完整关闭重开以及小程序内部导航都可能触发新的调试连接。旧 Page、locator、CDPSession 和 MCP 账本 ID 不能继续使用。
2. agent-browser 先 `tab list`，选择本次发现的 webview 对应 tab，再选当前业务 frame。新页批量出现时，客户端可能默认激活 appservice 兼容视图；不要依赖 active 或历史 t1／webview-0。
3. Playwright 从仍连接的 BrowserContext 重新取得当前 Page/frame，继续按具体业务 selector 事件等待，固定 60 秒。如果操作本身可能替换 Page，响应监听放在 BrowserContext 层，并在收到实际响应后重新取得 Page；绑在旧 Page 上的超时不能直接解释成网络捕获失败。
4. 必需的旧正文在替换前导出；MCP 旧账本清空，agent-browser 已开启的 HAR 可跨替换继续记录。恢复后实际发出请求，核对方法、状态、双侧正文、大小与接收端，再判断捕获恢复；不保证断连期间全部在途请求。
5. 解码／Hook 异常计数变化时，先用 `inspect_runtime(component="hooks")` 读取 `recent_errors`：当前进程最近 10 条摘要，每条 detail 最多 2 KiB；用 `stage` 区分 input／decode／serialize／forward，用 `error_class`、`frame_id` 定位失败。`failure_capture` 只返回长度、截断等元数据；内存仅留最近 3 条失败帧，单帧及总量最多 16 MiB，按条数／总字节淘汰，不保留成功帧、不自动写盘。确需复现时，在同一进程通过内部诊断接口 `InjectorManager.failed_frame(frame_id)` 显式取出样本；它不是额外 MCP tool。截断样本只能分析前缀，不能据此声称整帧重放成功。
6. 原生 filter 的捕获类型名沿用 `cbor_message`，输入仍可能是 JSON：真实关闭事件 `Inspector.detached / target_closed` 为 UTF-8 JSON，不能只凭 Hook 类型名按 CBOR 解码。入口明确识别 JSON 对象；CBOR 按容器计算深度，tag-24 包装不额外占容器层级，容器栈上限 300、连续 tag 上限 16，长度／编码／尾部检查仍生效。保留失败输入→核对格式／边界→原帧重放→同场景真机复验；不建立版本表或现场身份档案。
