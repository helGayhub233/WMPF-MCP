# 10 · Windows 链路补齐与真机验收交接

> Windows 实施进度（2026-10-17）：下文历史基线与验收要求保留。PATH-04/05/09 已实现并完成本机单项验证；PATH-07/08 本地盘符、中文空格、缓存与环境继承部分通过，UNC／跨盘／符号链接待验。PE x86_64 的 win64-legacy 提取／静态复核与独立 Windows Hook 已实现，当前真实 DLL 的 12 项静态复核通过，JS ABI 边界回归通过；`applet_webview`／`webview` 两类已证明过滤调用点列表及精确 returnAddress guard 已实现。
> 本轮动态进展：唯一已核验的目标 browser 实际 armed，raw 实测 `1+1=2`；修复后 Portal 六项检查及 context／frame 发现通过。Playwright 通过原生 CDP 读取真实“羊了个羊”页面正文并截图，agent-browser eval 返回 2；一次受控 WebView GET 的 HAR 正文为 887 字节，与接收端 SHA-256 一致。先前 context 发现失败由旧 guard 遗漏 webview 事件调用点导致，保留该历史失败与修复范围。
> 新会话复验：原生回连、raw 返回 2、Portal 六项检查通过。默认 Portal 20000–20003 被外部 PID 4 占用，正确拒绝接管；显式使用 20102 后成功。标准 Playwright 的 canvas count 和真实菜单点击成功，菜单可恢复关闭；agent-browser eval 返回 2。双客户端受控 WebView GET／POST／HEAD 均实际到达接收端，Playwright 中文 POST 为 62 字节；agent 首次 PowerShell stdin 编码成问号，保留该错误记录，仅验收 harness 改 UTF-8 OutputEncoding 后，65 字节中文 POST 正确，不计为产品缺陷。
> 原生网络边界：实际小游戏逻辑 context 的公共 wx.getNetworkType 返回 wifi；公共 wx.request 的 fail 回调 Error.stack 定位 SDK 第 593970 行 Ee 任务状态回调，已确认创建任务后失败。仍返回 `request:fail invalid url` 且未到接收端，不能宣称 wx 原生捕获通过。
> 当前业务验收：固定名自有隔离世界修复已原生通过真实 canvas、图片与字体等待及 observer／binding 清理。京东真实业务 frame 的标准 Playwright Frame.evaluate 返回 2，正文／DOM、中文 fill、input.value 与 wx-input[value] 回读通过；agent-browser 输入、互读、清空和返回首页亦已交叉核对，MCP 精确业务 frame 的搜索／首页 selector 等待通过。小游戏默认 context 的 globalThis.eval／eval 为 undefined 是该页面的限制；agent-browser 0.39.1 的 eval 使用默认 realm，不能用其结果声称已求值所选业务 frame。
> Portal C-04 已重载并通过原生复验：根连接及 browser CDPSession 的 Target.createTarget 均返回 -32000，未知方法返回 -32601；拒绝后原页 Runtime.evaluate 仍返回 2。
> 历史失败窗口保留：跨 source 的 JSON／CBOR 整值浮点表示差异曾造成 redirect final 重复，首跳未知正文大小曾误记为 0；该旧窗口不计通过。指纹归一化与 HAR 重定向未知大小修正已回归并实际载入原生服务，随后完成二方校准。
> 最终网络实证：r1／r2／r99 共六组客户端记录、44 条请求在接收端、MCP HAR 与真实连续 agent HAR 中均为 1:1:1，未见重复、缺失或已知字段不匹配；合计 616 match／302 unknown／4 truncated，整体仍为 incomplete。N02 r99 已实测 302→307→200 多跳及声明 4096 字节、实际仅写入 1024 字节后的受控断流；失败正文与前两跳未知正文没有改记为完整匹配。
> 本轮止测边界：用户明确要求停止新增测试、避免过度测试。正式窗口为 3103.769081 秒（约 51 分 44 秒），仅完成 1 次实际重开；原“至少 30 分钟、6 次重开”规范矩阵保留，6 次未完成，不以 1 次替代或继续补做。本次按已执行范围收尾，不宣称原完整矩阵通过。
> Windows M-01 当前实证：Term5 修正后真实 prepare 完成，主程序拉起、用户登录确认通过，files_modified=false；匹配 restore 成功且 already_original=true。两棵原目录及对应备份的生产 tree_digest 与记录一致，每侧 67 个文件、1250835600 字节。维护完成后的 legacy 登录 Q&A 选择取消，notification=cancelled，保留已完成操作；这不是维护执行中取消。
> 历史维护失败保留：先前 force_stop 的 E_PERMISSION／WinError 5、已停 3 个范围内 PID 及完整备份记录不追改为成功；此前无 TTY 的 legacy 通知 EOF 为 harness 问题。后续成功不反推旧失败的具体 API 原因。
> 取消覆盖：X03 在真实 attach／create_script／load 三个原生阶段内的普通 Task 取消、清理与重新 armed 已通过；未覆盖硬截止。公开 MCP 的 X01／X02／X04 及维护 M02 仍未覆盖，不用维护完成后的 Q&A 取消替代。
> 现有证据为本地验收产物：`artifacts/continuous-term5-window-b.json`、`artifacts/har-three-way-term5-window-b-20261017-final.json`、`artifacts/native-mcp/maintenance-prepare-term5-native.json`、`artifacts/native-mcp/maintenance-restore-term5-cancel.json`、`artifacts/native-cancel-20261017-recovery-7884/summary.json`；不随仓库提交原始现场数据。
> 未通过／未覆盖：N05 公共 wx.request 仍返回 `request:fail invalid url`，未到接收端，根因未证明；公开 MCP X01／X02／X04、维护 M02、完整 6 次重开及其余未执行路径分支保持开放。本轮已按用户要求止测，不再追加这些用例；既有单项实证不等同完整 Windows 矩阵通过。之后另开验收时仍须核对所有目标 browser 均 armed，不能据受限环境 WinError 5 推导目标要求管理员。

> 基线：v0.1.0 源码，2026-10-17。本文是交给 Windows 测试员和开发者的执行单，**不是 Windows 已支持声明**。现有真实微信整链验收仅覆盖 macOS arm64。
> 只沿方法链补实现、记录当轮结果，不建立微信版本兼容表、机器身份档案或长期证据模型。版本标签未知时仍可分析。

## 1. 接手后先做什么

先读 [执行流手册](08-执行流手册.md)、[审查清单](审查清单.md) 和本文。测试员执行第 2～4 节；遇到现有未实现分支就交给开发者按第 5 节补齐。动态前提满足后，再执行第 6～9 节，最后按第 10 节回传。

**当前 Windows PE x86_64 已有“Hook → 9421 → Portal → 客户端”的真实单项链路实证；本次按用户要求收窄验收范围，未完成下文原完整矩阵。** 安装成功、PE 能反汇编、普通 Chromium 能连接、模拟 runtime 测试通过，仍不能替代对应 Windows 原生用例。下表保留本轮实施前的阻断基线；当前状态以页首说明为准。

| 本轮前可执行项 | 本轮前阻断基线，后续逐项补齐与验收 |
| --- | --- |
| 安装、启动前 doctor、MCP 初始化、13 个工具的接口检查 | PATH-04：应用／数据根与真实 executable 范围未接通，进程仍按名称查找 |
| 包与系统观察、显式 PE 文件的 summary／strings／xref／disasm／calls | PATH-05：默认实际 DLL 未传入体检和分析，缺文件时可能用目录冒充模块 |
| 指定缓存根后的包发现、解包及源码查询；实际缓存布局待本系统验证 | PATH-09：原生端口／代理诊断未实现；PATH-07／08：缓存、盘符／UNC 和变量继承待原生验证 |
| 共享协议／Portal 的受控测试、静态 PE 样本回归 | PE 偏移提取与静态校验、Windows Hook 模块／ISA／ABI／原生 CDP 旁路均未实现 |
| 检查“不支持”是否如实报告，是否在副作用前阻断 | Windows 应用备份／维护／强停／拉起／还原后端未实现；manage_wechat 连 dry_run 也不支持 |

“未实现”交给开发者；“有实现待验证”交给对应系统测试员；“当轮通过”只覆盖实际系统、目标 ISA 和用例；已经通过的分支发生回归，记为“当前失效”。不要把预期的平台阻断记成微信某个版本不兼容。

### 分工与平台选择

| 接手者 | 工作与交付 |
| --- | --- |
| Windows 测试员 | 真实安装与路径、静态链、错误分支；补实现后执行登录／重开交互、业务、网络、取消和稳定性，回传通过项及首个阻断点 |
| Windows 开发者 | 按第 5 节逐项补后端、补有意义的回归；在真实目标上验证，不删除检查来制造成功 |
| 其他平台测试员 | 复用 P0–P7 和验收判据，替换平台定位／格式／ISA／ABI／维护实现；Linux／Ubuntu 对应 PATH-06，不套用 Windows 命令 |

建议先做 Windows x64 宿主上的实际 x64 PE 链。Windows ARM64 的原生 ARM64 与仿真 x64 分开执行；只有拿到真实 x86_32 模块时才增加该分支。**宿主硬件、Python／Frida 运行环境和目标 PE ISA 分别核对**，不以 platform.machine() 或安装目录名替代目标 ISA。需要判断仿真时，开发者可用 [IsWow64Process2](https://learn.microsoft.com/en-us/windows/win32/api/wow64apiset/nf-wow64apiset-iswow64process2) 查询进程与原生机器架构，API 失败保持未知。

Ubuntu 是 Linux 的发行版；macOS x86_64 也缺动态后端。Windows 的通过记录不能关闭这些平台的缺口。

## 2. 准备源码、依赖与路径

交接材料包含本项目源码、锁文件、本文和所引用的 docs。**当前 docs/、tmp/ 为本地资料，不随 wheel／sdist 分发**；交接时另附文档，不要求测试员能访问作者机器上的历史 tmp。安装包内通用手册可通过 MCP resource `wmpf://manual/execution-flow` 获取。

需要 Python ≥ 3.11、uv，以及有权限操作的微信与测试小程序；客户端验收另需 Node.js、Playwright 和 agent-browser。先使用当前普通用户检查，权限不足时依据具体错误处理；不默认要求管理员，不关闭系统保护。记录实际工具版本用于理解当轮结果即可，不维护版本表。

以下为 **PowerShell** 命令。替换项目路径；本轮输出目录可以自行改名，重复验收另建目录保留前次失败结果。

```powershell
$WmpfProject = (Resolve-Path -LiteralPath 'D:\测试项目\WMPF-MCP').Path
Set-Location -LiteralPath $WmpfProject
$WmpfRun = Join-Path $WmpfProject 'tmp\windows_acceptance_01'
New-Item -ItemType Directory -Force -Path $WmpfRun | Out-Null

Get-Command uv, python -ErrorAction Continue | Select-Object Name, Source
uv sync --locked --extra extract --extra dynamic
if ($LASTEXITCODE -ne 0) { throw '依赖安装失败：先记录错误，不进入动态链' }
uv run --locked --no-sync wmpf-mcp doctor --goal automation
uv run --locked --no-sync python scripts/audit_mcp_contracts.py
```

以 doctor 报告的解释器和实际导入结果为准。全局 python／pip 的成功不能证明 MCP 虚拟环境可用；SDK 无法启动时，用同一项目解释器执行 `.venv\Scripts\python.exe -m wmpf_mcp.bootstrap doctor --goal automation`。某个依赖没有适用的本机包时，回传解析／安装错误，不用别的 ISA 环境伪装本机通过。无网络且依赖已缓存时才加 offline；不把网络下载失败归为 Hook 故障。

### 2.1 只读核对当前进程与实际 DLL

先手动启动微信并登录；必要时打开一次小程序以观察模块布局，**这不是正式捕获轮次**。准备 Hook 后，正式验收仍需完整关闭再打开。只查看候选进程，不强停。

```powershell
Get-CimInstance Win32_Process |
  Where-Object { $_.Name -match '^(Weixin|WeChat).*\.exe$' } |
  Select-Object ProcessId, ParentProcessId, Name, ExecutablePath
```

名称筛选只是找候选。选定确实属于本次安装的 runtime PID，再查看模块；下例 PID 必须替换，变量不要命名为 PowerShell 的只读 `$PID`。

```powershell
$WmpfRuntimePid = 12345
try {
  (Get-Process -Id $WmpfRuntimePid -ErrorAction Stop).Modules |
    Where-Object { $_.ModuleName -ieq 'flue.dll' } |
    Select-Object ModuleName, FileName, BaseAddress, ModuleMemorySize
} catch {
  Write-Warning ('模块读取失败，结果未知：' + $_.Exception.Message)
}
```

`flue.dll` 是当前 Windows 适配器使用的候选名，不保证所有安装布局相同。未找到时检查真实模块列表与实际装载关系；读取失败／空路径不能用“最大数字版本目录”顶替。目录有 DLL 也不证明当前 PID 加载了它。只把确认后的文件路径交给后续静态分析。

当前源码已分开 Windows 应用根与数据根：应用默认在 `%ProgramFiles%/Tencent/Weixin`、`%ProgramFiles%/Tencent/WeChat` 中按此顺序选择已存在目录，两者均不存在时保留前者作为候选；缓存独立默认在 `%APPDATA%/Tencent/xwechat/radium`。插件根仍从 `radium` 的兄弟 `xplugin/Plugins/RadiumWMPF` 推导，运行时以真实 executable 和已装载 DLL 核验范围，无运行实例时只接受唯一离线 DLL，缺失或歧义均明确报告。本轮 PATH-04／05 已实现并完成本机单项验证；安装文件、用户数据、runtime 插件仍可位于不同位置，其他布局须另验。历史上把 AppData 当应用根的发现缺口保留在第 1 节基线表，不再描述为现版行为。

### 2.2 端口与代理的人工观察

```powershell
try {
  Get-NetTCPConnection -State Listen -ErrorAction Stop |
    Where-Object { $_.LocalPort -in @(9421, 10000, 20000) } |
    Select-Object LocalAddress, LocalPort, OwningProcess
} catch {
  Write-Warning ('监听查询失败，结果未知：' + $_.Exception.Message)
}
```

该查询按 [Microsoft Get-NetTCPConnection](https://learn.microsoft.com/en-us/powershell/module/nettcpip/get-nettcpconnection) 读取监听与所属进程。命令成功且没有匹配项，只表示当次未观察到这些 TCP 监听；绑定时仍可能冲突。命令缺失、权限错误、输出解析失败均为 unknown。检查占用者的真实程序路径，不执行按名称批量 taskkill，不自动接管或结束外部服务。

当前 MCP 已实现 PATH-09：端口先查询 Get-NetTCPConnection，失败时回退 netstat，报告自有／外部／混合占用或当次未观察到；两种查询均不能可靠取得结果时才保留 unknown。代理分别报告 MCP 进程继承的环境变量、当前用户 WinINET 静态代理／PAC／自动发现与 WinHTTP 机器默认配置，各来源查询失败分别保留 unknown，不能解释为关闭。单个代理面板或一条 WinHTTP 查询不能代表所有代理路径；配置观察也不证明 PAC 决策或 localhost 实际可达性。人工观察用于交叉核对，本轮原生监听与代理单项已验证，完整动态网络另验。

## 3. mcp.json：默认只列三个配置项

与项目 [mcp.json.example](../mcp.json.example) 保持一致，默认 env 只列微信应用路径、裸 CDP 端口和 Portal 端口三个配置项。将以下配置并入实际 MCP 客户端，替换项目目录和实际应用路径；缓存、状态和源码工作目录使用服务端默认值，无需额外填写。

```json
{
  "mcpServers": {
    "wmpf-mcp": {
      "command": "uv",
      "args": [
        "--directory", "D:/测试项目/WMPF-MCP",
        "run", "wmpf-mcp"
      ],
      "env": {
        "WMPF_MCP_WECHAT_APP": "D:/Apps/Weixin",
        "WMPF_MCP_CDP_PORT": "10000",
        "WMPF_MCP_PORTAL_PORT": "20000"
      }
    }
  }
}
```

command／args 是 MCP 启动配置：--directory 填项目的真实绝对路径，不是微信安装目录；服务端变量展开不处理这些 args。客户端找不到 uv 时，将 command 改成实际 uv.exe 的绝对路径。

| 默认 env 配置项 | 语义与验收要求 |
| --- | --- |
| WMPF_MCP_WECHAT_APP | 实际应用安装根或明确的主程序 .exe；Windows 已按真实 executable 与实际装载 DLL 核验安装／插件范围，进程名相同的外部安装不纳入；缺失、模块读取失败或歧义须阻断，单独配置成功不代表动态链通过 |
| WMPF_MCP_CDP_PORT | 默认 10000，裸 CDP；调整时同步修改相关探针与客户端地址 |
| WMPF_MCP_PORTAL_PORT | 默认 20000，browser-level Portal；调整时同步修改 Playwright／agent-browser 地址 |

9421 是 runtime 固定回连端口，无对应配置键。应用路径和两个端口沿用默认值时也可省略相应 env 项；上述三个是默认模板列出的可选配置，不是强制填写要求。Windows PATH-04／05 的历史实现缺口已补齐并完成本机单项验证；新布局或当前模块不满足核验条件时，按第 5 节方法定位具体阻断，不重复实现已有分支。

### 3.1 可选高级覆盖：只在专项测试需要时添加

以下三个目录键不放进默认 mcp.json 模板。服务端按平台及当前 MCP 用户环境自动解析默认目录；只有缓存迁移、默认布局不适用或需要隔离测试数据时，才按需向 env 添加对应项。

| 高级可选项 | 需要覆盖的情况 |
| --- | --- |
| WMPF_MCP_RADIUM_DIR | 已确认实际包缓存不在默认位置；它与安装根独立，不因应用迁移而自动改变 |
| WMPF_MCP_HOME | 需要把本地参数、备份等状态放到指定位置 |
| WMPF_MCP_WORKSPACE | 需要把反编译源码工作目录放到指定位置 |

JSON 路径可写 `D:/目录` 或 `D:\\目录`。应用路径及高级可选目录路径支持 `~`、`$VAR`、`${VAR}`。**字面量 `%APPDATA%`、`$env:APPDATA` 不属于服务端展开语法**；PowerShell 自己的变量语法与 JSON 内字符串不要混用。

GUI 客户端不一定继承另一个 PowerShell 窗口刚设置的变量。把所需变量放进客户端 env，重启 MCP，核对 check_environment 返回的 `path_configuration`、配置来源和告警。未定义／空值／循环变量应在写文件、监听、维护前失败；不要手动创建名字含 `${VAR}` 的目录消除报错。

PATH-07／08 专项验收时，再分别覆盖默认路径、显式自定义路径、空格／中文、跨盘、实际可访问的 UNC、GUI 客户端变量继承，以及非法变量的前置阻断；不用为首次安装预填全部目录键。UNC 不可达与解析错误分开记录；macOS 上模拟 Windows 字符串不算通过。

## 4. 阶段 A：现版即可执行的检查

以下 Python 形式是 **MCP 工具调用示意，交给 MCP 客户端执行，不是在 PowerShell 直接运行**。路径和地址占位值先替换。先刷新 tools/list，应有 13 个工具；不要额外寻找独立的 package／系统／版本检查工具，它们已合并在 check_environment。

```python
check_environment(goal="automation", scope="all")
check_environment(goal="automation", scope="packages")
inspect_binary(view="summary", binary_path="D:/实际加载路径/flue.dll")
inspect_binary(view="strings", binary_path="D:/实际加载路径/flue.dll",
               pattern="OnLoadStart", limit=50)
```

| 编号 | 操作 | 通过或预期结果 |
| --- | --- | --- |
| A-01 | doctor、initialize、tools/list、手册 resource／prompt | 同一解释器依赖可导入；接口为当前 13 个工具；旧客户端缓存刷新后再判断 |
| A-02 | check_environment 全量与 scoped | 按实际 implementation_gaps 区分已实现、单项通过与原生待验；本轮 PATH-04／05／09 已通过单项，PATH-07／08 部分通过，动态／维护未覆盖项仍保留。scope≠all 不宣称整体 ready，预检不替代动态验收 |
| A-03 | inspect_binary 显式实际 PE 文件 | summary 给出 PE 格式、实际 ISA 和映射；strings 与代码查询返回可解释结果。显式 binary_path 只是离线分析，不绑定 live PID，也不绕过动态检查 |
| A-04 | 不完整路径／无 DLL／多安装目录 | 返回明确缺失或歧义，不返回目录冒充模块，不按最大版本目录猜测。目录冒充模块与默认模块缺失是本轮前 PATH-04／05 的历史缺口；当前实现若再现则按回归处理，不靠硬编码绕过 |
| A-05 | check_offsets／prepare_offsets | 当前 PE x86_64／win64-legacy 后端已支持提取与静态复核，按真实模块核验必需角色；缺配置可能先报缺失，未实现的格式／ISA／ABI 仍明确不支持。import／force 不能绕过校验，静态通过不等于动态通过 |
| A-06 | start_runtime／manage_wechat 的平台边界 | 已接入的 Windows Hook／维护分支按各自前置条件执行，缺参数、静态复核失败、目标角色歧义或未支持格式／ISA／ABI 应在副作用前阻断。manage_wechat 不运行 macOS 维护命令；Windows prepare 做完整可校验备份而不改厂商文件，restore 只接受匹配且仍为原始内容的备份，force_resign 明确不支持；真实维护仍另验 |
| A-07 | 独立静态源码链 | 指定真实缓存后 inspect_source(view="applets") → decompile_applet(appid=...) → inspect_source(view="search"／"read")；核对实际文件内容，不以有输出目录代替解包成功 |

PE 分析沿 **summary → 相关字符串 → xref → disasm／calls → 角色谓词**，需要时继续：

```python
inspect_binary(view="xrefs", binary_path="D:/实际加载路径/flue.dll",
               address="从字符串结果复制的链接期 VA", scan_bytes=262144, limit=50)
inspect_binary(view="disasm", binary_path="D:/实际加载路径/flue.dll",
               address="从引用结果复制的链接期 VA", limit=80)
```

address 使用返回行的 **链接期 VA**；不是文件偏移、RVA 或运行时指针。PE 链接 VA = ImageBase + RVA，运行时地址 = 当前加载基址 + RVA，文件偏移按节映射换算。xref 有界空结果不证明函数不存在；按返回的 next_address 续查，必要时用外部反汇编工具补查间接引用。当前字符串工具搜 UTF-8 字面量，不能以搜不到 UTF-16 字符串判定功能不存在。

OnLoadStart、SendToClientFilter 等只是分析线索。名称变化时跟真实调用与数据流，不把 macOS 的文件名、数值偏移、寄存器或对象布局当成 Windows 答案。不支持的混合 ISA／ARM64EC 等情况明确停在格式／ISA 分支，不强制指定 arm64 假装支持。

只有测试职责时，到此即可提交 A 阶段结果和首个阻断点；下游按真实原因标记未执行，不能把已具备的后端误记为缺失，也无需反复重开小程序。

## 5. 阶段 B：开发者补齐顺序与关闭条件

下表保留本轮起始缺口编号、补齐依赖与关闭条件，属于历史问题及持续验收方法，不表示各分支目前仍未实现；当前进度以页首、本轮结果和实际 implementation_gaps 为准。只为剩余方法缺口提交可独立回归的改动，不维护版本记录；每项既要有受控用例，也要有真实 Windows 样本的结果。

| 顺序／编号 | 实现入口 | 必须补齐与关闭条件 |
| --- | --- | --- |
| B-01／PATH-04 | [Windows 适配器](../src/wmpf_mcp/platform/win32.py)、[路径配置](../src/wmpf_mcp/core/config.py) | 分开应用／数据根；按真实 executable 范围筛选进程，核对实际装载 DLL。运行与未运行时的定位分别定义；无确定选择时报告歧义，不取最大目录。相同进程名的外部安装不得进入维护／注入范围 |
| B-02／PATH-05 | 同上、[环境体检](../src/wmpf_mcp/tools/environment.py) | 实现 main_module_path 或统一的实际模块入口，传给体检、默认分析、参数复核和注入。默认与显式分析指向实际文件；缺文件不返回目录；不把离线 binary_path 当运行对象选择器 |
| B-03／PATH-07、08、09 | [路径展开](../src/wmpf_mcp/core/path_config.py)、[系统诊断](../src/wmpf_mcp/core/syscheck.py)、[缓存发现](../src/wmpf_mcp/static_chain/locator.py) | 原生路径／缓存用例通过；端口区分自有、外部占用、未观察到和 unknown；代理按来源报告，不将查询失败解释成关闭。人工 PowerShell 结果不能代替 MCP 实现 |
| B-04／PE 参数后端 | [分析服务](../src/wmpf_mcp/offsets/service.py)、[提取器](../src/wmpf_mcp/offsets/extractor.py)、[二进制查询](../src/wmpf_mcp/offsets/inspection.py) | 为实际 PE／ISA 实现角色提取及静态校验；extract 和 import 走同一有效校验；地址映射、调用关系、必需数据字段不满足则阻断。Windows 更新后对当前模块重新复核，不靠旧配置标签放行 |
| B-05／Windows Hook ABI | [注入入口](../src/wmpf_mcp/tools/_injection.py)、[Hook 模板](../src/wmpf_mcp/injector/templates/hook.js)、[会话管理](../src/wmpf_mcp/injector/manager.py) | 实现真实模块选择、ISA／调用约定、参数／对象字段、调试连接与原生 CDP 收发／过滤旁路。按真实角色选取全部 browser 目标，每个目标完整安装并 armed；真实 OnLoadStart 命中与 9421 setupContext，完整 DOM／事件可解码，不崩溃；不按 attach 成败筛选目标 |
| B-06／能力分支接通 | [环境体检](../src/wmpf_mcp/tools/environment.py)、[分析服务](../src/wmpf_mcp/offsets/service.py)、[注入入口](../src/wmpf_mcp/tools/_injection.py)、[缺口提示](../src/wmpf_mcp/platform/gaps.py) | 只给已实现的具体格式／ISA 接通分支，预检、提取、校验、注入的能力判断一致；先做受控回归，再进入原生验收，实测前保留待验证状态。删除 darwin 检查、只改 Arch 键或仅把环境标成 ready 均不算实现；剩余缺口继续提示 |
| B-07／Windows 维护 | [维护工具](../src/wmpf_mcp/tools/maintenance.py)、[平台维护](../src/wmpf_mcp/platform/maintenance.py) | 明确 Windows 自己的维护动作。变更前完整可校验备份；按真实安装范围收束进程及新子进程；有界退出等待；只拉起主程序并交接登录；匹配备份可还原，不覆盖已更新文件。未实现动作继续明确不支持 |

### Hook 与维护的重点挑战

Windows 的 OnLoadStart／SendToClientFilter 静态调用链来自 flue/browser。`Win32Adapter.hook_pids()` 只为注入选择角色：先验证安装范围内真实 executable 与 argv[0] 一致，再以完整 argv 没有 `--type`、真实父进程为配置安装根内的 Weixin.exe／WeChat.exe 确认 browser，所有满足条件的 browser 都要选择。renderer／gpu-process／utility 按实际 argv 显式列为 excluded；路径、argv、父进程缺失或歧义以及未知角色均阻断，不静默省略。`running_pids()`、实际 DLL 发现和维护仍覆盖安装范围内全部 runtime。utility 的 armed 不证明 browser 就绪；不能先 attach，再把失败 PID 改称非目标。

本轮原生初试部分失败：12 个 runtime 中 1 个 browser（PID 52008）、2 个 utility、8 个 renderer、1 个 GPU；2 个 utility 完整 armed，8 个 renderer 和 1 个 GPU 拒绝脚本 load。结合 flue/browser 的静态角色证据修正选择方法，不能从这次初试追认 browser armed 或整链成功。后续 raw 已实测 `1+1=2`，Playwright 已连接 Portal，并通过 CDP 读取真实“羊了个羊”页面正文；全部目标 browser 的覆盖核对及 P4–P7 剩余业务、网络与持续连接验收仍须完成。PID 仅用于解释本轮观察，不扩展为长期证据模型。

Portal context 先前发现失败另有明确的事件路径原因：旧过滤 guard 只接受 `applet_webview`，当前目标的 `Runtime.executionContextCreated` 与 `Network.requestWillBeSent` 经 `webview`。静态分析与原生观察共同证明后，将两类调用点列入 `FilterCallSites`，逐项复核源文件引用、函数边界、输入 span、输出槽、tag 和返回 ABI；在被调函数入口仅接受 `returnAddress` 等于列表中某个 call 实际下一条指令地址的调用。不得扩大为所有 caller、固定套用 call+5，worker 与无角色证据的调用点仍不启用。修复后的 Portal context／frame、真实 canvas 等待及京东业务 frame 的标准求值／输入已原生通过；完整 HAR、原生 wx.request 与持续连接仍待验收，当前网络修正须重载后重新核验。此处不记录具体版本偏移或私有 URL。

macOS 模板直接使用 arm64 寄存器、SceneChain、remoteDebug 字段与特定对象布局，不能移植几个偏移就称为 Windows 后端。Windows x64／ARM64 的函数参数、结构体、字符串布局、返回值与异常处理要分别分析；Frida 的 attach／native 调用约束参见 [JavaScript API](https://frida.re/docs/javascript-api/)。

遇到 unable to intercept function，先确定角色、地址、实际指令、已有插桩与可重定位条件。macOS arm64 曾改用被调函数入口核对调用方；该平台的 BL+4 不能直接搬到 x64，x64 call 长度也不能一律假定为 5。安装失败应回滚并阻断 armed，不吞错继续，不通过乱改分支、强置寄存器、tag 0→6 掩盖问题。

Windows 不执行 codesign、ad-hoc 或 SIP 流程。当前 IsUserAnAdmin → inject_mode 的结果只是权限线索；管理员状态既不能证明 attach 可行，也不能补出缺失的后端。先核对目标与操作者权限及实际 attach 错误，再决定处理方式，不把关闭防护或移除厂商签名作为安装步骤。

维护后端与动态后端分别验收。**已有合适运行条件时，可手动启动／登录微信，先验收动态链；这不关闭 B-07，也不能宣称自动维护整链通过。** 若实现维护前需要修改文件，先具备备份和还原，再做真实修改。

## 6. 阶段 C：后端补齐后执行 P0–P7

开始前明确本轮业务就绪 selector、可恢复的点击／输入动作、测试 HTTP 接收端与 wx.request 可实际访问的地址。先读实际 tools/list；实现变化后更新本文，不根据示例猜参数。

| 阶段 | 执行顺序 | 必须看到的结果；否则停在本阶段 |
| --- | --- | --- |
| P0 | check_environment(goal="automation", scope="all") | 同一解释器依赖可用；真实 PE、目标 ISA、进程与模块一致；对应后端已实现；没有未解释的阻断。environment_ready 只表示预检 |
| P1 | 手动启动并登录；manage_wechat 原生维护另验 | 仅拉起微信主程序，停在“进入微信”界面交给用户；现有 Q&A 取得登录确认后重做 P0。Windows 维护实现已具备，prepare 不修改厂商文件，仅备份、精确收束进程并拉起主程序；尚未完成的原生维护不以手动登录代替通过 |
| P2 | check_offsets；未就绪时 prepare_offsets(source="extract" 或 "import") | 当前实际模块静态角色与数据链校验通过；无已知版本标签也可分析；旧参数不直接复用 |
| P3 | start_runtime(component="all")；需要时 probe_runtime(layer="hooks") | 先 9421／裸 CDP 监听，再 Hook；按路径／argv／真实微信父进程核验的所有目标 browser 完整 armed、无准备失败；非 browser 显式 excluded，元数据缺失或歧义阻断；script.load 返回或某一个 PID 成功均不够 |
| P4 | MCP Form Q&A 提示完整关闭再打开小程序；确认后 probe_runtime(layer="reconnect") | 真实回连 socket 与 setupContext；不等同业务首页已加载 |
| P5 | probe_runtime(layer="raw", timeout_s=5) | 1+1 实际返回 2；裸 10000 没有 browser discovery，是已知负例，不能拿 Playwright 连接失败判引擎坏 |
| P6 | start_runtime(component="portal") → probe_runtime(layer="portal") → page 探针 → 双客户端业务 | /json/version、Target／session／frame／context 正常，业务内容可见；完成第 7 节，不只测握手 |
| P7 | query_traffic 核对第 8 节；结束持续 HAR，再 stop_runtime(component="all") | 网络事件与实际接收端一致；本 MCP 所有监听／Hook／等待清理，保留外部服务与微信登录状态 |

业务就绪示例，必须替换 selector；frame_name 可省略，限定时用实际发现值：

```python
probe_runtime(layer="page", ready_selector="[data-test='business-ready']")
```

**page 固定 60 秒这一档，不传 timeout_s**。使用 DOM／binding／资源事件，到条件满足即可返回；图片／字体按实际探针结果判断。非 page 探针默认 10 秒，最多 30 秒。客户端请求超时应容纳 60 秒及有界清理，不靠 sleep、重复 inspect_runtime 或“截图文件已生成”判断加载。

白屏先检查当前 target／frame 和实际资源状态。60 秒未满足返回 E_PAGE_NOT_READY，记录条件与当时观察；资源还在加载不直接判 CDP 损坏。失败后只有条件、资源或实现有变化才重新等待。

小程序重开提示必须等监听和 armed 就绪，使用现有 MCP Form Elicitation。客户端不支持 form 时由客户端 Q&A 转达并取得用户确认；不新增系统弹窗、浏览器或 iframe。确认打开只允许推进回连检查；用户取消时清理自有调试资源后返回，不能继续启动。重新提问不重做已完成的维护／注入，旧周期答案不复用。

## 7. 双客户端、target／session 与业务验收

Portal 提供现有 runtime 的 browser-level 兼容视图，不承诺完整 Chromium 能力。Playwright 官方也说明 [connectOverCDP 与 Playwright 协议连接存在能力差异](https://playwright.dev/docs/api/class-browsertype#browser-type-connect-over-cdp)。本项目以实际方法返回及业务结果验收。

### 7.1 Playwright：保留一个连接，按实际页面选择

在本轮独立测试目录安装 Playwright，避免改项目依赖；PowerShell 中执行：

```powershell
$WmpfClientDir = Join-Path $WmpfRun 'clients'
New-Item -ItemType Directory -Force -Path $WmpfClientDir | Out-Null
Set-Location -LiteralPath $WmpfClientDir
npm init -y
npm install playwright
node
```

连接 Portal 不需要在此下载 Chromium。普通 Chromium 对照是另一项测试，执行时按 Playwright 实际安装说明准备浏览器。下面在 **Node REPL** 中逐段执行并保持该进程；多行可用 `.editor` 输入，参见 [Node REPL](https://nodejs.org/api/repl.html)。

```javascript
var { chromium } = await import('playwright');
var browser = await chromium.connectOverCDP('http://127.0.0.1:20000', { timeout: 15000 });
var disconnects = 0;
browser.on('disconnected', () => { disconnects += 1; });
var pages = browser.contexts().flatMap(c => c.pages());
pages.map((p, i) => ({ i, url: p.url(), frames: p.frames().map(f => ({ name: f.name(), url: f.url() })) }));
```

根据上一步 discovery 与 page 探针的 matched 信息填写下面三个变量，不能固定选第一个 Page／外层壳：

```javascript
var selectedPageIndex = 0; // 换成刚才发现的业务 Page 索引
var observedFrameName = '替换为当次 matched.frame_name';
var readySelector = '[data-test="business-ready"]'; // 换成真实业务 selector
var page = pages[selectedPageIndex];
var frame = page.frames().find(f => f.name() === observedFrameName);
await frame.locator(readySelector).waitFor({ state: 'visible', timeout: 60000 });
await frame.evaluate(() => 1 + 1);
await frame.locator(readySelector).innerText();
await page.screenshot({ path: 'baseline.png' });
var session = await page.context().newCDPSession(page);
await session.send('Runtime.enable');
```

截图人工核对实际内容。后续在原进程保留 browser／默认 context，替换 runtime 后重新发现 pages／frame、建立新 CDPSession。记录旧 Page 关闭、旧 session 失效和新 session 命令成功；不能每轮重新 connectOverCDP 后声称持续连接恢复。Node 中的相对文件写到 clients 目录。

### 7.2 agent-browser：固定同一会话，重新选择当前 tab／frame

在另一个 PowerShell 窗口使用已经安装的 agent-browser，先记录 `agent-browser --version`、核对 `--help`。本项目不捆绑该客户端；CLI 不支持某命令时记录客户端限制，不发明 Portal 补丁。

```powershell
agent-browser --session wmpf-win --cdp 20000 tab list
# 用当次 tab list 返回值替换；不要照搬历史 t1、webview-0
$WmpfTabId = '替换为当前 webview 的 tabId'
agent-browser --session wmpf-win --cdp 20000 tab $WmpfTabId
agent-browser --session wmpf-win --cdp 20000 frame 'iframe[name="替换为实际frame名称"]'
agent-browser --session wmpf-win --cdp 20000 snapshot -i
agent-browser --session wmpf-win --cdp 20000 get text '[data-test="business-ready"]'
agent-browser --session wmpf-win --cdp 20000 network har start --content all
```

保留同一 agent 会话及 HAR；最后一条只执行一次，到所有轮次结束才 stop。每个命令显式带 --cdp；frame／selector 替换成实际值。get text 是页面命令，HTTP GET／POST／HEAD 应通过实际页面 fetch 或原生 wx.request 发出。

| 编号 | 必测动作 | 通过判据 |
| --- | --- | --- |
| C-01 | 两客户端连接／读取／求值／截图 | 读取相同业务内容，1+1=2，截图有实际正文；虚拟 appservice／webview 名字不证明两套独立 runtime |
| C-02 | 安全点击、输入、读取结果并恢复输入 | 可见业务变化可核对，两客户端读回一致；恢复原值。不要用产生订单等不可恢复操作当探针 |
| C-03 | 完整 DOM／可访问性快照、正常尺寸截图 | 检查大响应与深层结构，不只用短求值证明 CBOR 正常；解码失败进入第 9 节保留诊断 |
| C-04 | 未知 browser 方法、独立新页请求后恢复 | 未知根方法应返回 -32601；Target.createTarget 明确 -32000 不支持独立页。随后原页读取／命令仍正常；不允许空对象假成功，也不改成可任意创建上下文的产品承诺 |
| C-05 | runtime 替换后的 target／session | 真实断连与 setupContext、新 target 出现、旧 Page／session 失效，新对象页面操作和网络恢复；浏览器级连接持续，旧 ID 不复用 |

当前已知 agent-browser 某些 iframe 命令可能选中外层，HAR 的跳转／大小字段也曾在普通 Chromium 复现缺陷。命令失败时，与同一 context 的直接 CDP／Playwright 及普通 Chromium 对照，归属到具体客户端／Portal／runtime；不要把所有问题都归为微信。

## 8. HTTP、wx.request 与 HAR 完整性

准备自己可控且获准访问的 HTTP 接收端；先验证实际可达性、HTTPS／证书、CORS／预检、地址白名单等条件。用每轮／每客户端／每方法唯一 URL 标记请求，例如 `/wmpf/round-01/playwright/POST`；无需建立机器身份档案。禁止盲目重放业务写请求。

Playwright 在真实渲染 frame 发请求的例子（Node REPL；换成接收端真实 URL）：

```javascript
await frame.evaluate(async () => {
  const response = await fetch('https://替换为受控接收端/wmpf/baseline/playwright/POST', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ text: '中文正文', phase: 'baseline' })
  });
  return { status: response.status, body: await response.text() };
});
```

agent-browser 使用实际支持的 eval 调用同样请求并确认所在 frame；如果命令实际落到禁用 eval 的外层，先记录并处理客户端选择问题，不以 Node 主进程 fetch 或普通浏览器请求冒充小程序流量。

| 编号 | 覆盖内容 | 必须交叉核对 |
| --- | --- | --- |
| N-01 | 两客户端分别 GET／POST／HEAD | 接收端真实收到的 URL、方法、状态、请求头、POST 中文正文、响应头／正文；HEAD 响应正文为空。不只核对客户端宣称发出 |
| N-02 | 302／多跳、307 保留方法、404／失败请求 | 每跳独立 ledger id，Location 与方法变化符合实际接收记录；失败有明确状态，不凭末跳补首跳正文 |
| N-03 | gzip、二进制、已知大小及头部 | 编码实体大小／解码内容大小／含头传输大小分别核对；未知 -1，不能补 0。二进制 base64；ExtraInfo 中的头不漏、不串跳 |
| N-04 | 扩展方法 PUT／PATCH／DELETE／OPTIONS | 在受控端接受后再测；区分测试主动发出的 OPTIONS 与浏览器 CORS 预检，记录真实到达数量 |
| N-05 | 原生 wx.request 独立链 | 实际有 wx 能力的 context 发请求，对照原生回调、接收端、Network 事件及双侧 body；WebView fetch 通过不能关闭此项 |

wx.request 先发现实际 context 能力，不能仅凭 appservice target 名称认定。invalid url／白名单拒绝表示调用未发出，不算捕获成功或失败；接收端实际收到而没有 Network 事件，才定位原生网络链。POST 405 能证明请求／响应捕获，不能算业务 POST 成功。mmtls／ilink 等未测通道保留未覆盖。

MCP 工具核对方式：

```python
query_traffic(view="list", filter="/wmpf/baseline/", limit=100)
query_traffic(view="body", request_id="从当轮列表复制的跳次id", which="both")
query_traffic(view="har", filter="/wmpf/baseline/", limit=100, content="all")
```

调用方把最后一个回包的 `data.har` 原样保存为该段 `.har`；工具不直接写文件。**runtime 替换会清空 MCP ledger，必须在下一次关闭前导出当前段**；旧 request_id 不能跨轮用。agent-browser 自带 HAR 与 MCP HAR 分开保存，分别对接收端校验；不要相互覆盖或只检查文件能打开。

HAR 是协议语义记录，不是原始 TCP／HTTP 字节报文：cookie 头保留，但 cookie 数组尚未解析。当前 body 每侧最多 256 KiB，单份 HAR 正文总计 2 MiB、条目 4 MiB，导出最多 20 秒；ledger 最多 1000 条事务，测试流量控制在预算内。检查截断、取体失败、ExtraInfo 等待／溢出字段；有界截断按契约报告，不伪造完整正文。完整性用例使用确定大小的小样本，超限另做截断用例。

## 9. 替换、取消、稳定性与收尾

### 9.1 持续连接窗口

目标为 **至少 30 分钟、6 轮完整关闭重开**；是后续 Windows 的验收门槛，不是本文已取得的 Windows 结果。两个客户端保持原 browser 连接／agent 会话，agent HAR 一次 start 跨全程到 stop；按事件和业务条件等待，不用 sleep 脚本模拟用户重开。

每轮执行：

1. 导出当前 runtime 的 MCP HAR 和只读状态，记下本轮 target／session 与解码／Hook 错误计数；确认两个客户端仍连着。
2. 提示测试员完整关闭再打开同一测试小程序，微信主程序保持登录。只关闭窗口但没有真实 runtime 生命周期变化，不能记为替换通过。
3. 观察断连、setupContext 和 epoch／target 变化，执行一次有界 reconnect／raw／portal 检查，再按具体业务 selector 等待固定 60 秒。
4. 从最新 discovery 选择新 target／Page／frame／session；验证旧对象失效、新对象可用。agent 默认 active 可能变成 appservice，重新 tab list，不用历史编号。
5. 两客户端各读业务、做可恢复操作，各发 GET／POST／HEAD，核对接收端和本轮 HAR；6 轮每轮至少 6 个指定请求，基线和其他检查点另计。

同时记下 browser disconnected 次数、原连接是否被重建及 HAR 是否中断。选择页面期间真的发生 target 变化，可以根据新发现结果有界重新选择只读对象；不能盲目重放点击／POST。修复生产代码后重新建立明确的验收窗口；原失败保留，不把两个连接窗口拼成一次连续成功。

### 9.2 取消与维护分别验收

| 编号 | 触发点 | 通过判据 |
| --- | --- | --- |
| X-01 | 小程序打开 Q&A 选择取消／关闭 | 清理自有 Portal、Engine、Hook 后返回 cancelled／cleanup_complete；不继续回连，外部服务不动 |
| X-02 | 尚未满足 selector 时取消 page 等待 | 自有 observer／binding／socket／session 释放；之后可重新等待并操作页面，不误报业务完成 |
| X-03 | 真实 attach／create_script／load 中途取消 | 开发者用 Windows 原生阶段事件／受控阶段门确认取消发生在对应阶段内；回滚不残留会话，之后可重新 armed。不把原生操作结束后的取消或纯 Python 等待取消算此项 |
| X-04 | start_runtime 部分失败或取消 | 本次新资源收束，已有资源按契约保留；任一准备 PID 失败不出现重开成功提示；检查真实资源而非仅看工具已返回 |
| M-01 | Windows 维护后端完成后实际执行 | 先备份校验，再精确强停并处理新子进程，再执行已定义变更、拉起主程序、登录 Q&A；最后匹配备份还原并校验。不匹配／已更新安装明确拒绝覆盖 |
| M-02 | 维护失败／取消／持续再生 | 按既定有界截止停止，未完成强停不继续文件变更；文件变更失败可回滚。备份保留且用户得到真实结果；未实现的维护动作不算通过 |

纯取消等待与真实 Frida 原生取消分开；普通取消需按现有会话管理约定等待有界原生阶段收束，再回滚释放，硬截止另测。没有命中原生阶段就保留“未覆盖”，不能补写成功。

### 9.3 异常诊断与归属

| 现象 | 先看哪一段；下一步 |
| --- | --- |
| doctor／SDK 启动失败 | 同一解释器的导入错误／依赖安装，不进入 Hook；不要从全局 pip 成功推导 MCP 正常 |
| 模块 unknown、路径是目录、无 runtime | PATH-04／05、实际 executable／DLL／目标 ISA；显式文件只能推进离线分析 |
| E_UNSUPPORTED_ANALYSIS | 先确认缺的是 PE 校验还是动态 ABI 后端；按 B 阶段补实现，不改平台字段、不导入 Mac 偏移绕过 |
| attach 失败／unable to intercept | 实际权限、模块装载、角色地址／指令、Frida 错误；管理员标记与静态反汇编不能替代 attach 成功 |
| armed 但没有命中／9421 回连 | 当前 PID 是否处理这次加载、Hook 角色与参数、是否在 armed 后完整重开、端口是否被外部占用；不反复重签或无限等待 |
| raw 正常而 Portal／客户端异常 | discovery、Target/session 路由、实际方法错误；用同方法直接 CDP 和普通 Chromium 区分客户端问题 |
| 重开后 unknown tab／失效 session | 是否仍用旧 ID，重新发现当前 webview、Page／frame；先恢复只读命令，不自动重放业务写入 |
| 白屏／E_PAGE_NOT_READY | 业务 selector、当前 frame 与资源事件；完整加载前的空白截图不能判页面能力失效 |
| 请求发不出／HAR 缺项 | 先对照真实接收端与调用返回，再区分地址策略、context、native 事件、Portal ledger、客户端导出器 |
| CBOR／原生过滤异常 | 消息类型、失败阶段、长度、运行时替换边界、结构化错误摘要；完整 DOM／关闭事件分别复现，必要时有界保留原帧后本地重放 |

不无限写原始报文：沿现有边界保留最多 3 帧、总计 16 MiB，错误摘要最多 10 条、每条 2 KiB；先保存阶段／长度等摘要，确需内容才在本地验收辅助程序中有界导出。公共 MCP 没有新增“原帧下载”工具，不假定 query_traffic 能返回 CBOR 原帧。HAR／日志只回传本次问题需要的片段，清理认证信息与业务隐私，不添加遥测上报。

结束时先停止同一 agent HAR，保存原件，再释放客户端连接，最后调用 stop_runtime：

```powershell
# 原 agent 会话所在窗口执行；替换为本轮绝对输出路径
agent-browser --session wmpf-win --cdp 20000 network har stop 'D:/测试项目/WMPF-MCP/tmp/windows_acceptance_01/agent-continuous.har'
```

Playwright Node REPL 中 `await browser.close()` 释放本客户端连接，随后退出 REPL；MCP 客户端调用 `stop_runtime(component="all")`。核对自有监听、Hook 与等待确实释放；停止本轮辅助接收端／客户端会话，不按端口或程序名结束外部进程。保留微信主程序登录，维护备份不自动删除。

## 10. 回传模板与关闭规则

每轮交一个简短 Markdown 结果和必要附件即可。以下信息用于解释当轮测试，不扩展成机器身份／二进制指纹档案；PID／target／session 只在本轮定位与生命周期验证中使用。

```markdown
# Windows 当轮结果

- 测试日期／测试员：
- 源码基线：v0.1.0 + 本轮修改范围／提交号（有 Git 时填写）
- Windows 系统／构建（可获取时）、宿主架构：
- Python／Frida 运行环境、实际 PE 格式与 ISA；是否仿真：
- MCP 客户端与 Form Q&A 是否可用；Playwright／agent-browser 实际版本：
- 测试小程序、具体业务就绪条件、安全业务动作：
- 当前结论：静态链／动态链／自动维护链分别填写

| 用例／缺口编号 | 状态 | 预期与实际差异 | 首个错误／所属层 | 当轮附件 |
| --- | --- | --- | --- | --- |
| PATH-04 | 未实现／待验证／当轮通过／当前失效 | | | |
| A-01…A-07 | | | | |
| B-01…B-07 | | | | |
| C-01…C-05 | | | | |
| N-01…N-05 | | | | |
| X-01…X-04、M-01／02 | | | | |

- 双客户端持续窗口：起止／时长、真实重开轮数、断连／重建次数：
- 每轮指定请求：接收端／MCP HAR／agent HAR 的预期与实际数量：
- Hook／解码错误、保留诊断的上限与实际数量：
- 修复内容与回归命令／结果；Windows 原生复验结果：
- 首个阻断点、下游未执行项、下一步方法分支：
- 自有资源清理结果、文件是否修改、备份／还原结果：
```

回归使用项目既有工具契约审计与测试：`uv run --locked --no-sync python scripts/audit_mcp_contracts.py`、`uv run --locked --no-sync pytest -q`。把平台专有用例的合理跳过、真实失败和原生微信 opt-in 未执行分别列出；不能只写“pytest 通过”替代 Windows 微信验收。新后端需为真实缺陷补必要回归，不复制实现堆断言。

关闭某项缺口需同时满足：代码中实际有该分支、对应回归有效、目标 Windows／ISA 的真实执行通过、工具与文档不再宣称未实现。共享受控测试通过只关闭对应受控项。维护、原生 wx.request、双客户端业务和稳定性分别判断，未覆盖项继续保留。

将当轮结论补到 [审查清单](审查清单.md)，方法有变化时更新本文／执行流及包内手册，保持实际工具描述一致；**不更新或重建 debug.md，不建立版本表，不添加 Sentry**。历史 macOS 原始记录不改写成 Windows 结果。

### 可直接转交测试员／协作 Agent 的任务说明

> 请基于当前源码和 docs/10-Windows链路补齐与验收.md，在真实 Windows 上先完成 A 阶段。读取实际 tools/list 和 check_environment 的 implementation_gaps，按“实际模块／ISA → 字符串／xref／数据流 → 角色与静态校验 → 按 PID Hook／armed → 9421 → 裸 CDP → Portal → 客户端业务／网络／HAR”推进。当前代码已具备 Windows 路径与原生诊断、PE x86_64／win64-legacy 提取复核、独立 Hook ABI 和维护后端；PATH-04／05／09 本机单项已通过，其余部分通过或原生待验，按页首状态续接，B 阶段仅用于剩余缺陷及关闭条件，不重复实现已有分支。raw 与 Playwright 读取真实页面正文已有单项进展，过滤事件链修复后的 context／frame 及真实 canvas 业务等待已单项通过，真实输入、原生网络与持续运行仍待验收，完整 Windows 链尚未宣称成功。不要删除平台检查、复制 macOS 偏移或以管理员状态代替注入验证。具备动态条件后再提示用户重开；业务等待只用事件驱动固定 60 秒。分别验收原生 wx.request、runtime 替换、双客户端持续连接、HAR、真实中途取消及维护还原，异常有界保留并修复。回传当轮结果与剩余方法缺口，更新审查清单；不维护版本表／现场身份模型，不改 debug.md。
