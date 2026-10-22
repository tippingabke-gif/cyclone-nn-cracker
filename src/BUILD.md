# 构建说明

## 编译三版本控制器

环境：Windows x64，系统自带的 .NET Framework 4.x C# 编译器。下载并完整解压离线源码包；确认 `resources/` 下的三个运行 ZIP 和三个清单均存在。仓库自动生成的源码 ZIP 只包含文本源码，运行 ZIP 需从离线源码包补齐。

在源码包根目录打开 PowerShell，执行：

```powershell
$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$outputDirectory = Join-Path (Get-Location) 'out'
New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
$compileArgs = @(
    '/nologo', '/target:winexe', '/platform:x64', '/optimize+', '/debug-',
    '/r:System.Windows.Forms.dll', '/r:System.Drawing.dll',
    '/r:System.Web.Extensions.dll', '/r:System.IO.Compression.dll',
    '/r:Microsoft.CSharp.dll', '/win32manifest:controller\unlocker.manifest',
    '/out:out\象棋旋风破解器.exe'
)
foreach ($variant in @('OPT', 'COM', 'MAX')) {
    $compileArgs += '/resource:resources\Runtime' + $variant + '.zip,Runtime' + $variant + '.zip'
    $compileArgs += '/resource:resources\Runtime' + $variant + 'Manifest.json,Runtime' + $variant + 'Manifest.json'
}
$compileArgs += @(
    'controller\BackendOPT.cs', 'controller\BackendCOM.cs', 'controller\BackendMAX.cs',
    'controller\MaxLifecycle-v406.cs', 'controller\UnifiedLauncher-v406.cs'
)
& $compiler @compileArgs
if ($LASTEXITCODE -ne 0) { throw 'Controller compilation failed' }
```

该步骤仅编译控制器，使用随包的预编译运行组件。构建结果位于 `out/象棋旋风破解器.exe`，仍需按主项目说明配合对应原引擎与 NNUE 使用。

## 运行组件源码

运行层使用 Python 3.10 x64，主要外部依赖为 `pefile`、`capstone` 和 PyInstaller。入口分别为：

| 组件 | 入口 | 附加数据文件 |
| --- | --- | --- |
| OPT | `runtime/opt/hook_runtime_entry.py` | 同目录 `guest_startup_files.py`、`guest_examine.py` |
| COM | `runtime/com/hook_runtime_entry.py` | 同目录 `guest_startup_files.py`、`guest_examine.py` |
| MAX | `runtime/max/max_worker.py` | 同目录 `max_helpers.py`、`max_rsp.py`、`max_pipe.py` |

OPT / COM 的 PyInstaller 产物名称为 `CycloneHook`；MAX 为 `CycloneMaxWorker`，均使用 `--onedir --console`。构建时需要 `--hidden-import pefile`、`--collect-all capstone`，并使用 `--add-data` 包含表中附加数据文件。

OPT / COM 的 `CycloneNetwork.cs` 编译为对应运行目录中的 `CycloneNetwork.exe`。MAX 另使用 `controller/MaxNetwork-v406.cs` 与 `controller/MaxBridge-v406.cs`，分别编译为 `CycloneNetwork.exe` 和 `CycloneMaxBridge.exe`。MAX 的 SDE 目录、许可证及依赖结构以原运行组件为准。

修改运行组件后，应重新制作该版本的 ZIP，并生成路径到 SHA-256 的 JSON 清单，再编译控制器。上述运行层说明记录源码入口与组成；本次源码整理未重新验证全套运行组件构建环境。优先使用随包已核对的运行组件完成控制器构建。

鲨鱼启动器源码与构建步骤见 [已有项目](https://github.com/tippingabke-gif/chessshark-portable-launcher)，本源码包只包含旋风助手。
