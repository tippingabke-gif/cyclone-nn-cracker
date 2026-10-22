param(
    [string]$SourceDirectory = (Join-Path $PSScriptRoot '..\src'),
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\out\compile-check')
)
$ErrorActionPreference = 'Stop'
$sourceRoot = (Resolve-Path -LiteralPath $SourceDirectory).Path
$outputRoot = [IO.Path]::GetFullPath($OutputDirectory)
$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path -LiteralPath $compiler)) { throw '.NET Framework C# compiler is required' }
New-Item -ItemType Directory -Path $outputRoot -Force | Out-Null

function Compile-Only([string]$Name, [string[]]$SourceFiles, [string]$Target = 'exe') {
    $compileArgs = @(
        '/nologo', ('/target:' + $Target), '/platform:x64', '/optimize+', '/debug-',
        '/r:System.Windows.Forms.dll', '/r:System.Drawing.dll',
        '/r:System.Web.Extensions.dll', '/r:System.IO.Compression.dll',
        '/r:Microsoft.CSharp.dll', ('/out:' + (Join-Path $outputRoot ($Name + '.ci.exe')))
    )
    if ($Target -eq 'winexe') {
        $compileArgs += '/win32manifest:' + (Join-Path $sourceRoot 'controller\unlocker.manifest')
    }
    $compileArgs += @($SourceFiles | ForEach-Object { Join-Path $sourceRoot $_ })
    & $compiler @compileArgs
    if ($LASTEXITCODE -ne 0) { throw ('Compilation failed: ' + $Name) }
    Write-Output ('Compiled: ' + $Name)
}

Compile-Only 'Controller' @(
    'controller\BackendOPT.cs', 'controller\BackendCOM.cs', 'controller\BackendMAX.cs',
    'controller\MaxLifecycle-v406.cs', 'controller\UnifiedLauncher-v406.cs'
) 'winexe'
Compile-Only 'OPT-Network' @('runtime\opt\CycloneNetwork.cs')
Compile-Only 'COM-Network' @('runtime\com\CycloneNetwork.cs')
Compile-Only 'MAX-Network' @('controller\MaxNetwork-v406.cs')
Compile-Only 'MAX-Bridge' @('controller\MaxBridge-v406.cs')
Write-Output 'Compilation checks complete. No output was executed.'
Write-Output 'CI outputs omit runtime bundles and are not release executables.'
