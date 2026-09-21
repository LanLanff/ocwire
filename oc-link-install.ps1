# oc-link 控制端（A 端）一键安装：把常驻引擎（opencode 插件）装到本机。
# 装完重启 opencode / OpenChamber，然后把 B 端的邀请码发到聊天里添加设备即可。
$ErrorActionPreference = "Stop"

$here = $PSScriptRoot
$srcDir = if (Test-Path (Join-Path $here "plugin")) { Join-Path $here "plugin" } else { $here }
$pluginDir = Join-Path $env:USERPROFILE ".config\opencode\plugins"
$ocDir = Split-Path -Parent $pluginDir

Write-Host "======================================"
Write-Host "        oc-link 控制端安装（引擎）"
Write-Host "======================================"

# ---- 插件文件 ----
New-Item -ItemType Directory -Force -Path $pluginDir | Out-Null
foreach ($f in @("client.mjs", "oc-link.ts")) {
  $src = Join-Path $srcDir $f
  $dst = Join-Path $pluginDir $f
  if (-not (Test-Path $src)) { Write-Host "  [错误] 缺少 $f" -ForegroundColor Red; exit 1 }
  if ((Test-Path $dst) -and ((Get-FileHash $src).Hash -eq (Get-FileHash $dst).Hash)) {
    Write-Host "  [已是最新] $f" -ForegroundColor DarkGray
  } else {
    Copy-Item $src $dst -Force
    Write-Host "  [已安装] $f" -ForegroundColor Green
  }
}

# ---- 插件依赖 @opencode-ai/plugin：优先随包便携版，其次 npm ----
$depPkg = Join-Path $ocDir "node_modules\@opencode-ai\plugin\package.json"
if (Test-Path $depPkg) {
  Write-Host "  [已存在] 插件依赖" -ForegroundColor DarkGray
} else {
  $payload = Join-Path $here "payload\node_modules"
  if (Test-Path $payload) {
    New-Item -ItemType Directory -Force -Path (Join-Path $ocDir "node_modules") | Out-Null
    Copy-Item (Join-Path $payload "*") (Join-Path $ocDir "node_modules") -Recurse -Force
    Write-Host "  [已安装] 插件依赖（随包）" -ForegroundColor Green
  } elseif (Get-Command npm -ErrorAction SilentlyContinue) {
    Push-Location $ocDir
    try { npm i @opencode-ai/plugin@1.1.48 --no-audit --no-fund 2>&1 | Out-Null } finally { Pop-Location }
    if (Test-Path $depPkg) { Write-Host "  [已安装] 插件依赖（npm）" -ForegroundColor Green }
    else { Write-Host "  [警告] 依赖未装好，插件可能加载失败" -ForegroundColor Yellow }
  } else {
    Write-Host "  [警告] 依赖缺失且没有 npm；若插件加载失败请重跑或手动装依赖" -ForegroundColor Yellow
  }
}

Write-Host ""
Write-Host "完成！下一步：" -ForegroundColor Cyan
Write-Host "  1. 重启 opencode / OpenChamber"
Write-Host "  2. 把 B 端（被控端）生成的邀请码发到聊天里，说：用这个邀请码添加设备"
Write-Host "     （也可以直接说：添加设备 OCL2:...）"
Write-Host "  3. 之后直接说：连接 <设备名> / 在 <设备名> 上执行 <命令>"
