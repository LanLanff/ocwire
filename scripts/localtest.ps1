# 本地端到端测试：起中继 + agent，用测试客户端跑一条命令。
# 用法： powershell -ExecutionPolicy Bypass -File scripts\localtest.ps1
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
New-Item -ItemType Directory -Force -Path "$root\bin", "$root\data" | Out-Null

Write-Output "== 编译 =="
go build -o bin/hub.exe ./cmd/hub
go build -o bin/agent.exe ./cmd/agent
go build -o bin/octest.exe ./cmd/octest

Write-Output "== 创建测试设备 =="
$seed = & "$root\bin\hub.exe" -add "本地测试机" -data "$root\data\devices.json" | Out-String
Write-Output $seed
if ($seed -match "(OCL-[A-Z2-7-]+)") { $key = $Matches[1] } else { throw "没拿到配对密钥" }
Write-Output ("KEY=" + $key)

Get-Process hub, agent, octest -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 400

Write-Output "== 启动中继 =="
$hub = Start-Process -FilePath "$root\bin\hub.exe" `
  -ArgumentList @("-tunnel", "127.0.0.1:21122", "-admin", "127.0.0.1:21123", "-data", "$root\data\devices.json", "-cert", "$root\data\cert.pem", "-key", "$root\data\key.pem") `
  -PassThru -RedirectStandardOutput "$root\data\hub.out" -RedirectStandardError "$root\data\hub.err"
Start-Sleep -Seconds 2

Write-Output "== 启动 agent =="
$ag = Start-Process -FilePath "$root\bin\agent.exe" `
  -ArgumentList @("-hub", "127.0.0.1:21122", "-key", $key, "-insecure", "-name", "本地测试机") `
  -PassThru -RedirectStandardOutput "$root\data\agent.out" -RedirectStandardError "$root\data\agent.err"
Start-Sleep -Seconds 2

Write-Output "== 客户端执行命令 =="
$res = & "$root\bin\octest.exe" -hub "127.0.0.1:21122" -key $key -insecure -op exec -arg "echo hello-oc-link" 2>&1 | Out-String
Write-Output $res

Write-Output "== 收尾 =="
Stop-Process -Id $ag.Id -Force -ErrorAction SilentlyContinue
Stop-Process -Id $hub.Id -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 300
Write-Output "--- hub 日志 ---"; Get-Content "$root\data\hub.err" -ErrorAction SilentlyContinue
Write-Output "--- agent 日志 ---"; Get-Content "$root\data\agent.err" -ErrorAction SilentlyContinue
