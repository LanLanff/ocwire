# oc-link local end-to-end test (ASCII only for PS5.1 compatibility).
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
New-Item -ItemType Directory -Force -Path "$root\bin", "$root\data" | Out-Null

Write-Output "== build =="
go build -o bin/hub.exe ./cmd/hub
go build -o bin/agent.exe ./cmd/agent
go build -o bin/octest.exe ./cmd/octest

Write-Output "== seed device =="
$seed = & "$root\bin\hub.exe" -add "local-test" -data "$root\data\devices.json" | Out-String
Write-Output $seed
if ($seed -match "(OCL-[A-Z2-7-]+)") { $key = $Matches[1] } else { throw "no pairing key" }
Write-Output ("KEY=" + $key)

Get-Process hub, agent, octest -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 400

Write-Output "== start hub =="
$hubArgs = @("-tunnel", "127.0.0.1:21122", "-admin", "127.0.0.1:21123", "-data", "$root\data\devices.json", "-cert", "$root\data\cert.pem", "-key", "$root\data\key.pem")
$hub = Start-Process -FilePath "$root\bin\hub.exe" -ArgumentList $hubArgs -PassThru -RedirectStandardOutput "$root\data\hub.out" -RedirectStandardError "$root\data\hub.err"
Start-Sleep -Seconds 2

Write-Output "== start agent =="
$agArgs = @("-hub", "127.0.0.1:21122", "-key", $key, "-insecure", "-name", "local-test")
$ag = Start-Process -FilePath "$root\bin\agent.exe" -ArgumentList $agArgs -PassThru -RedirectStandardOutput "$root\data\agent.out" -RedirectStandardError "$root\data\agent.err"
Start-Sleep -Seconds 2

Write-Output "== run client =="
$res = & "$root\bin\octest.exe" -hub "127.0.0.1:21122" -key $key -insecure -op exec -arg "echo hello-oc-link" 2>&1 | Out-String
Write-Output $res

Write-Output "== cleanup =="
Stop-Process -Id $ag.Id -Force -ErrorAction SilentlyContinue
Stop-Process -Id $hub.Id -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 300
Write-Output "--- hub log ---"; Get-Content "$root\data\hub.err" -ErrorAction SilentlyContinue
Write-Output "--- agent log ---"; Get-Content "$root\data\agent.err" -ErrorAction SilentlyContinue
