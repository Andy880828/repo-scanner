# repo-scanner/scan.ps1
# 整合 Trivy / Semgrep / Gitleaks / OSV-Scanner + 提示詞注入偵測的安全掃描器
#
# 用法:
#   .\scan.ps1 -Target "C:\path\to\repo"
#   .\scan.ps1                       # 掃描目前目錄
#   .\scan.ps1 -Target ... -SkipDbUpdate   # Trivy 跳過 DB 更新（更快，需先跑過一次）

param(
    [string]$Target = (Get-Location).Path,
    [switch]$SkipDbUpdate
)

# 注意：不用 'Stop' — docker.exe 的 stderr 警告（如 DOCKER_INSECURE_NO_IPTABLES_RAW）
# 在 Stop 模式會被包成 NativeCommandError 誤觸終止。改靠 $LASTEXITCODE 顯式判斷成敗。
$ErrorActionPreference = 'Continue'

# ── 載入 lib 模組 ────────────────────────────────────────────────────────────
. (Join-Path $PSScriptRoot 'src\lib\Common.ps1')
. (Join-Path $PSScriptRoot 'src\lib\PromptInjection.ps1')
. (Join-Path $PSScriptRoot 'src\lib\Report.ps1')

# 掃描器定義（image / output）抽離於 config/scanners.json
$scanners = Get-ScannerConfig (Join-Path $PSScriptRoot 'config\scanners.json')
$img = Get-ImageMap $scanners

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Repo Security Scanner" -ForegroundColor Cyan
Write-Host " 掃描目標: $Target" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# ── Preflight ────────────────────────────────────────────────────────────────
if (-not (Test-Path $Target)) {
    Write-Host "[ERROR] 找不到掃描目標: $Target" -ForegroundColor Red
    exit 2
}
if (-not (Test-DockerRunning)) { exit 2 }
if (-not (Confirm-ScannerImages $scanners)) { exit 2 }

$cacheDir = Initialize-TrivyCache

# 結果目錄
$resultsDir = Join-Path $PSScriptRoot 'results'
New-Item -ItemType Directory -Path $resultsDir -Force | Out-Null
Get-ChildItem -Path $resultsDir -Filter '*.json' -ErrorAction SilentlyContinue | Remove-Item -Force

# Docker 掛載路徑（Windows → /c/... 格式）
$dTarget  = ConvertTo-DockerPath $Target
$dResults = ConvertTo-DockerPath $resultsDir
$dCache   = ConvertTo-DockerPath $cacheDir

# ── 平行啟動四個容器（各自寫 JSON 到 /out）────────────────────────────────────
Write-Host "[scan] 平行啟動 Trivy / Semgrep / Gitleaks / OSV..." -ForegroundColor Yellow

$trivyArgs = @(
    'run','--rm',
    '-v',"${dTarget}:/repo",
    '-v',"${dResults}:/out",
    '-v',"${dCache}:/root/.cache/trivy",
    $img.Trivy,
    'fs','/repo','--scanners','vuln,secret,misconfig',
    '--format','json','--output','/out/trivy.json','--exit-code','0'
)
if ($SkipDbUpdate) { $trivyArgs += '--skip-db-update' }

$semgrepArgs = @(
    'run','--rm',
    '-v',"${dTarget}:/src",
    '-v',"${dResults}:/out",
    $img.Semgrep,
    'semgrep','--config=p/security-audit','--config=p/secrets',
    '--no-git-ignore','--json','--output','/out/semgrep.json','/src'
)

$gitleaksArgs = @(
    'run','--rm',
    '-v',"${dTarget}:/path",
    '-v',"${dResults}:/out",
    $img.Gitleaks,
    'detect','--source','/path','--no-git',
    '--report-format','json','--report-path','/out/gitleaks.json','--exit-code','0'
)

$osvArgs = @(
    'run','--rm',
    '-v',"${dTarget}:/repo",
    '-v',"${dResults}:/out",
    $img.Osv,
    'scan','source','-r','/repo','--format','json','--output','/out/osv.json'
)

$jobDef = { param($dockerArgs) & docker @dockerArgs 2>&1 }

$jobs = @(
    Start-Job -Name 'Trivy'    -ScriptBlock $jobDef -ArgumentList (,$trivyArgs)
    Start-Job -Name 'Semgrep'  -ScriptBlock $jobDef -ArgumentList (,$semgrepArgs)
    Start-Job -Name 'Gitleaks' -ScriptBlock $jobDef -ArgumentList (,$gitleaksArgs)
    Start-Job -Name 'OSV'      -ScriptBlock $jobDef -ArgumentList (,$osvArgs)
)

# ── 容器執行中，同時跑本機注入掃描 ──────────────────────────────────────────
Write-Host "[scan] 提示詞注入掃描中（本機）..." -ForegroundColor Yellow
$injection = Invoke-PromptInjectionScan -Target $Target

# ── 等待所有容器收斂 ────────────────────────────────────────────────────────
Write-Host "[scan] 等待容器掃描完成..." -ForegroundColor Yellow
$null = Wait-Job -Job $jobs
foreach ($j in $jobs) {
    if ($j.State -eq 'Failed') {
        Write-Host "[WARN] $($j.Name) 任務失敗（報告中該工具將顯示 0 發現）" -ForegroundColor DarkYellow
    }
    Receive-Job -Job $j *> $null
}
Remove-Job -Job $jobs -Force

# ── 產生彙整報告 ────────────────────────────────────────────────────────────
Write-Host "[scan] 產生彙整報告..." -ForegroundColor Yellow
$report = New-ScanReport -Target $Target -ResultsDir $resultsDir -InjectionFindings $injection

# ── Console 摘要 ────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " 掃描完成" -ForegroundColor Green
Write-Host " 總發現數    : $($report.TotalFindings)" -ForegroundColor White
Write-Host " 最高嚴重度  : $($report.HighestSeverity)" -ForegroundColor White
Write-Host " 報告        : $($report.ReportPath)" -ForegroundColor White
Write-Host "========================================" -ForegroundColor Cyan

# exit code 反映嚴重度（保留 CI 相容性）
if ($Global:SeverityRank[$report.HighestSeverity] -ge $Global:SeverityRank['HIGH']) {
    exit 1
}
exit 0
