# repo-scanner/scan.ps1
# 用法: .\scan.ps1 -Target "C:\path\to\repo"
# 用法: .\scan.ps1  (不帶參數則掃描目前目錄)

param(
    [string]$Target = (Get-Location).Path
)

# 將 Windows 路徑轉為 Docker 可用格式 (e.g. C:\foo -> /c/foo)
function ConvertTo-DockerPath {
    param([string]$WinPath)
    $resolved = (Resolve-Path $WinPath).Path
    $drive = $resolved.Substring(0, 1).ToLower()
    $rest = $resolved.Substring(2) -replace '\\', '/'
    return "/$drive$rest"
}

$DockerTarget = ConvertTo-DockerPath $Target

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Repo Security Scanner" -ForegroundColor Cyan
Write-Host " 掃描目標: $Target" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# ── 1. Trivy：漏洞 + Secrets + 設定錯誤 ──────────────────────────────────────
Write-Host "[1/4] Trivy 漏洞掃描..." -ForegroundColor Yellow
docker run --rm `
    -v "${DockerTarget}:/repo" `
    aquasec/trivy:latest fs /repo `
    --scanners vuln,secret,misconfig `
    --exit-code 0
Write-Host ""

# ── 2. Semgrep：靜態程式碼分析 ───────────────────────────────────────────────
Write-Host "[2/4] Semgrep 靜態分析..." -ForegroundColor Yellow
docker run --rm `
    -v "${DockerTarget}:/src" `
    returntocorp/semgrep:latest `
    semgrep --config=p/security-audit --config=p/secrets `
    --no-git-ignore `
    /src
Write-Host ""

# ── 3. Gitleaks：Hardcoded Token / Secret ────────────────────────────────────
Write-Host "[3/4] Gitleaks Secret 偵測..." -ForegroundColor Yellow
docker run --rm `
    -v "${DockerTarget}:/path" `
    zricethezav/gitleaks:latest `
    detect --source /path --no-git
Write-Host ""

# ── 4. 提示詞注入 Pattern 掃描 ───────────────────────────────────────────────
Write-Host "[4/4] 提示詞注入 Pattern 掃描..." -ForegroundColor Yellow

$injectionPatterns = @(
    "ignore previous instructions",
    "disregard (your|all|the) instructions",
    "override system",
    "you are now",
    "forget your",
    "ignore your",
    "do not follow",
    "bypass",
    "jailbreak",
    "DAN mode",
    "pretend you",
    "act as if",
    "<!-- inject",
    "\[INST\]",
    "<\|system\|>"
)

$extensions = @("*.md","*.txt","*.json","*.yaml","*.yml","*.html","*.rst","*.csv","*.xml")
$found = $false

foreach ($ext in $extensions) {
    Get-ChildItem -Path $Target -Recurse -Filter $ext -ErrorAction SilentlyContinue | ForEach-Object {
        $file = $_
        $content = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue
        if ($content) {
            foreach ($pattern in $injectionPatterns) {
                if ($content -imatch $pattern) {
                    Write-Host "[WARN] 疑似提示詞注入: $($file.FullName)" -ForegroundColor Red
                    Write-Host "       匹配 pattern: $pattern" -ForegroundColor DarkRed
                    $found = $true
                }
            }
        }
    }
}

if (-not $found) {
    Write-Host "[OK] 未發現已知提示詞注入 pattern" -ForegroundColor Green
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " 掃描完成！" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
