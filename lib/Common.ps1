# lib/Common.ps1
# 共用工具：Docker 路徑轉換、preflight 檢查、image 確認
# 由 scan.ps1 透過 dot-source 載入

# 掃描所需的 Docker image 清單（單一事實來源）
$Global:ScannerImages = @{
    Trivy    = 'aquasec/trivy:latest'
    Semgrep  = 'returntocorp/semgrep:latest'
    Gitleaks = 'zricethezav/gitleaks:latest'
    Osv      = 'ghcr.io/google/osv-scanner:latest'
}

# 將 Windows 路徑轉為 Docker 可掛載格式 (e.g. C:\foo -> /c/foo)
function ConvertTo-DockerPath {
    param([Parameter(Mandatory)][string]$WinPath)
    $resolved = (Resolve-Path -LiteralPath $WinPath -ErrorAction Stop).Path
    $drive = $resolved.Substring(0, 1).ToLower()
    $rest = $resolved.Substring(2) -replace '\\', '/'
    return "/$drive$rest"
}

# 確認 Docker Desktop 已啟動；失敗回傳 $false 並印出友善訊息
function Test-DockerRunning {
    Write-Host "[preflight] 檢查 Docker..." -ForegroundColor DarkGray
    # 本地抑制 stderr 警告，僅以 exit code 判斷
    $ErrorActionPreference = 'SilentlyContinue'
    docker info 2>$null 1>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[ERROR] 無法連線到 Docker。請先啟動 Docker Desktop 再重試。" -ForegroundColor Red
        return $false
    }
    return $true
}

# 確認所需 image 已存在，缺的自動 pull（避免 pull 進度噪音混入掃描輸出）
function Confirm-ScannerImages {
    param([Parameter(Mandatory)][hashtable]$Images)

    foreach ($name in $Images.Keys) {
        $image = $Images[$name]
        docker image inspect $image *> $null
        if ($LASTEXITCODE -ne 0) {
            Write-Host "[preflight] 拉取 $name image ($image)..." -ForegroundColor DarkGray
            docker pull $image
            if ($LASTEXITCODE -ne 0) {
                Write-Host "[ERROR] 無法拉取 $image" -ForegroundColor Red
                return $false
            }
        }
    }
    return $true
}

# 確保 Trivy DB 快取目錄存在（持久化避免每次重抓漏洞 DB）
function Initialize-TrivyCache {
    $cacheDir = Join-Path $env:USERPROFILE '.cache\trivy'
    if (-not (Test-Path $cacheDir)) {
        New-Item -ItemType Directory -Path $cacheDir -Force | Out-Null
    }
    return $cacheDir
}
