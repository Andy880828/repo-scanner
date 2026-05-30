# src/lib/Common.ps1
# 共用工具：掃描器設定載入、Docker 路徑轉換、preflight 檢查、image 確認
# 由 scan.ps1 透過 dot-source 載入

# 從 config/scanners.json 載入掃描器定義（image / output / description）。
# 抽離成資料檔，讓未來跨平台核心（GUI）能共用同一份定義。
# 回傳：name → { image, output, description } 的物件陣列。
function Get-ScannerConfig {
    param([Parameter(Mandatory)][string]$ConfigPath)
    if (-not (Test-Path $ConfigPath)) {
        throw "找不到掃描器設定檔: $ConfigPath"
    }
    # 必須指定 -Encoding UTF8：PS 5.1 的 Get-Content 預設用 ANSI(CP950)，會破壞中文 → JSON 解析失敗
    $json = Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if (-not $json.scanners) {
        throw "設定檔格式錯誤：缺少 'scanners' 陣列"
    }
    return $json.scanners
}

# 由掃描器定義陣列建立 name → image 的查找表
function Get-ImageMap {
    param([Parameter(Mandatory)][object[]]$Scanners)
    $map = @{}
    foreach ($s in $Scanners) { $map[$s.name] = $s.image }
    return $map
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
    param([Parameter(Mandatory)][object[]]$Scanners)

    foreach ($s in $Scanners) {
        docker image inspect $s.image *> $null
        if ($LASTEXITCODE -ne 0) {
            Write-Host "[preflight] 拉取 $($s.name) image ($($s.image))..." -ForegroundColor DarkGray
            docker pull $s.image
            if ($LASTEXITCODE -ne 0) {
                Write-Host "[ERROR] 無法拉取 $($s.image)" -ForegroundColor Red
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
