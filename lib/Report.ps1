# lib/Report.ps1
# 解析各工具 JSON 輸出 + 注入掃描結果 → 產生 Markdown 彙整報告
# 由 scan.ps1 透過 dot-source 載入

# 嚴重度排序（數字越大越嚴重）用於計算「最高嚴重度」
$Global:SeverityRank = @{
    'CRITICAL' = 5; 'HIGH' = 4; 'MEDIUM' = 3; 'LOW' = 2; 'UNKNOWN' = 1; 'INFO' = 0
}

# null-safe 取得嚴重度排序值（未知/空 → 0）
function Get-Rank {
    param($Severity)
    $r = $Global:SeverityRank[[string]$Severity]
    if ($null -eq $r) { return 0 }
    return $r
}

function Get-HighestSeverity {
    param([string[]]$Severities)
    $valid = @($Severities | Where-Object { $_ })
    if ($valid.Count -eq 0) { return '-' }
    return ($valid | Sort-Object { Get-Rank $_ } -Descending | Select-Object -First 1)
}

# 安全載入 JSON 檔（工具失敗時檔案可能不存在或為空）
function Read-JsonFile {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return $null }
    $raw = Get-Content -LiteralPath $Path -Raw -ErrorAction SilentlyContinue
    if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
    try { return $raw | ConvertFrom-Json } catch { return $null }
}

# ── 各工具正規化解析 → 統一 { Severity, Title, Location } ────────────────────

# 註：PowerShell 的 @($null) 會產生「含一個 null 元素」的陣列，故統一用
# Where-Object { $_ } 過濾掉空屬性產生的幽靈元素。

function ConvertFrom-TrivyJson {
    param($Json)
    $items = @()
    foreach ($r in @($Json.Results | Where-Object { $_ })) {
        foreach ($v in @($r.Vulnerabilities | Where-Object { $_ })) {
            $items += [PSCustomObject]@{ Severity = $v.Severity; Title = "$($v.VulnerabilityID) ($($v.PkgName) $($v.InstalledVersion))"; Location = $r.Target }
        }
        foreach ($s in @($r.Secrets | Where-Object { $_ })) {
            $items += [PSCustomObject]@{ Severity = $s.Severity; Title = "Secret: $($s.RuleID)"; Location = "$($r.Target):$($s.StartLine)" }
        }
        foreach ($m in @($r.Misconfigurations | Where-Object { $_ })) {
            $items += [PSCustomObject]@{ Severity = $m.Severity; Title = "Misconfig: $($m.ID)"; Location = $r.Target }
        }
    }
    return $items
}

function ConvertFrom-GitleaksJson {
    param($Json)
    $items = @()
    foreach ($f in @($Json | Where-Object { $_ })) {
        $items += [PSCustomObject]@{ Severity = 'HIGH'; Title = "$($f.RuleID): $($f.Description)"; Location = "$($f.File):$($f.StartLine)" }
    }
    return $items
}

function ConvertFrom-SemgrepJson {
    param($Json)
    $map = @{ 'ERROR' = 'HIGH'; 'WARNING' = 'MEDIUM'; 'INFO' = 'LOW' }
    $items = @()
    foreach ($r in @($Json.results | Where-Object { $_ })) {
        $sev = $map[[string]$r.extra.severity]; if (-not $sev) { $sev = 'MEDIUM' }
        $items += [PSCustomObject]@{ Severity = $sev; Title = $r.check_id; Location = "$($r.path):$($r.start.line)" }
    }
    return $items
}

function ConvertFrom-OsvJson {
    param($Json)
    $items = @()
    foreach ($r in @($Json.results | Where-Object { $_ })) {
        foreach ($p in @($r.packages | Where-Object { $_ })) {
            foreach ($v in @($p.vulnerabilities | Where-Object { $_ })) {
                $items += [PSCustomObject]@{ Severity = 'HIGH'; Title = "$($v.id) ($($p.package.name))"; Location = $r.source.path }
            }
        }
    }
    return $items
}

# 產生 Markdown 報告，回傳整體最高嚴重度供 exit code 使用
function New-ScanReport {
    param(
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][string]$ResultsDir,
        [object[]]$InjectionFindings
    )

    $parsed = [ordered]@{
        'Trivy'    = ConvertFrom-TrivyJson    (Read-JsonFile (Join-Path $ResultsDir 'trivy.json'))
        'Semgrep'  = ConvertFrom-SemgrepJson  (Read-JsonFile (Join-Path $ResultsDir 'semgrep.json'))
        'Gitleaks' = ConvertFrom-GitleaksJson (Read-JsonFile (Join-Path $ResultsDir 'gitleaks.json'))
        'OSV'      = ConvertFrom-OsvJson      (Read-JsonFile (Join-Path $ResultsDir 'osv.json'))
    }

    $allSeverities = @()
    $sb = [System.Text.StringBuilder]::new()
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

    [void]$sb.AppendLine("# Repo Security Scan Report")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("- **掃描目標**：``$Target``")
    [void]$sb.AppendLine("- **時間**：$ts")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("## 摘要")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("| 工具 | 發現數 | 最高嚴重度 |")
    [void]$sb.AppendLine("|------|--------|-----------|")

    foreach ($tool in $parsed.Keys) {
        $items = $parsed[$tool]
        $sev = Get-HighestSeverity ($items | ForEach-Object { $_.Severity })
        $allSeverities += ($items | ForEach-Object { $_.Severity })
        [void]$sb.AppendLine("| $tool | $($items.Count) | $sev |")
    }
    $injSev = Get-HighestSeverity ($InjectionFindings | ForEach-Object { $_.Severity })
    $allSeverities += ($InjectionFindings | ForEach-Object { $_.Severity })
    [void]$sb.AppendLine("| Prompt Injection | $($InjectionFindings.Count) | $injSev |")
    [void]$sb.AppendLine("")

    # 各工具詳細區段
    foreach ($tool in $parsed.Keys) {
        $items = $parsed[$tool]
        [void]$sb.AppendLine("## $tool")
        [void]$sb.AppendLine("")
        if ($items.Count -eq 0) {
            [void]$sb.AppendLine("_無發現。_")
        } else {
            [void]$sb.AppendLine("| 嚴重度 | 項目 | 位置 |")
            [void]$sb.AppendLine("|--------|------|------|")
            foreach ($it in ($items | Sort-Object { Get-Rank $_.Severity } -Descending | Select-Object -First 50)) {
                [void]$sb.AppendLine("| $($it.Severity) | $($it.Title) | $($it.Location) |")
            }
            if ($items.Count -gt 50) { [void]$sb.AppendLine("`n_（僅顯示前 50 筆，完整內容見 ``$tool.json``）_") }
        }
        [void]$sb.AppendLine("")
    }

    # 提示詞注入區段
    [void]$sb.AppendLine("## Prompt Injection")
    [void]$sb.AppendLine("")
    if (-not $InjectionFindings -or $InjectionFindings.Count -eq 0) {
        [void]$sb.AppendLine("_未發現已知注入特徵。_")
    } else {
        [void]$sb.AppendLine("| 嚴重度 | 類型 | 內容 | 位置 | 備註 |")
        [void]$sb.AppendLine("|--------|------|------|------|------|")
        foreach ($f in ($InjectionFindings | Sort-Object { Get-Rank $_.Severity } -Descending)) {
            $note = if ($f.NeedsReview) { '需人工確認' } else { '' }
            $detail = ([string]$f.Detail) -replace '\|', '\|'
            [void]$sb.AppendLine("| $($f.Severity) | $($f.Type) | $detail | $($f.File):$($f.Line) | $note |")
        }
    }
    [void]$sb.AppendLine("")

    $reportPath = Join-Path $ResultsDir ("scan-report-{0}.md" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
    $sb.ToString() | Out-File -LiteralPath $reportPath -Encoding UTF8

    return [PSCustomObject]@{
        ReportPath      = $reportPath
        HighestSeverity = Get-HighestSeverity $allSeverities
        TotalFindings   = $allSeverities.Count
    }
}
