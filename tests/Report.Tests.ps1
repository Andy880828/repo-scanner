# tests/Report.Tests.ps1 — Pester 5
# 測試 src/lib/Report.ps1 的解析、排序與報告產生邏輯

BeforeAll {
    $repoRoot = Split-Path $PSScriptRoot -Parent
    . (Join-Path $repoRoot 'src\lib\Report.ps1')
}

Describe 'Get-Rank' {
    It 'CRITICAL 排序值為 5'        { Get-Rank 'CRITICAL' | Should -Be 5 }
    It '大小寫不敏感（high → 4）'    { Get-Rank 'high'     | Should -Be 4 }
    It '未知嚴重度回 0'             { Get-Rank 'FOO'      | Should -Be 0 }
    It 'null 回 0'                  { Get-Rank $null      | Should -Be 0 }
}

Describe 'Get-HighestSeverity' {
    It '回傳最嚴重的一項' {
        Get-HighestSeverity @('LOW','CRITICAL','MEDIUM') | Should -Be 'CRITICAL'
    }
    It '空陣列回 -' {
        Get-HighestSeverity @() | Should -Be '-'
    }
    It '過濾 null / 空字串後計算' {
        Get-HighestSeverity @($null,'','HIGH') | Should -Be 'HIGH'
    }
}

Describe 'ConvertFrom-TrivyJson' {
    It '過濾掉 Vulnerabilities 為 null 的幽靈元素（@($null) 陷阱）' {
        $json = [pscustomobject]@{ Results = @(
            [pscustomobject]@{
                Target = 'package-lock.json'
                Vulnerabilities = @([pscustomobject]@{ Severity='CRITICAL'; VulnerabilityID='CVE-1'; PkgName='lodash'; InstalledVersion='4.17.4' })
                Secrets = $null
                Misconfigurations = $null
            },
            [pscustomobject]@{ Target = 'empty'; Vulnerabilities = $null; Secrets = $null; Misconfigurations = $null }
        )}
        $items = ConvertFrom-TrivyJson $json
        @($items).Count | Should -Be 1
        $items[0].Severity | Should -Be 'CRITICAL'
        $items[0].Title    | Should -Match 'CVE-1'
    }

    It '解析 secret 發現' {
        $json = [pscustomobject]@{ Results = @(
            [pscustomobject]@{
                Target = 'config.txt'
                Vulnerabilities = $null
                Secrets = @([pscustomobject]@{ Severity='CRITICAL'; RuleID='github-pat'; StartLine=1 })
                Misconfigurations = $null
            }
        )}
        $items = ConvertFrom-TrivyJson $json
        @($items).Count | Should -Be 1
        $items[0].Title | Should -Match 'github-pat'
    }
}

Describe 'ConvertFrom-OsvJson' {
    It '解析 package 的 vulnerabilities' {
        $json = [pscustomobject]@{ results = @(
            [pscustomobject]@{
                source = [pscustomobject]@{ path = '/repo/package-lock.json' }
                packages = @([pscustomobject]@{
                    package = [pscustomobject]@{ name = 'lodash' }
                    vulnerabilities = @(
                        [pscustomobject]@{ id = 'GHSA-aaa' },
                        [pscustomobject]@{ id = 'GHSA-bbb' }
                    )
                })
            }
        )}
        $items = ConvertFrom-OsvJson $json
        @($items).Count | Should -Be 2
        $items[0].Title | Should -Match 'GHSA-aaa'
    }

    It '空結果不產生發現' {
        $json = [pscustomobject]@{ results = @() }
        @(ConvertFrom-OsvJson $json).Count | Should -Be 0
    }
}

Describe 'New-ScanReport (整合)' {
    BeforeAll {
        $script:results = Join-Path $TestDrive 'results'
        New-Item -ItemType Directory -Path $script:results -Force | Out-Null

        # 放入 Trivy JSON（1 個 CRITICAL vuln）
        @'
{ "Results": [ { "Target": "package-lock.json",
  "Vulnerabilities": [ { "Severity": "CRITICAL", "VulnerabilityID": "CVE-2019-10744", "PkgName": "lodash", "InstalledVersion": "4.17.4" } ] } ] }
'@ | Out-File -LiteralPath (Join-Path $script:results 'trivy.json') -Encoding ascii

        # 其餘工具給空結果
        '{ "results": [] }' | Out-File -LiteralPath (Join-Path $script:results 'semgrep.json') -Encoding ascii
        '[]'                | Out-File -LiteralPath (Join-Path $script:results 'gitleaks.json') -Encoding ascii
        '{ "results": [] }' | Out-File -LiteralPath (Join-Path $script:results 'osv.json') -Encoding ascii

        $injection = @(
            [pscustomobject]@{ File='CLAUDE.md'; Line=4; Type='Keyword(AI-config)'; Detail='ignore previous instructions'; Severity='CRITICAL'; NeedsReview=$false }
        )

        $script:report = New-ScanReport -Target 'C:\x' -ResultsDir $script:results -InjectionFindings $injection
    }

    It '產生報告檔' {
        Test-Path $script:report.ReportPath | Should -BeTrue
    }

    It '整體最高嚴重度為 CRITICAL' {
        $script:report.HighestSeverity | Should -Be 'CRITICAL'
    }

    It '報告內容含 Trivy 的 CVE 與注入發現' {
        $md = Get-Content -LiteralPath $script:report.ReportPath -Raw
        $md | Should -Match 'CVE-2019-10744'
        $md | Should -Match 'Keyword\(AI-config\)'
    }
}
