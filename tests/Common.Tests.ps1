# tests/Common.Tests.ps1 — Pester 5
# 測試 src/lib/Common.ps1 的純邏輯（不觸發 Docker）

BeforeAll {
    $repoRoot = Split-Path $PSScriptRoot -Parent
    . (Join-Path $repoRoot 'src\lib\Common.ps1')
}

Describe 'ConvertTo-DockerPath' {
    It '把現有 Windows 路徑轉成 /drive/... 格式（小寫磁碟、正斜線）' {
        $result = ConvertTo-DockerPath $PSScriptRoot
        $result | Should -Match '^/[a-z]/'
        $result | Should -Not -Match '\\'
        $result | Should -Not -Match ':'
    }

    It '路徑不存在時拋錯' {
        { ConvertTo-DockerPath 'C:\__no_such_path_12345__' } | Should -Throw
    }
}

Describe 'Get-ScannerConfig' {
    BeforeAll {
        $script:cfg = Join-Path $TestDrive 'scanners.json'
        @'
{ "scanners": [
  { "name": "Trivy", "image": "aquasec/trivy:latest", "output": "trivy.json", "description": "x" },
  { "name": "Osv",   "image": "ghcr.io/google/osv-scanner:latest", "output": "osv.json", "description": "y" }
] }
'@ | Out-File -LiteralPath $script:cfg -Encoding ascii
    }

    It '載入 scanners 陣列並保留欄位' {
        $s = Get-ScannerConfig $script:cfg
        $s.Count | Should -Be 2
        $s[0].name  | Should -Be 'Trivy'
        $s[0].image | Should -Be 'aquasec/trivy:latest'
    }

    It '檔案不存在時拋錯' {
        { Get-ScannerConfig (Join-Path $TestDrive 'missing.json') } | Should -Throw
    }

    It '缺少 scanners 欄位時拋錯' {
        $bad = Join-Path $TestDrive 'bad.json'
        '{ "foo": 1 }' | Out-File -LiteralPath $bad -Encoding ascii
        { Get-ScannerConfig $bad } | Should -Throw
    }
}

Describe 'Get-ImageMap' {
    It '由掃描器陣列建立 name → image 查找表' {
        $scanners = @(
            [pscustomobject]@{ name = 'Trivy'; image = 'aquasec/trivy:latest' }
            [pscustomobject]@{ name = 'Osv';   image = 'ghcr.io/google/osv-scanner:latest' }
        )
        $map = Get-ImageMap $scanners
        $map.Trivy | Should -Be 'aquasec/trivy:latest'
        $map.Osv   | Should -Be 'ghcr.io/google/osv-scanner:latest'
    }
}
