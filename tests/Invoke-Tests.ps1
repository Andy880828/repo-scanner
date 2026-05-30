# tests/Invoke-Tests.ps1
# 執行全部 Pester 單元測試。
#
# 需求：Pester 5+
#   Install-Module Pester -Scope CurrentUser -MinimumVersion 5.0 -Force -SkipPublisherCheck
#
# 用法：
#   .\tests\Invoke-Tests.ps1
#   .\tests\Invoke-Tests.ps1 -CI    # 失敗時以非 0 結束（供 CI 把關）

param([switch]$CI)

Import-Module Pester -MinimumVersion 5.0 -ErrorAction Stop

$config = New-PesterConfiguration
$config.Run.Path = $PSScriptRoot
$config.Output.Verbosity = 'Detailed'
if ($CI) { $config.Run.Exit = $true }

Invoke-Pester -Configuration $config
