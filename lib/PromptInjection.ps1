# lib/PromptInjection.ps1
# 強化版提示詞注入偵測（純 PowerShell，不需 Docker）
# 偵測三類：明文注入關鍵字、隱藏 Unicode 字元、AI 設定檔內的可疑指令
# 由 scan.ps1 透過 dot-source 載入

# 明文注入關鍵字（合併成單一 regex 以單次比對）
$Global:InjectionKeywords = @(
    'ignore (previous|all|above|prior) instructions'
    'disregard (your|all|the|previous) instructions'
    'override (system|your) (prompt|instructions)'
    'you are now'
    'forget (your|all|everything)'
    'do not follow'
    'new instructions:'
    'system prompt'
    'jailbreak'
    'DAN mode'
    'pretend (you|to be)'
    'act as if'
    '<!--\s*inject'
    '\[INST\]'
    '<\|system\|>'
    'reveal (your|the) (system )?prompt'
    'exfiltrat'
    'send .{0,20}(to|via) (http|curl|webhook)'
)

# AI 助手設定檔（注入攻擊首要藏匿點）— 依檔名精準鎖定
$Global:AiConfigNames = @(
    'CLAUDE.md', 'AGENTS.md', 'GEMINI.md', 'copilot-instructions.md'
    '.cursorrules', '.windsurfrules', '.clinerules', '.aider.conf.yml'
)

# 文件 / 設定副檔名（高風險，明文掃描）
$Global:DocExtensions = @('.md', '.txt', '.json', '.yaml', '.yml', '.html', '.rst', '.csv', '.xml', '.toml')

# 程式碼副檔名（掃註解中的注入，誤判率較高 → 標記需人工確認）
$Global:CodeExtensions = @('.py', '.js', '.ts', '.tsx', '.jsx', '.sh', '.ps1', '.rb', '.go')

# 判斷單一 Unicode codepoint 是否為可疑隱藏字元
function Test-HiddenCodepoint {
    param([int]$Cp)
    return (
        $Cp -eq 0x200B -or $Cp -eq 0x200C -or $Cp -eq 0x200D -or $Cp -eq 0xFEFF -or
        ($Cp -ge 0x202A -and $Cp -le 0x202E) -or   # 雙向覆蓋 LRE/RLE/PDF/LRO/RLO
        ($Cp -ge 0x2066 -and $Cp -le 0x2069) -or   # 雙向隔離 LRI/RLI/FSI/PDI
        ($Cp -ge 0xE0000 -and $Cp -le 0xE007F)     # 隱形 tag 字元
    )
}

# 掃描單一行中的隱藏字元，回傳發現物件陣列
function Find-HiddenCharsInLine {
    param([string]$Line, [int]$LineNo, [string]$FilePath)

    $results = @()
    $i = 0
    while ($i -lt $Line.Length) {
        $ch = $Line[$i]
        if ([System.Char]::IsHighSurrogate($ch) -and ($i + 1) -lt $Line.Length) {
            $cp = [System.Char]::ConvertToUtf32($Line, $i)
            $i += 2
        } else {
            $cp = [int]$ch
            $i += 1
        }
        # 略過行首 BOM（U+FEFF 在檔案開頭屬正常）
        if ($cp -eq 0xFEFF -and $LineNo -eq 1 -and $i -le 1) { continue }
        if (Test-HiddenCodepoint $cp) {
            $results += [PSCustomObject]@{
                File        = $FilePath
                Line        = $LineNo
                Type        = 'HiddenChar'
                Detail      = ('U+{0:X4}' -f $cp)
                Severity    = 'HIGH'
                NeedsReview = $false
            }
        }
    }
    return $results
}

# 主入口：掃描目標目錄，回傳所有注入相關發現
function Invoke-PromptInjectionScan {
    param([Parameter(Mandatory)][string]$Target)

    $keywordRegex = ($Global:InjectionKeywords -join '|')
    $findings = [System.Collections.Generic.List[object]]::new()

    $allFiles = Get-ChildItem -Path $Target -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Extension -in $Global:DocExtensions -or
            $_.Extension -in $Global:CodeExtensions -or
            $_.Name -in $Global:AiConfigNames
        }

    foreach ($file in $allFiles) {
        $isCode = $file.Extension -in $Global:CodeExtensions
        $isAiConfig = $file.Name -in $Global:AiConfigNames

        # 每個檔案只讀一次（取代舊版巢狀重複讀檔）
        $lines = Get-Content -LiteralPath $file.FullName -ErrorAction SilentlyContinue
        if (-not $lines) { continue }

        $lineNo = 0
        foreach ($line in $lines) {
            $lineNo++

            # 1) 明文關鍵字
            if ($line -imatch $keywordRegex) {
                $findings.Add([PSCustomObject]@{
                    File        = $file.FullName
                    Line        = $lineNo
                    Type        = if ($isAiConfig) { 'Keyword(AI-config)' } else { 'Keyword' }
                    Detail      = $Matches[0].Trim()
                    Severity    = if ($isAiConfig) { 'CRITICAL' } elseif ($isCode) { 'MEDIUM' } else { 'HIGH' }
                    NeedsReview = $isCode
                })
            }

            # 2) 隱藏 Unicode 字元
            foreach ($hit in (Find-HiddenCharsInLine -Line $line -LineNo $lineNo -FilePath $file.FullName)) {
                $findings.Add($hit)
            }
        }
    }

    return $findings
}
