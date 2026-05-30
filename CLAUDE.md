# CLAUDE.md

給 Claude Code（及任何貢獻者）的專案指引。動工前請先讀完「關鍵陷阱」一節。

## 專案概述

`repo-scanner` 是一個在沙箱外快速檢查可疑 repo 的安全掃描器，整合四個 Docker 化的掃描工具
（Trivy / Semgrep / Gitleaks / OSV-Scanner）並附加自製的提示詞注入偵測，平行執行後彙整成
單一 Markdown 報告。目前以 Windows PowerShell CLI 實作，**長期目標是做成跨平台介面化工具**
（見 `docs/architecture.md`）。

## 目錄結構

```
repo-scanner/
├── scan.ps1                  # CLI 進入點：preflight → 平行掃描 → 彙整報告
├── config/
│   └── scanners.json         # 掃描器定義（image/output/description）— 資料而非程式碼
├── src/lib/
│   ├── Common.ps1            # 設定載入、路徑轉換、Docker preflight、image 確認
│   ├── PromptInjection.ps1   # 隱藏 Unicode 字元 + AI 設定檔注入偵測（純 PowerShell）
│   └── Report.ps1            # 解析各工具 JSON → 產生 Markdown 報告
├── tests/                    # Pester 5 單元測試
│   └── Invoke-Tests.ps1      # 測試執行器
├── docs/architecture.md      # 跨平台演進方向
├── docker-compose.yml        # 單獨執行各工具用
└── results/                  # 掃描輸出（gitignored）
```

## 關鍵陷阱（Windows / PowerShell，務必遵守）

1. **`.ps1` 必須存成 UTF-8 with BOM**。Windows PowerShell 5.1 對無 BOM 的檔案會用 ANSI 碼頁
   （CP950）解讀，使中文註解的位元組被誤判成 `}`/`"`，造成假性語法錯誤。**但 `.json` 檔絕不能有 BOM** —
   OSV 的 Go JSON parser 會因開頭 BOM 報「invalid character」。簡言之：程式碼要 BOM、資料檔不要 BOM。

2. **`@($null)` 不是空陣列**，而是「含一個 null 元素的長度 1 陣列」。處理可能為 null 的 JSON 屬性時，
   一律用 `@($x | Where-Object { $_ })` 過濾，否則會產生欄位全空的幽靈物件並讓 `Sort-Object` 拋錯。

3. **不要用 `$ErrorActionPreference = 'Stop'` 包住原生 CLI 呼叫**。`docker.exe` 往 stderr 印的無害
   警告（如 `DOCKER_INSECURE_NO_IPTABLES_RAW`）在 Stop 模式會被包成 NativeCommandError 誤觸終止。
   一律靠 `$LASTEXITCODE` 顯式判斷成敗。

4. **測試斷言 `.Count` 前要 `@()` 包裹**。單一物件在 PS 5.1 的 `(...).Count` 可能回 `$null`。

## 常用指令

```powershell
.\scan.ps1 -Target "C:\path\to\repo"      # 完整掃描
.\scan.ps1 -Target "..." -SkipDbUpdate    # 第二次起跳過 Trivy DB 更新
.\tests\Invoke-Tests.ps1                   # 跑單元測試
```

## 如何新增一個掃描器

1. 在 `config/scanners.json` 的 `scanners` 陣列加一筆 `{ name, image, output, description }`。
2. 在 `scan.ps1` 仿照現有的 `$trivyArgs` 等，新增該工具的 docker 參數陣列（指定 `/out/<output>`），
   並加入 `Start-Job` 清單。
3. 在 `src/lib/Report.ps1` 新增對應的 `ConvertFrom-<Tool>Json` 解析函數，並掛進 `New-ScanReport`
   的 `$parsed` 區塊。
4. 在 `tests/Report.Tests.ps1` 補上該解析函數的測試。

## 程式碼慣例

- 多個小檔、單一職責；JSON 解析必須對缺漏欄位有防禦性（null-safe）。
- 報告以「結構化 Markdown 檔」為主、console 僅顯示摘要（因平行輸出會交錯）。
- 新增純邏輯函數時一併補 Pester 測試（Docker 相關的協調邏輯不強求單元測試）。
