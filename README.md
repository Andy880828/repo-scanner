# Repo Security Scanner

在沙箱外快速檢查可疑 repo 的**供應鏈漏洞**、**外洩密鑰**與**提示詞注入**。
四個掃描器平行執行，結果彙整成單一 Markdown 報告。

## 需求
- Docker Desktop（已啟動）
- PowerShell 5+

## 快速開始

```powershell
cd C:\Users\Andy\Desktop\repo-scanner

# 掃描指定 repo（平行執行 + 產生報告）
.\scan.ps1 -Target "C:\Users\Andy\Downloads\某個可疑套件"

# 掃描目前目錄
.\scan.ps1

# 第二次起可跳過 Trivy DB 更新，更快
.\scan.ps1 -Target "..." -SkipDbUpdate
```

掃描完成後，報告位於 `results\scan-report-<時間戳>.md`，原始 JSON 同樣保留在 `results\` 供細查。

## 掃描項目

| 工具 | 掃描內容 |
|------|---------|
| Trivy | CVE 漏洞、hardcoded secrets、設定錯誤（含 DB 快取） |
| Semgrep | 程式碼安全 pattern、注入漏洞 |
| Gitleaks | API key、token、密碼外洩 |
| OSV-Scanner | lockfile 感知的依賴漏洞（npm/pip/go…） |
| 內建注入掃描 | 明文注入關鍵字、**隱藏 Unicode 字元**、**AI 設定檔**（CLAUDE.md / .cursorrules…） |

## 效能設計

- **平行執行**：四個容器同時跑，注入掃描在本機同步進行。
- **Trivy DB 快取**：掛載 `%USERPROFILE%\.cache\trivy`，第二次起省去重抓漏洞 DB。
- **Preflight**：先確認 Docker 已啟動並預拉 image，避免 pull 噪音混入掃描輸出。

## 單獨執行某個工具

```powershell
$env:SCAN_TARGET = "C:\path\to\repo"
docker compose run --rm trivy     # 或 semgrep / gitleaks / osv
```

## 注意事項

- **首次執行**會 pull 四個 image（約 1–2 GB），之後很快。
- **離線掃描不可信 repo**：Semgrep 的 `p/security-audit` 規則與 Trivy DB 首次需網路下載。若要完全離線（`--network none`）掃描高風險 repo，請先在可信網路下各跑一次預熱快取。
- **exit code**：最高嚴重度達 HIGH 以上回傳 `1`，否則 `0`（方便日後接 CI）。
- 程式碼註解中的注入關鍵字誤判率較高，報告中標記為「需人工確認」。

## 結構

```
repo-scanner/
├── scan.ps1                  # 協調器：preflight → 平行掃描 → 彙整報告
├── lib/
│   ├── Common.ps1            # 路徑轉換 + preflight + image 確認
│   ├── PromptInjection.ps1   # 隱藏字元 + AI 設定檔注入偵測
│   └── Report.ps1            # JSON 解析 + Markdown 報告
├── docker-compose.yml        # 單獨執行各工具
└── results/                  # 掃描輸出（gitignored）
```
