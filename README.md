# Repo Security Scanner

## 需求
- Docker Desktop（已啟動）
- PowerShell 5+

## 使用方式

### 方法 1：PowerShell 腳本（推薦）
```powershell
# 掃描指定 repo
.\scan.ps1 -Target "C:\Users\Andy\Downloads\some-repo"

# 掃描目前目錄
.\scan.ps1
```

### 方法 2：Docker Compose（單獨跑某個工具）
```powershell
# 只跑 trivy
$env:SCAN_TARGET = "C:\Users\Andy\Downloads\some-repo"
docker compose run trivy

# 只跑 semgrep
docker compose run semgrep
```

## 掃描項目

| 工具 | 掃描內容 |
|------|---------|
| Trivy | CVE 漏洞、hardcoded secrets、設定錯誤 |
| Semgrep | 程式碼安全 pattern、注入漏洞 |
| Gitleaks | API key、token、密碼外洩 |
| 自訂 grep | 提示詞注入 pattern |
