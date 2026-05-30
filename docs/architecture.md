# 架構與跨平台演進

> 目標：從目前的 Windows PowerShell CLI，演進成跨平台的介面化（GUI）安全掃描工具。

## 目前架構

```
┌─────────────┐     讀取      ┌──────────────────────┐
│  scan.ps1   │ ───────────▶ │ config/scanners.json │  ← 掃描器定義（共享契約）
│ (協調器/CLI) │              └──────────────────────┘
│             │
│  ┌────────────────── 平行 (Start-Job) ──────────────────┐
│  ▼            ▼            ▼            ▼                 │
│ Trivy      Semgrep     Gitleaks       OSV    + 本機注入掃描
│  │            │            │            │                 │
│  └──── 各自寫 results/<tool>.json ──────┘                 │
│             │                                            │
│             ▼                                            │
│      src/lib/Report.ps1  ──▶  results/scan-report-*.md   │
└─────────────────────────────────────────────────────────┘
```

**設計核心：把掃描器定義抽離成資料（`scanners.json`）**，而非寫死在程式碼。這是跨平台的關鍵 —
任何語言的核心都能讀同一份定義來決定要跑哪些容器。

## 邏輯分層（決定哪些能被重用）

| 層 | 現況 | 跨平台時的處置 |
|----|------|---------------|
| 掃描器定義 | `config/scanners.json` | **直接共用**（純資料） |
| 容器編排（平行、掛載、cache） | `scan.ps1` + `Start-Job` | 移植到核心語言（路徑掛載、平行為平台相依） |
| 注入偵測（隱藏字元/AI 設定檔） | `PromptInjection.ps1` | **演算法可移植**（純字串/Unicode 邏輯，跨語言一致） |
| 工具 JSON → 正規化發現 | `Report.ps1` 的 `ConvertFrom-*` | **可移植**（純資料轉換） |
| 報告/呈現 | Markdown 字串組裝 | 改由 GUI 渲染（資料與呈現分離） |

> 注入偵測與 JSON 正規化是「純邏輯」，最適合最先抽成語言中立的核心模組；容器編排因涉及
> OS 路徑掛載與平行模型，屬平台相依，最後處理。

## 演進路線（建議分階段）

**Phase 1（現況）**：PowerShell CLI，功能完整、有單元測試。

**Phase 2 — 抽出語言中立核心**
- 選定核心語言（建議 Rust 或 TypeScript/Node，視 GUI 框架而定）。
- 先移植「純邏輯」：注入偵測、JSON 正規化、報告資料模型。
- 容器編排改用該語言的 process API（取代 `Start-Job`），並輸出結構化結果物件（非 Markdown 字串）。

**Phase 3 — GUI 外殼**
- 候選框架：
  - **Tauri**（Rust 核心 + Web 前端）— 體積小、原生效能，與 Rust 核心契合。
  - **Electron**（Node 核心 + Web 前端）— 生態成熟，與 TS 核心契合。
  - **純 Web + 本機 agent** — 瀏覽器 UI 呼叫本機掃描服務。
- UI 呈現：即時各工具進度、可篩選的發現清單（依嚴重度/工具）、報告匯出。

**Phase 4 — 跨平台收尾**
- Docker 路徑掛載抽象：Windows `C:\x` → `/c/x`、macOS/Linux 直接用 POSIX 路徑（目前 `ConvertTo-DockerPath` 僅處理 Windows）。
- 提供無 Docker 後備（部分工具有原生二進位）。
- CI matrix（Windows/macOS/Linux）。

## 待決策（建立 GUI 前需確認）

- 核心語言與 GUI 框架（影響整體技術棧）。
- Docker 為唯一執行後端，或支援原生二進位後備。
- 報告資料模型 schema（GUI 與 CLI 共用的契約）。
