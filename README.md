# STR AdBlocker Rules

STR AdBlocker 的云端规则构建仓库。GitHub Actions 每天 03:17 UTC 自动构建，也
支持手动触发，把 7 个 provider 源的并集编译成 FlowGuard 生产 generation，
并以 GitHub Release 发布：

- `generation.tar.gz`：模块 `bin/update.sh cloud` 直接消费的不可变 generation；
- `latest.json`：token、规则数、provider digest 等元数据，用于变更检测。

构建工具链已内置在 `tools/`，工作流不依赖模块仓库在线可达。

## 手动触发

打开
<https://github.com/310DSD/STR-ADBlocker-rules/actions/workflows/build-rules.yml>
，点击 **Run workflow**。

## 模块接入

在设备上把 `/data/adb/str-adblocker/cloud-update-url` 配置为：

```text
https://github.com/310DSD/STR-ADBlocker-rules/releases/latest/download/generation.tar.gz
```

`service.sh` 默认每 21600 秒自动检查；WebUI「云端规则」行或 KernelSU
Action 可随时手动触发。模块端校验 ruleset token、规则数量边界、各产物
digest 与 provider digest 后才原子发布，失败时保留旧 generation。

## 数据源

- HaGeZi DNS Blocklists（multi）
- anti-AD EasyList
- 1Hosts Lite
- AdGuard DNS / Base / Chinese
- BanAD

构建工具链与派生产物遵循 GPL-3.0（见 `LICENSE`）；上游规则版权与许可证见
`THIRD_PARTY_NOTICES.md`。
