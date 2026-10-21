# STR AdBlocker Rules

STR AdBlocker 的云端规则构建仓库。GitHub Actions 每天 03:17 UTC 自动构建，也
支持手动触发，把 6 个 provider 源的并集编译成 FlowGuard 生产 generation，
并以 GitHub Release 发布。当前采用 family-aware union：普通主机至少被 1 个
provider 收录，敏感厂商家族要求至少 2 个 provider；在此之上叠加质量过滤：

- 单 provider、未分类、且位于 Tranco top-100k 的域名不进入 generation；
- `1hosts-lite` 的单 provider、未分类域名同样不进入 generation；
- 已归类为 ad/tracker/telemetry 的域名、敏感家族和用户 allowlist 不受该过滤影响。

这会减少正常站点和低质量长尾误报，同时保留 blocktest 覆盖。

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
- AdGuard DNS
- BanAD
- OISD（big）
- Tranco top-1m（仅构建时作为正常域名流行度信号，不进入规则产物）

构建工具链与派生产物遵循 GPL-3.0（见 `LICENSE`）；上游规则版权与许可证见
`THIRD_PARTY_NOTICES.md`。

## Default allowlist

`default-allowlist.txt` is the canonical default allowlist for cloud builds and is identical to the module's bundled copy. The build passes it via `--allowlist`, so compilers drop allowed domains from the rules and hotset while keeping parent suffix rules; the module daemon applies the same list at runtime.
