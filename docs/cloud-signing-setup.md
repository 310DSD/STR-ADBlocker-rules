# 云规则 generation 签名接入

模块侧（0.5.190+）已完成全部实现，本文件只描述部署步骤：

## 已实现（无需再改代码）

- `tools/build_cloud_generation.py`：环境变量 `STR_GENERATION_SIGNING_KEY` 存在时，
  对 `manifest` 的 sha256（ASCII hex）做 Ed25519 签名，生成 `generation.sig`
  并打包进 `generation.tar.gz`；优先用 Python `cryptography`，缺省回退到
  `openssl pkeyutl -sign -rawin`（GitHub runner 自带）。
- `.github/workflows/build-rules.yml`：`Build generation` step 已注入
  `STR_GENERATION_SIGNING_KEY: ${{ secrets.STR_GENERATION_SIGNING_KEY }}`。
- 模块 `fetch verify-gen`：校验签名，失败拒绝发布并保留旧规则。

## 部署步骤

1. 生成密钥对：

   ```sh
   openssl genpkey -algorithm ed25519 -out str_signing_key.pem
   openssl pkey -in str_signing_key.pem -pubout -out ed25519.pub
   ```

2. 在规则仓库（`310DSD/STR-ADBlocker-rules`）Settings → Secrets and variables →
   Actions 添加 `STR_GENERATION_SIGNING_KEY`（私钥 PEM 全文）。workflow 使用模块仓库
   的 `tools/` 与当前 `.github/workflows/build-rules.yml`（模板已在模块仓库，
   部署时按文件头注释复制到规则仓库）。

3. 新模块发布时把 `ed25519.pub` 放入模块 `rules/`。从此云更新强制校验：
   - `generation.sig` 缺失 → 拒绝更新并保留旧规则；
   - 签名无效/密钥不符 → 拒绝更新并保留旧规则；
   - 模块无公钥（旧版/dev）→ 跳过校验，行为与现在一致。

## 验收

- 本机：`tests/test_cloud_generation.py` 新增签名测试（cryptography 或 openssl 任一可用即执行，
  并反向验证签名）；模块侧验证器矩阵在 `native/cmd/fetch/verify_test.go`。
- 规则仓：手动跑一次 workflow，确认 `generation.tar.gz` 内含 `generation.sig`，
  并用模块 `fetch verify-gen` 验证。
