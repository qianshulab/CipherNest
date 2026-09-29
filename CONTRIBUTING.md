# 参与 CipherNest 开发

CipherNest 目前是未经独立安全审计的 beta。涉及保险库格式、主密码、备份、剪贴板或 WebDAV 的改动需要明确说明兼容性和失败路径。

## 反馈问题

- 普通缺陷请提交 issue，附上系统版本、CipherNest 版本、复现步骤、预期与实际结果。可以使用虚构条目和测试保险库。
- 不要在公开 issue、PR、截图、日志或测试文件中提交真实主密码、恢复码、WebDAV 应用密码、保险库文件或其他个人数据。
- 可利用的安全问题请先按 [安全政策](SECURITY.md) 私下报告，不要公开复现细节。

## 本地开发

项目要求 Node.js 24.x、pnpm 10.12.1、Rust 1.89.0 和对应平台的 Tauri 2 系统依赖。安装并检查：

```bash
corepack enable
corepack prepare pnpm@10.12.1 --activate
pnpm install --frozen-lockfile
pnpm check
cargo fmt --manifest-path src-tauri/Cargo.toml --check
cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets --all-features --locked -- -D warnings
```

平台依赖与打包命令见 [README](README.md)。请不要把 `node_modules`、`dist`、`src-tauri/target`、实际 `.cnvault` 文件、签名材料或本地环境文件加入版本控制。

## 提交 PR

请在描述中说明：

1. 用户能观察到的变化，以及关联的问题。
2. 对已有保险库、自动备份和 WebDAV 同步状态的兼容性影响；若改变格式或协议，说明旧版本如何处理。
3. 已执行的测试和平台；未完成的验证也请写明。
4. 界面改动的截图或短录屏，且其中只使用虚构数据。

修复漏洞或数据丢失风险时，优先增加能复现旧问题的测试。请保持测试使用虚构秘密，不依赖真实 WebDAV 账号。提交前运行 `git diff --check`，并确认未误提交本地数据或构建产物。
