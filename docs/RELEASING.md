# CipherNest beta 发布流程

本文只说明当前未审计 beta 的构建与发布边界。它不是可信签名部署指南，也不表示三个平台已经完成独立安全验证。

## 自动化行为

- 手动运行 `Package beta release` 只构建并保留 GitHub Actions artifacts，不创建 GitHub Release。
- 推送与项目版本完全一致的 `v*` 标签（例如 `v0.3.2`）后，工作流才会构建并创建 GitHub prerelease。
- 标签版本必须同时匹配 `package.json`、`src-tauri/tauri.conf.json` 与 `src-tauri/Cargo.toml`；不一致会直接失败。
- 每个构建显式指定目标架构，并检查最终原生可执行文件头，避免把 runner 的默认架构误标成发布架构。
- 发布阶段要求四个安装包全部存在，并重新核对构建阶段生成的 SHA-256；缺包、重复包或哈希不一致都会失败关闭。
- 每个新版本都必须先增加 `.github/release-notes/vX.Y.Z.md`。缺少经过复核的说明时不会发布。

当前资产集合：

| 平台 | 目标 | Release 资产 |
| --- | --- | --- |
| macOS | ARM64 / Apple Silicon | DMG |
| Windows | x86-64 | NSIS EXE |
| Linux | x86-64 GNU | AppImage、DEB |

Apple Silicon 从 macOS 11 起受支持，因此 ARM64 发布构建会把部署目标和 bundle 最低版本显式覆盖为 11.0；它不会沿用通用配置中面向旧 Intel 系统的 10.15 值。

工作流先创建草稿、上传完整资产，再转为 prerelease。失败时可能留下草稿，重跑可以覆盖草稿资产；已经发布的同名 Release 不会被自动覆盖。

## 发布前检查

1. 确认要发布的提交已经通过普通三平台 CI、人工界面检查和安全回归测试。
2. 更新三个项目版本文件，并增加对应的版本化发布说明。
3. 在分支上手动运行一次打包工作流，下载三个平台的 Actions artifacts，至少在真实目标系统安装和启动一次。
4. 检查应用图标、安装/卸载、三平台仅主密码解锁、旧版设备认证入口不可用、备份恢复与 WebDAV 手动同步。
5. 只让 `vX.Y.Z` 标签指向已经复核的不可变提交。标签触发的构建完成后，再核对 Release 的提交、文件名、文件大小和 `SHA256SUMS.txt`。

Windows 覆盖安装还需用真实 NSIS 安装包做数据保留演练：在旧版安装后创建保险库与可辨认的条目，在测试 WebDAV 空间配置同步并完成一次同步，确认 `%APPDATA%\com.ciphernest.vault\` 中存在保险库、`.sync` 和加密备份。关闭应用后直接运行新版安装包覆盖旧版；重新打开时应显示已有保险库，原主密码可解锁，条目和同步配置仍在，手动同步可完成。升级前后比较上述数据文件与备份目录，不应因安装而被删除或重置。如果安装器或应用标识符发生变化，必须重新执行此演练。

仓库是私有仓库时，Release 和下载链接仍受仓库权限控制；不要把临时 Actions artifact 链接当成长期分发地址。

## 当前签名边界

- macOS ARM64 包使用 ad-hoc 签名并检查 bundle 内部完整性，但没有 Developer ID 身份，也没有 notarization。Gatekeeper 仍可能阻止或警告；ad-hoc 签名不能证明发布者身份。
- Windows 包当前没有 Authenticode 签名，SmartScreen 可能警告；工作流只报告签名状态，不把“未签名”伪装成成功的发布者验证。
- Linux AppImage/DEB 当前没有项目级 GPG、Sigstore 或发行版仓库签名。
- `SHA256SUMS.txt` 只能帮助发现下载损坏或资产被替换；如果哈希文件和安装包来自同一被攻陷渠道，它不能替代可信代码签名。
- 当前没有签名自动更新器。用户不应安装来源不明的安装包，也不应绕过系统警告后把包当作已验证的正式发行版。

因此所有自动创建的版本都标为 **prerelease / 未审计 beta**。配置可信签名与安全保管的签名密钥、完成 notarization/Authenticode、验证 Linux 分发方案并做独立审计之前，不应改成 production/stable。

## 本地核对哈希

下载同一 Release 中的安装包和 `SHA256SUMS.txt` 后，在可信终端核对：

```text
macOS:   shasum -a 256 -c SHA256SUMS.txt
Linux:   sha256sum -c SHA256SUMS.txt
Windows: Get-FileHash <安装包路径> -Algorithm SHA256
```

Windows 的结果应与 `SHA256SUMS.txt` 中相同文件名对应的值逐字比较。校验成功只说明文件与该清单一致，不说明发布者身份可信。
