# CipherNest

**本地优先的加密密码库与密码生成器**，面向 Windows、macOS 和 Linux，使用 Tauri 2、Rust 与 TypeScript 构建。

> **项目状态：v0.3.3 未经过独立安全审计的 beta。** 安装包以 [v0.3.3 Release](https://github.com/qianshulab/CipherNest/releases/tag/v0.3.3) 页面实际发布的资产为准；`main` 分支可能包含尚未打包的修复。请先用非关键数据评估，使用独有的强主密码，并保留经过验证的异盘加密备份。

[下载](#下载与安装) · [快速开始](#快速开始) · [更新与数据保留](#更新与数据保留) · [WebDAV 同步](#可选的-webdav-手动同步) · [从源码构建](#从源码构建) · [安全边界](#安全设计与边界)

## 下载与安装

从 [v0.3.3 Release](https://github.com/qianshulab/CipherNest/releases/tag/v0.3.3) 下载与目标系统匹配的 **prerelease** 安装包；发布前该页面不会提供资产，可先查看 [全部 Releases](https://github.com/qianshulab/CipherNest/releases)：

| 平台 | 架构 | 发布文件 |
| --- | --- | --- |
| Windows | x86-64 | `CipherNest-<版本>-Windows-x86_64-setup.exe`（NSIS） |
| macOS | Apple Silicon / ARM64 | `CipherNest-<版本>-macOS-aarch64.dmg` |
| Linux | x86-64 | `CipherNest-<版本>-Linux-x86_64.AppImage` 或 `.deb` |

同一 Release 提供 `SHA256SUMS.txt`。下载后可在 macOS 使用 `shasum -a 256 -c SHA256SUMS.txt`，在 Linux 使用 `sha256sum -c SHA256SUMS.txt`；Windows 可用 `Get-FileHash <安装包路径> -Algorithm SHA256`，再与清单对应行比较。哈希只能检查文件与同一清单是否一致，不能证明发布者身份。

当前 macOS 包只有 ad-hoc 签名且未经 notarization；Windows 没有 Authenticode 签名，Linux 包也没有项目级可信签名。系统可能提示未知开发者。项目尚无自动更新器，更新需手动下载并安装新版。发布和签名说明见 [发布流程](docs/RELEASING.md)。

## 快速开始

1. 安装并启动 CipherNest，创建至少 12 个字符的主密码；建议使用不与其他服务复用的随机长口令。
2. 在保险库中新增条目，或用密码生成器生成并保存密码。条目可记录应用名称、用户名、密码、网址或主机地址、用途、备注和标签。
3. 从设置中导出 `.cnvault` 加密备份，另存到离线或异盘位置，并在隔离环境中验证可恢复。不要把自动备份当成唯一备份。
4. 需要多设备编辑时，再按下文配置可选的 WebDAV 手动同步。

**请妥善保存主密码。** CipherNest 没有账号、客服重置通道或保险库主密码恢复密钥。WebDAV 的 `CN1.` 同步恢复码不能代替主密码。

## 主要功能

- 本地保险库：创建、解锁、手动锁定，搜索、筛选、排序、编辑、收藏和删除条目。
- 随机密码生成：8–128 个字符，可选择字符类别、排除易混淆字符，以及启用“每类至少一个”。
- 本地安全提示：标出弱密码、重复密码和超过一年未更新的密码；不查询在线泄露数据库。
- 显示与会话控制：敏感字段默认遮罩，可设置显示时长、空闲自动锁定、窗口失焦锁定和剪贴板清除时间；系统从睡眠或休眠恢复时主动锁定。
- 加密导出与恢复：恢复前验证备份主密码并预览，明确确认后才替换现有保险库；内容修改前保留加密自动快照，最多 10 份。
- 可选的 WebDAV 手动加密同步：由用户在已解锁时创建、加入或点击同步；并发修改会保留可辨认的冲突副本。

当前没有浏览器扩展、自动填充、后台自动同步、托管账号、TOTP/设备便捷解锁、遥测或自动更新。Windows、macOS 和 Linux 均只接受主密码解锁。

## 更新与数据保留

应用标识符固定为 `com.ciphernest.vault`。保险库保存在系统应用数据目录中，与安装目录分开；正常覆盖安装沿用同一目录。当前数据布局为：

| 系统 | 通常的数据目录 |
| --- | --- |
| Windows | `%APPDATA%\com.ciphernest.vault\` |
| macOS | `~/Library/Application Support/com.ciphernest.vault/` |
| Linux | `$XDG_DATA_HOME/com.ciphernest.vault/`；未设置时通常为 `~/.local/share/com.ciphernest.vault/` |

`vault.cnvault` 是主保险库；`vault.cnvault.sync` 是仅在配置 WebDAV 后存在的本机加密同步配置，包含同步密钥、应用密码和 checkpoint；`backups/` 保存滚动加密快照。`.sync` **不包含在**应用内导出的 `.cnvault` 备份中。迁移到另一设备时，除保险库备份及其主密码外，还需另行保存 WebDAV 配置所需的 `CN1.` 恢复码和服务器凭据。

升级时先导出一份加密备份，关闭旧版应用，再运行新版安装包。若卸载流程提供删除应用数据的选项，不要选择它。安装后用原主密码解锁，核对条目与同步配置，再继续操作。发布者的 Windows 覆盖安装演练见 [发布流程](docs/RELEASING.md)。

从旧版升级到 v0.3.2 时，首次解锁会验证主密码、备份当前密文并轮换本地保险库根密钥；完成后不要降级到 v0.3.1 或更早版本。旧导出备份仍受导出时的主密码保护，不会被升级自动改写。

## 备份与恢复

- `.cnvault` 导出保持加密，不产生明文密码清单。恢复时需输入**该备份所属的主密码**，预览后明确确认才会替换当前保险库。
- 恢复前应用会尝试保留当前保险库的加密快照。自动快照通常与主文件同盘，不能抵御磁盘损坏、账号级删除或勒索软件；至少保留一份异盘或离线副本。
- 更改主密码只保护轮换后的当前数据；旧导出文件、自动快照和文件系统历史仍可能包含旧密码及已删除的秘密。
- 不要手工编辑 `vault.cnvault`，也不要让多台设备通过普通云盘同时打开同一活动文件。跨设备使用请通过应用内同步或显式加密备份迁移。

## 可选的 WebDAV 手动同步

创建同步空间需要 HTTPS WebDAV 目录、用户名和应用专用密码；加入已有空间还需要 `CN1.` 同步恢复码。应用会探测服务器对强 ETag 与条件请求的支持。同步默认关闭，只在保险库解锁且用户主动操作时连接；没有后台轮询。

远端保存由独立随机 256 位同步根密钥保护的加密 snapshot 和 head，不保存主密码、本地保险库根密钥、设备安全设置或 WebDAV 应用密码。本机的 `.sync` 文件另行加密。条目并发编辑采用三方合并；同一条目冲突和删除/修改冲突会留下副本供用户核对。同步不能代替备份。

**恢复码是高价值秘密。** 请与 WebDAV 应用密码分开离线保存。泄漏恢复码且远端对象可被取得时，历史同步内容可能被解密；停止本机同步或更改主密码都不会撤销共享同步密钥。服务端仍可删除、延迟或回滚数据，并可看到访问时间、账号、IP、对象数量与大小等元数据。新设备首次加入无法仅凭恢复码证明看到的是全局最新版本；长期离线设备也可能因验证链过长而无法继续同步。当前还没有经独立审计的协议或真实 WebDAV 提供商的完整跨平台互操作验证。详见 [同步设计](docs/SYNC_DESIGN.md)。

## 安全设计与边界

| 方面 | 当前实现 |
| --- | --- |
| 主密码与密钥 | Argon2id（64 MiB、3 次迭代、4 lanes、随机 salt）派生密钥包裹密钥；保险库正文使用独立随机 256 位根密钥。 |
| 加密与完整性 | HKDF-SHA-256 派生正文密钥；XChaCha20-Poly1305 认证加密保险库与同步正文。 |
| 本地持久化 | 保险库文件上限 16 MiB，同目录原子替换；内容写入前创建加密快照。 |
| 会话 | 后端空闲锁定、可选失焦锁定、系统恢复时锁定；密钥和部分缓冲区在释放时尽力清零。 |

本项目尚未完成独立安全审计。弱主密码仍可被持有保险库文件的攻击者离线猜测；保险库解锁期间，具有本机代码执行或调试权限的恶意软件可能读取明文。剪贴板清除是尽力而为，不能阻止系统历史记录和其他进程抢先读取。完整旧保险库可被回滚，因为本地没有外部可信单调锚点。自动备份会保留历史秘密，并与主文件通常位于同一设备。Windows 文件权限依赖应用数据目录继承的 ACL。

更多假设、已知风险和技术细节见 [威胁模型](docs/THREAT_MODEL.md)；报告漏洞请遵循 [安全政策](SECURITY.md)，不要在公开 issue 中附上可利用细节或真实秘密。

## 从源码构建

需要 Node.js 24.x、pnpm 10.12.1、Rust 1.89.0（CI 与发布所用版本），以及目标平台的 [Tauri 2 系统依赖](https://v2.tauri.app/start/prerequisites/)。仓库的 `.nvmrc`、`package.json` 和 `Cargo.toml` 记录了运行环境与 crate 的最低版本要求。

```bash
corepack enable
corepack prepare pnpm@10.12.1 --activate
pnpm install --frozen-lockfile
pnpm desktop:dev
```

运行前端测试、类型与生产构建、Rust 测试：

```bash
pnpm check
```

在当前操作系统构建安装包：

```bash
pnpm desktop:build
```

产物位于 `src-tauri/target/release/bundle/`。Windows 构建还需要 Microsoft C++ Build Tools、Windows SDK 和 WebView2；Linux 需要 WebKitGTK 等系统包。CI 覆盖 Windows、macOS、Linux，发布工作流的目标架构与签名边界见 [发布流程](docs/RELEASING.md)。构建通过不等于已完成实际安装、可访问性或安全审计。

## 参与贡献

欢迎通过 [Issues](https://github.com/qianshulab/CipherNest/issues) 讨论可复现的缺陷与功能需求。提交 PR 前请阅读 [贡献指南](CONTRIBUTING.md)，说明行为变化、数据兼容性与安全影响，附上对应测试，并运行 `pnpm check`。安全漏洞请使用 [私密报告方式](SECURITY.md)，不要公开真实保险库、主密码或恢复码。

## 许可证

本项目采用 [MIT License](LICENSE)。
