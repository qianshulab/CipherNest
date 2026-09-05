# 设备快速解锁的安全设计

状态：适用于 CipherNest 0.3.1 未审计 beta
最后核对代码：2026-09-05

## 结论

设备快速解锁是一个**默认关闭、由用户主动启用**的本机便利功能：

```text
主密码 OR 本机设备密钥 → 解封当前 Vault Root Key（VRK）
```

它不是“主密码 AND 第二因素”，因此不能宣传为保险库双因素认证。启用后，成功的 Touch ID 或 Windows Hello 可以在不再次输入主密码的情况下解锁当前保险库。希望始终要求主密码的用户应保持此功能关闭。

启用必须从一次主密码解锁的会话发起。随机生成的 256 位设备密钥不会交给 WebView，也不会写入保险库正文；Rust 后端使用它包裹当前 VRK，并把认证密文写入本机设备槽文件。平台安全机制负责保护设备密钥本身。

## macOS：Touch ID 门控的 Data Protection Keychain

macOS 将随机设备密钥保存为 generic-password Keychain item，并采用以下约束：

- `kSecAccessControlBiometryCurrentSet`：只有当前已登记的 Touch ID 指纹可释放条目；增加、删除或重新登记指纹会使条目失效。
- `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`：设备必须设置登录口令，条目不迁移到其他设备；取消设备口令会删除该保护等级的条目。
- `kSecAttrSynchronizable = false`：不通过 iCloud Keychain 同步。
- 每次增加、读取和删除都设置 `kSecUseDataProtectionKeychain = true`，避免落入 macOS 旧式 Keychain 语义。
- Keychain 的 service 固定，account 由 `vault_id + device_id` 构成；使用应用默认访问组，不配置共享 Keychain access group。

真正的安全边界是带 `SecAccessControl` 的 Keychain 查询：读取操作只有在系统完成 Touch ID 验证后才返回设备密钥。`LAContext.canEvaluatePolicy` 只用于判断 Touch ID 是否可用；一个先返回 `true`、再读取普通存储的认证流程可以被同进程代码跳过，不能替代 Keychain ACL。

这里刻意没有使用 `kSecAccessControlUserPresence`。后者可允许设备口令等系统回退，更适合标为“系统认证”，而不是“仅 Touch ID”。严格策略的代价是指纹集合变化后必须使用主密码重新启用快速解锁。

生产构建必须使用稳定的 bundle identifier 和可信代码签名身份。开发签名、重签名或应用访问组变化可能让原有 Keychain item 不再可访问。

Apple 资料：

- [使用 Face ID 或 Touch ID 访问 Keychain item](https://developer.apple.com/documentation/localauthentication/accessing-keychain-items-with-face-id-or-touch-id)
- [`biometryCurrentSet` 及登记变化后的失效语义](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/biometrycurrentset)
- [`kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`](https://developer.apple.com/documentation/security/ksecattraccessiblewhenpasscodesetthisdeviceonly)
- [`kSecUseDataProtectionKeychain`](https://developer.apple.com/documentation/security/ksecusedataprotectionkeychain)

## Windows：Windows Hello 平台认证器与 WebAuthn PRF

Windows 实现不把 `UserConsentVerifier` 的成功布尔值当作密钥。它使用 Win32 WebAuthn 的 PRF / `hmac-secret` 能力，让平台认证器在完成 Windows Hello 用户验证后产生 256 位秘密输出，再由该输出派生密钥包裹随机设备密钥。

启用前必须同时满足：

- `WebAuthNGetApiVersionNumber() >= 6`；
- `WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable()` 返回可用；
- 创建 credential 时强制 `WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM`；
- 创建和取 assertion 都使用 `WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED`；
- 创建结果明确报告 `bPrfEnabled = true`；
- 枚举到的 credential detail 至少为 version 2，且 `bBackedUp = false`。

拒绝 backed-up credential 是为了避免同步 passkey 破坏“仅本机”边界。该检查不只发生在登记时：每次解锁都在 assertion 前后重新枚举 credential，核对固定 RP、credential detail version ≥ 2 和 `bBackedUp = false`，属性失效即拒绝。Windows 新版本可能安装第三方 passkey provider，因此仅看到一个 WebAuthn 成功对话框，并不足以证明 credential 是本机且未备份。

当前 `windows` Rust 绑定完整覆盖 WebAuthn v6/v7。登记采用兼容且可审计的两步流程：先 `WebAuthNAuthenticatorMakeCredential` 启用 PRF，再立即以随机 32 字节 salt 调用 `WebAuthNAuthenticatorGetAssertion` 取得 PRF 输出。登记时可能出现两次 Windows Hello 提示。WebAuthn v8 支持在创建 credential 时同时求值 PRF，但当前依赖没有该结构的完整绑定；本项目不为减少一次登记提示而手写不稳定的 FFI 尾部结构。

Windows 本地记录只包含：格式版本、vault/device ID、credential ID、随机 PRF salt、nonce 和经过 XChaCha20-Poly1305 认证加密的设备密钥。包裹密钥由 PRF 输出通过 HKDF-SHA-256 派生，AAD 绑定所有上述身份与版本字段。记录本身不包含可直接使用的 PRF 秘密或明文设备密钥。

Windows Hello 可能选择 PIN、面部或指纹，应用不能可靠指定或获知具体方式，因此 UI 只称“Windows Hello”，不承诺“仅指纹”。平台 credential 通常能获得 TPM 保护，但软件和系统配置不同；本项目没有验证硬件 attestation，不能承诺每台设备都由 TPM 保管。

`UserConsentVerifier.RequestVerificationAsync` 只给出认证结果。将它与 DPAPI、Credential Manager 或普通文件读取串联，仍允许同一进程中的恶意代码跳过认证分支。`KeyCredential.RequestSignAsync` 能让 Hello 保护的私钥签名挑战，适合服务端认证，但签名结果不是秘密，也没有任意本地解密接口。离线保险库需要的是 WebAuthn PRF / `hmac-secret` 这类高熵秘密输出。

Microsoft 资料：

- [Windows WebAuthn API 概览及 `hmac-secret` 离线场景](https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/webauthn-apis)
- [`WebAuthNGetApiVersionNumber`](https://learn.microsoft.com/en-us/windows/win32/api/webauthn/nf-webauthn-webauthngetapiversionnumber)
- [`WebAuthNAuthenticatorMakeCredential`](https://learn.microsoft.com/en-us/windows/win32/api/webauthn/nf-webauthn-webauthnauthenticatormakecredential)
- [`WEBAUTHN_HMAC_SECRET_SALT`](https://learn.microsoft.com/en-us/windows/win32/api/webauthn/ns-webauthn-webauthn_hmac_secret_salt)
- [`WEBAUTHN_CREDENTIAL_DETAILS` 的备份状态](https://learn.microsoft.com/en-us/windows/win32/api/webauthn/ns-webauthn-webauthn_credential_details)
- [`UserConsentVerifier.RequestVerificationAsync`](https://learn.microsoft.com/en-us/uwp/api/windows.security.credentials.ui.userconsentverifier.requestverificationasync)
- [`KeyCredential.RequestSignAsync`](https://learn.microsoft.com/en-us/uwp/api/windows.security.credentials.keycredential.requestsignasync)
- [Microsoft 维护的 canonical `webauthn.h`](https://github.com/microsoft/webauthn/blob/master/webauthn.h)

## Linux：仅主密码

Linux 版本不提供设备快速解锁。桌面环境、Secret Service、PAM 和 fprintd 的实现差异很大；PAM/fprintd 通常只返回一次认证状态，Secret Service 也可能随登录会话自动解锁。把两者简单串联不能得到与 Keychain ACL 或 WebAuthn PRF 相同的密码学门控。

因此 Linux 保持主密码解锁，且不保存可绕过主密码的设备密钥。未来若支持具有 `hmac-secret`/PRF 的硬件安全密钥，应作为单独功能进行跨发行版威胁建模和测试。

## 为什么传统 Authenticator/TOTP 不适合离线解密

传统 Authenticator 应用按照 [RFC 6238 TOTP](https://www.rfc-editor.org/rfc/rfc6238) 用共享 seed、当前时间和短数字验证码完成认证。它很适合服务器拥有 seed、能够限速和锁定账号的在线登录，但不能直接成为安全的离线保险库解密密钥：

- 常见 6 位验证码只有约 20 bit 的当次搜索空间。复制了密文的攻击者不受应用内失败延迟限制，可以离线尝试全部验证码。
- 如果桌面应用为了离线校验而把同一 TOTP seed 存在保险库旁边，攻击者复制整套文件后也得到校验因子；若再用另一把密钥保护 seed，就回到了如何保护那把密钥的原问题。
- Authenticator 不会把其 TOTP seed 或高熵派生结果安全交给本应用。用户输入的短码只是认证声明，不是适合 AEAD/HKDF 的长期秘密。
- 经典 WebAuthn 签名 assertion 同样只是可公开验证的签名。只有明确支持 PRF/`hmac-secret` 的 passkey/认证器，才能在用户验证后给本地应用一个高熵、按 credential 隔离的秘密输出；并非所有 passkey 都支持该扩展。

若希望真正“每次解锁都需要第二因素”，协议必须把 `Argon2id(主密码)` 与 Keychain/WebAuthn PRF 提供的高熵设备秘密共同组合成包裹密钥，并移除同机可用的仅主密码解锁槽。CipherNest 当前没有实现该模式。

## 反编译、文件复制与攻击边界

CipherNest 的算法、源码、salt、nonce、AAD 结构和 KDF 参数都可以公开。应用不包含全局解密密钥或隐藏 pepper；安全性不依赖攻击者看不懂二进制。因此，反编译应用并复制锁定的加密文件，不会直接得到条目明文。

但复制的 envelope 提供了无限次离线猜测主密码的材料。攻击者可以对每个候选运行 Argon2id，再尝试解封 VRK；应用内延迟和 UI 锁定对此无效。Argon2id 只能提高单次猜测成本，不能补救短、可预测、复用或已经泄露的主密码。

快速解锁附属文件也按“可被复制和修改”设计：它们只保存认证密文和非秘密标识。macOS 明文设备密钥只在不可同步的 ThisDeviceOnly Keychain item 中；Windows 明文设备密钥需要未备份的平台 credential 产生正确 PRF 输出才能解封。

这些机制不防御已经在同一用户会话或已解锁进程中运行的恶意软件。键盘记录、内存读取、进程注入、恶意 WebView、屏幕/剪贴板抓取、管理员/root 或内核权限均可能取得主密码、设备密钥或解锁后的条目。设备快速解锁主要降低静态磁盘被盗和另一用户读取的风险，不是恶意主机隔离边界。

## 撤销、换主密码和历史快照

关闭快速解锁必须再次输入当前主密码。关闭快速解锁或更改主密码都会：

1. 生成新的随机 VRK，并以当前或新主密码重新包裹；
2. 用新 VRK 重新加密当前正文；
3. 删除当前设备 slots；
4. 尽力删除对应 Keychain item 或 Windows WebAuthn credential/本地记录。

这使旧设备槽不能解密**新的当前正文**。操作系统条目的删除是尽力而为；即使删除失败，旧设备密钥也只能解封旧 VRK。

轮换不能追溯销毁已经复制出去的历史。一个完整且内部匹配的旧快照——例如旧 envelope、旧 slots，以及旧主密码或仍可使用的旧平台 credential——仍可能解密该快照中的历史秘密。单独把旧 key-wrap、旧 slot 与新正文拼接会因 AEAD/AAD 或 VRK 不匹配而失败，但旧整套快照仍是合法历史。旧导出备份同样继续受导出时的主密码保护。

## 与 WebDAV 同步的关系

WebDAV 的 CN1 同步恢复码包含独立随机的 256 位 Sync Root Key，不是设备快速解锁凭据，也不能重置本地主密码。已解锁会话可以执行用户手动触发的同步；但查看 CN1 恢复码或停止当前设备同步仍要求重新输入当前主密码，单纯通过 Touch ID/Windows Hello 进入的会话不能绕过这一步。

更改主密码或关闭快速解锁会轮换本地 VRK，并把本机同步 sidecar 重新包裹到新 VRK 下；这不会自动轮换共享的同步根密钥、撤销 WebDAV 应用密码或清除远端不可变历史。若怀疑设备、旧本机数据、应用密码或 CN1 恢复码泄漏，需要在服务端撤销旧应用密码，并用可信设备创建全新的同步空间和恢复码后迁移；仅关闭快速解锁或更改主密码不够。恢复另一份保险库则不会把原同步配置静默绑定到恢复后的库。同步的共享密钥、回滚和撤销限制见[WebDAV 手动同步设计](SYNC_DESIGN.md)。

## 实现与测试不变量

- 设备密钥、PRF 输出和 VRK 不得通过 Tauri IPC 返回前端，也不得写入日志。
- 启用只能在主密码解锁状态下进行；设备快速解锁后的会话不能自行重新登记。
- 平台密钥写入成功而 slot 写入失败时，必须尽力删除平台条目。
- 任何平台认证、PRF、AEAD、AAD、长度或 provider 校验失败都必须 fail closed。
- Touch ID 指纹变化、Windows Hello 重置、credential 被删除或 backed-up 时，必须回退到主密码并重新登记。
- 三平台测试必须覆盖取消、锁定、重试、撤销、换主密码、恢复备份、附属文件篡改及平台记录缺失；真实安全属性不能只靠 mock 测试证明。
