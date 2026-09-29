use thiserror::Error;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("保险库已存在。")]
    AlreadyExists,
    #[error("尚未创建本地保险库。")]
    NotFound,
    #[error("保险库已锁定。")]
    Locked,
    #[error("无法解锁保险库，请检查主密码或文件是否正确。")]
    UnlockFailed,
    #[error("主密码至少需要 12 个字符。")]
    MasterPasswordTooShort,
    #[error("主密码过长。")]
    MasterPasswordTooLong,
    #[error("请求中的字段无效：{0}")]
    InvalidInput(String),
    #[error("找不到该条目。")]
    EntryNotFound,
    #[error("该条目已在其他操作中发生变化，请重新加载后再保存。")]
    RevisionConflict,
    #[error("条目标识已存在，不能重复创建。")]
    EntryAlreadyExists,
    #[error("保险库文件过大或格式不受支持。")]
    InvalidVault,
    #[error("备份恢复会话已失效，请重新选择备份文件。")]
    PendingRestoreUnavailable,
    #[error("预览后本地保险库已发生变化。为避免覆盖新数据，请重新选择并预览备份。")]
    RestoreTargetChanged,
    #[error(
        "检测到未完成的保险库恢复，无法自动确认磁盘状态。请保留应用数据目录并检查备份后再继续。"
    )]
    RestoreRecoveryFailed,
    #[error("同步预览已失效或远端内容已经变化，请重新检查远端保险库。")]
    PendingSyncPreviewUnavailable,
    #[error("请先验证备份密码，再确认恢复。")]
    PendingRestoreNotVerified,
    #[error("无法安全保存保险库。")]
    SaveFailed,
    #[error("保险库文件在当前会话期间发生变化。已停止写入；请锁定后重新解锁，检查数据后重试。")]
    VaultChangedOnDisk,
    #[error("保险库安全升级未完成。")]
    PasswordOnlyMigrationFailed,
    #[error("系统剪贴板不可用。")]
    Clipboard,
    #[error("WebDAV 同步正在进行，请等待当前操作完成。")]
    SyncBusy,
    #[error("尚未在此设备配置 WebDAV 同步。")]
    SyncNotConfigured,
    #[error("同步期间本地保险库已发生变化；远端内容未覆盖这些更改，请重新同步。")]
    SyncLocalChanged,
    #[error("{0}")]
    Sync(String),
    #[error("内部状态暂时不可用。")]
    StateUnavailable,
}

impl From<crate::sync::SyncError> for VaultError {
    fn from(error: crate::sync::SyncError) -> Self {
        Self::Sync(error.to_string())
    }
}

impl serde::Serialize for VaultError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

pub type VaultResult<T> = Result<T, VaultError>;
