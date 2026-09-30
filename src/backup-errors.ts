export type BackupPhase = "export" | "select" | "inspect" | "apply";

export interface BackupFailure {
  message: string;
  tone: "warning" | "error";
}

const TARGET_CHANGED = "预览后本地保险库已发生变化。为避免覆盖新数据，请重新选择并预览备份。";
const RECOVERY_FAILED = "检测到未完成的保险库恢复，无法自动确认磁盘状态。请保留应用数据目录并检查备份后再继续。";

const EXPORT_ERRORS = new Map<string, string>([
  ["请求中的字段无效：目标备份文件已存在，请选择其他文件名", "目标文件已存在。请另选文件名，避免覆盖旧备份。"],
  ["请求中的字段无效：备份位置不能覆盖当前保险库", "所选位置是当前保险库。请另选备份位置。"],
  ["请求中的字段无效：请将导出文件保存到自动备份目录以外的位置", "请将手动备份保存到自动备份目录以外的位置。"],
  ["请求中的字段无效：备份路径无效", "所选备份位置无效，请重新选择。"],
  ["无法安全保存保险库。", "备份未能写入。请检查目标目录权限和可用空间，然后重试。"],
  ["保险库已锁定。", "保险库已锁定。请重新解锁后导出备份。"],
]);

function backendMessage(error: unknown): string {
  const value = typeof error === "string" ? error : error instanceof Error ? error.message : "";
  return value.replace(/^Error:\s*/u, "").trim();
}

export function describeBackupFailure(phase: BackupPhase, error: unknown): BackupFailure {
  const message = backendMessage(error);
  if (phase === "export") {
    return {
      message: EXPORT_ERRORS.get(message) ?? "备份导出失败。请检查所选位置的权限与可用空间后重试。",
      tone: "error",
    };
  }
  if (message === TARGET_CHANGED) {
    return {
      message: "预览后本机保险库已变化，恢复已停止。请核对当前数据并重新选择备份。",
      tone: "warning",
    };
  }
  if (message === RECOVERY_FAILED) {
    return {
      message: "无法确认上次恢复的磁盘状态。请保留应用数据目录和备份文件，检查权限与磁盘后重启应用。",
      tone: "error",
    };
  }
  if (message === "备份恢复会话已失效，请重新选择备份文件。") {
    return { message: "备份预览已过期。请重新选择并验证备份。", tone: "warning" };
  }
  if (phase === "select") {
    return {
      message: message === "保险库文件过大或格式不受支持。"
        ? "无法读取所选文件：文件可能损坏、过大或不是 CipherNest 加密备份。请选择其他备份。"
        : "无法读取所选备份文件。请检查文件权限和完整性后重试。",
      tone: "error",
    };
  }
  if (phase === "inspect") {
    return {
      message: message === "无法解锁保险库，请检查主密码或文件是否正确。"
        ? "无法解密备份。请核对创建备份时的主密码；文件损坏也可能导致此错误。"
        : "备份验证失败。请重新选择文件并检查文件完整性。",
      tone: "error",
    };
  }
  return {
    message: message === "无法安全保存保险库。"
      ? "恢复未能确认完成。请先重启应用并核对保险库内容，再尝试恢复；保留原备份文件。"
      : "恢复未能确认完成。请先核对保险库状态，保留原备份文件后重试。",
    tone: "error",
  };
}
