import type { WebDavSyncStatus } from "./types";

type RelevantSyncStatus = Pick<
  WebDavSyncStatus,
  "configured" | "automatic" | "autoPaused" | "autoWarning" | "pendingLocalChanges"
>;

export interface WebDavV2SyncStatusFlags {
  configError: boolean;
  statusUncertain: boolean;
  remoteOutcomeUnknown: boolean;
}

export interface WebDavV2SyncPresentation {
  label: string;
  hint: string;
  tone: "error" | "warning" | "pending" | "ready" | "inactive";
}

/** Summarize the local CN2 state without claiming that every device is current. */
export function getWebDavV2SyncPresentation(
  status: RelevantSyncStatus,
  flags: WebDavV2SyncStatusFlags,
): WebDavV2SyncPresentation {
  if (flags.configError) {
    return {
      label: "本机同步配置需检查",
      hint: "无法验证此设备保存的同步配置。请重试读取，必要时重新连接。",
      tone: "error",
    };
  }
  if (!status.configured) {
    return {
      label: "尚未设置",
      hint: "连接 WebDAV 同步空间后，才能在设备间传递已保存的条目。",
      tone: "inactive",
    };
  }
  if (flags.remoteOutcomeUnknown) {
    return {
      label: "远端结果待确认",
      hint: "上次请求的远端结果未能确认。请重新同步并核对其他设备。",
      tone: "error",
    };
  }
  if (flags.statusUncertain) {
    return {
      label: "同步状态待确认",
      hint: "暂时无法确认本机同步状态。请重试读取。",
      tone: "error",
    };
  }
  if (status.autoPaused) {
    return {
      label: "自动同步已暂停",
      hint: "自动同步已暂停。请查看警告并手动同步核对。",
      tone: "error",
    };
  }
  if (status.autoWarning?.trim()) {
    return {
      label: "自动同步需检查",
      hint: "自动检查遇到问题。请查看具体警告并重试同步。",
      tone: "warning",
    };
  }
  if (status.pendingLocalChanges) {
    return {
      label: "本机修改待同步",
      hint: "本机有尚未确认上传的修改。请等待自动重试，或立即同步。",
      tone: "pending",
    };
  }
  if (!status.automatic) {
    return {
      label: "仅手动同步",
      hint: "此设备不会自动同步。保存修改后请手动同步。",
      tone: "warning",
    };
  }
  return {
    label: "已连接 · 自动同步",
    hint: "本机内容与上次同步检查点一致；其他设备需各自完成同步。",
    tone: "ready",
  };
}
