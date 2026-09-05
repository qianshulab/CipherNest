export type EntryField = "title" | "username" | "password" | "address" | "purpose" | "notes" | "tags";

export interface EntrySaveFailure {
  message: string;
  field?: EntryField;
}

const KNOWN_ENTRY_ERRORS = new Map<string, string>([
  ["保险库已锁定。", "保险库已锁定，请重新解锁后保存。"],
  ["找不到该条目。", "找不到该条目，可能已被删除。请返回列表后重试。"],
  ["该条目已在其他操作中发生变化，请重新加载后再保存。", "该条目已发生变化，请重新打开条目，确认最新内容后再保存。"],
  ["条目标识已存在，不能重复创建。", "无法创建条目：条目标识发生冲突，请重新新建后保存。"],
  ["无法安全保存保险库。", "无法安全写入保险库。现有内容未被覆盖，请检查可用空间后重试。"],
  ["WebDAV 同步正在进行，请等待当前操作完成。", "WebDAV 同步正在进行，请等待同步完成后再保存。"],
  ["内部状态暂时不可用。", "应用当前正忙，请稍后重试。"],
]);

const INVALID_INPUT_PREFIX = "请求中的字段无效：";
const GENERIC_SAVE_FAILURE = "无法保存条目。现有保险库内容未被覆盖，请重试。";

export function describeEntrySaveFailure(error: unknown): EntrySaveFailure {
  const raw = readableErrorText(error);
  if (!raw) return { message: GENERIC_SAVE_FAILURE };

  const known = KNOWN_ENTRY_ERRORS.get(raw);
  if (known) return { message: known };

  if (raw.startsWith(INVALID_INPUT_PREFIX)) {
    const reason = normalizeReason(raw.slice(INVALID_INPUT_PREFIX.length));
    if (!reason) return { message: GENERIC_SAVE_FAILURE };
    return {
      message: `无法保存：${reason}`,
      field: fieldForReason(reason),
    };
  }

  return { message: GENERIC_SAVE_FAILURE };
}

function readableErrorText(error: unknown): string | null {
  const candidate = typeof error === "string"
    ? error
    : error instanceof Error
      ? error.message
      : null;
  if (!candidate) return null;
  const normalized = candidate
    .replace(/^Error:\s*/u, "")
    .replace(/[\u0000-\u001f\u007f]/gu, " ")
    .replace(/\s+/gu, " ")
    .trim();
  return normalized.length <= 240 ? normalized : null;
}

function normalizeReason(reason: string): string | null {
  const normalized = reason.trim();
  if (!normalized || normalized.length > 120) return null;
  return /[。！？.!?]$/u.test(normalized) ? normalized : `${normalized}。`;
}

function fieldForReason(reason: string): EntryField | undefined {
  if (reason.includes("应用名称")) return "title";
  if (reason.includes("用户名")) return "username";
  if (reason.includes("密码")) return "password";
  if (/(?:网址|网站|主机|地址)/u.test(reason)) return "address";
  if (reason.includes("用途")) return "purpose";
  if (reason.includes("备注")) return "notes";
  if (reason.includes("标签")) return "tags";
  return undefined;
}
