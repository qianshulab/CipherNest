import { describe, expect, it } from "vitest";

import { describeBackupFailure, restoreRejectedBeforeWrite } from "./backup-errors";

describe("backup failure guidance", () => {
  it("identifies a pre-existing export target without inviting overwrite", () => {
    expect(describeBackupFailure("export", "请求中的字段无效：目标备份文件已存在，请选择其他文件名").message)
      .toContain("另选文件名");
  });

  it("distinguishes unreadable selections from failed decryption", () => {
    expect(describeBackupFailure("select", "保险库文件过大或格式不受支持。").message)
      .toContain("无法读取所选文件");
    expect(describeBackupFailure("inspect", "无法解锁保险库，请检查主密码或文件是否正确。").message)
      .toContain("主密码");
  });

  it("treats changed restore targets as a conflict", () => {
    expect(describeBackupFailure("apply", "预览后本地保险库已发生变化。为避免覆盖新数据，请重新选择并预览备份。")).toEqual({
      message: "预览后本机保险库已变化，恢复已停止。请核对当前数据并重新选择备份。",
      tone: "warning",
    });
  });

  it("reports an identical recovery point without claiming an uncertain write", () => {
    const sameVault = "请求中的字段无效：所选备份与当前保险库相同，无需恢复";
    expect(restoreRejectedBeforeWrite(sameVault)).toBe(true);
    expect(describeBackupFailure("apply", sameVault)).toEqual({
      message: "所选备份与当前保险库完全一致，无需恢复。",
      tone: "warning",
    });
  });

  it("keeps editing available for definite pre-write rejections", () => {
    const oldKey = "当前设备的 WebDAV 备份连接无法用所选旧备份的密钥保留。请先解锁当前保险库后重试；从 WebDAV 恢复时也可选择保存本次连接。";
    expect(restoreRejectedBeforeWrite(oldKey)).toBe(true);
    expect(describeBackupFailure("apply", oldKey).tone).toBe("warning");
    expect(restoreRejectedBeforeWrite("Error: WebDAV 同步正在进行，请等待当前操作完成。")).toBe(true);
    expect(restoreRejectedBeforeWrite("备份恢复会话已失效，请重新选择备份文件。")).toBe(true);
    expect(restoreRejectedBeforeWrite("预览后本地保险库已发生变化。为避免覆盖新数据，请重新选择并预览备份。")).toBe(true);
    expect(restoreRejectedBeforeWrite("无法安全保存保险库。")).toBe(false);
    expect(restoreRejectedBeforeWrite("内部状态暂时不可用。")).toBe(false);
  });

  it("does not promise an unchanged vault after an uncertain apply failure", () => {
    const failure = describeBackupFailure("apply", "无法安全保存保险库。");
    expect(failure.message).toContain("核对保险库内容");
    expect(failure.message).not.toContain("内容未被覆盖");
  });

  it("does not display unexpected platform details", () => {
    expect(describeBackupFailure("export", "Access denied: C:\\Users\\person\\secret.cnvault").message)
      .not.toContain("C:\\Users");
  });
});
