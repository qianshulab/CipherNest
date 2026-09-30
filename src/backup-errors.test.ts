import { describe, expect, it } from "vitest";

import { describeBackupFailure } from "./backup-errors";

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
