import { describe, expect, it } from "vitest";

import { describeEntrySaveFailure, describeUnlockFailure } from "./entry-errors";

describe("entry save error presentation", () => {
  it("shows backend validation reasons and links them to the relevant field", () => {
    expect(describeEntrySaveFailure("请求中的字段无效：网站或主机地址过长")).toEqual({
      message: "无法保存：网站或主机地址过长。",
      field: "address",
    });
    expect(describeEntrySaveFailure(new Error("请求中的字段无效：应用名称不能为空"))).toEqual({
      message: "无法保存：应用名称不能为空。",
      field: "title",
    });
  });

  it("turns revision conflicts into actionable guidance", () => {
    expect(describeEntrySaveFailure("该条目已在其他操作中发生变化，请重新加载后再保存。")).toEqual({
      message: "该条目已发生变化，请重新打开条目，确认最新内容后再保存。",
    });
  });

  it("does not expose unexpected backend or platform details", () => {
    expect(describeEntrySaveFailure("failed to write /Users/example/private/vault.cnvault")).toEqual({
      message: "无法保存条目。现有保险库内容未被覆盖，请重试。",
    });
    expect(describeEntrySaveFailure({ message: "secret internal detail" })).toEqual({
      message: "无法保存条目。现有保险库内容未被覆盖，请重试。",
    });
  });

  it("distinguishes a failed password-only migration without exposing unknown errors", () => {
    expect(describeUnlockFailure("保险库安全升级未完成。")).toContain("保险库升级未完成");
    expect(describeUnlockFailure(new Error("failed to write /private/vault.cnvault"))).toBe(
      "无法解锁保险库，请检查主密码或保险库文件是否正确。",
    );
  });
});
