import { describe, expect, it } from "vitest";

import { getWebDavV2SyncPresentation, type WebDavV2SyncStatusFlags } from "./sync-status";
import type { WebDavSyncStatus } from "./types";

const ready: WebDavSyncStatus = {
  configured: true,
  automatic: true,
  pendingLocalChanges: false,
};
const known: WebDavV2SyncStatusFlags = {
  configError: false,
  statusUncertain: false,
  remoteOutcomeUnknown: false,
};

describe("CN2 sync status presentation", () => {
  it("does not claim normal operation when a more urgent state exists", () => {
    const cases = [
      { status: ready, flags: { ...known, configError: true }, label: "本机同步配置需检查" },
      { status: ready, flags: { ...known, remoteOutcomeUnknown: true }, label: "远端结果待确认" },
      { status: ready, flags: { ...known, statusUncertain: true }, label: "同步状态待确认" },
      { status: { ...ready, autoPaused: true }, flags: known, label: "自动同步已暂停" },
      { status: { ...ready, autoWarning: "网络失败" }, flags: known, label: "自动同步需检查" },
      { status: { ...ready, pendingLocalChanges: true }, flags: known, label: "本机修改待同步" },
    ];
    for (const { status, flags, label } of cases) {
      expect(getWebDavV2SyncPresentation(status, flags).label).toBe(label);
    }
  });

  it("uses the most actionable state when multiple conditions overlap", () => {
    const status = { ...ready, autoPaused: true, autoWarning: "失败", pendingLocalChanges: true };
    expect(getWebDavV2SyncPresentation(status, { ...known, configError: true, remoteOutcomeUnknown: true }).label)
      .toBe("本机同步配置需检查");
    expect(getWebDavV2SyncPresentation(status, { ...known, remoteOutcomeUnknown: true, statusUncertain: true }).label)
      .toBe("远端结果待确认");
    expect(getWebDavV2SyncPresentation(status, known).label).toBe("自动同步已暂停");
  });

  it("distinguishes unconfigured, manual and ready states", () => {
    expect(getWebDavV2SyncPresentation({ ...ready, configured: false }, known).tone).toBe("inactive");
    expect(getWebDavV2SyncPresentation({ ...ready, automatic: false }, known).label).toBe("仅手动同步");
    expect(getWebDavV2SyncPresentation(ready, known).label).toBe("已连接 · 自动同步");
  });

  it("does not include WebDAV credentials or raw server warnings in the summary", () => {
    const status = {
      ...ready,
      endpointHost: "secret.example.test",
      username: "sensitive-user",
      autoWarning: "private server path /home/user",
    };
    const presentation = getWebDavV2SyncPresentation(status, known);
    const text = `${presentation.label} ${presentation.hint}`;
    expect(text).not.toContain(status.endpointHost);
    expect(text).not.toContain(status.username);
    expect(text).not.toContain(status.autoWarning);
  });
});
