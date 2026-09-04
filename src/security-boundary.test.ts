import { describe, expect, it } from "vitest";

import documentSource from "../index.html?raw";
import rendererSource from "./main.ts?raw";
import typesSource from "./types.ts?raw";

function sourceBetween(start: string, end: string): string {
  const startIndex = rendererSource.indexOf(start);
  const endIndex = rendererSource.indexOf(end, startIndex + start.length);
  if (startIndex < 0 || endIndex < 0) {
    throw new Error(`Unable to locate renderer section: ${start} -> ${end}`);
  }
  return rendererSource.slice(startIndex, endIndex);
}

describe("renderer security boundary", () => {
  it("uses a restrictive document policy with no remote script source", () => {
    expect(documentSource).toContain("script-src 'self'");
    expect(documentSource).toContain("object-src 'none'");
    expect(documentSource).toContain("frame-ancestors 'none'");
    expect(documentSource).not.toContain("unsafe-eval");
    expect(documentSource).not.toMatch(/<script[^>]+https?:\/\//i);
  });

  it("does not add browser storage, remote calls, unsafe HTML, or weak randomness", () => {
    expect(rendererSource).not.toMatch(/\b(?:localStorage|sessionStorage|indexedDB)\b/);
    expect(rendererSource).not.toMatch(/\b(?:fetch|XMLHttpRequest|WebSocket)\s*\(/);
    expect(rendererSource).not.toMatch(/\.(?:innerHTML|outerHTML)\s*=/);
    expect(rendererSource).not.toContain("insertAdjacentHTML");
    expect(rendererSource).not.toContain("Math.random");
    expect(rendererSource).not.toMatch(/\.style(?:\.|\[|\.setProperty)/);
  });

  it("delegates password generation, persistence, and clipboard writes to Rust", () => {
    expect(rendererSource).toContain('"generate_password"');
    expect(rendererSource).toContain('"save_entry"');
    expect(rendererSource).toContain('"copy_secret"');
    expect(rendererSource).toContain('"clear_owned_clipboard"');
  });

  it("keeps the quick-unlock status contract non-secret and camelCase", () => {
    expect(typesSource).toMatch(
      /export type QuickUnlockMethod = "touchId" \| "windowsHello" \| "unsupported";/,
    );
    const statusContract = typesSource.slice(
      typesSource.indexOf("export interface QuickUnlockStatus"),
      typesSource.indexOf("export interface RestoreSelection"),
    );
    expect(statusContract).toMatch(/available:\s*boolean;/);
    expect(statusContract).toMatch(/enabled:\s*boolean;/);
    expect(statusContract).toMatch(/method:\s*QuickUnlockMethod;/);
    expect(statusContract).toMatch(/label:\s*string;/);
    expect(statusContract).toMatch(/reason\?:\s*string;/);
    expect(statusContract).not.toMatch(/password|secret|deviceKey|wrappedKey/i);
  });

  it("keeps configured state independent from current device availability", () => {
    const normalize = sourceBetween(
      "function normalizeQuickUnlockStatus",
      "async function loadQuickUnlockStatus",
    );
    expect(normalize).toContain("enabled: Boolean(status.enabled)");
    expect(normalize).not.toMatch(/enabled:\s*available\s*&&/);

    const gate = sourceBetween("function renderGate", "function quickUnlockDeviceName");
    expect(gate).toContain(
      "state.quickUnlockStatus.available && state.quickUnlockStatus.enabled",
    );

    const settings = sourceBetween(
      "function renderQuickUnlockSettingsCard",
      "async function enableQuickUnlock",
    );
    expect(settings).toContain("if (!status.enabled && !status.available)");
    expect(settings).toContain("} else if (!status.enabled) {");
    expect(settings).toContain("} else {");
    expect(settings).toContain("if (status.reason) {");
    expect(settings).toContain("disableQuickUnlock(current.input, disableButton, error)");

    const disable = sourceBetween("async function disableQuickUnlock", "function pageHeader");
    expect(disable).toContain("!state.quickUnlockStatus.enabled");
    expect(disable).not.toContain("!state.quickUnlockStatus.available");
  });

  it("does not receive device secrets and sends only the current password when revoking", () => {
    expect(rendererSource).toContain('invokeCommand<void>("unlock_with_device")');
    expect(rendererSource).toContain('invokeCommand<void>("enable_quick_unlock")');
    expect(rendererSource).toContain(
      'invokeCommand<MasterPasswordChangeResult>("disable_quick_unlock", { currentPassword })',
    );

    const disable = sourceBetween("async function disableQuickUnlock", "function pageHeader");
    const clearInputIndex = disable.indexOf('passwordInput.value = ""');
    const invokeIndex = disable.indexOf('invokeCommand<MasterPasswordChangeResult>("disable_quick_unlock"');
    const clearLocalIndex = disable.indexOf('currentPassword = ""', invokeIndex);
    expect(clearInputIndex).toBeGreaterThan(-1);
    expect(invokeIndex).toBeGreaterThan(clearInputIndex);
    expect(clearLocalIndex).toBeGreaterThan(invokeIndex);
  });

  it("guards quick-unlock mutations against duplicate and stale responses", () => {
    const unlock = sourceBetween("async function unlockWithDevice", "function createPasswordField");
    const enable = sourceBetween("async function enableQuickUnlock", "async function disableQuickUnlock");
    const disable = sourceBetween("async function disableQuickUnlock", "function pageHeader");

    for (const operation of [unlock, enable, disable]) {
      expect(operation).toContain("state.quickUnlockOperation !== null");
      expect(operation).toContain("const epoch = state.epoch");
      expect(operation).toContain("epoch !== state.epoch");
    }
    expect(unlock).toContain('state.quickUnlockOperation = "unlock"');
    expect(unlock).toContain("await bootstrap()");
    expect(enable).toContain('state.quickUnlockOperation = "enable"');
    expect(disable).toContain('state.quickUnlockOperation = "disable"');

    for (const operation of [enable, disable]) {
      const reloadIndex = operation.indexOf("loadQuickUnlockStatus(");
      const staleCheckIndex = operation.indexOf("epoch !== state.epoch", reloadIndex);
      const stateWriteIndex = operation.indexOf(
        "state.quickUnlockStatus = quickUnlockStatus",
        reloadIndex,
      );
      expect(reloadIndex).toBeGreaterThan(-1);
      expect(staleCheckIndex).toBeGreaterThan(reloadIndex);
      expect(stateWriteIndex).toBeGreaterThan(staleCheckIndex);
    }
  });

  it("serializes quick-unlock changes with master-password rotation", () => {
    expect(rendererSource).toContain(
      'type QuickUnlockOperation = "unlock" | "enable" | "disable" | "changePassword" | "restore" | "settings" | null',
    );
    const controlHelper = sourceBetween(
      "function setSecurityMutationControlsDisabled",
      "function ensureLayers",
    );
    expect(controlHelper).toContain('querySelectorAll<HTMLButtonElement>("[data-security-mutation]")');

    const settings = sourceBetween("function renderSettingsPage", "function renderQuickUnlockSettingsCard");
    expect(settings).toContain('changeButton.dataset.securityMutation = "true"');
    expect(settings).toContain("changeButton.disabled || state.quickUnlockOperation !== null");
    expect(settings).toContain('state.quickUnlockOperation = "changePassword"');
    expect(settings).toContain("setSecurityMutationControlsDisabled(true)");

    const quickSettings = sourceBetween(
      "function renderQuickUnlockSettingsCard",
      "async function enableQuickUnlock",
    );
    expect(quickSettings.match(/dataset\.securityMutation = "true"/g)).toHaveLength(2);

    const enable = sourceBetween("async function enableQuickUnlock", "async function disableQuickUnlock");
    const disable = sourceBetween("async function disableQuickUnlock", "function pageHeader");
    for (const operation of [enable, disable]) {
      expect(operation).toContain("setSecurityMutationControlsDisabled(true)");
      expect(operation).toContain("setSecurityMutationControlsDisabled(false)");
    }
  });

  it("refreshes device enrollment after locking while a mutation may be in flight", () => {
    const lock = sourceBetween("async function performLock", "function clearSensitiveState");
    const lockCommandIndex = lock.indexOf('invokeCommand<void>("lock_vault")');
    const reloadIndex = lock.indexOf("await loadQuickUnlockStatus()", lockCommandIndex);
    const epochCheckIndex = lock.indexOf("lockEpoch === state.epoch", reloadIndex);
    const stateWriteIndex = lock.indexOf(
      "state.quickUnlockStatus = quickUnlockStatus",
      epochCheckIndex,
    );

    expect(lock).toContain("const lockEpoch = state.epoch");
    expect(lockCommandIndex).toBeGreaterThan(-1);
    expect(reloadIndex).toBeGreaterThan(lockCommandIndex);
    expect(epochCheckIndex).toBeGreaterThan(reloadIndex);
    expect(stateWriteIndex).toBeGreaterThan(epochCheckIndex);
  });

  it("reloads quick-unlock state after a successful master-password rotation", () => {
    const settings = sourceBetween("function renderSettingsPage", "function renderQuickUnlockSettingsCard");
    const changeIndex = settings.indexOf('invokeCommand<MasterPasswordChangeResult>("change_master_password"');
    const reloadIndex = settings.indexOf("loadQuickUnlockStatus({", changeIndex);
    const staleCheckIndex = settings.indexOf("operationEpoch === state.epoch", reloadIndex);
    const stateWriteIndex = settings.indexOf(
      "state.quickUnlockStatus = quickUnlockStatus",
      staleCheckIndex,
    );
    const renderIndex = settings.indexOf("renderMainShell()", stateWriteIndex);
    const noticeIndex = settings.indexOf("设备快速解锁已关闭", renderIndex);

    expect(changeIndex).toBeGreaterThan(-1);
    expect(reloadIndex).toBeGreaterThan(changeIndex);
    expect(staleCheckIndex).toBeGreaterThan(reloadIndex);
    expect(stateWriteIndex).toBeGreaterThan(staleCheckIndex);
    expect(renderIndex).toBeGreaterThan(stateWriteIndex);
    expect(noticeIndex).toBeGreaterThan(renderIndex);
  });

  it("preserves the last trusted enrollment state when a status refresh fails", () => {
    const loader = sourceBetween("async function loadQuickUnlockStatus", "function makeElement");
    expect(loader).toContain("fallback: QuickUnlockStatus = state.quickUnlockStatus");
    expect(loader).toContain("...fallback");
    expect(loader).toContain("已保留上一次可信状态");

    const enable = sourceBetween("async function enableQuickUnlock", "async function disableQuickUnlock");
    expect(enable).toMatch(
      /loadQuickUnlockStatus\(\{[\s\S]*\.\.\.state\.quickUnlockStatus,[\s\S]*enabled:\s*true/,
    );

    const disable = sourceBetween("async function disableQuickUnlock", "function pageHeader");
    expect(disable).toMatch(
      /loadQuickUnlockStatus\(\{[\s\S]*\.\.\.state\.quickUnlockStatus,[\s\S]*enabled:\s*false/,
    );

    const settings = sourceBetween("function renderSettingsPage", "function renderQuickUnlockSettingsCard");
    const changeIndex = settings.indexOf('invokeCommand<MasterPasswordChangeResult>("change_master_password"');
    const rotationReload = settings.slice(changeIndex, settings.indexOf("} catch", changeIndex));
    expect(rotationReload).toMatch(
      /loadQuickUnlockStatus\(\{[\s\S]*\.\.\.state\.quickUnlockStatus,[\s\S]*enabled:\s*false/,
    );
  });

  it("uses a two-stage, preview-before-apply restore and cleans up every non-apply exit", () => {
    const gate = sourceBetween("function renderGate", "function quickUnlockDeviceName");
    expect(gate).toContain('restore.dataset.securityMutation = "true"');
    const settings = sourceBetween("function renderSettingsPage", "function renderQuickUnlockSettingsCard");
    expect(settings).toContain('restoreButton.dataset.securityMutation = "true"');

    const restore = sourceBetween("async function restoreBackup", "async function manualLock");
    expect(restore).toContain("state.quickUnlockOperation !== null || state.syncOperation !== null");
    expect(restore).toContain("hasUnsavedDraft()");
    expect(restore).toContain("当前条目有未保存修改");
    expect(restore).toContain('state.quickUnlockOperation = "restore"');
    expect(restore).toContain("setSecurityMutationControlsDisabled(true)");
    expect(restore).toContain('invokeCommand<RestoreSelection | null>("select_backup_for_restore")');
    expect(restore).toContain('invokeCommand<RestorePreview>("inspect_selected_backup"');
    expect(restore).toContain("showRestorePreview(selection, preview)");
    expect(restore).toContain('invokeCommand<VaultStatus>("apply_selected_backup"');
    expect(restore).toContain('invokeCommand<void>("cancel_pending_restore")');
    expect(rendererSource).not.toContain('invokeCommand<string | null>("restore_backup"');
    expect(restore).toContain("operationEpoch !== state.epoch");

    const selectionIndex = restore.indexOf('"select_backup_for_restore"');
    const askIndex = restore.indexOf("await askMasterPassword", selectionIndex);
    const invokeIndex = restore.indexOf('invokeCommand<RestorePreview>("inspect_selected_backup"');
    const clearPasswordIndex = restore.indexOf('masterPassword = ""', invokeIndex);
    const previewIndex = restore.indexOf("showRestorePreview(selection, preview)", clearPasswordIndex);
    const applyIndex = restore.indexOf('"apply_selected_backup"', previewIndex);
    const revokeIndex = restore.indexOf("enabled: false", applyIndex);
    const bootstrapIndex = restore.indexOf("await bootstrap()", revokeIndex);
    expect(askIndex).toBeGreaterThan(selectionIndex);
    expect(invokeIndex).toBeGreaterThan(askIndex);
    expect(clearPasswordIndex).toBeGreaterThan(invokeIndex);
    expect(previewIndex).toBeGreaterThan(clearPasswordIndex);
    expect(applyIndex).toBeGreaterThan(previewIndex);
    expect(revokeIndex).toBeGreaterThan(applyIndex);
    expect(bootstrapIndex).toBeGreaterThan(revokeIndex);

    const preview = sourceBetween("function showRestorePreview", "function handleGlobalShortcut");
    for (const field of ["preview.fileName", "selection.fileSize", "preview.itemCount", "preview.updatedAt", "preview.generation", "preview.vaultIdShort"]) {
      expect(preview).toContain(field);
    }
    expect(preview).toContain("替换当前保险库");
    expect(preview).toContain('dialog.setAttribute("role", "alertdialog")');
  });

  it("narrows trusted native interactions and revalidates the vault fail-closed", () => {
    const trusted = sourceBetween("async function verifyVaultAfterTrustedSystemInteraction", "function inputValue");
    expect(trusted).toContain('invokeCommand<VaultStatus>("vault_status")');
    expect(trusted).toContain("await performLock");
    expect(trusted).toContain("trustedSystemInteractionDepth += 1");
    expect(trusted).toContain("trustedSystemInteractionDepth - 1");

    const unlock = sourceBetween("async function unlockWithDevice", "function createPasswordField");
    const enable = sourceBetween("async function enableQuickUnlock", "async function disableQuickUnlock");
    const backup = sourceBetween("async function exportBackup", "async function restoreBackup");
    const restore = sourceBetween("async function restoreBackup", "async function manualLock");
    for (const section of [unlock, enable, backup, restore]) {
      expect(section).toContain("withTrustedSystemInteraction");
    }

    const focus = sourceBetween("async function handleFocusChange", "function focusSearchAtEnd");
    expect(focus).toContain("hideAllManagedPasswordFields()");
    expect(focus).toContain("trustedSystemInteractionDepth > 0");
    expect(focus).toContain('invokeCommand<boolean>("handle_focus_change"');
    expect(focus).toContain("if (locked)");
    expect(focus).toContain("await performLock");
  });

  it("keeps WebDAV public status non-secret and makes synchronization explicit and single-flight", () => {
    const statusContract = typesSource.slice(
      typesSource.indexOf("export interface WebDavSyncStatus"),
      typesSource.indexOf("export interface WebDavCredentials"),
    );
    expect(statusContract).toContain("configured: boolean");
    expect(statusContract).toContain("pendingLocalChanges: boolean");
    expect(statusContract).not.toMatch(/appPassword|recoveryCode|rootKey|deviceId/i);

    const card = sourceBetween("function renderWebDavSyncSettingsCard", "function appendSyncMetadata");
    expect(card).toContain("创建同步空间");
    expect(card).toContain("加入已有空间");
    expect(card).toContain("立即同步");
    expect(card).toContain("保险库锁定时不会发起同步");
    expect(card).toContain("停止此设备同步只会移除本机配置");
    expect(card).toContain("本机配置无法验证 · 同步已停止");
    expect(card).toContain("清除本机同步配置");

    const operations = sourceBetween("function beginSyncOperation", "function pageHeader");
    for (const command of [
      "create_webdav_sync",
      "inspect_webdav_sync",
      "join_webdav_sync",
      "sync_webdav_now",
      "reveal_webdav_recovery_code",
      "disable_webdav_sync",
    ]) {
      expect(operations).toContain(`"${command}"`);
    }
    expect(operations).toContain("state.syncOperation !== null");
    expect(operations).toContain("setSecurityMutationControlsDisabled(true)");
    expect(operations).toContain("operationEpoch !== state.epoch");
    expect(operations).toContain("本机数据未被静默覆盖");
  });

  it("clears WebDAV secrets from forms and requires recovery-code acknowledgement", () => {
    const appState = sourceBetween("interface AppState", "const DEFAULT_SETTINGS");
    expect(appState).not.toMatch(/appPassword|recoveryCode|credentials/i);

    const connection = sourceBetween("function validateWebDavEndpointInput", "function showRecoveryCodeDialog");
    expect(connection).toContain('endpoint.protocol !== "https:"');
    expect(connection).toContain('endpoint.pathname.endsWith("/")');
    expect(connection).toContain('appPassword.input.value = ""');
    expect(connection).toContain('recovery.input.value = ""');
    expect(connection).toContain("hideAllManagedPasswordFields()");

    const recovery = sourceBetween("function showRecoveryCodeDialog", "function showWebDavJoinPreview");
    expect(recovery).toContain("这是本次创建流程唯一一次自动展示");
    expect(recovery).toContain("我已将恢复码保存在 WebDAV 之外的安全位置");
    expect(recovery).toContain("done.disabled = true");
    expect(recovery).toContain('input.value = ""');
    expect(recovery).toContain('copySecret(input.value, "恢复码")');

    const operations = sourceBetween("function beginSyncOperation", "function pageHeader");
    expect(operations).toContain("clearWebDavCredentials(credentials)");
    expect(operations).toContain("clearWebDavJoinDetails(details)");
    expect(operations).toContain('createResult.recoveryCode = ""');
    expect(operations).toContain('revealResult.recoveryCode = ""');
    expect(operations).toContain('preview.previewToken = ""');
  });

  it("previews first-device trust and protects remote replacement with a second confirmation", () => {
    const preview = sourceBetween("function showWebDavJoinPreview", "function showRestoreProgress");
    for (const field of ["preview.itemCount", "preview.updatedAt", "preview.sequence", "preview.syncIdShort"]) {
      expect(preview).toContain(field);
    }
    expect(preview).toContain("首次加入（TOFU）");
    expect(preview).toContain("合并（推荐）");
    expect(preview).toContain("以远端替换本机");

    const join = sourceBetween("async function joinWebDavSyncSpace", "async function syncWebDavNow");
    const previewIndex = join.indexOf("showWebDavJoinPreview");
    const dangerIndex = join.indexOf("再次确认：以远端内容替换本机", previewIndex);
    const applyIndex = join.indexOf('"join_webdav_sync"', dangerIndex);
    expect(previewIndex).toBeGreaterThan(-1);
    expect(dangerIndex).toBeGreaterThan(previewIndex);
    expect(applyIndex).toBeGreaterThan(dangerIndex);
  });

  it("handles master-password sync warnings and copies usernames and URLs through the owned clipboard", () => {
    const settings = sourceBetween("function renderSettingsPage", "function renderWebDavSyncSettingsCard");
    expect(settings).toContain('invokeCommand<MasterPasswordChangeResult>("change_master_password"');
    expect(settings).toContain("result.syncConfigPreserved");
    expect(settings).toContain("result.warning");

    const editor = sourceBetween("function renderEntryEditor", "function sectionHeading");
    expect(editor).toContain('addCopyAction(usernameField, "用户名")');
    expect(editor).toContain('addCopyAction(urlField, "网址")');
    const copy = sourceBetween("function addCopyAction", "function bindDraftInput");
    expect(copy).toContain("copy.hidden = !field.input.value");
    const clipboard = sourceBetween("async function copySecret", "function startClipboardTimer");
    expect(clipboard).toContain('invokeCommand<void>("copy_secret"');
  });

  it("serializes entry saves, freezes the editor, and carries the expected revision", () => {
    expect(typesSource).toMatch(/expectedRevision\?:\s*number;/);
    const save = sourceBetween("async function saveCurrentEntry", "function validateEntry");
    expect(save).toContain("state.entryMutation !== null");
    expect(save).toContain('state.entryMutation = "saving"');
    expect(save).toContain("setEntryEditorFrozen(true)");
    expect(save).toContain("input.expectedRevision = state.entryMeta.revision");
    expect(save).toContain("draftChangedWhileSaving");
    expect(save).toContain("serializeInput(state.draft) !== submittedSnapshot");
    expect(save).toContain("state.entryMutation = null");

    const shortcuts = sourceBetween("function handleGlobalShortcut", "ensureLayers()");
    expect(shortcuts).toContain("state.entryMutation");

    const manualLock = sourceBetween("async function manualLock", "async function performLock");
    expect(manualLock).toContain("state.entryMutation !== null");
    expect(manualLock).not.toContain("blockEntryActionWhileMutating()");
  });

  it("reflows settings into one full-width card stream at compact widths", () => {
    expect(rendererSource).toContain('window.matchMedia("(max-width: 1100px)")');
    const settings = sourceBetween("function renderSettingsPage", "function renderWebDavSyncSettingsCard");
    expect(settings).toContain("if (compactSettingsMedia.matches)");
    expect(settings).toContain("layout.append(security, quickUnlock, backup, master, sync)");
  });

  it("keeps modal interactions single-layered and blocks background shortcuts", () => {
    const modalHelpers = sourceBetween("function hasOpenModal", "function nextModalIds");
    expect(modalHelpers).toContain("app.inert = hidden");
    expect(modalHelpers).toContain('app.setAttribute("aria-hidden", "true")');
    expect(modalHelpers).toContain("if (hasOpenModal()) return false");

    const shortcuts = sourceBetween("function handleGlobalShortcut", "ensureLayers()");
    expect(shortcuts).toContain("if (hasOpenModal()");

    for (const start of ["function showConfirm", "function showUnsavedLockDialog", "function askMasterPassword", "function showRestoreProgress", "function showRestorePreview"]) {
      const section = rendererSource.slice(
        rendererSource.indexOf(start),
        rendererSource.indexOf("\nfunction ", rendererSource.indexOf(start) + start.length),
      );
      expect(section).toContain("hasOpenModal()");
      expect(section).toContain("activateModal(");
      expect(section).toContain('aria-labelledby');
      expect(section).toContain('aria-describedby');
    }
  });

  it("uses an unfiltered vault overview for persistent navigation and backup status", () => {
    expect(typesSource).toContain("export interface VaultOverview");
    const sidebar = sourceBetween("function renderSidebar", "function navItem");
    expect(sidebar).toContain("state.overview.totalEntries");
    expect(sidebar).toContain("state.overview.favoriteCount");
    expect(sidebar).toContain("state.overview.tags.slice(0, 8)");
    const settings = sourceBetween("function renderSettingsPage", "function renderQuickUnlockSettingsCard");
    expect(settings).toContain("state.overview.lastBackupAt");
    const bootstrap = sourceBetween("async function bootstrap", "function renderGate");
    expect(bootstrap).toContain('invokeCommand<VaultOverview>("vault_overview")');
  });

  it("soft-fails an invalid local sync sidecar without taking down the vault", () => {
    const loader = sourceBetween("async function loadWebDavSyncStatusSafely", "async function loadQuickUnlockStatus");
    expect(loader).toContain('invokeCommand<WebDavSyncStatus>("webdav_sync_status")');
    expect(loader).toContain("error: true");
    const bootstrap = sourceBetween("async function bootstrap", "function renderGate");
    expect(bootstrap).toContain("loadWebDavSyncStatusSafely");
    expect(bootstrap).toContain("state.syncStatusError = syncState.error");
    const disable = sourceBetween("async function disableWebDavSync", "function pageHeader");
    expect(disable).toContain("!state.syncStatus.configured && !state.syncStatusError");
    expect(disable).toContain('invokeCommand<void>("disable_webdav_sync"');
    expect(disable).toContain("state.syncStatusError = false");
  });

  it("auto-hides every managed password field and masks them on window blur", () => {
    const passwordField = sourceBetween("function createPasswordField", "function estimateMasterPassword");
    const revealHelper = sourceBetween("function hideManagedPasswordField", "function setEntryEditorFrozen");
    const focusHandler = sourceBetween("async function handleFocusChange", "function focusSearchAtEnd");
    expect(passwordField).toContain("revealManagedPasswordField(managedField)");
    expect(passwordField).toContain('aria-pressed');
    expect(revealHelper).toContain("state.settings.passwordRevealSeconds");
    expect(revealHelper).toContain("window.setTimeout(() => hideManagedPasswordField(field)");
    expect(focusHandler).toContain("hideAllManagedPasswordFields()");
  });

  it("disables generator result actions and closing while generation or save is busy", () => {
    const output = sourceBetween("function updateGeneratorOutput", "function toggleGeneratorVisibility");
    expect(output).toContain("state.generatorBusy || state.generatorApplying");
    expect(output).toContain("reveal.disabled = !resultReady");
    expect(output).toContain("copy.disabled = !resultReady");
    expect(output).toContain("copyOnly.disabled = !resultReady");
    expect(output).toContain("primary.disabled = !resultReady");
    expect(output).toContain("close.disabled = interactionBusy");

    const close = sourceBetween("function closeGenerator", "async function exportBackup");
    expect(close).toContain("if (!force && (state.generatorBusy || state.generatorApplying)) return");
  });

  it("uses non-nested entry controls and exposes core accessibility state", () => {
    const row = sourceBetween("function renderEntryRow", "function renderEntryDetail");
    expect(row).toContain('makeElement("button", "entry-row-main")');
    expect(row).toContain('row.setAttribute("role", "listitem")');
    expect(row).not.toContain('row.setAttribute("role", "button")');
    expect(row).toContain('select.setAttribute("aria-current", "true")');

    const textField = sourceBetween("function createTextField", "function bindDraftInput");
    expect(textField).toContain("input.required = true");
    expect(textField).toContain('input.setAttribute("aria-required", "true")');
    expect(rendererSource).toContain('button.setAttribute("aria-current", "page")');
    expect(rendererSource).toContain('loading.setAttribute("role", "status")');
  });
});
