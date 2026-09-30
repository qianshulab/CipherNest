import { describe, expect, it } from "vitest";

import documentSource from "../index.html?raw";
import cargoManifestSource from "../src-tauri/Cargo.toml?raw";
import commandsSource from "../src-tauri/src/commands.rs?raw";
import cryptoSource from "../src-tauri/src/crypto.rs?raw";
import backendEntrySource from "../src-tauri/src/lib.rs?raw";
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

  it("keeps master password as the only unlock path", () => {
    expect(typesSource).not.toMatch(/QuickUnlock|quickUnlock/);
    expect(rendererSource).not.toMatch(
      /QuickUnlock|quickUnlock|quick_unlock|unlock_with_device|Windows Hello|Touch ID|快速解锁|设备认证/,
    );

    const gate = sourceBetween("function renderGate", "function createPasswordField");
    expect(gate).toContain('invokeCommand<void>(isCreate ? "create_vault" : "unlock_vault"');
    expect(gate).toContain('"主密码"');
    expect(gate).toContain('"输入主密码"');
  });

  it("keeps native quick-auth implementations and dependencies removed", () => {
    const productionBackend = [backendEntrySource, commandsSource, cryptoSource].join("\n");
    expect(productionBackend).not.toMatch(
      /device_auth|quick_unlock|WindowsHello|MacosKeychain|WebAuthN/,
    );
    expect(cargoManifestSource).not.toMatch(
      /objc2-local-authentication|security-framework(?:-sys)?|Win32_Networking_WindowsWebServices/,
    );
  });

  it("serializes sensitive settings, password changes, restores, and sync", () => {
    expect(rendererSource).toContain(
      'type SecurityOperation = "changePassword" | "restore" | "settings" | null',
    );
    const controlHelper = sourceBetween(
      "function setSecurityMutationControlsDisabled",
      "function ensureLayers",
    );
    expect(controlHelper).toContain('querySelectorAll<HTMLButtonElement>("[data-security-mutation]")');

    const settings = sourceBetween("function renderSettingsPage", "function renderWebDavSyncSettingsCard");
    expect(settings).toContain('changeButton.dataset.securityMutation = "true"');
    expect(settings).toContain("changeButton.disabled || state.securityOperation !== null");
    expect(settings).toContain('state.securityOperation = "changePassword"');
    expect(settings).toContain("setSecurityMutationControlsDisabled(true)");
    expect(settings).toContain("state.securityOperation = null");

    const restore = sourceBetween("async function restoreBackup", "async function manualLock");
    expect(restore).toContain('state.securityOperation = "restore"');
    expect(restore).toContain('state.securityOperation === "restore"');

    const sync = sourceBetween("function beginSyncOperation", "function pageHeader");
    expect(sync).toContain("state.securityOperation !== null");
  });

  it("uses a two-stage, preview-before-apply restore and cleans up every non-apply exit", () => {
    const gate = sourceBetween("function renderGate", "function createPasswordField");
    expect(gate).toContain('restore.dataset.securityMutation = "true"');
    const settings = sourceBetween("function renderSettingsPage", "function renderWebDavSyncSettingsCard");
    expect(settings).toContain('restoreButton.dataset.securityMutation = "true"');

    const restore = sourceBetween("async function restoreBackup", "async function manualLock");
    expect(restore).toContain("state.securityOperation !== null || state.syncOperation !== null");
    expect(restore).toContain("hasUnsavedDraft()");
    expect(restore).toContain("当前条目有未保存修改");
    expect(restore).toContain('state.securityOperation = "restore"');
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
    const bootstrapIndex = restore.indexOf("await bootstrap()", applyIndex);
    expect(askIndex).toBeGreaterThan(selectionIndex);
    expect(invokeIndex).toBeGreaterThan(askIndex);
    expect(clearPasswordIndex).toBeGreaterThan(invokeIndex);
    expect(previewIndex).toBeGreaterThan(clearPasswordIndex);
    expect(applyIndex).toBeGreaterThan(previewIndex);
    expect(bootstrapIndex).toBeGreaterThan(applyIndex);

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

    const backup = sourceBetween("async function exportBackup", "async function restoreBackup");
    const restore = sourceBetween("async function restoreBackup", "async function manualLock");
    for (const section of [backup, restore]) {
      expect(section).toContain("withTrustedSystemInteraction");
    }

    const focus = sourceBetween("async function handleFocusChange", "function focusSearchAtEnd");
    expect(focus).toContain("hideAllManagedSensitiveInputs()");
    expect(focus).toContain("hideNotes()");
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
    expect(operations).toContain("请求可能已修改远端");
    expect(operations).toContain("state.syncRemoteOutcomeUnknown = true");
  });

  it("clears WebDAV secrets from forms and requires recovery-code acknowledgement", () => {
    const appState = sourceBetween("interface AppState", "const DEFAULT_SETTINGS");
    expect(appState).not.toMatch(/appPassword|recoveryCode|credentials/i);

    const connection = sourceBetween("function validateWebDavEndpointInput", "function showRecoveryCodeDialog");
    expect(connection).toContain('endpoint.protocol !== "https:"');
    expect(connection).toContain('endpoint.pathname.endsWith("/")');
    expect(connection).toContain('appPassword.input.value = ""');
    expect(connection).toContain('recovery.input.value = ""');
    expect(connection).toContain("hideAllManagedSensitiveInputs()");

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

  it("never presents a stale local sync checkpoint after a committed content mutation", () => {
    const mutations = [
      sourceBetween("async function saveCurrentEntry", "function presentEntrySaveFailure"),
      sourceBetween("async function deleteCurrentEntry", "async function toggleFavorite"),
      sourceBetween("async function toggleFavorite", "async function toggleCurrentFavorite"),
      sourceBetween("async function toggleCurrentFavorite", "function setCurrentEntryRevision"),
      sourceBetween("async function applyGeneratedPassword", "function closeGenerator"),
    ];
    for (const mutation of mutations) {
      expect(mutation).toContain("recordLocalSyncMutation()");
      expect(mutation).toContain("refreshSyncStatusAfterMutation(epoch)");
    }
    const statusCard = sourceBetween("function renderWebDavSyncSettingsCard", "function appendSensitiveSyncMetadata");
    expect(statusCard).toContain("state.syncStatusUncertain");
    expect(statusCard).toContain("state.syncRemoteOutcomeUnknown");
    expect(statusCard).toContain("无法确认本机同步状态");
    expect(statusCard).toContain("上次同步请求的远端结果未能确认");
    const localRefresh = sourceBetween("async function refreshSyncStatusAfterMutation", "function makeElement");
    expect(localRefresh).not.toContain("syncRemoteOutcomeUnknown = false");
  });

  it("returns newly created items to the full list from a conflict-only view", () => {
    const create = sourceBetween("async function createNewEntry", "function emptyEntryInput");
    const generator = sourceBetween("async function applyGeneratedPassword", "function closeGenerator");
    expect(create).toContain("state.conflictsOnly = false");
    expect(generator).toContain("state.conflictsOnly = false");
  });

  it("keeps ambiguous restore and WebDAV outcomes visible without exposing retry secrets", () => {
    const fatal = sourceBetween("function renderFatal", "async function bootstrap");
    expect(fatal).not.toContain("数据未被修改");
    const bootstrap = sourceBetween("async function bootstrap", "function renderGate");
    expect(bootstrap).toContain('invokeCommand<void>("lock_vault")');
    const restore = sourceBetween("async function restoreBackup", "async function manualLock");
    expect(restore).toContain("const refreshed = await bootstrap()");
    expect(restore).toContain("if (refreshed)");
    expect(restore).toContain('restorePhase === "apply"');
    expect(restore).toContain("clearSensitiveState(true)");
    expect(restore).toContain('invokeCommand<void>("lock_vault")');
    expect(restore).toContain('invokeCommand<VaultStatus>("vault_status")');
    expect(restore).toContain("if (!lockedStatus || lockedStatus.unlocked)");
    const retryHint = sourceBetween("interface WebDavRetryHint", "interface ManagedSensitiveInput");
    expect(retryHint).toContain("endpoint: string");
    expect(retryHint).toContain("username: string");
    expect(retryHint).not.toMatch(/appPassword|recoveryCode/);
    const create = sourceBetween("async function createWebDavSyncSpace", "async function joinWebDavSyncSpace");
    expect(create).toContain("若服务器已出现新空间但本机没有取得恢复码");
    expect(create).toContain("loadWebDavSyncStatusSafely");
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

  it("masks entry metadata by default and copies it through the owned clipboard", () => {
    const summaryType = typesSource.slice(
      typesSource.indexOf("export interface EntrySummary"),
      typesSource.indexOf("export interface VaultEntry"),
    );
    expect(summaryType).not.toMatch(/\b(?:username|url|purpose|notes|tags|password)\b/);
    const settings = sourceBetween("function renderSettingsPage", "function renderWebDavSyncSettingsCard");
    expect(settings).toContain('invokeCommand<MasterPasswordChangeResult>("change_master_password"');
    expect(settings).toContain("result.syncConfigPreserved");
    expect(settings).toContain("result.warning");

    const editor = sourceBetween("function renderEntryEditor", "function sectionHeading");
    expect(editor).toContain('addSensitiveTextActions(usernameField, "用户名")');
    expect(editor).toContain('addSensitiveTextActions(purposeField, "用途")');
    expect(editor).toContain('addSensitiveTextActions(urlField, "地址")');
    expect(editor).toContain('addSensitiveTextActions(tagsField, "标签")');
    expect(editor).toContain("notes.readOnly = true");
    expect(editor).toContain("CONCEALED_TEXT");
    expect(editor).not.toContain("draft.purpose) copy.append");
    expect(editor).toContain('"网站或主机地址"');
    expect(editor).not.toContain('urlField.input.type = "url"');
    const sensitiveInput = sourceBetween("function addSensitiveTextActions", "function revealNotes");
    expect(sensitiveInput).toContain('field.input.type = "password"');
    expect(sensitiveInput).toContain("setOptionalActionAvailable(copy, Boolean(field.input.value))");
    expect(sensitiveInput).toContain("revealManagedSensitiveInput(managedField)");
    const row = sourceBetween("function renderEntryRow", "function renderEntryDetail");
    expect(row).toContain('select.setAttribute("aria-label", `${entry.title}');
    expect(row).toContain("securityFlagSummary(entry.securityFlags)");
    expect(row).not.toMatch(/entry\.(?:username|purpose|tags)/);
    const list = sourceBetween("function renderEntryList", "function renderListSkeleton");
    expect(list).toContain('search.type = "password"');
    expect(list).toContain("revealManagedSensitiveInput(managedSearch)");
    const generator = sourceBetween("function renderGeneratorDialog", "function generatorToggle");
    for (const field of ["generatorUser", "generatorPurpose", "generatorUrl", "generatorTags"]) {
      expect(generator).toContain(`addSensitiveTextActions(${field},`);
    }
    const syncSettings = sourceBetween("function renderWebDavSyncSettingsCard", "function appendSyncMetadata");
    expect(syncSettings).toContain('appendSensitiveSyncMetadata(metadata, "服务器"');
    expect(syncSettings).toContain('appendSensitiveSyncMetadata(metadata, "用户名"');
    const syncConnection = sourceBetween("function askWebDavConnection", "function showRecoveryCodeDialog");
    expect(syncConnection).toContain('addSensitiveTextActions(endpoint, "WebDAV 地址")');
    expect(syncConnection).toContain('addSensitiveTextActions(username, "WebDAV 用户名")');
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
    expect(save).toContain('presentEntrySaveFailure(error, "editor")');

    const favorite = sourceBetween("async function toggleCurrentFavorite", "function updateSnapshotFavorite");
    expect(favorite).toContain('invokeCommand<number>("set_favorite"');
    expect(favorite).toContain("setCurrentEntryRevision(id, revision)");

    const generator = sourceBetween("function renderGenerator", "function generatorToggle");
    expect(generator).toContain('"网站或主机地址"');
    expect(generator).not.toContain('generatorUrl.input.type = "url"');

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
    expect(settings).toContain("layout.append(security, backup, master, sync)");
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
    expect(sidebar).not.toContain("state.overview.tags");
    const settings = sourceBetween("function renderSettingsPage", "function renderWebDavSyncSettingsCard");
    expect(settings).toContain("state.overview.lastBackupAt");
    const bootstrap = sourceBetween("async function bootstrap", "function renderGate");
    expect(bootstrap).toContain('invokeCommand<VaultOverview>("vault_overview")');
  });

  it("soft-fails an invalid local sync sidecar without taking down the vault", () => {
    const loader = sourceBetween("async function loadWebDavSyncStatusSafely", "function makeElement");
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

  it("auto-hides every managed sensitive field and masks notes on window blur", () => {
    const passwordField = sourceBetween("function createPasswordField", "function estimateMasterPassword");
    const revealHelper = sourceBetween("function hideManagedSensitiveInput", "function setEntryEditorFrozen");
    const notesHelper = sourceBetween("function revealNotes", "function bindDraftInput");
    const focusHandler = sourceBetween("async function handleFocusChange", "function focusSearchAtEnd");
    expect(passwordField).toContain("revealManagedSensitiveInput(managedField)");
    expect(passwordField).toContain('aria-pressed');
    expect(revealHelper).toContain("state.settings.passwordRevealSeconds");
    expect(revealHelper).toContain("window.setTimeout(() => hideManagedSensitiveInput(field)");
    expect(notesHelper).toContain("window.setTimeout(hideNotes");
    expect(notesHelper).toContain('input.value = state.draft?.notes ? CONCEALED_TEXT : ""');
    const editor = sourceBetween("function renderEntryEditor", "function sectionHeading");
    expect(editor).toContain("revealedNotesInput === notes && !notes.readOnly");
    expect(editor).toContain("hideNotes()");
    expect(focusHandler).toContain("hideAllManagedSensitiveInputs()");
    expect(focusHandler).toContain("hideNotes()");
    const modal = sourceBetween("function activateModal", "function deactivateModal");
    expect(modal).toContain("hideAllManagedSensitiveInputs()");
    expect(modal).toContain("hideNotes()");
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
