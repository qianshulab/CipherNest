import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import brandLogoUrl from "./assets/ciphernest-logo-ui-v1.png";
import { describeBackupFailure, type BackupPhase } from "./backup-errors";
import { describeEntrySaveFailure, describeUnlockFailure, type EntryField } from "./entry-errors";
import { visibleListRows } from "./list-window";
import { captureViewPosition, restoreViewPosition } from "./view-state";
import "./styles.css";

import type {
  EntryInput,
  EntrySort,
  EntrySummary,
  GeneratedPassword,
  GeneratorOptions,
  MasterPasswordChangeResult,
  RestorePreview,
  RestoreSelection,
  SecurityIssue,
  SecurityIssueKind,
  SecurityReport,
  ToastKind,
  VaultEntry,
  VaultOverview,
  VaultSettings,
  VaultStatus,
  VaultView,
  WebDavCreateResult,
  WebDavCredentials,
  WebDavJoinMode,
  WebDavRecoveryCode,
  WebDavRemotePreview,
  WebDavSyncOutcome,
  WebDavSyncStatus,
} from "./types";

type IconName =
  | "alert"
  | "archive"
  | "back"
  | "check"
  | "chevron"
  | "copy"
  | "download"
  | "eye"
  | "eyeOff"
  | "favorite"
  | "key"
  | "lock"
  | "menu"
  | "plus"
  | "refresh"
  | "search"
  | "settings"
  | "shield"
  | "tag"
  | "trash"
  | "upload"
  | "x";

interface EntryMeta {
  id?: string;
  createdAt?: number;
  updatedAt?: number;
  passwordUpdatedAt?: number;
  revision?: number;
}

interface GeneratorDraft {
  title: string;
  username: string;
  purpose: string;
  url: string;
  tags: string[];
}

interface WebDavJoinDetails {
  credentials: WebDavCredentials;
  recoveryCode: string;
}

interface WebDavBackupStatus {
  configured: boolean;
  endpoint?: string;
  username?: string;
  automatic?: boolean;
  pending?: boolean;
  lastUploadAt?: number;
  lastUploadedGeneration?: number;
  warning?: string;
}

interface WebDavBackupItem {
  fileName: string;
  fileSize: number;
  generation: number;
  updatedAt: number;
  vaultIdShort: string;
}

type SecurityOperation = "changePassword" | "restore" | "settings" | "backup" | null;
type EntryMutation = "saving" | "deleting" | "favoriting" | null;
type SyncOperation = "create" | "inspect" | "join" | "sync" | "auto" | "reveal" | "disable" | null;

interface WebDavRetryHint {
  mode: "create" | "join";
  endpoint: string;
  username: string;
  message: string;
}

interface ManagedSensitiveInput {
  input: HTMLInputElement;
  button: HTMLButtonElement;
  label: string;
  timeout: ReturnType<typeof setTimeout> | null;
}

interface AppState {
  status: VaultStatus;
  overview: VaultOverview;
  backupOperationError: string | null;
  webdavBackupStatus: WebDavBackupStatus;
  webdavBackupStatusError: boolean;
  securityOperation: SecurityOperation;
  syncStatus: WebDavSyncStatus;
  syncStatusError: boolean;
  syncStatusUncertain: boolean;
  syncRemoteOutcomeUnknown: boolean;
  webdavRetry: WebDavRetryHint | null;
  syncOperation: SyncOperation;
  settings: VaultSettings;
  view: VaultView;
  sort: EntrySort;
  query: string;
  conflictsOnly: boolean;
  entries: EntrySummary[];
  visibleEntryCount: number;
  entryListKey: string;
  listLoading: boolean;
  listError: boolean;
  selectedId: string | null;
  entryMeta: EntryMeta;
  draft: EntryInput | null;
  draftSnapshot: string;
  entryRevisionConflict: boolean;
  entryMutation: EntryMutation;
  detailLoading: boolean;
  report: SecurityReport | null;
  visibleIssueCount: number;
  reportLoading: boolean;
  reportError: boolean;
  passwordVisible: boolean;
  mobileNavOpen: boolean;
  generatorOpen: boolean;
  generatorSource: "standalone" | "entry";
  generatorOptions: GeneratorOptions;
  generatorDraft: GeneratorDraft;
  generatorResult: GeneratedPassword | null;
  generatorBusy: boolean;
  generatorApplying: boolean;
  generatorVisible: boolean;
  epoch: number;
}

const DEFAULT_SETTINGS: VaultSettings = {
  autoLockMinutes: 5,
  clipboardClearSeconds: 20,
  passwordRevealSeconds: 10,
  lockOnBlur: false,
};

const DEFAULT_GENERATOR_OPTIONS: GeneratorOptions = {
  length: 20,
  lowercase: true,
  uppercase: true,
  digits: true,
  symbols: true,
  excludeAmbiguous: false,
  requireEach: true,
};

const CONCEALED_TEXT = "••••••••••••";
const ENTRY_REVISION_CONFLICT = "该条目已在其他操作中发生变化，请重新加载后再保存。";
const MASTER_PASSWORD_TOO_WEAK = "主密码包含常见或易预测模式，请改用独有的长随机词组。";
const RESTORE_TARGET_CHANGED = "预览后本地保险库已发生变化。为避免覆盖新数据，请重新选择并预览备份。";

const EMPTY_STATUS: VaultStatus = {
  exists: false,
  unlocked: false,
  itemCount: 0,
  autoLockMinutes: 5,
};

const EMPTY_OVERVIEW: VaultOverview = {
  totalEntries: 0,
  favoriteCount: 0,
  securityIssueCount: 0,
  syncConflictCount: 0,
  autoBackup: {
    count: 0,
    currentCovered: false,
    inspectionFailed: false,
  },
};

const EMPTY_SYNC_STATUS: WebDavSyncStatus = {
  configured: false,
  pendingLocalChanges: false,
};

const state: AppState = {
  status: { ...EMPTY_STATUS },
  overview: { ...EMPTY_OVERVIEW },
  backupOperationError: null,
  webdavBackupStatus: { configured: false },
  webdavBackupStatusError: false,
  securityOperation: null,
  syncStatus: { ...EMPTY_SYNC_STATUS },
  syncStatusError: false,
  syncStatusUncertain: false,
  syncRemoteOutcomeUnknown: false,
  webdavRetry: null,
  syncOperation: null,
  settings: { ...DEFAULT_SETTINGS },
  view: "all",
  sort: "updated_desc",
  query: "",
  conflictsOnly: false,
  entries: [],
  visibleEntryCount: 200,
  entryListKey: "",
  listLoading: false,
  listError: false,
  selectedId: null,
  entryMeta: {},
  draft: null,
  draftSnapshot: "",
  entryRevisionConflict: false,
  entryMutation: null,
  detailLoading: false,
  report: null,
  visibleIssueCount: 200,
  reportLoading: false,
  reportError: false,
  passwordVisible: false,
  mobileNavOpen: false,
  generatorOpen: false,
  generatorSource: "standalone",
  generatorOptions: { ...DEFAULT_GENERATOR_OPTIONS },
  generatorDraft: emptyGeneratorDraft(),
  generatorResult: null,
  generatorBusy: false,
  generatorApplying: false,
  generatorVisible: false,
  epoch: 0,
};

const app = document.querySelector<HTMLElement>("#app")!;
if (!app) throw new Error("缺少应用挂载节点");
const compactNavigationMedia = window.matchMedia("(max-width: 860px)");
const compactSettingsMedia = window.matchMedia("(max-width: 1100px)");
const ENTRY_PAGE_SIZE = 200;

const iconPaths: Record<IconName, string[]> = {
  alert: ["M12 9v4", "M12 17h.01", "M10.3 3.6 2.4 17.2a2 2 0 0 0 1.8 2.8h15.6a2 2 0 0 0 1.8-2.8L13.7 3.6a2 2 0 0 0-3.4 0Z"],
  archive: ["M4 7v12h16V7", "M2 3h20v4H2z", "M9 11h6"],
  back: ["m15 18-6-6 6-6"],
  check: ["m5 12 4 4L19 6"],
  chevron: ["m9 18 6-6-6-6"],
  copy: ["M8 8h12v12H8z", "M16 8V4H4v12h4"],
  download: ["M12 3v12", "m7 10 5 5 5-5", "M5 21h14"],
  eye: ["M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12Z", "M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6Z"],
  eyeOff: ["m3 3 18 18", "M10.6 10.7a2 2 0 0 0 2.7 2.7", "M9.9 4.2A10.5 10.5 0 0 1 12 4c6.5 0 10 8 10 8a15 15 0 0 1-2.1 3.2", "M6.6 6.6C3.7 8.4 2 12 2 12s3.5 8 10 8c1.4 0 2.6-.3 3.7-.7"],
  favorite: ["m12 3 2.8 5.7 6.2.9-4.5 4.4 1 6.2-5.5-2.9-5.5 2.9 1-6.2-4.5-4.4 6.2-.9Z"],
  key: ["M21 2 13.6 9.4", "M15.5 7.5 18 10", "M12 11a5 5 0 1 1-3-3.9"],
  lock: ["M6 10h12v11H6z", "M8 10V7a4 4 0 0 1 8 0v3", "M12 14v3"],
  menu: ["M4 7h16", "M4 12h16", "M4 17h16"],
  plus: ["M12 5v14", "M5 12h14"],
  refresh: ["M20 6v5h-5", "M4 18v-5h5", "M18.5 9A7 7 0 0 0 6 6.5L4 11", "M5.5 15A7 7 0 0 0 18 17.5l2-4.5"],
  search: ["m21 21-4.4-4.4", "M11 18a7 7 0 1 0 0-14 7 7 0 0 0 0 14Z"],
  settings: ["M12 15.5a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7Z", "M19.4 15a1.7 1.7 0 0 0 .3 1.9l.1.1-2 3.4-.2-.1a1.7 1.7 0 0 0-1.9.1l-.7.4a1.7 1.7 0 0 0-1 1.5v.2h-4v-.2a1.7 1.7 0 0 0-1-1.5l-.7-.4a1.7 1.7 0 0 0-1.9-.1l-.2.1-2-3.4.1-.1a1.7 1.7 0 0 0 .3-1.9v-.8a1.7 1.7 0 0 0-1.3-1.5H3v-4h.3a1.7 1.7 0 0 0 1.3-1.5v-.8a1.7 1.7 0 0 0-.3-1.9l-.1-.1 2-3.4.2.1a1.7 1.7 0 0 0 1.9-.1l.7-.4a1.7 1.7 0 0 0 1-1.5V1h4v.2a1.7 1.7 0 0 0 1 1.5l.7.4a1.7 1.7 0 0 0 1.9.1l.2-.1 2 3.4-.1.1a1.7 1.7 0 0 0-.3 1.9v.8a1.7 1.7 0 0 0 1.3 1.5h.3v4h-.3a1.7 1.7 0 0 0-1.3 1.5Z"],
  shield: ["M12 22s8-3.8 8-10V5l-8-3-8 3v7c0 6.2 8 10 8 10Z", "m9 12 2 2 4-5"],
  tag: ["M20 13 13 20l-9-9V4h7l9 9Z", "M8.5 8.5h.01"],
  trash: ["M4 7h16", "M9 7V4h6v3", "m7 7 1 13h10l1-13", "M10 11v5", "M14 11v5"],
  upload: ["M12 21V9", "m7 14 5-5 5 5", "M5 3h14"],
  x: ["M6 6l12 12", "M18 6 6 18"],
};

let listDebounce: ReturnType<typeof setTimeout> | null = null;
let generatorDebounce: ReturnType<typeof setTimeout> | null = null;
let revealTimeout: ReturnType<typeof setTimeout> | null = null;
let revealTicker: ReturnType<typeof setInterval> | null = null;
let generatorRevealTimeout: ReturnType<typeof setTimeout> | null = null;
let clipboardTimeout: ReturnType<typeof setTimeout> | null = null;
let clipboardTicker: ReturnType<typeof setInterval> | null = null;
let clipboardDeadline = 0;
let autoLockTimeout: ReturnType<typeof setTimeout> | null = null;
let lastActivitySent = 0;
let listRequestId = 0;
let backupStatusRequestId = 0;
let syncStatusRequestId = 0;
let remoteContentRefreshActive = false;
let remoteContentRefreshQueued = false;
let pendingRemoteContentRender = false;
let generatorRequestId = 0;
let generatorFocusRelease: (() => void) | null = null;
let activeModalClose: (() => void) | null = null;
let modalSequence = 0;
let trustedSystemInteractionDepth = 0;
let settingsUiEpoch = -1;
const revealedSensitiveInputs = new Set<ManagedSensitiveInput>();
let revealedNotesInput: HTMLTextAreaElement | null = null;
let notesRevealButton: HTMLButtonElement | null = null;
let notesRevealTimeout: ReturnType<typeof setTimeout> | null = null;

function emptyGeneratorDraft(): GeneratorDraft {
  return { title: "", username: "", purpose: "", url: "", tags: [] };
}

function normalizeSettings(settings: VaultSettings): VaultSettings {
  return {
    autoLockMinutes: settings.autoLockMinutes,
    clipboardClearSeconds: [10, 20, 30, 60].includes(settings.clipboardClearSeconds)
      ? settings.clipboardClearSeconds
      : 20,
    passwordRevealSeconds: settings.passwordRevealSeconds,
    lockOnBlur: settings.lockOnBlur,
  };
}

function normalizeWebDavSyncStatus(status: WebDavSyncStatus): WebDavSyncStatus {
  return {
    configured: Boolean(status.configured),
    automatic: Boolean(status.automatic),
    autoPaused: Boolean(status.autoPaused),
    autoWarning: status.autoWarning || undefined,
    endpointHost: status.endpointHost || undefined,
    username: status.username || undefined,
    syncIdShort: status.syncIdShort || undefined,
    lastSyncAt: Number.isFinite(status.lastSyncAt) ? status.lastSyncAt : undefined,
    remoteSequence: Number.isFinite(status.remoteSequence) ? status.remoteSequence : undefined,
    pendingLocalChanges: Boolean(status.pendingLocalChanges),
  };
}

async function loadWebDavSyncStatusSafely(
  fallback: WebDavSyncStatus = EMPTY_SYNC_STATUS,
): Promise<{ status: WebDavSyncStatus; error: boolean }> {
  try {
    const status = await invokeCommand<WebDavSyncStatus>("webdav_sync_status");
    return { status: normalizeWebDavSyncStatus(status), error: false };
  } catch {
    return { status: normalizeWebDavSyncStatus(fallback), error: true };
  }
}

async function loadWebDavBackupStatusSafely(
  fallback: WebDavBackupStatus = { configured: false },
): Promise<{ status: WebDavBackupStatus; error: boolean }> {
  try {
    const status = await invokeCommand<WebDavBackupStatus>("webdav_backup_status");
    return {
      status: {
        configured: Boolean(status.configured),
        endpoint: status.endpoint || undefined,
        username: status.username || undefined,
        automatic: Boolean(status.automatic),
        pending: Boolean(status.pending),
        lastUploadAt: Number.isFinite(status.lastUploadAt) ? status.lastUploadAt : undefined,
        lastUploadedGeneration: Number.isFinite(status.lastUploadedGeneration)
          ? status.lastUploadedGeneration
          : undefined,
        warning: status.warning || undefined,
      },
      error: false,
    };
  } catch {
    return { status: { ...fallback }, error: true };
  }
}

async function refreshWebDavBackupStatus(epoch: number): Promise<void> {
  const requestId = ++backupStatusRequestId;
  const result = await loadWebDavBackupStatusSafely(state.webdavBackupStatus);
  if (requestId !== backupStatusRequestId || epoch !== state.epoch || !state.status.unlocked) return;
  state.webdavBackupStatus = result.status;
  state.webdavBackupStatusError = result.error;
  if (!hasOpenModal()) {
    if (state.view === "settings" && state.securityOperation === null) {
      document.querySelector<HTMLElement>(".webdav-backup-settings")?.replaceWith(renderWebDavBackupSettings());
      document.querySelector<HTMLElement>(".settings-webdav-overview")?.replaceWith(renderWebDavOverview());
    }
    document.querySelector<HTMLElement>(".statusbar")?.replaceWith(renderStatusbar());
  }
}

async function refreshWebDavSyncStatus(epoch: number): Promise<void> {
  const requestId = ++syncStatusRequestId;
  const result = await loadWebDavSyncStatusSafely(state.syncStatus);
  if (requestId !== syncStatusRequestId || epoch !== state.epoch || !state.status.unlocked) return;
  state.syncStatus = result.status;
  state.syncStatusError = result.error;
  state.syncStatusUncertain = result.error;
  if (hasOpenModal()) return;
  if (state.view === "settings" && state.syncOperation === null) {
    const currentCard = document.querySelector<HTMLElement>(".settings-sync-card");
    if (currentCard) {
      const nextCard = renderWebDavSyncSettingsCard();
      nextCard.classList.add("settings-sync-card");
      currentCard.replaceWith(nextCard);
    }
    document.querySelector<HTMLElement>(".settings-webdav-overview")?.replaceWith(renderWebDavOverview());
  }
  document.querySelector<HTMLElement>(".statusbar")?.replaceWith(renderStatusbar());
}

async function refreshAfterAutoSyncedContent(): Promise<void> {
  if (!state.status.unlocked) return;
  if (remoteContentRefreshActive) {
    remoteContentRefreshQueued = true;
    return;
  }
  remoteContentRefreshActive = true;
  try {
    do {
      remoteContentRefreshQueued = false;
      const epoch = state.epoch;
      const selectedId = state.selectedId;
      const [overview, list] = await Promise.allSettled([
        loadVaultOverview(epoch),
        loadEntries(false, epoch, false, false),
      ]);
      if (epoch !== state.epoch || !state.status.unlocked) return;
      if (overview.status === "rejected" || list.status === "rejected" || (list.status === "fulfilled" && !list.value)) {
        pendingRemoteContentRender = true;
        showToast("远端修改已写入本机，但界面列表未能完整刷新。请点击“重试读取”。", "warning", 7600);
        continue;
      }
      if (
        hasUnsavedDraft()
        || state.entryMutation !== null
        || state.securityOperation !== null
        || state.syncOperation !== null
        || hasOpenModal()
        || state.view === "settings"
      ) {
        pendingRemoteContentRender = true;
        document.querySelector<HTMLElement>(".statusbar")?.replaceWith(renderStatusbar());
        showToast("其他设备的修改已合并到本机。当前表单已保留；保存前请核对最新条目。", "warning", 7600);
        continue;
      }
      if (selectedId && state.selectedId === selectedId && state.draft) {
        if (!state.entries.some((entry) => entry.id === selectedId)) {
          clearEntryDraft();
          state.selectedId = null;
        } else {
          try {
            const entry = await invokeCommand<VaultEntry>("get_entry", { id: selectedId });
            if (
              epoch === state.epoch
              && state.status.unlocked
              && state.selectedId === selectedId
              && !hasUnsavedDraft()
              && state.entryMutation === null
            ) {
              hidePassword();
              clearEntryDraft();
              state.selectedId = selectedId;
              state.entryMeta = {
                id: entry.id,
                createdAt: entry.createdAt,
                updatedAt: entry.updatedAt,
                passwordUpdatedAt: entry.passwordUpdatedAt,
                revision: entry.revision,
              };
              state.draft = entryInputFromVault(entry);
              state.draftSnapshot = serializeInput(state.draft);
            }
            clearVaultEntrySensitiveFields(entry);
          } catch {
            if (epoch === state.epoch && state.selectedId === selectedId) {
              clearEntryDraft();
              state.selectedId = null;
            }
          }
        }
      }
      if (epoch !== state.epoch || !state.status.unlocked) return;
      if (hasUnsavedDraft()) {
        pendingRemoteContentRender = true;
        showToast("其他设备的修改已合并到本机。当前编辑仍保留，请核对后再保存。", "warning", 7600);
        continue;
      }
      renderMainShell();
    } while (remoteContentRefreshQueued && state.status.unlocked);
  } finally {
    remoteContentRefreshActive = false;
  }
}

function recordLocalSyncMutation(): void {
  if (!state.syncStatus.configured || state.syncStatusError) return;
  state.syncStatus = { ...state.syncStatus, pendingLocalChanges: true };
}

async function refreshSyncStatusAfterMutation(epoch: number): Promise<void> {
  if (!state.syncStatus.configured || state.syncStatusError) return;
  const result = await loadWebDavSyncStatusSafely(state.syncStatus);
  if (epoch !== state.epoch || !state.status.unlocked) return;
  if (result.error) {
    state.syncStatusUncertain = true;
    return;
  }
  state.syncStatus = result.status;
  state.syncStatusUncertain = false;
}

function makeElement<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  className?: string,
  text?: string,
): HTMLElementTagNameMap[K] {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined) element.textContent = text;
  return element;
}

function icon(name: IconName, size = 18): SVGSVGElement {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("width", String(size));
  svg.setAttribute("height", String(size));
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "1.8");
  svg.setAttribute("stroke-linecap", "round");
  svg.setAttribute("stroke-linejoin", "round");
  svg.setAttribute("aria-hidden", "true");
  for (const data of iconPaths[name]) {
    const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
    path.setAttribute("d", data);
    svg.append(path);
  }
  return svg;
}

function brandIcon(className = "brand-icon"): HTMLImageElement {
  const image = makeElement("img", className);
  image.src = brandLogoUrl;
  image.alt = "";
  image.draggable = false;
  image.setAttribute("aria-hidden", "true");
  return image;
}

function makeButton(
  label: string,
  className: string,
  handler: () => void | Promise<void>,
  iconName?: IconName,
): HTMLButtonElement {
  const button = makeElement("button", className);
  button.type = "button";
  if (iconName) button.append(icon(iconName));
  const text = makeElement("span", "button-label", label);
  button.append(text);
  button.addEventListener("click", () => void handler());
  return button;
}

function iconButton(
  label: string,
  name: IconName,
  handler: () => void | Promise<void>,
  className = "icon-button",
): HTMLButtonElement {
  const button = makeElement("button", className);
  button.type = "button";
  button.setAttribute("aria-label", label);
  button.title = label;
  button.append(icon(name));
  button.addEventListener("click", () => void handler());
  return button;
}

function clearNode(node: Element): void {
  node.replaceChildren();
}

function invokeCommand<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  return args === undefined ? invoke<T>(command) : invoke<T>(command, args);
}

async function verifyVaultAfterTrustedSystemInteraction(): Promise<void> {
  if (!state.status.unlocked) return;
  try {
    const status = await invokeCommand<VaultStatus>("vault_status");
    if (!status.unlocked) {
      await performLock("设备交互期间会话已超时，保险库已安全锁定。", true);
      return;
    }
    state.status = status;
    recordActivity();
  } catch {
    await performLock("无法确认保险库会话状态，已安全锁定。", true);
  }
}

async function withTrustedSystemInteraction<T>(operation: () => Promise<T>): Promise<T> {
  trustedSystemInteractionDepth += 1;
  try {
    return await operation();
  } finally {
    trustedSystemInteractionDepth = Math.max(0, trustedSystemInteractionDepth - 1);
    if (trustedSystemInteractionDepth === 0) {
      await verifyVaultAfterTrustedSystemInteraction();
    }
  }
}

function inputValue(id: string): string {
  return document.querySelector<HTMLInputElement>(`#${id}`)?.value ?? "";
}

function hasOpenModal(): boolean {
  const region = document.querySelector<HTMLElement>("#modal-region");
  return Boolean(activeModalClose || (region && region.childElementCount > 0));
}

function setModalBackgroundHidden(hidden: boolean): void {
  app.inert = hidden;
  if (hidden) app.setAttribute("aria-hidden", "true");
  else app.removeAttribute("aria-hidden");
  const toastRegion = document.querySelector<HTMLElement>("#toast-region");
  if (toastRegion) {
    toastRegion.inert = hidden;
    if (hidden) toastRegion.setAttribute("aria-hidden", "true");
    else toastRegion.removeAttribute("aria-hidden");
  }
}

function activateModal(close: () => void): boolean {
  if (hasOpenModal()) return false;
  hideAllManagedSensitiveInputs();
  hidePassword();
  hideGeneratorPassword();
  hideNotes();
  activeModalClose = close;
  setModalBackgroundHidden(true);
  return true;
}

function deactivateModal(): void {
  activeModalClose = null;
  setModalBackgroundHidden(false);
  if (pendingRemoteContentRender) {
    window.setTimeout(() => {
      if (
        !pendingRemoteContentRender
        || !state.status.unlocked
        || hasOpenModal()
        || hasUnsavedDraft()
        || state.entryMutation !== null
        || state.securityOperation !== null
        || state.syncOperation !== null
        || state.view === "settings"
      ) return;
      renderMainShell();
    }, 0);
  }
}

function dismissActiveModal(): void {
  const close = activeModalClose;
  if (close) {
    close();
    return;
  }
  const region = document.querySelector<HTMLElement>("#modal-region");
  if (region) clearNode(region);
  deactivateModal();
}

function nextModalIds(prefix: string): { title: string; description: string } {
  modalSequence += 1;
  return {
    title: `${prefix}-title-${modalSequence}`,
    description: `${prefix}-description-${modalSequence}`,
  };
}

function hideManagedSensitiveInput(field: ManagedSensitiveInput): void {
  if (field.timeout) window.clearTimeout(field.timeout);
  field.timeout = null;
  field.input.type = "password";
  clearNode(field.button);
  field.button.append(icon("eye"));
  field.button.setAttribute("aria-label", `显示${field.label}`);
  field.button.setAttribute("aria-pressed", "false");
  field.button.title = `显示${field.label}`;
  revealedSensitiveInputs.delete(field);
}

function revealManagedSensitiveInput(field: ManagedSensitiveInput): void {
  for (const revealed of Array.from(revealedSensitiveInputs)) {
    if (revealed !== field) hideManagedSensitiveInput(revealed);
  }
  hidePassword();
  hideGeneratorPassword();
  hideNotes();
  if (field.timeout) window.clearTimeout(field.timeout);
  field.input.type = "text";
  clearNode(field.button);
  field.button.append(icon("eyeOff"));
  field.button.setAttribute("aria-label", `隐藏${field.label}`);
  field.button.setAttribute("aria-pressed", "true");
  field.button.title = `隐藏${field.label}`;
  const seconds = Math.max(1, state.settings.passwordRevealSeconds || DEFAULT_SETTINGS.passwordRevealSeconds);
  field.timeout = window.setTimeout(() => hideManagedSensitiveInput(field), seconds * 1000);
  revealedSensitiveInputs.add(field);
}

function hideAllManagedSensitiveInputs(): void {
  for (const field of Array.from(revealedSensitiveInputs)) hideManagedSensitiveInput(field);
}

function setEntryEditorFrozen(frozen: boolean): void {
  const editor = document.querySelector<HTMLElement>(".entry-editor");
  if (!editor) return;
  editor.setAttribute("aria-busy", frozen ? "true" : "false");
  editor
    .querySelectorAll<HTMLInputElement | HTMLTextAreaElement | HTMLButtonElement | HTMLSelectElement>(
      "input, textarea, button, select",
    )
    .forEach((control) => {
      control.disabled = frozen;
    });
}

function blockEntryActionWhileMutating(): boolean {
  if (state.securityOperation !== null) {
    showToast("正在完成安全设置，请稍候。", "info", 2200);
    return true;
  }
  if (state.syncOperation !== null) {
    showToast("正在完成手动同步，请稍候。", "info", 2200);
    return true;
  }
  if (state.entryMutation === null) return false;
  const message = state.entryMutation === "saving"
    ? "条目正在加密保存，请稍候。"
    : state.entryMutation === "deleting"
      ? "条目正在删除，请稍候。"
      : "正在更新收藏状态，请稍候。";
  showToast(message, "info", 2200);
  return true;
}

function setBusy(button: HTMLButtonElement, busy: boolean, busyLabel = "处理中…"): void {
  if (!button.dataset.idleLabel) button.dataset.idleLabel = button.textContent ?? "";
  button.disabled = busy;
  button.classList.toggle("is-loading", busy);
  const label = button.querySelector<HTMLElement>(".button-label");
  if (label) label.textContent = busy ? busyLabel : button.dataset.idleLabel;
  else button.textContent = busy ? busyLabel : button.dataset.idleLabel;
}

function setSecurityMutationControlsDisabled(disabled: boolean): void {
  document
    .querySelectorAll<HTMLButtonElement>("[data-security-mutation]")
    .forEach((button) => {
      button.disabled = disabled;
    });
}

function ensureLayers(): void {
  if (!document.querySelector("#toast-region")) {
    const region = makeElement("div", "toast-region");
    region.id = "toast-region";
    region.setAttribute("aria-live", "polite");
    region.setAttribute("aria-atomic", "false");
    document.body.append(region);
  }
  if (!document.querySelector("#modal-region")) {
    const region = makeElement("div", "modal-region");
    region.id = "modal-region";
    document.body.append(region);
  }
}

function showToast(message: string, kind: ToastKind = "info", duration = 3600): void {
  const region = document.querySelector<HTMLElement>("#toast-region");
  if (!region) return;
  const activeDialog = document.querySelector<HTMLElement>("#modal-region [role='dialog']");
  if (activeDialog) {
    const announcement = makeElement("span", "sr-only", message);
    announcement.setAttribute("role", kind === "error" ? "alert" : "status");
    activeDialog.append(announcement);
    window.setTimeout(() => announcement.remove(), duration);
  }
  const toast = makeElement("div", `toast toast-${kind}`);
  toast.setAttribute("role", kind === "error" ? "alert" : "status");
  toast.append(icon(kind === "success" ? "check" : kind === "error" || kind === "warning" ? "alert" : "shield", 17));
  toast.append(makeElement("span", "toast-message", message));
  const close = iconButton("关闭通知", "x", () => toast.remove(), "toast-close");
  toast.append(close);
  region.append(toast);
  window.setTimeout(() => {
    toast.classList.add("toast-leave");
    window.setTimeout(() => toast.remove(), 180);
  }, duration);
}

function renderLoading(label = "正在打开本地保险库…"): void {
  hideAllManagedSensitiveInputs();
  clearNode(app);
  const screen = makeElement("main", "loading-screen");
  const mark = makeElement("div", "brand-mark brand-mark-large brand-logo");
  mark.append(brandIcon());
  const loadingLabel = makeElement("p", "loading-label", label);
  loadingLabel.setAttribute("role", "status");
  loadingLabel.setAttribute("aria-live", "polite");
  screen.append(mark, loadingLabel);
  const bar = makeElement("div", "loading-bar");
  bar.append(makeElement("span"));
  screen.append(bar);
  app.append(screen);
}

function renderFatal(): void {
  hideAllManagedSensitiveInputs();
  clearNode(app);
  const screen = makeElement("main", "loading-screen");
  const card = makeElement("section", "fatal-card");
  card.setAttribute("role", "alert");
  const badge = makeElement("div", "status-icon status-icon-danger");
  badge.append(icon("alert", 24));
  card.append(badge, makeElement("h1", "", "无法启动保险库"));
  card.append(makeElement("p", "muted", "无法确认当前保险库状态。请保留备份文件，检查应用数据目录权限，然后重试读取。"));
  card.append(makeButton("重试", "button button-primary", retryAfterFatal, "refresh"));
  screen.append(card);
  app.append(screen);
}

async function retryAfterFatal(): Promise<void> {
  await invokeCommand<void>("lock_vault").catch(() => undefined);
  const status = await invokeCommand<VaultStatus>("vault_status").catch(() => null);
  if (!status || status.unlocked) {
    renderFatal();
    showToast("仍无法确认保险库已锁定。请关闭应用，保留备份并检查数据目录。", "error", 9000);
    return;
  }
  await bootstrap();
}

async function bootstrap(): Promise<boolean> {
  state.epoch += 1;
  backupStatusRequestId += 1;
  const epoch = state.epoch;
  state.securityOperation = null;
  renderLoading();
  try {
    const status = await invokeCommand<VaultStatus>("vault_status");
    if (epoch !== state.epoch) return false;
    state.status = status;
    if (!status.exists || !status.unlocked) {
      clearSensitiveState(true);
      renderGate();
      return true;
    }
    const [settings, overview, syncState, backupState] = await Promise.all([
      invokeCommand<VaultSettings>("get_settings"),
      invokeCommand<VaultOverview>("vault_overview"),
      loadWebDavSyncStatusSafely({ ...EMPTY_SYNC_STATUS }),
      loadWebDavBackupStatusSafely(),
      loadEntries(false, epoch),
    ]);
    if (epoch !== state.epoch) return false;
    state.settings = normalizeSettings(settings);
    state.overview = overview;
    state.syncStatus = syncState.status;
    state.syncStatusError = syncState.error;
    state.syncStatusUncertain = false;
    state.webdavBackupStatus = backupState.status;
    state.webdavBackupStatusError = backupState.error;
    if (!syncState.status.configured) state.syncRemoteOutcomeUnknown = false;
    state.status.itemCount = overview.totalEntries;
    scheduleAutoLock();
    renderMainShell();
    return true;
  } catch {
    if (epoch === state.epoch) {
      state.status.unlocked = false;
      clearSensitiveState(true);
      await Promise.allSettled([
        invokeCommand<void>("clear_owned_clipboard"),
        invokeCommand<void>("lock_vault"),
      ]);
      if (epoch !== state.epoch) return false;
      renderFatal();
    }
    return false;
  }
}

function renderGate(): void {
  hideAllManagedSensitiveInputs();
  clearNode(app);
  const isCreate = !state.status.exists;
  const screen = makeElement("main", "gate-screen");
  const ambient = makeElement("div", "gate-ambient");
  screen.append(ambient);

  const brand = makeElement("div", "gate-brand");
  const mark = makeElement("div", "brand-mark brand-logo");
  mark.append(brandIcon());
  const brandCopy = makeElement("div");
  brandCopy.append(makeElement("strong", "brand-name", "CIPHERNEST"));
  brandCopy.append(makeElement("span", "brand-subtitle", "LOCAL PASSWORD VAULT"));
  brand.append(mark, brandCopy);

  const offline = makeElement("div", "offline-badge");
  offline.append(
    makeElement("span", "status-dot"),
    makeElement("span", "", "本地优先 · 远端功能按设置运行"),
  );

  const card = makeElement("section", "gate-card");
  card.setAttribute("aria-labelledby", "gate-title");
  const eyebrow = makeElement("div", "eyebrow", isCreate ? "INITIALIZE VAULT" : "SECURE SESSION");
  const title = makeElement("h1", "gate-title", isCreate ? "创建本地保险库" : "解锁保险库");
  title.id = "gate-title";
  const intro = makeElement(
    "p",
    "gate-intro",
    isCreate
      ? "所有条目仅以加密形式保存在这台设备上。请使用一个易记但足够长的主密码。"
      : "本地保险库已锁定。解锁后才能查看条目与元数据。",
  );
  card.append(eyebrow, title, intro);

  const form = makeElement("form", "gate-form");
  form.noValidate = true;
  const passwordGroup = createPasswordField(
    "gate-master-password",
    "主密码",
    isCreate ? "建议使用 5–7 个随机单词" : "输入主密码",
    "current-password",
  );
  form.append(passwordGroup.wrapper);

  let confirmInput: HTMLInputElement | null = null;
  let strengthFill: HTMLElement | null = null;
  let strengthText: HTMLElement | null = null;
  if (isCreate) {
    passwordGroup.input.autocomplete = "new-password";
    const confirmGroup = createPasswordField("gate-confirm-password", "确认主密码", "再次输入主密码", "new-password");
    confirmInput = confirmGroup.input;
    form.append(confirmGroup.wrapper);

    const strength = makeElement("div", "strength-block");
    const strengthHeader = makeElement("div", "strength-header");
    strengthHeader.append(makeElement("span", "muted-small", "主密码强度"));
    strengthText = makeElement("strong", "strength-label", "尚未输入");
    strengthHeader.append(strengthText);
    const track = makeElement("div", "strength-track");
    strengthFill = makeElement("span", "strength-fill");
    track.append(strengthFill);
    const advice = makeElement("p", "field-help", "仅作保守的本地提示，不是安全证明；主密码不会被发送，遗忘后也无法代为恢复。");
    strength.append(strengthHeader, track, advice);
    form.append(strength);

    passwordGroup.input.addEventListener("input", () => {
      const result = estimateMasterPassword(passwordGroup.input.value);
      if (strengthFill && strengthText) {
        strengthFill.dataset.level = result.level;
        strengthText.textContent = result.label;
      }
    });

    const warning = makeElement("div", "inline-notice inline-notice-warning");
    warning.append(icon("alert", 18));
    warning.append(makeElement("p", "", "主密码与恢复备份密码均丢失后，保险库无法恢复。我们不会保存主密码副本。"));
    form.append(warning);
  }

  const error = makeElement("p", "form-error");
  error.id = "gate-error";
  error.setAttribute("role", "alert");
  form.append(error);

  const submit = makeButton(
    isCreate ? "创建本地保险库" : "解锁保险库",
    "button button-primary button-full",
    () => undefined,
    isCreate ? "shield" : "lock",
  );
  submit.type = "submit";
  form.append(submit);

  const restore = makeButton("从加密备份恢复", "button button-ghost button-full", restoreBackup, "upload");
  restore.dataset.securityMutation = "true";
  restore.disabled = state.securityOperation !== null;
  form.append(restore);
  const restoreRemote = makeButton("从 WebDAV 恢复", "button button-ghost button-full", () => restoreBackup("webdav"), "download");
  restoreRemote.dataset.securityMutation = "true";
  restoreRemote.disabled = state.securityOperation !== null;
  form.append(restoreRemote);

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (submit.disabled || state.securityOperation !== null) return;
    error.textContent = "";
    let masterPassword = passwordGroup.input.value;
    if (isCreate) {
      if (masterPassword.length < 12) {
        error.textContent = "主密码至少需要 12 个字符；更推荐使用 5–7 个随机单词。";
        passwordGroup.input.focus();
        return;
      }
      if (masterPassword !== confirmInput?.value) {
        error.textContent = "两次输入的主密码不一致。";
        confirmInput?.focus();
        return;
      }
    } else if (!masterPassword) {
      error.textContent = "请输入主密码。";
      passwordGroup.input.focus();
      return;
    }

    hideAllManagedSensitiveInputs();
    setBusy(submit, true, isCreate ? "正在创建…" : "正在解锁…");
    try {
      await invokeCommand<void>(isCreate ? "create_vault" : "unlock_vault", { masterPassword });
      passwordGroup.input.value = "";
      if (confirmInput) confirmInput.value = "";
      masterPassword = "";
      await bootstrap();
    } catch (caught) {
      passwordGroup.input.value = "";
      if (confirmInput) confirmInput.value = "";
      masterPassword = "";
      error.textContent = isCreate
        ? isWeakMasterPasswordError(caught)
          ? MASTER_PASSWORD_TOO_WEAK
          : "无法创建保险库。数据未被保存，请检查磁盘权限后重试。"
        : describeUnlockFailure(caught);
      setBusy(submit, false);
      passwordGroup.input.focus();
    }
  });

  card.append(form);
  const footer = makeElement("div", "gate-footer");
  footer.append(
    icon("shield", 14),
    makeElement("span", "", "零遥测 · 锁定时不发起远端请求"),
  );
  card.append(footer);

  const layout = makeElement("div", "gate-layout");
  const top = makeElement("header", "gate-topbar");
  top.append(brand, offline);
  layout.append(top, card);
  screen.append(layout);
  app.append(screen);
  window.setTimeout(() => passwordGroup.input.focus(), 0);
}

function createPasswordField(
  id: string,
  labelText: string,
  placeholder: string,
  autocomplete: HTMLInputElement["autocomplete"],
): { wrapper: HTMLElement; input: HTMLInputElement } {
  const wrapper = makeElement("div", "field-group");
  const label = makeElement("label", "field-label", labelText);
  label.htmlFor = id;
  const inputWrap = makeElement("div", "input-with-action");
  const input = makeElement("input", "input") as HTMLInputElement;
  input.id = id;
  input.type = "password";
  input.placeholder = placeholder;
  input.autocomplete = autocomplete;
  input.spellcheck = false;
  input.maxLength = 1024;
  input.required = true;
  input.setAttribute("aria-required", "true");
  let managedField: ManagedSensitiveInput;
  const reveal = iconButton("显示密码", "eye", () => {
    if (input.type === "password") revealManagedSensitiveInput(managedField);
    else hideManagedSensitiveInput(managedField);
  });
  reveal.setAttribute("aria-pressed", "false");
  managedField = { input, button: reveal, label: "密码", timeout: null };
  inputWrap.append(input, reveal);
  wrapper.append(label, inputWrap);
  return { wrapper, input };
}

function estimateMasterPassword(value: string): { label: string; level: string } {
  if (!value) return { label: "尚未输入", level: "empty" };
  const normalized = value.toLocaleLowerCase();
  const compact = normalized.replace(/\s+/g, "");
  const predictable = /(?:password|qwerty|letmein|admin|iloveyou|123456|abcdef)/i.test(compact)
    || /^(.)\1+$/u.test(value)
    || /(?:012345|123456|234567|abcdef|qwerty)/i.test(compact);
  if (predictable) return { label: "模式过于可预测", level: "0" };
  const length = Array.from(value).length;
  if (length < 12) return { label: "长度不足", level: "0" };
  const wordCount = value.trim().split(/\s+/).filter(Boolean).length;
  if (wordCount >= 5 && length >= 20) return { label: "长词组 · 请确认词语随机", level: "4" };
  if (length >= 24) return { label: "长度较充足", level: "4" };
  if (length >= 18) return { label: "长度良好", level: "3" };
  if (length >= 15) return { label: "建议再增加长度", level: "2" };
  return { label: "仅达到最低长度", level: "1" };
}

function renderMainShell(): void {
  if (!state.status.unlocked) {
    renderGate();
    return;
  }
  const reusableSettingsCards = state.view === "settings" && settingsUiEpoch === state.epoch
    ? {
        security: app.querySelector<HTMLElement>(".settings-security-card"),
        master: app.querySelector<HTMLElement>(".settings-master-card"),
      }
    : null;
  const position = captureViewPosition(app);
  hideAllManagedSensitiveInputs();
  hideNotes();
  clearNode(app);
  const shell = makeElement("div", "app-shell");
  shell.dataset.view = state.view;
  const topbar = renderTopbar();
  shell.append(topbar);

  const body = makeElement("div", "app-body");
  const sidebar = renderSidebar();
  body.append(sidebar);
  const content = makeElement("main", "main-content");
  content.id = "main-content";
  if (state.view === "security") content.append(renderSecurityPage());
  else if (state.view === "settings") {
    const settingsPage = renderSettingsPage();
    if (reusableSettingsCards?.security && reusableSettingsCards.master) {
      settingsPage.querySelector(".settings-security-card")?.replaceWith(reusableSettingsCards.security);
      settingsPage.querySelector(".settings-master-card")?.replaceWith(reusableSettingsCards.master);
    }
    content.append(settingsPage);
    settingsUiEpoch = state.epoch;
  }
  else content.append(renderVaultColumns());
  body.append(content);
  shell.append(body);
  const statusbar = renderStatusbar();
  shell.append(statusbar);
  app.append(shell);
  setMobileNavOpen(state.mobileNavOpen);
  setModalBackgroundHidden(hasOpenModal());
  setEntryEditorFrozen(
    state.entryMutation !== null || state.syncOperation !== null || state.securityOperation !== null,
  );
  updateClipboardStatus();
  if (!hasOpenModal()) restoreViewPosition(app, position, state.view);
  if (!hasOpenModal() && state.view !== "settings" && !hasUnsavedDraft()) {
    pendingRemoteContentRender = false;
  }
}

function needsBackupAttention(): boolean {
  const backup = state.overview.autoBackup;
  return backup.inspectionFailed || !backup.currentCovered || Boolean(backup.warning);
}

function currentAutoBackupNeedsAttention(): boolean {
  const backup = state.overview.autoBackup;
  return backup.inspectionFailed || !backup.currentCovered;
}

function renderTopbar(): HTMLElement {
  const topbar = makeElement("header", "topbar");
  const left = makeElement("div", "topbar-left");
  const menu = iconButton("打开导航", "menu", () => {
    setMobileNavOpen(!state.mobileNavOpen, true);
  }, "icon-button mobile-menu");
  menu.dataset.focusKey = "topbar-menu";
  menu.setAttribute("aria-controls", "vault-sidebar");
  menu.setAttribute("aria-expanded", String(state.mobileNavOpen));
  const mark = makeElement("div", "brand-mark brand-mark-small brand-logo");
  mark.append(brandIcon());
  const name = makeElement("div", "topbar-brand");
  name.append(makeElement("strong", "", "CIPHERNEST"), makeElement("span", "", "LOCAL VAULT"));
  const stateBadge = makeElement("div", "vault-state");
  stateBadge.append(makeElement("span", "status-dot"), makeElement("span", "", "已解锁"));
  left.append(menu, mark, name, stateBadge);
  if (needsBackupAttention()) {
    const backupAlert = makeButton("备份状态需检查", "backup-attention", () => switchView("settings"), "alert");
    backupAlert.dataset.focusKey = "backup-attention";
    backupAlert.setAttribute("aria-label", "备份状态需检查，打开设置查看详情");
    backupAlert.title = "当前保险库的备份状态需检查。打开设置查看详情。";
    left.append(backupAlert);
  }

  const actions = makeElement("div", "topbar-actions");
  const generate = makeButton("生成密码", "button button-ghost topbar-button", () => openGenerator("standalone"), "key");
  generate.dataset.focusKey = "topbar-generator";
  generate.title = shortcutTitle("G");
  generate.dataset.securityMutation = "true";
  const add = makeButton("新建条目", "button button-primary topbar-button", createNewEntry, "plus");
  add.dataset.focusKey = "topbar-add";
  add.title = shortcutTitle("N");
  add.dataset.securityMutation = "true";
  const lock = iconButton("立即锁定", "lock", manualLock, "icon-button lock-button");
  lock.dataset.focusKey = "topbar-lock";
  lock.title = `立即锁定 (${shortcutLabel("L")})`;
  actions.append(generate, add, lock);
  topbar.append(left, actions);
  return topbar;
}

function renderSidebar(): HTMLElement {
  const overlay = makeElement("div", `sidebar-overlay${state.mobileNavOpen ? " is-open" : ""}`);
  overlay.setAttribute("aria-hidden", "true");
  overlay.addEventListener("click", () => {
    setMobileNavOpen(false, true);
  });
  const sidebar = makeElement("aside", `sidebar${state.mobileNavOpen ? " is-open" : ""}`);
  sidebar.id = "vault-sidebar";
  sidebar.setAttribute("aria-label", "保险库导航");
  if (compactNavigationMedia.matches && !state.mobileNavOpen) {
    sidebar.inert = true;
    sidebar.setAttribute("aria-hidden", "true");
  }

  const heading = makeElement("div", "sidebar-heading");
  const headingLabel = makeElement("span", "sidebar-heading-label");
  headingLabel.append(brandIcon("sidebar-brand-icon"), makeElement("span", "", "保险库"));
  heading.append(headingLabel);
  heading.append(iconButton("关闭导航", "x", () => {
    setMobileNavOpen(false, true);
  }, "icon-button sidebar-close"));
  sidebar.append(heading);

  const nav = makeElement("nav", "sidebar-nav");
  nav.append(
    navItem("all", "全部条目", "key", state.overview.totalEntries),
    navItem("favorites", "收藏", "favorite", state.overview.favoriteCount),
    navItem("security", "安全检查", "shield", undefined, totalSecurityFlags()),
  );
  if (state.overview.syncConflictCount > 0) {
    const conflicts = makeElement("button", `nav-item${state.conflictsOnly ? " is-active" : ""}`);
    conflicts.type = "button";
    conflicts.dataset.focusKey = "nav-conflicts";
    if (state.conflictsOnly) conflicts.setAttribute("aria-current", "page");
    conflicts.append(
      icon("alert", 18),
      makeElement("span", "nav-label", "同步冲突"),
      makeElement("span", "nav-alert", String(state.overview.syncConflictCount)),
    );
    conflicts.addEventListener("click", () => void showSyncConflictEntries());
    nav.append(conflicts);
  }
  sidebar.append(nav);

  const tagSection = makeElement("section", "sidebar-tags");
  tagSection.append(
    makeElement("h2", "sidebar-section-title", "敏感字段"),
    makeElement("p", "sidebar-empty", "账号、地址、用途、备注和标签默认隐藏"),
  );
  sidebar.append(tagSection);

  const bottom = makeElement("div", "sidebar-bottom");
  bottom.append(navItem("settings", "设置", "settings"));
  const local = makeElement("div", "local-only-card");
  local.append(icon("shield", 18));
  const localCopy = makeElement("div");
  localCopy.append(
    makeElement("strong", "", state.syncStatus.configured || state.webdavBackupStatus.configured ? "本地优先" : "本机保险库"),
    makeElement(
      "span",
      "",
      state.syncStatusError
        ? "同步配置需在设置中处理"
        : state.syncStatus.autoPaused
          ? "自动同步已暂停 · 请核对"
        : state.webdavBackupStatus.configured && state.webdavBackupStatus.automatic
          ? state.syncStatus.configured
            ? `自动远端备份 · ${state.syncStatus.automatic ? "自动双向同步" : "手动双向同步"}`
            : "远端备份自动上传"
          : state.syncStatus.configured
            ? state.syncStatus.automatic ? "自动双向加密同步" : "手动双向加密同步"
            : state.webdavBackupStatus.configured
              ? "远端备份需手动上传"
              : "远端功能默认关闭",
    ),
  );
  local.append(localCopy);
  bottom.append(local);
  sidebar.append(bottom);

  const fragment = makeElement("div", "sidebar-wrap");
  fragment.append(overlay, sidebar);
  return fragment;
}

function navItem(
  view: VaultView,
  label: string,
  iconName: IconName,
  count?: number,
  alertCount?: number,
): HTMLButtonElement {
  const active = state.view === view && !(view === "all" && state.conflictsOnly);
  const button = makeElement("button", `nav-item${active ? " is-active" : ""}`);
  button.type = "button";
  button.dataset.focusKey = `nav-${view}`;
  if (active) button.setAttribute("aria-current", "page");
  button.append(icon(iconName, 18), makeElement("span", "nav-label", label));
  if (alertCount) {
    const badge = makeElement("span", "nav-alert", String(alertCount));
    badge.setAttribute("aria-label", `${alertCount} 个问题`);
    button.append(badge);
  } else if (count !== undefined) {
    button.append(makeElement("span", "nav-count", String(count)));
  }
  button.addEventListener("click", () => void switchView(view));
  return button;
}

function totalSecurityFlags(): number {
  return state.overview.securityIssueCount;
}

function setMobileNavOpen(open: boolean, restoreFocus = false): void {
  const compact = compactNavigationMedia.matches;
  state.mobileNavOpen = compact && open;
  const menu = document.querySelector<HTMLButtonElement>(".mobile-menu");
  menu?.setAttribute("aria-expanded", String(state.mobileNavOpen));
  document.querySelector(".sidebar-overlay")?.classList.toggle("is-open", state.mobileNavOpen);
  const sidebar = document.querySelector<HTMLElement>(".sidebar");
  sidebar?.classList.toggle("is-open", state.mobileNavOpen);
  if (sidebar) {
    sidebar.inert = compact && !state.mobileNavOpen;
    if (sidebar.inert) sidebar.setAttribute("aria-hidden", "true");
    else sidebar.removeAttribute("aria-hidden");
  }
  const content = document.querySelector<HTMLElement>(".main-content");
  const actions = document.querySelector<HTMLElement>(".topbar-actions");
  const statusbar = document.querySelector<HTMLElement>(".statusbar");
  for (const element of [content, actions, statusbar]) {
    if (!element) continue;
    element.inert = state.mobileNavOpen;
    if (state.mobileNavOpen) element.setAttribute("aria-hidden", "true");
    else element.removeAttribute("aria-hidden");
  }
  if (restoreFocus) {
    window.setTimeout(() => {
      const target = state.mobileNavOpen
        ? document.querySelector<HTMLButtonElement>(".sidebar-close")
        : document.querySelector<HTMLButtonElement>(".mobile-menu");
      target?.focus();
    }, 0);
  }
}

async function switchView(view: VaultView): Promise<void> {
  if (blockEntryActionWhileMutating()) return;
  if (view === state.view) {
    if (state.mobileNavOpen) setMobileNavOpen(false, true);
    if (view === "all" && state.conflictsOnly) {
      state.conflictsOnly = false;
      await loadEntries(true);
      return;
    }
    if (state.listError && (view === "all" || view === "favorites")) await loadEntries(true);
    return;
  }
  if (hasUnsavedDraft()) {
    const discard = await showConfirm(
      "放弃未保存的修改？",
      "切换页面将丢弃当前条目的未保存内容。",
      "放弃修改",
      true,
    );
    if (!discard) return;
  }
  if (state.view === "settings" && !await confirmLeavingUnsavedSettings()) return;
  clearEntryDraft();
  state.view = view;
  state.conflictsOnly = false;
  state.mobileNavOpen = false;
  if (view === "security") {
    state.reportLoading = true;
    state.reportError = false;
    renderMainShell();
    await loadSecurityReport();
  } else if (view === "all" || view === "favorites") {
    state.listLoading = true;
    renderMainShell();
    await loadEntries(true);
  } else {
    renderMainShell();
    if (view === "settings") void refreshWebDavBackupStatus(state.epoch);
  }
}

function hasUnsavedSettings(): boolean {
  if (state.view !== "settings" || !state.status.unlocked) return false;
  const autoLock = document.querySelector<HTMLSelectElement>("#setting-auto-lock");
  const clipboard = document.querySelector<HTMLSelectElement>("#setting-clipboard");
  const reveal = document.querySelector<HTMLSelectElement>("#setting-reveal");
  const lockOnBlur = document.querySelector<HTMLInputElement>("#setting-lock-blur");
  const masterInputs = document.querySelectorAll<HTMLInputElement>(".settings-master-card input");
  if (Array.from(masterInputs).some((input) => Boolean(input.value))) return true;
  if (!autoLock || !clipboard || !reveal || !lockOnBlur) return false;
  return Number(autoLock.value) !== state.settings.autoLockMinutes
    || Number(clipboard.value) !== state.settings.clipboardClearSeconds
    || Number(reveal.value) !== state.settings.passwordRevealSeconds
    || lockOnBlur.checked !== state.settings.lockOnBlur;
}

async function confirmLeavingUnsavedSettings(): Promise<boolean> {
  if (!hasUnsavedSettings()) return true;
  return showConfirm(
    "放弃未保存的设置？",
    "安全偏好或主密码表单仍有未提交的输入。切换页面会丢弃这些输入。",
    "放弃输入",
    true,
  );
}

function renderVaultColumns(): HTMLElement {
  const columns = makeElement("div", `vault-columns${state.draft || state.detailLoading ? " show-detail" : ""}`);
  columns.append(renderEntryList(), renderEntryDetail());
  return columns;
}

function renderEntryList(): HTMLElement {
  const panel = makeElement("section", "entry-list-panel");
  panel.setAttribute("aria-label", state.conflictsOnly ? "同步冲突条目" : state.view === "favorites" ? "收藏条目" : "全部条目");
  const header = makeElement("div", "list-header");
  const titleRow = makeElement("div", "list-title-row");
  const title = makeElement("h1", "panel-title", state.conflictsOnly ? "同步冲突" : state.view === "favorites" ? "收藏" : "全部条目");
  const count = makeElement("span", "count-chip", String(state.entries.length));
  count.setAttribute("role", "status");
  count.setAttribute("aria-live", "polite");
  count.setAttribute("aria-label", `共 ${state.entries.length.toLocaleString("zh-CN")} 个匹配条目`);
  titleRow.append(title, count);
  header.append(titleRow);

  const searchWrap = makeElement("div", "search-wrap");
  searchWrap.append(icon("search", 17));
  const search = makeElement("input", "search-input") as HTMLInputElement;
  search.id = "vault-search";
  search.type = "password";
  search.placeholder = "搜索名称、账号、用途或标签";
  search.value = state.query;
  search.autocomplete = "off";
  search.spellcheck = false;
  search.setAttribute("aria-label", "搜索保险库条目（内容已隐藏）");
  let managedSearch: ManagedSensitiveInput;
  const searchReveal = iconButton("显示搜索内容", "eye", () => {
    if (search.type === "password") revealManagedSensitiveInput(managedSearch);
    else hideManagedSensitiveInput(managedSearch);
  }, "search-reveal");
  searchReveal.setAttribute("aria-pressed", "false");
  const searchActions = makeElement("div", "search-actions");
  const clearSearch = iconButton("清除搜索", "x", () => {
    state.query = "";
    hideManagedSensitiveInput(managedSearch);
    void loadEntries(true, undefined, true);
  }, "search-clear");
  setOptionalActionAvailable(clearSearch, Boolean(state.query));
  managedSearch = { input: search, button: searchReveal, label: "搜索内容", timeout: null };
  search.addEventListener("input", () => {
    state.query = search.value;
    setOptionalActionAvailable(clearSearch, Boolean(search.value));
    if (listDebounce) window.clearTimeout(listDebounce);
    listDebounce = window.setTimeout(() => void loadEntries(true), 220);
  });
  searchActions.append(searchReveal, clearSearch);
  searchWrap.append(search, searchActions);
  header.append(searchWrap);

  const toolbar = makeElement("div", "list-toolbar");
  const selectWrap = makeElement("div", "select-wrap compact-select");
  const sort = makeElement("select", "select") as HTMLSelectElement;
  sort.dataset.focusKey = "entry-sort";
  sort.setAttribute("aria-label", "条目排序");
  const options: Array<[EntrySort, string]> = [
    ["updated_desc", "最近更新"],
    ["title_asc", "名称 A–Z"],
    ["created_desc", "最近创建"],
  ];
  for (const [value, label] of options) {
    const option = makeElement("option", "", label) as HTMLOptionElement;
    option.value = value;
    option.selected = state.sort === value;
    sort.append(option);
  }
  sort.addEventListener("change", () => {
    state.sort = sort.value as EntrySort;
    void loadEntries(true);
  });
  selectWrap.append(sort, icon("chevron", 15));
  const newEntry = makeButton("新建", "button button-small button-secondary", createNewEntry, "plus");
  newEntry.dataset.focusKey = "entry-new";
  toolbar.append(selectWrap, newEntry);
  if (state.conflictsOnly) {
    toolbar.append(makeButton("返回全部条目", "button button-small button-ghost", async () => {
      state.conflictsOnly = false;
      await loadEntries(true);
    }, "x"));
  }
  header.append(toolbar);
  panel.append(header);

  const list = makeElement("div", "entry-list");
  list.dataset.scrollKey = "entry-list";
  list.setAttribute("role", "list");
  list.setAttribute("aria-busy", String(state.listLoading));
  if (state.listLoading) {
    const loadingStatus = makeElement("span", "sr-only", "正在读取条目列表…");
    loadingStatus.setAttribute("role", "status");
    list.append(loadingStatus);
    for (let index = 0; index < 5; index += 1) list.append(renderListSkeleton());
  } else if (state.listError) {
    const failure = makeElement("div", "list-empty");
    failure.setAttribute("role", "listitem");
    const graphic = makeElement("div", "empty-icon");
    graphic.append(icon("alert", 25));
    failure.append(
      graphic,
      makeElement("h2", "", "条目列表未能读取"),
      makeElement("p", "", "当前没有显示旧列表，以免把过期内容当成最新数据。"),
      makeButton("重试读取", "button button-secondary button-small", () => { void loadEntries(true); }, "refresh"),
    );
    list.append(failure);
  } else if (!state.entries.length) {
    list.append(renderListEmpty());
  } else {
    const windowed = visibleListRows(state.entries, state.visibleEntryCount, state.selectedId);
    if (windowed.selectedBeyondPage) {
      const selected = makeElement("div", "entry-pinned-selection");
      selected.append(makeElement("span", "entry-pinned-label", "当前打开的条目 · 位于后续列表"));
      selected.append(renderEntryRow(windowed.selectedBeyondPage));
      list.append(selected);
    }
    for (const entry of windowed.page) list.append(renderEntryRow(entry));
    if (state.entries.length > state.visibleEntryCount) {
      const progress = makeElement("div", "list-pagination");
      progress.setAttribute("role", "listitem");
      progress.append(makeElement(
        "span",
        "list-progress",
        `已显示 ${state.visibleEntryCount.toLocaleString("zh-CN")} / ${state.entries.length.toLocaleString("zh-CN")} 项`,
      ));
      const more = makeButton("加载更多条目", "button button-secondary button-small", () => {
        const firstNew = state.entries[state.visibleEntryCount];
        state.visibleEntryCount = Math.min(state.entries.length, state.visibleEntryCount + ENTRY_PAGE_SIZE);
        renderMainShell();
        if (firstNew) {
          const key = `entry-${firstNew.id}-select`;
          Array.from(document.querySelectorAll<HTMLElement>("[data-focus-key]"))
            .find((element) => element.dataset.focusKey === key)
            ?.focus();
        }
      });
      more.dataset.focusKey = "entry-load-more";
      progress.append(more);
      list.append(progress);
    }
  }
  panel.append(list);
  return panel;
}

function renderListSkeleton(): HTMLElement {
  const row = makeElement("div", "entry-row skeleton-row");
  row.setAttribute("aria-hidden", "true");
  row.append(makeElement("span", "skeleton skeleton-avatar"));
  const lines = makeElement("div", "skeleton-lines");
  lines.append(makeElement("span", "skeleton skeleton-line skeleton-line-wide"), makeElement("span", "skeleton skeleton-line"));
  row.append(lines);
  return row;
}

function renderListEmpty(): HTMLElement {
  const empty = makeElement("div", "list-empty");
  empty.setAttribute("role", "listitem");
  const graphic = makeElement("div", "empty-icon");
  graphic.append(icon(state.query ? "search" : state.conflictsOnly ? "alert" : state.view === "favorites" ? "favorite" : "key", 25));
  empty.append(graphic);
  if (state.query) {
    empty.append(makeElement("h2", "", "没有匹配的条目"), makeElement("p", "", "未找到匹配的内容。"));
    empty.append(makeButton("清除搜索", "button button-ghost button-small", () => {
      state.query = "";
      void loadEntries(true);
    }, "x"));
  } else if (state.conflictsOnly) {
    empty.append(makeElement("h2", "", "没有待核对的同步冲突"), makeElement("p", "", "同步产生的冲突副本会显示在这里。"));
  } else if (state.view === "favorites") {
    empty.append(makeElement("h2", "", "还没有收藏"), makeElement("p", "", "点击条目旁的星标即可快速访问。"));
  } else {
    empty.append(makeElement("h2", "", "保险库还是空的"), makeElement("p", "", "生成一个强密码，并和应用信息一起保存。"));
    empty.append(makeButton("生成并保存", "button button-primary button-small", () => openGenerator("standalone"), "key"));
  }
  return empty;
}

function renderEntryRow(entry: EntrySummary): HTMLElement {
  const row = makeElement("div", `entry-row${state.selectedId === entry.id ? " is-selected" : ""}`);
  row.setAttribute("role", "listitem");
  const select = makeElement("button", "entry-row-main");
  select.type = "button";
  select.dataset.focusKey = `entry-${entry.id}-select`;
  select.setAttribute("aria-label", `${entry.title}${entry.securityFlags.length ? `，${securityFlagSummary(entry.securityFlags)}` : ""}`);
  if (state.selectedId === entry.id) select.setAttribute("aria-current", "true");
  const avatar = makeElement("div", "entry-avatar", firstCharacter(entry.title));
  avatar.setAttribute("aria-hidden", "true");
  avatar.classList.add(titleHueClass(entry.title));
  const body = makeElement("div", "entry-row-body");
  const first = makeElement("div", "entry-row-title");
  first.append(makeElement("strong", "truncate", entry.title));
  if (entry.securityFlags.length) {
    const warning = makeElement("span", "issue-dot");
    warning.title = securityFlagSummary(entry.securityFlags);
    warning.setAttribute("aria-label", warning.title);
    warning.setAttribute("role", "img");
    first.append(warning);
  }
  const subtitle = makeElement("span", "entry-subtitle truncate", "敏感信息已隐藏");
  const meta = makeElement("div", "entry-row-meta");
  const privacy = makeElement("span", "entry-private-label", "PRIVATE");
  privacy.setAttribute("aria-hidden", "true");
  meta.append(privacy);
  const updated = makeElement("time", "entry-time", formatCompactDate(entry.updatedAt));
  const updatedDate = new Date(entry.updatedAt);
  if (!Number.isNaN(updatedDate.getTime())) updated.dateTime = updatedDate.toISOString();
  meta.append(updated);
  body.append(first, subtitle, meta);
  const star = iconButton(entry.favorite ? `取消收藏“${entry.title}”` : `收藏“${entry.title}”`, "favorite", async () => toggleFavorite(entry), `entry-star${entry.favorite ? " is-active" : ""}`);
  star.dataset.focusKey = `entry-${entry.id}-favorite`;
  star.setAttribute("aria-pressed", String(entry.favorite));
  select.append(avatar, body);
  select.addEventListener("click", () => void selectEntry(entry.id));
  row.append(select, star);
  return row;
}

function renderEntryDetail(): HTMLElement {
  const panel = makeElement("section", "entry-detail-panel");
  panel.dataset.scrollKey = "entry-detail";
  panel.setAttribute("aria-label", "条目详情");
  if (state.detailLoading) {
    const loading = makeElement("div", "detail-loading");
    loading.setAttribute("role", "status");
    loading.setAttribute("aria-live", "polite");
    loading.append(makeElement("div", "spinner"), makeElement("p", "", "正在解密所选条目…"));
    panel.append(loading);
    return panel;
  }
  if (!state.draft) {
    const empty = makeElement("div", "detail-empty");
    const graphic = makeElement("div", "detail-empty-graphic");
    graphic.append(icon("shield", 42));
    empty.append(graphic, makeElement("h2", "", "选择一个条目"));
    empty.append(makeElement("p", "", "只有在你明确打开条目时，敏感内容才会进入当前会话，并默认保持遮罩。"));
    const shortcuts = makeElement("div", "shortcut-pills");
    shortcuts.append(shortcutPill(shortcutLabel("N"), "新建"), shortcutPill(shortcutLabel("G"), "生成"));
    empty.append(shortcuts);
    panel.append(empty);
    return panel;
  }
  panel.append(renderEntryEditor());
  return panel;
}

function shortcutPill(keys: string, label: string): HTMLElement {
  const pill = makeElement("span", "shortcut-pill");
  pill.append(makeElement("kbd", "", keys), document.createTextNode(label));
  return pill;
}

function renderEntryEditor(): HTMLElement {
  const draft = state.draft as EntryInput;
  const editor = makeElement("div", "entry-editor");
  editor.setAttribute(
    "aria-busy",
    String(state.entryMutation !== null || state.syncOperation !== null || state.securityOperation !== null),
  );
  const top = makeElement("header", "editor-header");
  const identity = makeElement("div", "editor-identity");
  identity.append(iconButton("返回条目列表", "back", returnToList, "icon-button mobile-back"));
  const avatar = makeElement("div", "entry-avatar entry-avatar-large", firstCharacter(draft.title || "新"));
  avatar.classList.add(titleHueClass(draft.title || "new"));
  const copy = makeElement("div", "editor-heading");
  copy.append(makeElement("span", "eyebrow", state.entryMeta.id ? "CREDENTIAL" : "NEW CREDENTIAL"));
  copy.append(makeElement("h1", "truncate", draft.title || "新建密码条目"));
  identity.append(avatar, copy);
  const controls = makeElement("div", "editor-header-actions");
  const favorite = iconButton(draft.favorite ? "取消收藏" : "收藏", "favorite", toggleCurrentFavorite, `icon-button${draft.favorite ? " is-favorite" : ""}`);
  favorite.setAttribute("aria-pressed", String(draft.favorite));
  controls.append(favorite);
  if (state.entryMeta.id) controls.append(iconButton("删除条目", "trash", deleteCurrentEntry, "icon-button danger-hover"));
  top.append(identity, controls);
  editor.append(top);

  if (state.entryRevisionConflict) {
    const conflict = makeElement("div", "inline-notice inline-notice-warning editor-conflict-notice");
    conflict.setAttribute("role", "alert");
    const saveCopy = makeButton("另存当前草稿为新条目", "button button-secondary button-small", saveConflictedDraftAsNewEntry, "plus");
    saveCopy.dataset.securityMutation = "true";
    saveCopy.disabled = state.entryMutation !== null || state.syncOperation !== null || state.securityOperation !== null;
    conflict.append(
      icon("alert", 17),
      makeElement("p", "", "此条目已在另一台设备修改或删除。当前未保存的草稿仍在编辑器中。可另存为新条目，再核对两份内容。"),
      saveCopy,
    );
    editor.append(conflict);
  }

  const form = makeElement("form", "editor-form");
  form.noValidate = true;
  const section = makeElement("section", "form-section");
  section.append(sectionHeading("基本信息", "应用、账号与密码只保存在加密保险库中。"));

  const titleField = createTextField("entry-title", "应用名称", draft.title, "例如 GitHub", true, 200);
  bindDraftInput(titleField.input, "title");
  section.append(titleField.wrapper);

  const two = makeElement("div", "form-grid-two");
  const usernameField = createTextField("entry-username", "用户名或邮箱", draft.username, "name@example.com", false, 500);
  bindDraftInput(usernameField.input, "username");
  addSensitiveTextActions(usernameField, "用户名");
  const purposeField = createTextField("entry-purpose", "用途", draft.purpose, "例如：公司后台管理员", false, 500);
  bindDraftInput(purposeField.input, "purpose");
  addSensitiveTextActions(purposeField, "用途");
  two.append(usernameField.wrapper, purposeField.wrapper);
  section.append(two);

  const passwordGroup = makeElement("div", "field-group");
  const passwordLabel = makeElement("label", "field-label", "密码");
  passwordLabel.htmlFor = "entry-password";
  const passwordWrap = makeElement("div", "secret-field");
  const password = makeElement("input", "input secret-input") as HTMLInputElement;
  password.id = "entry-password";
  password.type = state.passwordVisible ? "text" : "password";
  password.value = draft.password;
  password.autocomplete = "new-password";
  password.spellcheck = false;
  password.maxLength = 4096;
  password.addEventListener("input", () => {
    if (state.draft) state.draft.password = password.value;
    clearFieldError("entry-password");
  });
  const secretActions = makeElement("div", "secret-actions");
  const reveal = iconButton(state.passwordVisible ? "隐藏密码" : "显示密码", state.passwordVisible ? "eyeOff" : "eye", togglePasswordVisibility);
  reveal.id = "password-reveal-button";
  reveal.setAttribute("aria-pressed", String(state.passwordVisible));
  const copyPassword = iconButton("复制密码", "copy", () => copySecret(password.value));
  const generate = makeButton("生成", "button button-small button-secondary", () => openGenerator("entry"), "refresh");
  secretActions.append(reveal, copyPassword, generate);
  passwordWrap.append(password, secretActions);
  const passwordError = makeElement("p", "field-error");
  passwordError.id = "entry-password-error";
  passwordError.setAttribute("aria-live", "polite");
  const revealHint = makeElement("p", "field-help");
  revealHint.id = "password-reveal-hint";
  revealHint.textContent = state.passwordVisible ? "密码将在短时间后自动隐藏。" : "默认隐藏；显示后会自动重新遮罩。";
  passwordGroup.append(passwordLabel, passwordWrap, passwordError, revealHint);
  section.append(passwordGroup);

  const urlField = createTextField("entry-url", "网站或主机地址", draft.url, "例如 example.com、10.0.0.5:3389 或 3389", false, 2048);
  bindDraftInput(urlField.input, "url");
  addSensitiveTextActions(urlField, "地址");
  urlField.wrapper.append(makeElement("p", "field-help", "可填写网站、IP、主机名、端口或其他地址标记；仅作为纯文本保存，应用不会自动访问。"));
  section.append(urlField.wrapper);
  form.append(section);

  const detailSection = makeElement("section", "form-section");
  detailSection.append(sectionHeading("组织与备注", "这些字段同样会被加密，不参与密码正文搜索。"));
  const tagsField = createTextField("entry-tags", "标签", draft.tags.join(", "), "工作, 管理员", false, 1400);
  tagsField.input.addEventListener("input", () => {
    if (state.draft) state.draft.tags = parseTags(tagsField.input.value);
  });
  addSensitiveTextActions(tagsField, "标签");
  tagsField.wrapper.append(makeElement("p", "field-help", "使用逗号分隔，最多保留 20 个标签。"));
  detailSection.append(tagsField.wrapper);

  const notesGroup = makeElement("div", "field-group");
  const notesLabel = makeElement("label", "field-label", "备注");
  notesLabel.htmlFor = "entry-notes";
  const notes = makeElement("textarea", "textarea") as HTMLTextAreaElement;
  notes.id = "entry-notes";
  notes.value = draft.notes ? CONCEALED_TEXT : "";
  notes.placeholder = "点击显示按钮后输入或编辑备注。";
  notes.readOnly = true;
  notes.autocomplete = "off";
  notes.spellcheck = false;
  notes.classList.add("concealed-notes");
  notes.maxLength = 20000;
  const notesWrap = makeElement("div", "notes-with-actions");
  const notesActions = makeElement("div", "notes-actions");
  const revealNotesButton = iconButton("显示并编辑备注", "eye", () => {
    if (revealedNotesInput === notes && !notes.readOnly) hideNotes();
    else revealNotes(notes, revealNotesButton);
  });
  revealNotesButton.setAttribute("aria-pressed", "false");
  const copyNotes = iconButton("复制备注", "copy", () => copySecret(state.draft?.notes ?? "", "备注"));
  setOptionalActionAvailable(copyNotes, Boolean(draft.notes));
  notes.addEventListener("input", () => {
    if (state.draft) state.draft.notes = notes.value;
    setOptionalActionAvailable(copyNotes, Boolean(notes.value));
    clearFieldError("entry-notes");
    if (revealedNotesInput === notes) scheduleNotesHide();
  });
  notes.addEventListener("blur", (event) => {
    // Let the reveal button handle its own click; hide when editing moves elsewhere.
    if (event.relatedTarget !== revealNotesButton && revealedNotesInput === notes) hideNotes();
  });
  const notesError = makeElement("p", "field-error");
  notesError.id = "entry-notes-error";
  notesError.setAttribute("aria-live", "polite");
  notesActions.append(revealNotesButton, copyNotes);
  notesWrap.append(notes, notesActions);
  notesGroup.append(
    notesLabel,
    notesWrap,
    notesError,
    makeElement("p", "field-help", "默认隐藏；显示后可编辑，并会按敏感字段显示时长自动重新遮罩。"),
  );
  detailSection.append(notesGroup);
  form.append(detailSection);

  if (state.entryMeta.id) {
    const meta = makeElement("dl", "entry-metadata");
    appendMetadata(meta, "创建", state.entryMeta.createdAt);
    appendMetadata(meta, "更新", state.entryMeta.updatedAt);
    appendMetadata(meta, "密码更新", state.entryMeta.passwordUpdatedAt);
    if (state.entryMeta.revision !== undefined) appendMetadata(meta, "本地版本", `r${state.entryMeta.revision}`, false);
    form.append(meta);
  }

  const footer = makeElement("footer", "editor-footer");
  const dirtyState = makeElement("div", "save-state");
  dirtyState.append(makeElement("span", hasUnsavedDraft() ? "unsaved-dot" : "saved-dot"));
  dirtyState.append(makeElement(
    "span",
    "",
    state.entryMutation !== null
      ? state.entryMutation === "saving"
        ? "正在加密保存…"
        : state.entryMutation === "deleting"
          ? "正在删除条目…"
          : "正在更新收藏…"
      : hasUnsavedDraft()
        ? "有未保存的修改"
        : state.entryMeta.id
          ? "已保存到本地"
          : "填写后保存",
  ));
  const actions = makeElement("div", "editor-actions");
  const cancel = makeButton("取消", "button button-ghost", cancelEditing);
  const save = makeButton("保存条目", "button button-primary", async () => {
    await saveCurrentEntry(save);
  }, "check");
  save.title = shortcutTitle("S");
  actions.append(cancel, save);
  footer.append(dirtyState, actions);
  form.append(footer);
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    void saveCurrentEntry(save);
  });
  editor.append(form);
  if (state.passwordVisible) syncPasswordRevealHint();
  return editor;
}

function sectionHeading(title: string, description: string): HTMLElement {
  const heading = makeElement("div", "section-heading");
  heading.append(makeElement("h2", "", title), makeElement("p", "", description));
  return heading;
}

function createTextField(
  id: string,
  labelText: string,
  value: string,
  placeholder: string,
  required: boolean,
  maxLength: number,
): { wrapper: HTMLElement; input: HTMLInputElement } {
  const wrapper = makeElement("div", "field-group");
  const label = makeElement("label", "field-label");
  label.htmlFor = id;
  label.append(document.createTextNode(labelText));
  if (required) label.append(makeElement("span", "required-mark", "必填"));
  const input = makeElement("input", "input") as HTMLInputElement;
  input.id = id;
  input.type = "text";
  input.value = value;
  input.placeholder = placeholder;
  input.maxLength = maxLength;
  if (required) {
    input.required = true;
    input.setAttribute("aria-required", "true");
  }
  const error = makeElement("p", "field-error");
  error.id = `${id}-error`;
  error.setAttribute("aria-live", "polite");
  wrapper.append(label, input, error);
  return { wrapper, input };
}

function addSensitiveTextActions(
  field: { wrapper: HTMLElement; input: HTMLInputElement },
  label: string,
): void {
  field.input.type = "password";
  field.input.autocomplete = "off";
  field.input.spellcheck = false;
  field.input.classList.add("sensitive-text-input");
  const inputWrap = makeElement("div", "input-with-action sensitive-input-with-actions");
  const actions = makeElement("div", "sensitive-input-actions");
  let managedField: ManagedSensitiveInput;
  const reveal = iconButton(`显示${label}`, "eye", () => {
    if (field.input.type === "password") revealManagedSensitiveInput(managedField);
    else hideManagedSensitiveInput(managedField);
  });
  reveal.setAttribute("aria-pressed", "false");
  const copy = iconButton(`复制${label}`, "copy", () => copySecret(field.input.value, label));
  if (field.input.id.startsWith("generator-")) {
    reveal.classList.add("generator-config-control");
    copy.classList.add("generator-config-control");
  }
  setOptionalActionAvailable(copy, Boolean(field.input.value));
  field.input.addEventListener("input", () => {
    setOptionalActionAvailable(copy, Boolean(field.input.value));
  });
  managedField = { input: field.input, button: reveal, label, timeout: null };
  field.wrapper.insertBefore(inputWrap, field.input);
  actions.append(reveal, copy);
  inputWrap.append(field.input, actions);
}

function setOptionalActionAvailable(button: HTMLButtonElement, available: boolean): void {
  button.hidden = !available;
  button.disabled = !available;
  button.tabIndex = available ? 0 : -1;
  if (available) button.removeAttribute("aria-hidden");
  else button.setAttribute("aria-hidden", "true");
}

function revealNotes(input: HTMLTextAreaElement, button: HTMLButtonElement): void {
  hideNotes();
  hideAllManagedSensitiveInputs();
  hidePassword();
  hideGeneratorPassword();
  revealedNotesInput = input;
  notesRevealButton = button;
  input.readOnly = false;
  input.classList.remove("concealed-notes");
  input.value = state.draft?.notes ?? "";
  clearNode(button);
  button.append(icon("eyeOff"));
  button.setAttribute("aria-label", "隐藏备注");
  button.setAttribute("aria-pressed", "true");
  button.title = "隐藏备注";
  scheduleNotesHide();
  input.focus();
  input.setSelectionRange(input.value.length, input.value.length);
}

function scheduleNotesHide(): void {
  if (notesRevealTimeout) window.clearTimeout(notesRevealTimeout);
  const seconds = Math.max(1, state.settings.passwordRevealSeconds || DEFAULT_SETTINGS.passwordRevealSeconds);
  notesRevealTimeout = window.setTimeout(hideNotes, seconds * 1000);
}

function hideNotes(): void {
  if (notesRevealTimeout) window.clearTimeout(notesRevealTimeout);
  notesRevealTimeout = null;
  const input = revealedNotesInput;
  if (input?.isConnected && !input.readOnly) {
    if (state.draft) state.draft.notes = input.value;
    input.value = state.draft?.notes ? CONCEALED_TEXT : "";
    input.readOnly = true;
    input.classList.add("concealed-notes");
  }
  if (notesRevealButton?.isConnected) {
    clearNode(notesRevealButton);
    notesRevealButton.append(icon("eye"));
    notesRevealButton.setAttribute("aria-label", "显示并编辑备注");
    notesRevealButton.setAttribute("aria-pressed", "false");
    notesRevealButton.title = "显示并编辑备注";
  }
  revealedNotesInput = null;
  notesRevealButton = null;
}

function bindDraftInput(input: HTMLInputElement, key: "title" | "username" | "purpose" | "url"): void {
  input.addEventListener("input", () => {
    if (state.draft) state.draft[key] = input.value;
    clearFieldError(input.id);
  });
}

function appendMetadata(list: HTMLDListElement, label: string, value?: string | number, formatDate = true): void {
  if (value === undefined || value === "") return;
  const group = makeElement("div", "metadata-item");
  group.append(makeElement("dt", "", label), makeElement("dd", "", formatDate ? formatFullDate(value) : String(value)));
  list.append(group);
}

function renderSecurityPage(): HTMLElement {
  const page = makeElement("div", "workspace-page security-page");
  page.dataset.scrollKey = "workspace-page";
  const header = pageHeader("SECURITY REPORT", "安全检查", "检查弱密码、重复使用和长期未更换的密码。所有分析均在本机完成。");
  const refresh = makeButton("重新检查", "button button-secondary", async () => {
    state.reportLoading = true;
    state.reportError = false;
    renderMainShell();
    await loadSecurityReport();
  }, "refresh");
  header.append(refresh);
  page.append(header);

  if (state.reportLoading) {
    const grid = makeElement("div", "security-summary-grid");
    for (let index = 0; index < 4; index += 1) grid.append(makeElement("div", "summary-card skeleton-card"));
    page.append(grid, renderPageLoading("正在本机分析保险库…"));
    return page;
  }

  if (state.reportError || !state.report) {
    const failure = makeElement("section", "content-card issue-card");
    failure.setAttribute("role", "alert");
    failure.append(
      makeElement("h2", "", state.reportError ? "安全检查未完成" : "尚未运行安全检查"),
      makeElement("p", "", state.reportError
        ? "当前无法读取检查结果。请重新检查；在检查成功前不会显示安全结论。"
        : "点击“重新检查”分析当前保险库。"),
    );
    page.append(failure);
    return page;
  }

  const report = state.report;
  const grid = makeElement("div", "security-summary-grid");
  grid.append(
    securitySummary("已检查条目", report.totalEntries, "shield", "neutral"),
    securitySummary("弱密码", report.weakCount, "alert", report.weakCount ? "danger" : "safe"),
    securitySummary("重复使用", report.reusedCount, "copy", report.reusedCount ? "warning" : "safe"),
    securitySummary("长期未更换", report.staleCount, "archive", report.staleCount ? "warning" : "safe"),
  );
  page.append(grid);

  const card = makeElement("section", "content-card issue-card");
  const cardHeader = makeElement("div", "content-card-header");
  cardHeader.append(makeElement("div", "", undefined));
  const headerCopy = cardHeader.firstElementChild as HTMLElement;
  headerCopy.append(makeElement("h2", "", report.issues.length ? `${report.issues.length} 个待处理问题` : "未发现明显问题"));
  headerCopy.append(makeElement("p", "", report.issues.length ? "逐项修改可以降低凭据被撞库或猜测的风险。" : "这不代表绝对安全，请继续保持设备与主密码安全。"));
  card.append(cardHeader);

  if (!report.issues.length) {
    const safe = makeElement("div", "security-empty");
    const badge = makeElement("div", "safe-icon");
    badge.append(icon("check", 30));
    safe.append(badge, makeElement("h3", "", "当前未发现弱、重复或陈旧密码"));
    safe.append(makeElement("p", "", "检查不会联网，也不会向第三方发送密码或密码哈希。"));
    card.append(safe);
  } else {
    const list = makeElement("div", "issue-list");
    for (const [index, issue] of report.issues.slice(0, state.visibleIssueCount).entries()) {
      list.append(renderIssueRow(issue, index));
    }
    if (report.issues.length > state.visibleIssueCount) {
      const progress = makeElement("div", "list-pagination");
      progress.append(makeElement("span", "list-progress", `已显示 ${state.visibleIssueCount.toLocaleString("zh-CN")} / ${report.issues.length.toLocaleString("zh-CN")} 个问题`));
      const more = makeButton("加载更多问题", "button button-secondary button-small", () => {
        const firstNew = state.visibleIssueCount;
        state.visibleIssueCount = Math.min(report.issues.length, firstNew + ENTRY_PAGE_SIZE);
        renderMainShell();
        document.querySelector<HTMLElement>(`[data-focus-key='security-issue-${firstNew}']`)?.focus();
      });
      more.dataset.focusKey = "security-load-more";
      progress.append(more);
      list.append(progress);
    }
    card.append(list);
  }
  page.append(card);

  const privacy = makeElement("div", "inline-notice");
  privacy.append(icon("shield", 18), makeElement("p", "", "安全检查只分析当前已解锁会话，不查询在线泄露数据库，也不会保存未加密的密码指纹。"));
  page.append(privacy);
  return page;
}

function securitySummary(label: string, value: number, iconName: IconName, tone: string): HTMLElement {
  const card = makeElement("div", `summary-card summary-${tone}`);
  const iconWrap = makeElement("div", "summary-icon");
  iconWrap.append(icon(iconName, 20));
  const body = makeElement("div");
  body.append(makeElement("strong", "summary-value", String(value)), makeElement("span", "summary-label", label));
  card.append(iconWrap, body);
  return card;
}

function renderIssueRow(issue: SecurityIssue, index: number): HTMLElement {
  const meta = issueKindMeta(issue.kind);
  const row = makeElement("button", "issue-row");
  row.type = "button";
  row.dataset.focusKey = `security-issue-${index}`;
  const badge = makeElement("div", `issue-kind issue-kind-${meta.tone}`);
  badge.append(icon(meta.icon, 17));
  const copy = makeElement("div", "issue-copy");
  const titleRow = makeElement("div", "issue-title-row");
  titleRow.append(makeElement("strong", "truncate", issue.title), makeElement("span", `issue-label issue-label-${meta.tone}`, meta.label));
  copy.append(titleRow, makeElement("p", "", issue.message));
  row.append(badge, copy, icon("chevron", 17));
  row.addEventListener("click", () => void openIssue(issue.entryId));
  return row;
}

function issueKindMeta(kind: SecurityIssueKind | string): { label: string; tone: string; icon: IconName } {
  if (kind === "weak") return { label: "弱密码", tone: "danger", icon: "alert" };
  if (kind === "reused") return { label: "重复使用", tone: "warning", icon: "copy" };
  if (kind === "stale") return { label: "长期未更换", tone: "warning", icon: "archive" };
  return { label: "需要检查", tone: "neutral", icon: "shield" };
}

async function openIssue(entryId: string): Promise<void> {
  state.view = "all";
  state.conflictsOnly = false;
  state.query = "";
  renderMainShell();
  await loadEntries(true);
  await selectEntry(entryId);
}

function renderSettingsPage(): HTMLElement {
  const page = makeElement("div", "workspace-page settings-page");
  page.dataset.scrollKey = "workspace-page";
  page.append(pageHeader("LOCAL PREFERENCES", "设置", "管理本机安全设置、加密备份与多设备同步。"));
  page.append(renderWebDavOverview());

  const layout = makeElement("div", "settings-layout");

  const security = makeElement("section", "content-card settings-card settings-security-card");
  security.append(settingsCardHeader("shield", "锁定与隐私", "减少敏感字段停留在屏幕和剪贴板中的时间。"));
  const form = makeElement("form", "settings-form");
  form.noValidate = true;
  form.append(
    createSelectSetting("setting-auto-lock", "空闲自动锁定", "无操作一段时间后清除当前会话。", [
      [1, "1 分钟"],
      [5, "5 分钟（推荐）"],
      [10, "10 分钟"],
      [15, "15 分钟"],
      [30, "30 分钟"],
    ], state.settings.autoLockMinutes),
    createSelectSetting("setting-clipboard", "剪贴板自动清除", "仅清除仍由本应用写入的内容。", [
      [10, "10 秒"],
      [20, "20 秒（推荐）"],
      [30, "30 秒"],
      [60, "60 秒"],
    ], state.settings.clipboardClearSeconds),
    createSelectSetting("setting-reveal", "敏感字段显示时长", "密码、账号、地址、用途、备注和标签到期后自动重新遮罩。", [
      [5, "5 秒"],
      [10, "10 秒（推荐）"],
      [20, "20 秒"],
      [30, "30 秒"],
    ], state.settings.passwordRevealSeconds),
  );
  const blurSetting = createToggleSetting("setting-lock-blur", "窗口失焦时锁定", "切换到其他应用时立即要求重新解锁。", state.settings.lockOnBlur);
  form.append(blurSetting.wrapper);
  const settingError = makeElement("p", "form-error");
  settingError.id = "settings-error";
  settingError.setAttribute("role", "alert");
  const saveSettings = makeButton("保存安全设置", "button button-primary", async () => {
    if (
      saveSettings.disabled
      || !state.status.unlocked
      || state.securityOperation !== null
      || state.syncOperation !== null
    ) return;
    const settings: VaultSettings = {
      autoLockMinutes: Number(inputValue("setting-auto-lock")),
      clipboardClearSeconds: Number(inputValue("setting-clipboard")),
      passwordRevealSeconds: Number(inputValue("setting-reveal")),
      lockOnBlur: document.querySelector<HTMLInputElement>("#setting-lock-blur")?.checked ?? false,
    };
    const epoch = state.epoch;
    state.securityOperation = "settings";
    settingError.textContent = "";
    setSecurityMutationControlsDisabled(true);
    setBusy(saveSettings, true, "正在保存…");
    try {
      await invokeCommand<void>("update_settings", { settings });
      if (
        epoch !== state.epoch
        || !state.status.unlocked
        || state.securityOperation !== "settings"
      ) return;
      state.settings = settings;
      state.status.autoLockMinutes = settings.autoLockMinutes;
      scheduleAutoLock();
      await loadVaultOverview(epoch).catch(() => undefined);
      if (epoch !== state.epoch || !state.status.unlocked) return;
      renderMainShell();
      showToast("安全设置已保存。", "success");
    } catch {
      if (epoch !== state.epoch || !state.status.unlocked) return;
      settingError.textContent = "无法保存设置，请重试。";
    } finally {
      if (epoch === state.epoch && state.securityOperation === "settings") {
        state.securityOperation = null;
        setBusy(saveSettings, false);
        setSecurityMutationControlsDisabled(false);
      }
    }
  }, "check");
  saveSettings.dataset.securityMutation = "true";
  saveSettings.disabled = state.securityOperation !== null || state.syncOperation !== null;
  form.append(settingError, saveSettings);
  security.append(form);

  const backup = makeElement("section", "content-card settings-card settings-backup-card");
  backup.append(settingsCardHeader("archive", "加密备份", "本机快照、文件导出与 WebDAV 单向远端备份。"));
  const autoBackup = state.overview.autoBackup;
  const autoStatus = makeElement("div", "inline-notice inline-notice-compact");
  autoStatus.append(icon(autoBackup.inspectionFailed || autoBackup.warning ? "alert" : "shield", 17));
  const autoCopy = makeElement("p");
  autoCopy.append(makeElement("strong", "", "本机自动快照"), document.createElement("br"));
  autoCopy.append(document.createTextNode(autoBackup.inspectionFailed
    ? "状态未知：快照检查失败，请检查应用数据目录并另行导出加密备份。"
    : `每次成功保存后为当前版本建立快照，最多保留 10 份。现有 ${autoBackup.count} 份；${autoBackup.latestAt ? `最近 ${formatFullDate(autoBackup.latestAt)}` : "暂无快照"}；${autoBackup.currentCovered ? "当前版本已有快照" : "当前版本尚无可确认的快照"}。`));
  autoStatus.append(autoCopy);
  backup.append(autoStatus);
  if (autoBackup.warning) {
    const autoWarning = makeElement("div", "inline-notice inline-notice-warning inline-notice-compact");
    autoWarning.append(icon("alert", 17), makeElement("p", "", autoBackup.warning));
    backup.append(autoWarning);
  }
  if (state.backupOperationError) {
    const operationError = makeElement("div", "inline-notice inline-notice-warning inline-notice-compact");
    operationError.setAttribute("role", "alert");
    operationError.append(icon("alert", 17), makeElement("p", "", state.backupOperationError));
    backup.append(operationError);
  }
  const backupStatus = makeElement(
    "p",
    "backup-last-export",
    state.overview.lastBackupAt
      ? `上次手动导出：${formatFullDate(state.overview.lastBackupAt)}`
      : "上次手动导出：尚未导出",
  );
  const backupNotice = makeElement("div", "inline-notice inline-notice-compact");
  backupNotice.append(icon("alert", 17), makeElement("p", "", "可从本机快照、外部加密文件或 WebDAV 远端副本恢复。本机快照不能防范设备损坏或整盘丢失；请保留独立副本，并定期验证可恢复性。未保存的编辑内容不在备份中。"));
  const backupActions = makeElement("div", "settings-actions");
  const exportButton = makeButton("导出加密备份", "button button-secondary", async () => exportBackup(exportButton), "download");
  exportButton.dataset.securityMutation = "true";
  exportButton.disabled = state.syncOperation !== null || state.securityOperation !== null;
  const restoreButton = makeButton("恢复加密备份（含本机快照）", "button button-ghost", restoreBackup, "upload");
  restoreButton.dataset.securityMutation = "true";
  restoreButton.disabled = state.securityOperation !== null || state.syncOperation !== null;
  backupActions.append(exportButton, restoreButton);
  backup.append(backupStatus, backupNotice, backupActions);
  backup.append(renderWebDavBackupSettings());

  const master = makeElement("section", "content-card settings-card settings-master-card");
  master.append(settingsCardHeader("key", "更改主密码", "更改用于解锁本地保险库的主密码。"));
  const masterForm = makeElement("form", "settings-form compact-form");
  masterForm.noValidate = true;
  const current = createPasswordField("current-master-password", "当前主密码", "输入当前主密码", "current-password");
  const next = createPasswordField("new-master-password", "新主密码", "至少 12 个字符", "new-password");
  const confirm = createPasswordField("confirm-new-master-password", "确认新主密码", "再次输入新主密码", "new-password");
  const masterError = makeElement("p", "form-error");
  masterError.setAttribute("role", "alert");
  const changeButton = makeButton("更改主密码", "button button-secondary", () => undefined, "key");
  changeButton.type = "submit";
  changeButton.dataset.securityMutation = "true";
  changeButton.disabled = state.securityOperation !== null || state.syncOperation !== null;
  masterForm.append(current.wrapper, next.wrapper, confirm.wrapper, masterError, changeButton);
  masterForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (changeButton.disabled || state.securityOperation !== null || state.syncOperation !== null) return;
    let currentPassword = current.input.value;
    let newPassword = next.input.value;
    masterError.textContent = "";
    if (!currentPassword) {
      masterError.textContent = "请输入当前主密码。";
      current.input.focus();
      return;
    }
    if (newPassword.length < 12) {
      masterError.textContent = "新主密码至少需要 12 个字符。";
      next.input.focus();
      return;
    }
    if (newPassword !== confirm.input.value) {
      masterError.textContent = "两次输入的新主密码不一致。";
      confirm.input.focus();
      return;
    }
    hideAllManagedSensitiveInputs();
    const operationEpoch = state.epoch;
    const syncWasConfigured = state.syncStatus.configured;
    state.securityOperation = "changePassword";
    setSecurityMutationControlsDisabled(true);
    setBusy(changeButton, true, "正在更改…");
    try {
      current.input.value = "";
      next.input.value = "";
      confirm.input.value = "";
      const changeRequest = invokeCommand<MasterPasswordChangeResult>("change_master_password", {
        currentPassword,
        newPassword,
      });
      currentPassword = "";
      newPassword = "";
      const result = await changeRequest;
      const syncState = result.syncConfigPreserved
        ? await loadWebDavSyncStatusSafely(state.syncStatus)
        : { status: { ...EMPTY_SYNC_STATUS }, error: false };
      const backupState = await loadWebDavBackupStatusSafely();
      await loadVaultOverview(operationEpoch).catch(() => undefined);
      if (operationEpoch === state.epoch && state.status.unlocked) {
        state.syncStatus = syncState.status;
        state.syncStatusError = syncState.error;
        state.syncStatusUncertain = false;
        backupStatusRequestId += 1;
        state.webdavBackupStatus = backupState.status;
        state.webdavBackupStatusError = backupState.error;
        if (!syncState.status.configured) state.syncRemoteOutcomeUnknown = false;
        state.securityOperation = null;
        renderMainShell();
        const baseMessage = "主密码已更改并轮换保险库密钥。旧备份仍使用原密码。";
        if (result.warning) {
          showToast(`${baseMessage} ${result.warning}`, "warning", 7600);
        } else if (!result.syncConfigPreserved && syncWasConfigured) {
          showToast(`${baseMessage} WebDAV 同步配置未能保留，请重新配置。`, "warning", 7600);
        } else {
          showToast(
            `${baseMessage}${syncWasConfigured && result.syncConfigPreserved ? " WebDAV 同步配置已安全重新加密。" : ""}`,
            "success",
            6600,
          );
        }
      }
    } catch (caught) {
      current.input.value = "";
      next.input.value = "";
      confirm.input.value = "";
      currentPassword = "";
      newPassword = "";
      if (operationEpoch !== state.epoch) return;
      state.securityOperation = null;
      setSecurityMutationControlsDisabled(false);
      masterError.textContent = isWeakMasterPasswordError(caught)
        ? MASTER_PASSWORD_TOO_WEAK
        : "无法更改主密码，请检查当前主密码后重试。";
      current.input.focus();
    } finally {
      setBusy(changeButton, false);
    }
  });
  master.append(masterForm);

  const sync = renderWebDavSyncSettingsCard();
  sync.classList.add("settings-sync-card");

  if (compactSettingsMedia.matches) {
    layout.append(security, backup, master, sync);
  } else {
    const primaryColumn = makeElement("div", "settings-column");
    const secondaryColumn = makeElement("div", "settings-column");
    primaryColumn.append(security, sync);
    secondaryColumn.append(backup, master);
    layout.append(primaryColumn, secondaryColumn);
  }
  page.append(layout);
  return page;
}

function renderWebDavOverview(): HTMLElement {
  const syncSummary = state.syncStatusError
    ? "配置需检查"
    : !state.syncStatus.configured
      ? "未配置"
      : state.syncStatus.autoPaused
        ? "自动同步已暂停"
        : state.syncStatus.automatic ? "自动运行" : "仅手动运行";
  const backupSummary = state.webdavBackupStatusError
    ? "配置需检查"
    : !state.webdavBackupStatus.configured
      ? "未配置"
      : state.webdavBackupStatus.automatic ? "自动上传" : "仅手动上传";
  const webdavOverview = makeElement("div", "inline-notice inline-notice-compact settings-webdav-overview");
  webdavOverview.append(icon("shield", 17));
  const webdavOverviewText = makeElement("p");
  webdavOverviewText.append(
    makeElement("strong", "", "WebDAV 同步与备份"),
    document.createElement("br"),
    document.createTextNode(
      `双向同步：${syncSummary}；历史备份：${backupSummary}。同步合并设备间的修改，备份保留可恢复的整库版本。`,
    ),
  );
  webdavOverview.append(webdavOverviewText);
  return webdavOverview;
}

function reflowSettingsLayout(): void {
  if (!state.status.unlocked || state.view !== "settings") return;
  const layout = document.querySelector<HTMLElement>(".settings-layout");
  const security = layout?.querySelector<HTMLElement>(".settings-security-card");
  const backup = layout?.querySelector<HTMLElement>(".settings-backup-card");
  const master = layout?.querySelector<HTMLElement>(".settings-master-card");
  const sync = layout?.querySelector<HTMLElement>(".settings-sync-card");
  if (!layout || !security || !backup || !master || !sync) return;
  const focused = layout.contains(document.activeElement) ? document.activeElement as HTMLElement : null;
  if (compactSettingsMedia.matches) {
    layout.replaceChildren(security, backup, master, sync);
  } else {
    const primary = makeElement("div", "settings-column");
    const secondary = makeElement("div", "settings-column");
    primary.append(security, sync);
    secondary.append(backup, master);
    layout.replaceChildren(primary, secondary);
  }
  if (focused?.isConnected) focused.focus({ preventScroll: true });
}

function renderWebDavBackupSettings(): HTMLElement {
  const section = makeElement("section", "webdav-backup-settings");
  const heading = makeElement("div", "webdav-backup-heading");
  heading.append(icon("upload", 17), makeElement("h3", "", "WebDAV 单向远端备份"));
  section.append(heading);

  if (state.webdavBackupStatusError) {
    const warning = makeElement("div", "inline-notice inline-notice-warning inline-notice-compact");
    warning.setAttribute("role", "alert");
    warning.append(icon("alert", 17), makeElement("p", "", "无法读取本机 WebDAV 备份配置。可重试读取，或重新配置并验证连接；远端已有备份不会因此删除。"));
    const retry = makeButton("重试读取状态", "button button-ghost", async () => {
      if (state.securityOperation !== null || state.syncOperation !== null) return;
      setBusy(retry, true, "正在读取…");
      await refreshWebDavBackupStatus(state.epoch);
      if (retry.isConnected) setBusy(retry, false);
    }, "refresh");
    const reconfigure = makeButton("重新配置", "button button-secondary", configureWebDavBackup, "settings");
    const disable = makeButton("移除本机故障配置", "button button-danger-ghost", disableWebDavBackup, "x");
    for (const button of [reconfigure, disable]) {
      button.dataset.securityMutation = "true";
      button.disabled = state.securityOperation !== null || state.syncOperation !== null;
    }
    const actions = makeElement("div", "settings-actions webdav-backup-actions");
    actions.append(retry, reconfigure, disable);
    warning.append(actions);
    section.append(warning);
    return section;
  }

  const status = state.webdavBackupStatus;
  const summary = makeElement("p", "webdav-backup-summary", status.configured
    ? status.automatic
      ? "保存后会自动上传最新加密快照，并保留远端历史版本。恢复需手动选取备份并完整替换本机；不会自动合并其他设备的修改。"
      : "已配置远端目录。点击“立即上传”时创建加密备份；恢复需手动选取备份并完整替换本机。"
    : "将加密备份单向上传到已有的 WebDAV HTTPS 目录，保留历史副本供以后整库恢复。不会自动合并其他设备的修改。");
  section.append(summary);
  if (status.configured && status.automatic) {
    section.append(makeElement("p", "webdav-backup-storage-note", "远端快照使用不同文件名保留，未被合并的版本可能分别占用空间；目前不会自动清理。请定期检查 WebDAV 存储空间。"));
  }

  if (status.configured) {
    const target = (() => {
      try { return status.endpoint ? new URL(status.endpoint).host : "已配置"; }
      catch { return "已配置"; }
    })();
    const details = makeElement("div", "webdav-backup-details");
    details.append(
      makeElement("span", "", `目标服务：${target}`),
      makeElement("span", "", status.lastUploadAt
        ? `最近上传：${formatFullDate(status.lastUploadAt)}${status.lastUploadedGeneration !== undefined ? ` · 第 ${status.lastUploadedGeneration} 代` : ""}`
        : "尚无可确认的远端上传"),
    );
    if (status.automatic) {
      details.append(makeElement("span", "", status.pending
        ? "当前版本待上传；网络中断或提前锁定时，将在下次解锁后重试。"
        : "当前版本已确认上传。"));
    }
    section.append(details);
  }

  if (status.warning) {
    const warning = makeElement("div", "inline-notice inline-notice-warning inline-notice-compact");
    warning.setAttribute("role", "alert");
    warning.append(icon("alert", 17), makeElement("p", "", status.warning));
    section.append(warning);
  }

  const actions = makeElement("div", "settings-actions webdav-backup-actions");
  const addAction = (label: string, className: string, handler: () => void | Promise<void>, iconName: IconName) => {
    const button = makeButton(label, className, handler, iconName);
    button.dataset.securityMutation = "true";
    button.disabled = state.securityOperation !== null || state.syncOperation !== null;
    actions.append(button);
  };
  if (status.configured) {
    addAction("立即上传加密备份", "button button-primary", uploadWebDavBackup, "upload");
    addAction("查看并恢复远端备份", "button button-secondary", () => restoreBackup("webdav"), "download");
    addAction("刷新备份状态", "button button-ghost", () => refreshWebDavBackupStatus(state.epoch), "refresh");
    addAction("修改备份设置", "button button-ghost", configureWebDavBackup, "settings");
    addAction("停用远端备份", "button button-danger-ghost", disableWebDavBackup, "x");
  } else {
    addAction("配置 WebDAV 备份", "button button-secondary", configureWebDavBackup, "plus");
  }
  section.append(actions);
  return section;
}

function renderWebDavSyncSettingsCard(): HTMLElement {
  const card = makeElement("section", "content-card settings-card sync-card");
  card.append(settingsCardHeader("shield", "多设备加密同步", "双向合并条目。配置同步空间后，可选择仅手动同步或在解锁期间自动检查；保险库锁定时不会发起同步。"));
  const content = makeElement("div", "sync-status");
  const status = state.syncStatus;
  const syncNeedsAttention = state.syncStatusError || Boolean(status.autoPaused || status.autoWarning);
  const badge = makeElement(
    "div",
    `sync-badge${syncNeedsAttention ? " has-error" : status.configured ? " is-enabled" : ""}`,
  );
  badge.append(
    makeElement("span", `status-dot${syncNeedsAttention ? " status-dot-error" : status.configured ? "" : " status-dot-muted"}`),
    makeElement(
      "strong",
      "",
      state.syncStatusError
        ? "本机配置无法验证 · 同步已停止"
        : status.configured && status.autoPaused
          ? "自动同步已暂停 · 需要核对"
          : status.configured && status.automatic
            ? "已配置 · 解锁期间自动同步"
            : status.configured ? "已配置 · 仅手动同步" : "默认关闭",
    ),
  );
  content.append(badge);

  if (state.syncStatusError) {
    content.append(makeElement(
      "p",
      "",
      "保险库本身仍可正常使用，但本机的加密同步配置无法通过验证。CipherNest 不会使用这份配置发起同步。",
    ));
    const notice = makeElement("div", "inline-notice inline-notice-warning inline-notice-compact sync-notice");
    notice.append(
      icon("alert", 17),
      makeElement("p", "", "如需重新配置，请先用当前主密码清除损坏的本机同步配置。此操作不会删除服务器上的加密对象。"),
    );
    const actions = makeElement("div", "sync-actions");
    const clear = makeButton("清除本机同步配置", "button button-danger-ghost", disableWebDavSync, "trash");
    clear.dataset.securityMutation = "true";
    clear.disabled = state.syncOperation !== null || state.securityOperation !== null;
    actions.append(clear);
    content.append(notice, actions);
  } else if (!status.configured) {
    content.append(makeElement(
      "p",
      "",
      "通过 WebDAV 在设备间传递条目修改。创建或加入同步空间后可启用自动同步；远端备份是独立的历史恢复点。同步冲突会保留副本供核对。",
    ));
    const notice = makeElement("div", "inline-notice inline-notice-compact sync-notice");
    notice.append(
      icon("alert", 17),
      makeElement("p", "", "服务器仍可观察文件大小与同步时间，也可能删除或回滚文件；首次加入新设备无法独立证明服务器提供的是最新版本。"),
    );
    const actions = makeElement("div", "sync-actions");
    const create = makeButton("创建同步空间", "button button-secondary", createWebDavSyncSpace, "plus");
    const join = makeButton("加入已有空间", "button button-ghost", joinWebDavSyncSpace, "download");
    for (const button of [create, join]) {
      button.dataset.securityMutation = "true";
      button.disabled = state.syncOperation !== null || state.securityOperation !== null;
    }
    actions.append(create, join);
    content.append(notice, actions);
    if (state.webdavRetry) {
      const retry = makeElement("div", "inline-notice inline-notice-warning sync-retry-notice");
      retry.setAttribute("role", "alert");
      retry.append(icon("alert", 17));
      const copy = makeElement("div", "sync-retry-copy");
      copy.append(
        makeElement("strong", "", state.webdavRetry.mode === "create" ? "创建未完成" : "加入未完成"),
        makeElement("p", "", state.webdavRetry.message),
        makeElement("p", "", "重试时会保留目录地址和用户名；应用专用密码及恢复码需要重新输入。"),
      );
      const retryAction = makeButton(
        "重试配置",
        "button button-secondary button-small",
        state.webdavRetry.mode === "create" ? createWebDavSyncSpace : joinWebDavSyncSpace,
        "refresh",
      );
      retryAction.disabled = state.syncOperation !== null || state.securityOperation !== null;
      copy.append(retryAction);
      retry.append(copy);
      content.append(retry);
    }
  } else {
    const metadata = makeElement("dl", "sync-metadata");
    appendSensitiveSyncMetadata(metadata, "服务器", status.endpointHost || "已配置");
    appendSensitiveSyncMetadata(metadata, "用户名", status.username || "—");
    appendSyncMetadata(metadata, "同步 ID", status.syncIdShort || "—");
    appendSyncMetadata(metadata, "远端序列", status.remoteSequence === undefined ? "尚未记录" : `#${status.remoteSequence.toLocaleString("zh-CN")}`);
    appendSyncMetadata(metadata, "上次完成", status.lastSyncAt ? formatFullDate(status.lastSyncAt) : "尚未完成同步");
    content.append(metadata);

    const localState = makeElement(
      "div",
      `sync-local-state${state.syncRemoteOutcomeUnknown || state.syncStatusUncertain || status.pendingLocalChanges ? " has-pending" : ""}`,
    );
    localState.append(
      icon(state.syncRemoteOutcomeUnknown || state.syncStatusUncertain || status.pendingLocalChanges ? "alert" : "check", 16),
      makeElement(
        "span",
        "",
        state.syncRemoteOutcomeUnknown
          ? "上次同步请求的远端结果未能确认；请重新同步并核对其他设备"
          : state.syncStatusUncertain
          ? "无法确认本机同步状态；请检查应用数据目录并重新读取或同步"
          : status.pendingLocalChanges
            ? "本机有尚未同步的修改"
            : "本机内容与上次同步检查点一致",
      ),
    );
    content.append(localState);
    if (status.autoWarning) {
      const autoNotice = makeElement("div", "inline-notice inline-notice-warning inline-notice-compact sync-notice");
      autoNotice.setAttribute("role", "status");
      autoNotice.append(icon("alert", 17), makeElement("p", "", status.autoWarning));
      content.append(autoNotice);
    }
    if (state.overview.syncConflictCount > 0) {
      const conflicts = makeElement("div", "inline-notice inline-notice-warning sync-conflicts-notice");
      conflicts.append(
        icon("alert", 17),
        makeElement("p", "", `本机有 ${state.overview.syncConflictCount} 个待核对的同步冲突副本。核对后可移除“同步冲突”标签；标签已满的副本请修改标题末尾的冲突标记。`),
      );
      conflicts.append(makeButton("查看冲突副本", "button button-secondary button-small", showSyncConflictEntries, "search"));
      content.append(conflicts);
    }

    const notice = makeElement("div", "inline-notice inline-notice-compact sync-notice");
    notice.append(
      icon("shield", 17),
      makeElement("p", "", "同步密钥与主密码相互独立。停止此设备同步只会移除本机配置，不会删除服务器上的加密对象。"),
    );
    const actions = makeElement("div", "sync-actions sync-actions-configured");
    const syncNow = makeButton("立即同步", "button button-primary", syncWebDavNow, "refresh");
    const automatic = makeButton(
      status.automatic ? "关闭自动同步" : "启用自动同步",
      "button button-secondary",
      toggleWebDavAutoSync,
      status.automatic ? "x" : "check",
    );
    const reveal = makeButton("查看恢复码", "button button-ghost", revealWebDavRecoveryCode, "eye");
    const disable = makeButton("停止此设备同步", "button button-danger-ghost", disableWebDavSync, "x");
    for (const button of [syncNow, automatic, reveal, disable]) {
      button.dataset.securityMutation = "true";
      button.disabled = state.syncOperation !== null || state.securityOperation !== null;
    }
    actions.append(syncNow, automatic, reveal, disable);
    content.append(makeElement("p", "field-help", "自动同步仅在保险库解锁期间运行：保存修改后会检查远端，并定期拉取其他设备的修改。远端提交结果无法确认时会暂停，需手动同步核对。"));
    content.append(notice, actions);
  }

  card.append(content);
  return card;
}

function appendSyncMetadata(list: HTMLDListElement, label: string, value: string): void {
  const item = makeElement("div", "sync-metadata-item");
  item.append(makeElement("dt", "", label), makeElement("dd", "", value));
  list.append(item);
}

function appendSensitiveSyncMetadata(list: HTMLDListElement, label: string, value: string): void {
  const item = makeElement("div", "sync-metadata-item sync-metadata-sensitive");
  const valueCell = makeElement("dd");
  const input = makeElement("input", "input sync-metadata-input") as HTMLInputElement;
  input.value = value;
  input.readOnly = true;
  input.setAttribute("aria-label", `${label}（已隐藏）`);
  valueCell.append(input);
  addSensitiveTextActions({ wrapper: valueCell, input }, label);
  item.append(makeElement("dt", "", label), valueCell);
  list.append(item);
}

function beginSyncOperation(operation: Exclude<SyncOperation, null>): number | null {
  if (
    !state.status.unlocked
    || state.syncOperation !== null
    || state.securityOperation !== null
    || state.entryMutation !== null
  ) return null;
  state.syncOperation = operation;
  setSecurityMutationControlsDisabled(true);
  return state.epoch;
}

function finishSyncOperation(operationEpoch: number): void {
  if (operationEpoch !== state.epoch || !state.status.unlocked) return;
  state.syncOperation = null;
  setSecurityMutationControlsDisabled(false);
  if (state.view === "settings" && !hasOpenModal()) renderMainShell();
}

function clearWebDavCredentials(credentials: WebDavCredentials | null): void {
  if (!credentials) return;
  credentials.endpoint = "";
  credentials.username = "";
  credentials.appPassword = "";
}

function clearWebDavJoinDetails(details: WebDavJoinDetails | null): void {
  if (!details) return;
  clearWebDavCredentials(details.credentials);
  details.recoveryCode = "";
}

async function applyWebDavOutcome(outcome: WebDavSyncOutcome, operationEpoch: number, joined = false): Promise<void> {
  if (operationEpoch !== state.epoch || !state.status.unlocked) return;
  state.syncStatus = normalizeWebDavSyncStatus(outcome.status);
  state.syncStatusError = false;
  state.syncStatusUncertain = false;
  state.syncRemoteOutcomeUnknown = false;
  state.webdavRetry = null;
  state.overview.syncConflictCount += outcome.conflicts;
  let listRefreshed = true;
  if (outcome.kind === "downloaded" || outcome.kind === "merged") {
    clearEntryDraft();
    state.report = null;
    listRefreshed = await loadEntries(false, operationEpoch, false, false);
  }
  await loadVaultOverview(operationEpoch).catch(() => undefined);
  if (operationEpoch !== state.epoch || !state.status.unlocked) return;
  const sequence = `远端序列 #${outcome.sequence.toLocaleString("zh-CN")}`;
  const autoNote = joined && outcome.status.automatic ? " 此设备已启用自动同步，可在设置中关闭。" : "";
  if (!listRefreshed) {
    showToast(
      `同步已提交（${sequence}），但条目列表未能刷新。请切换到条目页重新读取；若仍失败，点击“重试读取”${outcome.conflicts > 0 ? `，然后核对 ${outcome.conflicts} 个冲突副本` : ""}。${autoNote}`,
      "warning",
      8200,
    );
    return;
  }
  if (outcome.conflicts > 0) {
    showToast(
      `同步完成（${sequence}）。已保留 ${outcome.conflicts} 个冲突副本，并标记“同步冲突”供你核对。${autoNote}`,
      "warning",
      7200,
    );
    return;
  }
  const messages: Record<WebDavSyncOutcome["kind"], string> = {
    upToDate: `已检查服务器，本机与远端均为最新（${sequence}）。`,
    uploaded: `本机加密修改已上传（${sequence}）。`,
    downloaded: `远端加密修改已下载并应用（${sequence}）。`,
    merged: `本机与远端修改已安全合并（${sequence}）。`,
  };
  showToast(`${messages[outcome.kind]}${autoNote}`, "success", 6200);
}

function describeWebDavNetworkFailure(error: unknown, fallback: string): string {
  const message = typeof error === "string" ? error : error instanceof Error ? error.message : "";
  const guidance = new Map<string, string>([
    ["WebDAV 网络请求超时。请检查网络及服务器端口。", "WebDAV 请求超时。请检查服务器地址、网络和 HTTPS 端口后重试。"],
    ["无法建立 WebDAV HTTPS 连接。请检查服务器是否可达、端口是否启用 HTTPS，以及证书是否可信且与域名匹配。", "无法建立 HTTPS 连接。请确认端口启用了 HTTPS，且证书受本机信任并与访问域名或 IP 匹配。"],
    ["WebDAV HTTPS 证书链不受信任。请检查服务器证书链。", "WebDAV 服务的证书链无法验证。请确认该 HTTPS 服务发送了站点证书及所需中间证书，并检查签发机构是否受本机信任。"],
    ["WebDAV 服务器返回了不支持的状态码 401。", "WebDAV 身份验证失败（401）。请检查用户名和应用专用密码。"],
    ["WebDAV 服务器返回了不支持的状态码 403。", "WebDAV 拒绝访问（403）。请检查账号对该目录的读取、创建、修改和删除权限。"],
    ["WebDAV 服务器返回了不支持的状态码 404。", "WebDAV 目录不存在（404）。请先在服务器创建目录，并核对完整地址。"],
    ["WebDAV 服务器返回了不支持的状态码 405。", "WebDAV 方法被拒绝（405）。请检查服务器及反向代理是否允许 WebDAV 请求。"],
    ["WebDAV 服务器返回了不支持的状态码 409。", "WebDAV 目录发生冲突（409）。请确认父目录存在，并重新检查目录权限。"],
    ["WebDAV 服务器返回了不支持的状态码 412。", "远端版本已变化（412）。本机内容未被覆盖，请重新同步并核对冲突副本。"],
    ["WebDAV 地址不是现有集合。", "填写的地址不是现有 WebDAV 目录。请先创建目录，并以“/”结束地址。"],
    ["远端尚未初始化此 CipherNest 同步空间。", "该目录中尚无 CipherNest 同步空间。请核对地址，或先在第一台设备创建同步空间。"],
    ["远端已存在此 CipherNest 同步空间。", "该目录已有同步空间。若你持有对应恢复码，请使用“加入已有空间”。"],
    ["远端已被另一台设备更新，请重新拉取并合并。", "远端已被另一台设备更新。本机内容未被覆盖，请重新同步并核对冲突副本。"],
    ["WebDAV 服务器不支持安全同步所需的条件请求或强 ETag。", "服务器缺少安全同步所需的强 ETag 或条件写入能力。请检查 WebDAV 服务和反向代理配置。"],
    ["同步恢复码无效。", "同步恢复码无效。请核对完整的 CN1 恢复码。"],
    ["本地同步状态无效或已损坏。", "本机同步配置无法验证，同步已停止。请检查设备上的同步配置。"],
    ["本地保险库版本早于上次同步版本，已拒绝覆盖远端数据。", "本机保险库版本早于同步检查点。请先导出本机备份，核对其他设备后再处理。"],
    ["检测到远端回滚、分叉或缺失的父快照。", "远端同步历史无法通过安全检查。请先导出本机备份，再核对服务器与其他设备。"],
    ["远端快照链超过安全检查上限。", "远端历史超过安全检查上限。请先导出本机备份，再核对较新的可信设备。"],
    ["同步期间本地保险库已发生变化；远端内容未覆盖这些更改，请重新同步。", "同步期间本机保险库发生变化，远端内容未覆盖本机修改。请重新同步。"],
  ]);
  return guidance.get(message) ?? fallback;
}

async function createWebDavSyncSpace(): Promise<void> {
  if (state.syncStatus.configured || state.syncStatusError) return;
  if (hasUnsavedDraft()) {
    showToast("请先保存或放弃当前条目的修改，再创建同步空间。", "warning");
    return;
  }
  const operationEpoch = beginSyncOperation("create");
  if (operationEpoch === null) return;
  let credentials: WebDavCredentials | null = null;
  let createResult: WebDavCreateResult | null = null;
  let recoveryCode = "";
  let retryEndpoint = "";
  let retryUsername = "";
  try {
    credentials = await askWebDavConnection("create", state.webdavRetry?.mode === "create" ? state.webdavRetry : null);
    if (!credentials || operationEpoch !== state.epoch) return;
    retryEndpoint = credentials.endpoint;
    retryUsername = credentials.username;
    const closeProgress = showRestoreProgress(
      "正在验证 WebDAV 并创建加密同步空间…",
      "界面会暂时锁定编辑；已经发送的密文请求可能在应用随后锁定时继续完成。",
      true,
    );
    try {
      const createRequest = invokeCommand<WebDavCreateResult>("create_webdav_sync", {
        credentials: { ...credentials },
      });
      clearWebDavCredentials(credentials);
      createResult = await createRequest;
    } finally {
      closeProgress();
    }
    if (operationEpoch !== state.epoch || !state.status.unlocked) return;
    state.syncStatus = normalizeWebDavSyncStatus(createResult.status);
    state.syncStatusError = false;
    state.syncStatusUncertain = false;
    state.syncRemoteOutcomeUnknown = false;
    state.webdavRetry = null;
    await loadVaultOverview(operationEpoch).catch(() => undefined);
    recoveryCode = createResult.recoveryCode;
    createResult.recoveryCode = "";
    await showRecoveryCodeDialog(recoveryCode, true, "保存 WebDAV 恢复码");
    recoveryCode = "";
    if (operationEpoch !== state.epoch || !state.status.unlocked) return;
    showToast("加密同步空间已创建，并已启用自动同步。保险库解锁期间会检查远端；可在设置中关闭。", "success", 6600);
  } catch (error) {
    if (operationEpoch === state.epoch) {
      const explanation = describeWebDavNetworkFailure(error, "无法创建同步空间。请检查 HTTPS 地址、目录权限和应用专用密码后重试。");
      let message = createResult
        ? "远端空间已创建，但本机未能确认后续设置。请保留已取得的恢复码并重新检查本机状态。"
        : `${explanation} 若服务器已出现新空间但本机没有取得恢复码，请改用新的空目录；勿删除其他设备使用中的内容。`;
      const statusProbe = await loadWebDavSyncStatusSafely(state.syncStatus);
      if (operationEpoch !== state.epoch) return;
      if (statusProbe.error) {
        state.syncStatusError = true;
        state.webdavRetry = null;
        message = "本机同步配置无法读取。同步已停止；请在设置中检查或清除本机同步配置，保留远端数据。";
      } else if (statusProbe.status.configured) {
        state.syncStatus = statusProbe.status;
        state.syncRemoteOutcomeUnknown = true;
        state.webdavRetry = null;
        message = "本机同步配置已存在，但创建结果未能确认。请用当前主密码查看并保存恢复码，再核对远端状态。";
      } else if (retryEndpoint) {
        state.webdavRetry = { mode: "create", endpoint: retryEndpoint, username: retryUsername, message };
      }
      showToast(message, "error", 8200);
    }
  } finally {
    clearWebDavCredentials(credentials);
    if (createResult) createResult.recoveryCode = "";
    recoveryCode = "";
    finishSyncOperation(operationEpoch);
  }
}

async function joinWebDavSyncSpace(): Promise<void> {
  if (state.syncStatus.configured || state.syncStatusError) return;
  if (hasUnsavedDraft()) {
    showToast("请先保存或放弃当前条目的修改，再加入同步空间。", "warning");
    return;
  }
  const operationEpoch = beginSyncOperation("inspect");
  if (operationEpoch === null) return;
  let details: WebDavJoinDetails | null = null;
  let preview: WebDavRemotePreview | null = null;
  let retryEndpoint = "";
  let retryUsername = "";
  let joinSubmitted = false;
  try {
    details = await askWebDavConnection("join", state.webdavRetry?.mode === "join" ? state.webdavRetry : null);
    if (!details || operationEpoch !== state.epoch) return;
    retryEndpoint = details.credentials.endpoint;
    retryUsername = details.credentials.username;

    const closeInspection = showRestoreProgress(
      "正在读取并验证远端加密快照…",
      "当前步骤只读取并验证密文，不会立即替换本机保险库。",
      true,
    );
    try {
      preview = await invokeCommand<WebDavRemotePreview>("inspect_webdav_sync", {
        request: {
          credentials: { ...details.credentials },
          recoveryCode: details.recoveryCode,
        },
      });
    } finally {
      closeInspection();
    }
    if (operationEpoch !== state.epoch || !state.status.unlocked) return;

    const mode = await showWebDavJoinPreview(preview, state.overview.totalEntries);
    if (!mode || operationEpoch !== state.epoch) return;
    if (mode === "remote" && preview.localHasHistory) {
      const replace = await showConfirm(
        "再次确认：以远端内容替换本机？",
        `本机现有 ${state.overview.totalEntries.toLocaleString("zh-CN")} 个条目及删除历史将被远端快照替换。若不确定，请取消并选择“合并（推荐）”。`,
        "确认以远端替换",
        true,
      );
      if (!replace || operationEpoch !== state.epoch) return;
    }

    state.syncOperation = "join";
    const closeJoin = showRestoreProgress(
      mode === "merge" ? "正在安全合并本机与远端内容…" : "正在应用远端加密快照…",
      "界面会暂时锁定编辑；后端会用本机版本与远端条件写入防止静默覆盖。",
      true,
    );
    let outcome: WebDavSyncOutcome;
    try {
      joinSubmitted = true;
      const joinRequest = invokeCommand<WebDavSyncOutcome>("join_webdav_sync", {
        request: {
          credentials: { ...details.credentials },
          recoveryCode: details.recoveryCode,
          previewToken: preview.previewToken,
          mode,
          confirmReplace: mode === "remote" && preview.localHasHistory,
        },
      });
      preview.previewToken = "";
      clearWebDavJoinDetails(details);
      outcome = await joinRequest;
    } finally {
      closeJoin();
    }
    await applyWebDavOutcome(outcome, operationEpoch, true);
  } catch (error) {
    if (operationEpoch === state.epoch) {
      const explanation = describeWebDavNetworkFailure(error, "无法加入此同步空间。请检查凭据、恢复码及服务器状态。");
      let message = joinSubmitted
        ? `${explanation} 请求可能已修改远端；请先在可信设备核对远端状态，再重新读取并加入。`
        : explanation;
      const statusProbe = await loadWebDavSyncStatusSafely(state.syncStatus);
      if (operationEpoch !== state.epoch) return;
      if (statusProbe.error) {
        state.syncStatusError = true;
        state.webdavRetry = null;
        message = "本机同步配置无法读取。同步已停止；请在设置中检查或清除本机同步配置，保留远端数据。";
      } else if (statusProbe.status.configured) {
        state.syncStatus = statusProbe.status;
        state.syncRemoteOutcomeUnknown = joinSubmitted;
        state.webdavRetry = null;
        message = joinSubmitted
          ? "本机加入配置已存在，但远端提交结果待确认。请重新同步并核对冲突副本。"
          : explanation;
      } else if (retryEndpoint) {
        state.webdavRetry = { mode: "join", endpoint: retryEndpoint, username: retryUsername, message };
      }
      showToast(message, "error", 8200);
    }
  } finally {
    clearWebDavJoinDetails(details);
    if (preview) preview.previewToken = "";
    finishSyncOperation(operationEpoch);
  }
}

async function syncWebDavNow(): Promise<void> {
  if (!state.syncStatus.configured || state.syncStatusError) return;
  if (hasUnsavedDraft()) {
    showToast("请先保存或放弃当前条目的修改，再同步。", "warning");
    return;
  }
  const operationEpoch = beginSyncOperation("sync");
  if (operationEpoch === null) return;
  const closeProgress = showRestoreProgress(
    "正在比较并同步端到端加密快照…",
    "界面会暂时锁定编辑；已经发送的密文请求可能在应用随后锁定时继续完成。",
    true,
  );
  try {
    const outcome = await invokeCommand<WebDavSyncOutcome>("sync_webdav_now");
    closeProgress();
    await applyWebDavOutcome(outcome, operationEpoch);
  } catch (error) {
    closeProgress();
    if (operationEpoch === state.epoch) {
      state.syncRemoteOutcomeUnknown = true;
      const explanation = describeWebDavNetworkFailure(error, "同步结果无法确认。请检查网络、服务器或并发修改后重试。");
      showToast(`${explanation} 请求可能已修改远端；请重新检查同步状态后再继续编辑其他设备。`, "error", 8200);
      renderMainShell();
    }
  } finally {
    closeProgress();
    finishSyncOperation(operationEpoch);
  }
}

async function toggleWebDavAutoSync(): Promise<void> {
  if (!state.syncStatus.configured || state.syncStatusError) return;
  const operationEpoch = beginSyncOperation("auto");
  if (operationEpoch === null) return;
  const enabled = !state.syncStatus.automatic;
  try {
    const status = await invokeCommand<WebDavSyncStatus>("set_webdav_auto_sync", { enabled });
    if (operationEpoch !== state.epoch || !state.status.unlocked) return;
    state.syncStatus = normalizeWebDavSyncStatus(status);
    state.syncStatusUncertain = false;
    renderMainShell();
    showToast(
      enabled
        ? status.autoPaused
          ? "自动同步设置已保存。请先手动同步，核对上次未确认的远端结果。"
          : "自动同步已启用。保险库解锁期间会检查远端修改。"
        : "自动同步已关闭。仍可使用“立即同步”。",
      enabled && status.autoPaused ? "warning" : "success",
      6200,
    );
  } catch (error) {
    if (operationEpoch !== state.epoch) return;
    showToast(describeWebDavNetworkFailure(error, "无法更改自动同步设置，请重试。"), "error", 6200);
  } finally {
    finishSyncOperation(operationEpoch);
  }
}

async function revealWebDavRecoveryCode(): Promise<void> {
  if (!state.syncStatus.configured || state.syncStatusError) return;
  const operationEpoch = beginSyncOperation("reveal");
  if (operationEpoch === null) return;
  let currentPassword: string | null = null;
  let revealResult: WebDavRecoveryCode | null = null;
  let recoveryCode = "";
  try {
    currentPassword = await askMasterPassword(
      "查看 WebDAV 恢复码",
      "恢复码可以解密服务器上的同步数据。请先用当前主密码确认身份。",
      "验证并查看",
      "当前主密码",
      "输入当前主密码",
    );
    if (currentPassword === null || operationEpoch !== state.epoch) return;
    const revealRequest = invokeCommand<WebDavRecoveryCode>("reveal_webdav_recovery_code", { currentPassword });
    currentPassword = "";
    revealResult = await revealRequest;
    if (operationEpoch !== state.epoch || !state.status.unlocked) return;
    recoveryCode = revealResult.recoveryCode;
    revealResult.recoveryCode = "";
    await showRecoveryCodeDialog(recoveryCode, false, "WebDAV 恢复码");
  } catch {
    if (operationEpoch === state.epoch) showToast("无法查看恢复码，请检查当前主密码后重试。", "error", 5200);
  } finally {
    currentPassword = "";
    if (revealResult) revealResult.recoveryCode = "";
    recoveryCode = "";
    finishSyncOperation(operationEpoch);
  }
}

async function disableWebDavSync(): Promise<void> {
  if (!state.syncStatus.configured && !state.syncStatusError) return;
  const operationEpoch = beginSyncOperation("disable");
  if (operationEpoch === null) return;
  let currentPassword: string | null = null;
  try {
    const clearingInvalidState = state.syncStatusError;
    const confirmed = await showConfirm(
      clearingInvalidState ? "清除无法验证的本机同步配置？" : "停止此设备的 WebDAV 同步？",
      "只会删除本机保存的加密同步配置与检查点；服务器上的加密快照不会删除，以后仍可凭恢复码重新加入。",
      clearingInvalidState ? "继续清除本机配置" : "继续停止同步",
      true,
    );
    if (!confirmed || operationEpoch !== state.epoch) return;
    currentPassword = await askMasterPassword(
      clearingInvalidState ? "确认清除本机同步配置" : "确认停止此设备同步",
      "请输入当前主密码，确认你有权移除此设备上的同步密钥。远端加密对象仍会保留。",
      clearingInvalidState ? "清除本机同步配置" : "停止此设备同步",
      "当前主密码",
      "输入当前主密码",
    );
    if (currentPassword === null || operationEpoch !== state.epoch) return;
    const disableRequest = invokeCommand<void>("disable_webdav_sync", { currentPassword });
    currentPassword = "";
    await disableRequest;
    if (operationEpoch !== state.epoch || !state.status.unlocked) return;
    state.syncStatus = { ...EMPTY_SYNC_STATUS };
    state.syncStatusError = false;
    state.syncStatusUncertain = false;
    state.syncRemoteOutcomeUnknown = false;
    state.webdavRetry = null;
    showToast(
      clearingInvalidState
        ? "无法验证的本机同步配置已清除；服务器上的加密对象未被删除。"
        : "此设备的同步已停止；服务器上的加密对象未被删除。",
      "success",
      5600,
    );
  } catch {
    if (operationEpoch === state.epoch) showToast("无法停止同步，请检查当前主密码后重试。", "error", 5200);
  } finally {
    currentPassword = "";
    finishSyncOperation(operationEpoch);
  }
}

function pageHeader(eyebrow: string, title: string, description: string): HTMLElement {
  const header = makeElement("header", "page-header");
  const copy = makeElement("div");
  copy.append(makeElement("span", "eyebrow", eyebrow), makeElement("h1", "", title), makeElement("p", "", description));
  header.append(copy);
  return header;
}

function settingsCardHeader(iconName: IconName, title: string, description: string): HTMLElement {
  const header = makeElement("div", "settings-card-header");
  const badge = makeElement("div", "settings-icon");
  badge.append(icon(iconName, 20));
  const copy = makeElement("div");
  copy.append(makeElement("h2", "", title), makeElement("p", "", description));
  header.append(badge, copy);
  return header;
}

function createSelectSetting(
  id: string,
  title: string,
  description: string,
  options: Array<[number, string]>,
  selected: number,
): HTMLElement {
  const row = makeElement("div", "setting-row");
  const label = makeElement("label", "setting-copy");
  label.htmlFor = id;
  label.append(makeElement("strong", "", title), makeElement("span", "", description));
  const wrap = makeElement("div", "select-wrap setting-select");
  const select = makeElement("select", "select") as HTMLSelectElement;
  select.id = id;
  for (const [value, text] of options) {
    const option = makeElement("option", "", text) as HTMLOptionElement;
    option.value = String(value);
    option.selected = value === selected;
    select.append(option);
  }
  wrap.append(select, icon("chevron", 14));
  row.append(label, wrap);
  return row;
}

function createToggleSetting(id: string, title: string, description: string, checked: boolean): { wrapper: HTMLElement; input: HTMLInputElement } {
  const row = makeElement("label", "setting-row toggle-row");
  row.htmlFor = id;
  const copy = makeElement("span", "setting-copy");
  copy.append(makeElement("strong", "", title), makeElement("span", "", description));
  const toggle = makeElement("span", "toggle");
  const input = makeElement("input") as HTMLInputElement;
  input.id = id;
  input.type = "checkbox";
  input.checked = checked;
  const track = makeElement("span", "toggle-track");
  track.append(makeElement("span", "toggle-thumb"));
  toggle.append(input, track);
  row.append(copy, toggle);
  return { wrapper: row, input };
}

function renderPageLoading(label: string): HTMLElement {
  const loading = makeElement("div", "page-loading");
  loading.setAttribute("role", "status");
  loading.setAttribute("aria-live", "polite");
  loading.append(makeElement("div", "spinner"), makeElement("p", "", label));
  return loading;
}

function renderStatusbar(): HTMLElement {
  const statusbar = makeElement("footer", "statusbar");
  const left = makeElement("div", "statusbar-group");
  left.append(
    icon("shield", 13),
  );
  const syncLabel = state.syncStatusError
    ? "同步已停止 · 查看设置"
    : state.syncRemoteOutcomeUnknown
      ? "远端同步结果待确认 · 查看设置"
      : state.syncStatusUncertain
        ? "同步状态待确认 · 查看设置"
        : state.syncStatus.autoPaused
          ? "自动同步已暂停 · 查看设置"
          : state.syncStatus.autoWarning
            ? "自动同步需检查 · 查看设置"
        : state.syncStatus.configured && state.syncStatus.pendingLocalChanges
          ? "本机修改待同步 · 查看设置"
          : state.syncStatus.configured
            ? state.syncStatus.automatic ? "本地优先 · 自动同步" : "本地优先 · 手动同步"
            : "本地保险库";
  if (state.syncStatus.configured || state.syncStatusError) {
    const syncLink = makeButton(syncLabel, "statusbar-sync-link", () => switchView("settings"));
    syncLink.dataset.focusKey = "statusbar-sync";
    left.append(syncLink);
  } else {
    left.append(makeElement("span", "", syncLabel));
  }
  const backupLabel = state.webdavBackupStatusError
    ? "远端备份状态未知"
    : state.webdavBackupStatus.warning
      ? "远端备份需处理"
      : state.webdavBackupStatus.configured && state.webdavBackupStatus.automatic && state.webdavBackupStatus.pending
        ? "远端备份待上传"
        : null;
  if (backupLabel) {
    left.append(makeElement("span", "status-separator", "•"));
    const backupLink = makeButton(`${backupLabel} · 查看设置`, `statusbar-backup-link${state.webdavBackupStatusError || state.webdavBackupStatus.warning ? " has-error" : ""}`, () => switchView("settings"));
    backupLink.dataset.focusKey = "statusbar-backup";
    left.append(backupLink);
  }
  left.append(makeElement("span", "status-separator", "•"));
  left.append(makeElement("span", "", `空闲 ${state.settings.autoLockMinutes} 分钟自动锁定`));
  const clipboard = makeElement("button", "clipboard-status");
  clipboard.id = "clipboard-status";
  clipboard.type = "button";
  clipboard.hidden = true;
  clipboard.addEventListener("click", () => void clearClipboardNow(true));
  const shortcuts = makeElement("div", "statusbar-shortcuts");
  shortcuts.append(shortcutPill(shortcutLabel("F"), "搜索"), shortcutPill(shortcutLabel("L"), "锁定"));
  statusbar.append(left, clipboard, shortcuts);
  return statusbar;
}

async function showSyncConflictEntries(): Promise<void> {
  if (state.view === "all" && hasUnsavedDraft()) {
    const discard = await showConfirm(
      "放弃未保存的修改？",
      "查看同步冲突会关闭当前编辑的条目。未保存的输入将丢失。",
      "放弃修改",
      true,
    );
    if (!discard) return;
  }
  if (state.view !== "all") await switchView("all");
  if (state.view !== "all" || !state.status.unlocked) return;
  clearEntryDraft();
  state.conflictsOnly = true;
  state.query = "";
  await loadEntries(true);
}

async function loadEntries(
  render = true,
  requestedEpoch = state.epoch,
  restoreSearchFocus = false,
  notifyFailure = true,
): Promise<boolean> {
  const epoch = requestedEpoch;
  const requestId = ++listRequestId;
  state.listLoading = true;
  if (render && state.status.unlocked) renderMainShell();
  const args: Record<string, unknown> = {
    filter: state.conflictsOnly ? "conflicts" : state.view === "favorites" ? "favorites" : "all",
    sort: state.sort,
  };
  const query = state.query.trim();
  const listKey = JSON.stringify([args.filter, state.sort, query]);
  if (query) args.query = query;
  try {
    const entries = await invokeCommand<EntrySummary[]>("list_entries", args);
    if (epoch !== state.epoch || requestId !== listRequestId || !state.status.unlocked) {
      return false;
    }
    state.entries = entries;
    const listChanged = state.entryListKey !== listKey;
    if (listChanged) state.visibleEntryCount = ENTRY_PAGE_SIZE;
    state.entryListKey = listKey;
    state.status.itemCount = Math.max(state.status.itemCount, entries.length);
    state.listLoading = false;
    state.listError = false;
    if (render) {
      renderMainShell();
      if (listChanged) {
        const list = document.querySelector<HTMLElement>(".entry-list");
        if (list) list.scrollTop = 0;
      }
      if (restoreSearchFocus) focusSearchAtEnd();
    }
    return true;
  } catch {
    if (epoch !== state.epoch || requestId !== listRequestId) return false;
    state.entries = [];
    state.listLoading = false;
    state.listError = true;
    if (render || (document.querySelector(".entry-list") && !hasUnsavedDraft() && state.view !== "settings")) renderMainShell();
    if (notifyFailure) showToast("无法读取条目列表。列表已隐藏，请点击“重试读取”。", "error");
    return false;
  }
}

async function loadVaultOverview(requestedEpoch = state.epoch): Promise<void> {
  try {
    const overview = await invokeCommand<VaultOverview>("vault_overview");
    if (requestedEpoch !== state.epoch || !state.status.unlocked) return;
    state.overview = overview;
    state.status.itemCount = overview.totalEntries;
  } catch (error) {
    if (requestedEpoch === state.epoch && state.status.unlocked) {
      state.overview.autoBackup = {
        count: 0,
        currentCovered: false,
        inspectionFailed: true,
        warning: "无法确认本机自动快照状态，请另行导出加密备份。",
      };
    }
    throw error;
  }
}

async function loadSecurityReport(): Promise<void> {
  const epoch = state.epoch;
  try {
    const report = await invokeCommand<SecurityReport>("security_report");
    if (epoch !== state.epoch || !state.status.unlocked) return;
    state.report = report;
    state.visibleIssueCount = ENTRY_PAGE_SIZE;
    state.reportLoading = false;
    state.reportError = false;
    renderMainShell();
  } catch {
    if (epoch !== state.epoch) return;
    state.report = null;
    state.reportLoading = false;
    state.reportError = true;
    renderMainShell();
    showToast("无法完成安全检查，请重试。", "error");
  }
}

async function selectEntry(id: string): Promise<boolean> {
  if (blockEntryActionWhileMutating()) return false;
  if (id === state.selectedId && state.draft) return true;
  if (hasUnsavedDraft()) {
    const discard = await showConfirm("放弃未保存的修改？", "打开其他条目将丢弃当前修改。", "放弃修改", true);
    if (!discard) return false;
  }
  hidePassword();
  clearEntryDraft();
  state.selectedId = id;
  state.detailLoading = true;
  renderMainShell();
  const epoch = state.epoch;
  try {
    const entry = await invokeCommand<VaultEntry>("get_entry", { id });
    if (epoch !== state.epoch || state.selectedId !== id || !state.status.unlocked) {
      clearVaultEntrySensitiveFields(entry);
      return false;
    }
    state.entryMeta = {
      id: entry.id,
      createdAt: entry.createdAt,
      updatedAt: entry.updatedAt,
      passwordUpdatedAt: entry.passwordUpdatedAt,
      revision: entry.revision,
    };
    state.entryRevisionConflict = false;
    state.draft = entryInputFromVault(entry);
    state.draftSnapshot = serializeInput(state.draft);
    clearVaultEntrySensitiveFields(entry);
    state.detailLoading = false;
    renderMainShell();
    return true;
  } catch {
    if (epoch !== state.epoch || state.selectedId !== id) return false;
    state.detailLoading = false;
    state.selectedId = null;
    renderMainShell();
    showToast("无法打开该条目，请重试。", "error");
    return false;
  }
}

async function createNewEntry(): Promise<void> {
  if (blockEntryActionWhileMutating()) return;
  if (hasUnsavedDraft()) {
    const discard = await showConfirm("放弃未保存的修改？", "新建条目将丢弃当前修改。", "放弃并新建", true);
    if (!discard) return;
  }
  if (state.view === "settings" && !await confirmLeavingUnsavedSettings()) return;
  clearEntryDraft();
  state.view = "all";
  state.conflictsOnly = false;
  state.selectedId = null;
  state.entryMeta = {};
  state.draft = emptyEntryInput();
  state.draftSnapshot = serializeInput(state.draft);
  state.detailLoading = false;
  renderMainShell();
  window.setTimeout(() => document.querySelector<HTMLInputElement>("#entry-title")?.focus(), 0);
}

function emptyEntryInput(): EntryInput {
  return { title: "", username: "", password: "", url: "", purpose: "", notes: "", tags: [], favorite: false };
}

function entryInputFromVault(entry: VaultEntry): EntryInput {
  return {
    id: entry.id,
    title: entry.title,
    username: entry.username,
    password: entry.password,
    url: entry.url,
    purpose: entry.purpose,
    notes: entry.notes,
    tags: [...entry.tags],
    favorite: entry.favorite,
  };
}

function clearVaultEntrySensitiveFields(entry: VaultEntry): void {
  entry.username = "";
  entry.password = "";
  entry.url = "";
  entry.purpose = "";
  entry.notes = "";
  entry.tags.length = 0;
}

function cloneEntryInput(input: EntryInput): EntryInput {
  return { ...input, tags: [...input.tags] };
}

function serializeInput(input: EntryInput): string {
  return JSON.stringify(input);
}

function hasUnsavedDraft(): boolean {
  return Boolean(state.draft && serializeInput(state.draft) !== state.draftSnapshot);
}

async function saveConflictedDraftAsNewEntry(): Promise<void> {
  if (!state.entryRevisionConflict || !state.draft || !state.status.unlocked) return;
  if (state.entryMutation !== null || state.syncOperation !== null || state.securityOperation !== null) return;
  const copy = cloneEntryInput(state.draft);
  delete copy.id;
  delete copy.expectedRevision;
  const suffix = "（本机草稿）";
  if (!copy.title.endsWith(suffix) && [...copy.title].length + [...suffix].length <= 200) {
    copy.title += suffix;
  }
  if (!copy.tags.includes("同步冲突") && copy.tags.length < 20) copy.tags.push("同步冲突");
  clearEntryDraft();
  state.view = "all";
  state.conflictsOnly = false;
  state.draft = copy;
  state.draftSnapshot = serializeInput(emptyEntryInput());
  renderMainShell();
  await saveCurrentEntry();
}

async function saveCurrentEntry(button?: HTMLButtonElement): Promise<boolean> {
  if (
    !state.draft
    || !state.status.unlocked
    || state.entryMutation !== null
    || state.syncOperation !== null
    || state.securityOperation !== null
  ) return false;
  if (!validateEntry(state.draft)) return false;
  const submittedDraft = cloneEntryInput(state.draft);
  const submittedSnapshot = serializeInput(submittedDraft);
  const input = cloneEntryInput(submittedDraft);
  if (input.id && state.entryMeta.revision !== undefined) {
    input.expectedRevision = state.entryMeta.revision;
  }
  const epoch = state.epoch;
  let committed = false;
  state.entryMutation = "saving";
  if (button) setBusy(button, true, "正在加密保存…");
  setEntryEditorFrozen(true);
  try {
    const summary = await invokeCommand<EntrySummary>("save_entry", { input });
    committed = true;
    if (epoch !== state.epoch || !state.status.unlocked || state.entryMutation !== "saving") return false;
    recordLocalSyncMutation();
    state.selectedId = summary.id;
    state.status.itemCount = Math.max(state.status.itemCount, state.entries.length + (input.id ? 0 : 1));
    const listRefreshed = await loadEntries(false, epoch, false, false);
    await loadVaultOverview(epoch).catch(() => undefined);
    await refreshSyncStatusAfterMutation(epoch);
    const entry = await invokeCommand<VaultEntry>("get_entry", { id: summary.id });
    if (epoch !== state.epoch || !state.status.unlocked || state.entryMutation !== "saving") {
      clearVaultEntrySensitiveFields(entry);
      return false;
    }
    state.entryMeta = {
      id: entry.id,
      createdAt: entry.createdAt,
      updatedAt: entry.updatedAt,
      passwordUpdatedAt: entry.passwordUpdatedAt,
      revision: entry.revision,
    };
    state.entryRevisionConflict = false;
    const draftChangedWhileSaving = Boolean(
      state.draft && serializeInput(state.draft) !== submittedSnapshot,
    );
    if (draftChangedWhileSaving && state.draft) {
      state.draft.id = entry.id;
      const savedBaseline = cloneEntryInput(submittedDraft);
      savedBaseline.id = entry.id;
      state.draftSnapshot = serializeInput(savedBaseline);
    } else {
      state.draft = entryInputFromVault(entry);
      state.draftSnapshot = serializeInput(state.draft);
    }
    clearVaultEntrySensitiveFields(entry);
    state.report = null;
    state.entryMutation = null;
    renderMainShell();
    const backupNeedsAttention = currentAutoBackupNeedsAttention();
    showToast(
      !listRefreshed
        ? draftChangedWhileSaving
          ? "上一版已保存，新的编辑仍保留；条目列表刷新失败，请重试读取。"
          : "条目已加密保存，但列表刷新失败，请点击“重试读取”。"
        : backupNeedsAttention
          ? "条目已保存，但无法确认当前版本的自动备份。请打开设置检查备份状态并导出加密备份。"
        : draftChangedWhileSaving
          ? "上一版已保存；保存期间检测到的新修改仍保留在编辑器中。"
          : "条目已加密保存到本地。",
      !listRefreshed || draftChangedWhileSaving || backupNeedsAttention ? "warning" : "success",
    );
    return true;
  } catch (error) {
    if (epoch !== state.epoch || !state.status.unlocked) return false;
    state.entryMutation = null;
    if (button) setBusy(button, false);
    setEntryEditorFrozen(false);
    if (committed) {
      clearEntryDraft();
      await loadVaultOverview(epoch).catch(() => undefined);
      await refreshSyncStatusAfterMutation(epoch);
      const listRefreshed = await loadEntries(true, epoch, false, false);
      showToast(
        listRefreshed
          ? "条目已保存，但详情刷新失败。请重新打开条目确认内容。"
          : "条目已保存，但详情和列表刷新失败。请重试读取条目列表。",
        "warning",
        5200,
      );
      return true;
    }
    if (isEntryRevisionConflict(error) || error === "找不到该条目。") {
      state.entryRevisionConflict = true;
      renderMainShell();
      showToast("该条目已有远端修改。草稿仍在；可点击“另存当前草稿为新条目”保存，再核对内容。", "warning", 7600);
      return false;
    }
    presentEntrySaveFailure(error, "editor");
    return false;
  }
}

function presentEntrySaveFailure(error: unknown, context: "editor" | "generator"): void {
  const failure = describeEntrySaveFailure(error);
  const fieldId = failure.field ? entryFieldId(failure.field, context) : null;
  if (fieldId) setFieldError(fieldId, failure.message.replace(/^无法保存：/u, ""), true);
  showToast(failure.message, "error", 4800);
}

function isEntryRevisionConflict(error: unknown): boolean {
  return error === ENTRY_REVISION_CONFLICT
    || (error instanceof Error && error.message === ENTRY_REVISION_CONFLICT);
}

function isWeakMasterPasswordError(error: unknown): boolean {
  return error === MASTER_PASSWORD_TOO_WEAK
    || (error instanceof Error && error.message === MASTER_PASSWORD_TOO_WEAK);
}

function entryFieldId(field: EntryField, context: "editor" | "generator"): string | null {
  const prefix = context === "editor" ? "entry" : "generator";
  const suffixes: Partial<Record<EntryField, string>> = context === "editor"
    ? { title: "title", username: "username", password: "password", address: "url", purpose: "purpose", notes: "notes", tags: "tags" }
    : { title: "app", username: "user", address: "url", purpose: "purpose", tags: "tags" };
  const suffix = suffixes[field];
  return suffix ? `${prefix}-${suffix}` : null;
}

function validateEntry(input: EntryInput): boolean {
  clearFieldError("entry-title");
  clearFieldError("entry-password");
  let valid = true;
  if (!input.title.trim()) {
    setFieldError("entry-title", "请输入应用名称。", true);
    valid = false;
  }
  if (!input.password) {
    setFieldError("entry-password", "请输入或生成密码。", valid);
    valid = false;
  }
  if (input.tags.length > 20) {
    showToast("最多可保存 20 个标签。", "warning");
    valid = false;
  }
  return valid;
}

function setFieldError(id: string, message: string, focus: boolean): void {
  const input = document.querySelector<HTMLElement>(`#${id}`);
  const error = document.querySelector<HTMLElement>(`#${id}-error`);
  input?.setAttribute("aria-invalid", "true");
  input?.setAttribute("aria-describedby", `${id}-error`);
  if (error) error.textContent = message;
  if (focus) input?.focus();
}

function clearFieldError(id: string): void {
  const input = document.querySelector<HTMLElement>(`#${id}`);
  const error = document.querySelector<HTMLElement>(`#${id}-error`);
  input?.removeAttribute("aria-invalid");
  input?.removeAttribute("aria-describedby");
  if (error) error.textContent = "";
}

async function cancelEditing(): Promise<void> {
  if (blockEntryActionWhileMutating()) return;
  if (hasUnsavedDraft()) {
    const discard = await showConfirm("放弃未保存的修改？", "当前输入不会写入保险库。", "放弃修改", true);
    if (!discard) return;
  }
  clearEntryDraft();
  renderMainShell();
}

async function returnToList(): Promise<void> {
  if (blockEntryActionWhileMutating()) return;
  if (hasUnsavedDraft()) {
    const discard = await showConfirm("返回并放弃修改？", "当前输入不会写入保险库。", "放弃修改", true);
    if (!discard) return;
  }
  clearEntryDraft();
  renderMainShell();
}

function clearEntryDraft(): void {
  hideAllManagedSensitiveInputs();
  hidePassword();
  hideNotes();
  if (state.draft) {
    state.draft.username = "";
    state.draft.password = "";
    state.draft.url = "";
    state.draft.purpose = "";
    state.draft.notes = "";
    state.draft.tags.length = 0;
  }
  state.draft = null;
  state.draftSnapshot = "";
  state.entryRevisionConflict = false;
  state.entryMutation = null;
  state.selectedId = null;
  state.entryMeta = {};
  state.detailLoading = false;
}

async function deleteCurrentEntry(): Promise<void> {
  if (blockEntryActionWhileMutating()) return;
  const id = state.entryMeta.id;
  const expectedRevision = state.entryMeta.revision;
  const title = state.entries.find((entry) => entry.id === id)?.title || state.draft?.title || "此条目";
  if (!id || expectedRevision === undefined) return;
  const discardUnsavedDraft = hasUnsavedDraft();
  const confirmed = await showConfirm(
    `删除“${title}”？`,
    discardUnsavedDraft
      ? "当前条目有未保存的修改。继续将丢弃这些修改并删除已保存的条目；本机自动快照或以前导出的备份中可能仍有旧版本。此操作无法在应用内撤销。"
      : "该条目将从当前保险库删除，但仍可能存在于本机自动快照或以前导出的加密备份中。此操作无法在应用内撤销。",
    discardUnsavedDraft ? "放弃修改并删除" : "删除条目",
    true,
  );
  if (!confirmed || !state.status.unlocked || state.entryMeta.id !== id) return;
  const epoch = state.epoch;
  state.entryMutation = "deleting";
  setEntryEditorFrozen(true);
  try {
    await invokeCommand<void>("delete_entry", { id, expectedRevision });
    if (
      epoch !== state.epoch
      || !state.status.unlocked
      || state.entryMutation !== "deleting"
      || state.entryMeta.id !== id
    ) return;
    recordLocalSyncMutation();
    clearEntryDraft();
    state.status.itemCount = Math.max(0, state.status.itemCount - 1);
    state.report = null;
    await loadVaultOverview(epoch).catch(() => undefined);
    await refreshSyncStatusAfterMutation(epoch);
    const listRefreshed = await loadEntries(true, epoch, false, false);
    showToast(
      listRefreshed
        ? "条目已删除。既有快照和导出文件不会被自动修改。"
        : "条目已删除，但列表刷新失败。请点击“重试读取”。",
      listRefreshed ? "success" : "warning",
    );
  } catch (error) {
    if (epoch !== state.epoch || !state.status.unlocked) return;
    if (state.entryMutation === "deleting") state.entryMutation = null;
    setEntryEditorFrozen(false);
    if (isEntryRevisionConflict(error)) {
      const listRefreshed = await loadEntries(true, epoch, false, false);
      showToast(
        listRefreshed
          ? "该条目已有新版本，未执行删除。请重新打开条目，核对最新内容后再操作。"
          : "该条目已有新版本，未执行删除；列表也未能刷新。请重试读取后核对。",
        "warning",
        5600,
      );
    } else {
      showToast("无法删除条目，请重试。", "error");
    }
  } finally {
    if (epoch === state.epoch && state.entryMutation === "deleting") {
      state.entryMutation = null;
      setEntryEditorFrozen(false);
    }
  }
}

async function toggleFavorite(entry: EntrySummary): Promise<void> {
  if (blockEntryActionWhileMutating()) return;
  const epoch = state.epoch;
  const id = entry.id;
  const favorite = !entry.favorite;
  const expectedRevision = entry.revision;
  state.entryMutation = "favoriting";
  setEntryEditorFrozen(true);
  try {
    const revision = await invokeCommand<number>("set_favorite", { id, favorite, expectedRevision });
    if (epoch !== state.epoch || !state.status.unlocked || state.entryMutation !== "favoriting") return;
    recordLocalSyncMutation();
    const currentSummary = state.entries.find((item) => item.id === id);
    if (currentSummary) {
      currentSummary.favorite = favorite;
      currentSummary.revision = revision;
    }
    if (state.draft?.id === id && state.entryMeta.revision === expectedRevision) {
      state.draft.favorite = favorite;
      updateSnapshotFavorite(favorite);
      setCurrentEntryRevision(id, revision);
    } else if (state.draft?.id === id && !hasUnsavedDraft()) {
      clearEntryDraft();
    }
    const [, listRefreshed] = await Promise.all([
      loadVaultOverview(epoch).catch(() => undefined),
      loadEntries(false, epoch, false, false),
      refreshSyncStatusAfterMutation(epoch),
    ]);
    if (epoch !== state.epoch || !state.status.unlocked || state.entryMutation !== "favoriting") return;
    state.entryMutation = null;
    renderMainShell();
    if (!listRefreshed) showToast("收藏状态已保存，但列表刷新失败。请点击“重试读取”。", "warning", 5200);
  } catch (error) {
    if (epoch !== state.epoch || !state.status.unlocked) return;
    if (state.entryMutation === "favoriting") state.entryMutation = null;
    setEntryEditorFrozen(false);
    if (isEntryRevisionConflict(error)) {
      const listRefreshed = await loadEntries(true, epoch, false, false);
      showToast(
        listRefreshed
          ? "该条目已有新版本，收藏状态未修改。请重新打开条目后再操作。"
          : "该条目已有新版本，收藏状态未修改；列表也未能刷新。请重试读取后核对。",
        "warning",
        5600,
      );
    } else {
      showToast("无法更新收藏状态。", "error");
    }
  } finally {
    if (epoch === state.epoch && state.entryMutation === "favoriting") {
      state.entryMutation = null;
      setEntryEditorFrozen(false);
    }
  }
}

async function toggleCurrentFavorite(): Promise<void> {
  if (blockEntryActionWhileMutating()) return;
  if (!state.draft) return;
  const favorite = !state.draft.favorite;
  if (!state.draft.id) {
    state.draft.favorite = favorite;
    renderMainShell();
    return;
  }
  const epoch = state.epoch;
  const id = state.draft.id;
  const expectedRevision = state.entryMeta.revision;
  if (expectedRevision === undefined) return;
  state.entryMutation = "favoriting";
  setEntryEditorFrozen(true);
  try {
    const revision = await invokeCommand<number>("set_favorite", { id, favorite, expectedRevision });
    if (
      epoch !== state.epoch
      || !state.status.unlocked
      || state.entryMutation !== "favoriting"
      || state.draft?.id !== id
    ) return;
    recordLocalSyncMutation();
    state.draft.favorite = favorite;
    updateSnapshotFavorite(favorite);
    setCurrentEntryRevision(id, revision);
    const summary = state.entries.find((entry) => entry.id === id);
    if (summary) {
      summary.favorite = favorite;
      summary.revision = revision;
    }
    await loadVaultOverview(epoch).catch(() => undefined);
    await refreshSyncStatusAfterMutation(epoch);
    const listRefreshed = await loadEntries(false, epoch, false, false);
    if (
      epoch !== state.epoch
      || !state.status.unlocked
      || state.entryMutation !== "favoriting"
      || state.draft?.id !== id
    ) return;
    state.entryMutation = null;
    renderMainShell();
    if (!listRefreshed) showToast("收藏状态已保存，但列表刷新失败。请点击“重试读取”。", "warning", 5200);
  } catch (error) {
    if (epoch !== state.epoch || !state.status.unlocked) return;
    if (state.entryMutation === "favoriting") state.entryMutation = null;
    setEntryEditorFrozen(false);
    if (isEntryRevisionConflict(error)) {
      const listRefreshed = await loadEntries(true, epoch, false, false);
      showToast(
        listRefreshed
          ? "该条目已有新版本，收藏状态未修改。请重新打开条目后再操作。"
          : "该条目已有新版本，收藏状态未修改；列表也未能刷新。请重试读取后核对。",
        "warning",
        5600,
      );
    } else {
      showToast("无法更新收藏状态。", "error");
    }
  } finally {
    if (epoch === state.epoch && state.entryMutation === "favoriting") {
      state.entryMutation = null;
      setEntryEditorFrozen(false);
    }
  }
}

function setCurrentEntryRevision(id: string, revision: number): void {
  if (state.entryMeta.id !== id) return;
  state.entryMeta.revision = revision;
}

function updateSnapshotFavorite(favorite: boolean): void {
  if (!state.draftSnapshot) return;
  try {
    const original = JSON.parse(state.draftSnapshot) as EntryInput;
    original.favorite = favorite;
    state.draftSnapshot = serializeInput(original);
  } catch {
    // A malformed in-memory snapshot is treated as dirty and never written automatically.
  }
}

function togglePasswordVisibility(): void {
  if (state.passwordVisible) {
    hidePassword();
    return;
  }
  hideAllManagedSensitiveInputs();
  hideGeneratorPassword();
  hideNotes();
  state.passwordVisible = true;
  const input = document.querySelector<HTMLInputElement>("#entry-password");
  if (input) input.type = "text";
  const button = document.querySelector<HTMLButtonElement>("#password-reveal-button");
  if (button) {
    clearNode(button);
    button.append(icon("eyeOff"));
    button.setAttribute("aria-label", "隐藏密码");
    button.setAttribute("aria-pressed", "true");
    button.title = "隐藏密码";
  }
  startPasswordRevealTimer();
}

function startPasswordRevealTimer(): void {
  if (revealTimeout) window.clearTimeout(revealTimeout);
  if (revealTicker) window.clearInterval(revealTicker);
  const duration = Math.max(1, state.settings.passwordRevealSeconds) * 1000;
  const deadline = Date.now() + duration;
  revealTimeout = window.setTimeout(hidePassword, duration);
  revealTicker = window.setInterval(() => syncPasswordRevealHint(deadline), 1000);
  syncPasswordRevealHint(deadline);
}

function syncPasswordRevealHint(deadline?: number): void {
  const hint = document.querySelector<HTMLElement>("#password-reveal-hint");
  if (!hint || !state.passwordVisible) return;
  const seconds = deadline ? Math.max(1, Math.ceil((deadline - Date.now()) / 1000)) : state.settings.passwordRevealSeconds;
  hint.textContent = `密码已显示，将在 ${seconds} 秒后自动隐藏。`;
}

function hidePassword(): void {
  state.passwordVisible = false;
  if (revealTimeout) window.clearTimeout(revealTimeout);
  if (revealTicker) window.clearInterval(revealTicker);
  revealTimeout = null;
  revealTicker = null;
  const input = document.querySelector<HTMLInputElement>("#entry-password");
  if (input) input.type = "password";
  const button = document.querySelector<HTMLButtonElement>("#password-reveal-button");
  if (button) {
    clearNode(button);
    button.append(icon("eye"));
    button.setAttribute("aria-label", "显示密码");
    button.setAttribute("aria-pressed", "false");
    button.title = "显示密码";
  }
  const hint = document.querySelector<HTMLElement>("#password-reveal-hint");
  if (hint) hint.textContent = "默认隐藏；显示后会自动重新遮罩。";
}

async function copySecret(secret: string, label = "密码"): Promise<void> {
  if (!secret) {
    showToast(`没有可复制的${label}。`, "warning");
    return;
  }
  const epoch = state.epoch;
  try {
    await invokeCommand<void>("copy_secret", { secret });
    if (epoch !== state.epoch || !state.status.unlocked) return;
    startClipboardTimer(state.settings.clipboardClearSeconds);
    showToast(`${label}已复制，将在 ${state.settings.clipboardClearSeconds} 秒后清除。`, "success");
  } catch {
    if (epoch !== state.epoch || !state.status.unlocked) return;
    showToast(`无法复制${label}到系统剪贴板。`, "error");
  }
}

function startClipboardTimer(seconds: number): void {
  stopClipboardTimer();
  const safeSeconds = [10, 20, 30, 60].includes(seconds) ? seconds : 20;
  clipboardDeadline = Date.now() + safeSeconds * 1000;
  clipboardTimeout = window.setTimeout(() => void clearClipboardNow(false), safeSeconds * 1000);
  clipboardTicker = window.setInterval(updateClipboardStatus, 1000);
  updateClipboardStatus();
}

function stopClipboardTimer(): void {
  if (clipboardTimeout) window.clearTimeout(clipboardTimeout);
  if (clipboardTicker) window.clearInterval(clipboardTicker);
  clipboardTimeout = null;
  clipboardTicker = null;
}

function updateClipboardStatus(): void {
  const element = document.querySelector<HTMLButtonElement>("#clipboard-status");
  if (!element) return;
  if (clipboardDeadline === 0) {
    element.hidden = true;
    return;
  }
  element.hidden = false;
  clearNode(element);
  element.append(icon("copy", 13));
  const seconds = Math.max(0, Math.ceil((clipboardDeadline - Date.now()) / 1000));
  element.append(document.createTextNode(`${seconds} 秒后清除 · 点击立即清除`));
}

async function clearClipboardNow(showFeedback: boolean): Promise<void> {
  const hadClipboard = clipboardDeadline !== 0;
  stopClipboardTimer();
  clipboardDeadline = 0;
  updateClipboardStatus();
  if (!hadClipboard) return;
  try {
    await invokeCommand<void>("clear_owned_clipboard");
    if (showFeedback) showToast("已清除本应用写入的剪贴板内容。", "success");
  } catch {
    if (showFeedback) showToast("无法确认剪贴板已清除。", "error");
  }
}

function openGenerator(source: "standalone" | "entry"): void {
  if (!state.status.unlocked || hasOpenModal() || blockEntryActionWhileMutating()) return;
  hideAllManagedSensitiveInputs();
  hidePassword();
  hideNotes();
  state.generatorOpen = true;
  state.generatorSource = source;
  state.generatorResult = null;
  state.generatorVisible = false;
  state.generatorApplying = false;
  state.generatorDraft = source === "entry" && state.draft
    ? {
        title: state.draft.title,
        username: state.draft.username,
        purpose: state.draft.purpose,
        url: state.draft.url,
        tags: [...state.draft.tags],
      }
    : emptyGeneratorDraft();
  renderGeneratorDialog();
  void requestGeneratedPassword();
}

function renderGeneratorDialog(): void {
  const region = document.querySelector<HTMLElement>("#modal-region");
  if (!region) return;
  if (hasOpenModal()) return;
  clearNode(region);
  if (!state.generatorOpen) return;
  if (!activateModal(() => closeGenerator(true))) {
    state.generatorOpen = false;
    return;
  }
  const overlay = makeElement("div", "modal-overlay generator-overlay");
  const dialog = makeElement("section", "generator-dialog");
  dialog.setAttribute("role", "dialog");
  dialog.setAttribute("aria-modal", "true");
  dialog.setAttribute("aria-labelledby", "generator-title");

  const header = makeElement("header", "dialog-header");
  const titleWrap = makeElement("div");
  titleWrap.append(makeElement("span", "eyebrow", "SECURE GENERATOR"));
  const title = makeElement("h1", "", state.generatorSource === "entry" ? "为当前条目生成密码" : "生成并保存密码");
  title.id = "generator-title";
  titleWrap.append(title, makeElement("p", "", "随机数由系统安全随机源在 Rust 核心中生成。"));
  const close = iconButton("关闭生成器", "x", () => closeGenerator());
  close.id = "generator-close";
  header.append(titleWrap, close);
  dialog.append(header);

  const body = makeElement("div", "generator-body");
  const preview = makeElement("section", "generator-preview");
  const previewHead = makeElement("div", "generator-preview-head");
  previewHead.append(makeElement("span", "", "生成结果"));
  const entropy = makeElement("span", "entropy-chip", "等待生成…");
  entropy.id = "generator-entropy";
  entropy.setAttribute("role", "status");
  entropy.setAttribute("aria-live", "polite");
  previewHead.append(entropy);
  const resultWrap = makeElement("div", "generated-secret");
  const result = makeElement("input", "generated-password") as HTMLInputElement;
  result.id = "generated-password";
  result.type = state.generatorVisible ? "text" : "password";
  result.readOnly = true;
  result.value = state.generatorResult?.password ?? "";
  result.setAttribute("aria-label", "生成的密码");
  const resultActions = makeElement("div", "generated-actions");
  const reveal = iconButton(state.generatorVisible ? "隐藏生成的密码" : "显示生成的密码", state.generatorVisible ? "eyeOff" : "eye", toggleGeneratorVisibility);
  reveal.id = "generator-reveal";
  reveal.setAttribute("aria-pressed", String(state.generatorVisible));
  const copy = iconButton("复制生成的密码", "copy", () => copySecret(state.generatorResult?.password ?? ""));
  copy.id = "generator-copy";
  resultActions.append(reveal, copy);
  resultWrap.append(result, resultActions);
  const strength = makeElement("div", "entropy-bar");
  strength.id = "generator-entropy-bar";
  strength.append(makeElement("span"));
  const privacy = makeElement("p", "generator-privacy");
  privacy.id = "generator-privacy";
  privacy.textContent = "生成结果不会被记录；只有点击保存后才会进入保险库。";
  preview.append(previewHead, resultWrap, strength, privacy);
  body.append(preview);

  const columns = makeElement("div", "generator-columns");
  const optionsCard = makeElement("section", "generator-section");
  optionsCard.append(makeElement("h2", "", "生成规则"));
  const lengthRow = makeElement("div", "length-setting");
  const lengthLabel = makeElement("label", "field-label", "密码长度");
  lengthLabel.htmlFor = "generator-length";
  const range = makeElement("input", "range") as HTMLInputElement;
  range.id = "generator-length";
  range.type = "range";
  range.min = "8";
  range.max = "128";
  range.value = String(state.generatorOptions.length);
  range.classList.add("generator-config-control");
  const number = makeElement("input", "input number-input") as HTMLInputElement;
  number.type = "number";
  number.min = "8";
  number.max = "128";
  number.value = String(state.generatorOptions.length);
  number.classList.add("generator-config-control");
  number.setAttribute("aria-label", "密码长度数值");
  const updateLength = (value: number) => {
    const normalized = Math.max(8, Math.min(128, Math.round(value || 8)));
    state.generatorOptions.length = normalized;
    range.value = String(normalized);
    number.value = String(normalized);
    scheduleGenerate();
  };
  range.addEventListener("input", () => updateLength(Number(range.value)));
  number.addEventListener("change", () => updateLength(Number(number.value)));
  lengthRow.append(lengthLabel, range, number);
  optionsCard.append(lengthRow);

  const optionGrid = makeElement("div", "option-grid");
  optionGrid.append(
    generatorToggle("gen-lowercase", "小写字母", "a–z", "lowercase"),
    generatorToggle("gen-uppercase", "大写字母", "A–Z", "uppercase"),
    generatorToggle("gen-digits", "数字", "0–9", "digits"),
    generatorToggle("gen-symbols", "符号", "! @ # …", "symbols"),
    generatorToggle("gen-ambiguous", "排除易混字符", "0 O 1 l I", "excludeAmbiguous"),
    generatorToggle("gen-require", "每类至少一个", "满足所选字符类型", "requireEach"),
  );
  optionsCard.append(optionGrid);
  const optionError = makeElement("p", "form-error");
  optionError.id = "generator-option-error";
  optionError.setAttribute("role", "alert");
  optionsCard.append(optionError);

  const metadataCard = makeElement("section", "generator-section");
  metadataCard.append(makeElement("h2", "", state.generatorSource === "entry" ? "一并更新条目信息" : "保存信息"));
  metadataCard.append(makeElement("p", "section-caption", state.generatorSource === "entry" ? "应用后会把这些字段同步回当前编辑器。" : "应用名称与用途会和密码一次性加密保存。"));
  const generatorTitle = createTextField("generator-app", "应用名称", state.generatorDraft.title, "例如 GitHub", true, 200);
  generatorTitle.input.classList.add("generator-config-control");
  bindGeneratorInput(generatorTitle.input, "title");
  const metaTwo = makeElement("div", "form-grid-two");
  const generatorUser = createTextField("generator-user", "用户名或邮箱", state.generatorDraft.username, "name@example.com", false, 500);
  generatorUser.input.classList.add("generator-config-control");
  bindGeneratorInput(generatorUser.input, "username");
  addSensitiveTextActions(generatorUser, "用户名");
  const generatorPurpose = createTextField("generator-purpose", "用途", state.generatorDraft.purpose, "例如：工作账号", false, 500);
  generatorPurpose.input.classList.add("generator-config-control");
  bindGeneratorInput(generatorPurpose.input, "purpose");
  addSensitiveTextActions(generatorPurpose, "用途");
  metaTwo.append(generatorUser.wrapper, generatorPurpose.wrapper);
  const generatorUrl = createTextField("generator-url", "网站或主机地址", state.generatorDraft.url, "例如 example.com、10.0.0.5:3389 或 3389", false, 2048);
  generatorUrl.input.classList.add("generator-config-control");
  generatorUrl.input.autocomplete = "off";
  generatorUrl.input.spellcheck = false;
  bindGeneratorInput(generatorUrl.input, "url");
  addSensitiveTextActions(generatorUrl, "地址");
  generatorUrl.wrapper.append(makeElement("p", "field-help", "支持网站、IP、主机名、端口或其他地址标记。"));
  const generatorTags = createTextField("generator-tags", "标签", state.generatorDraft.tags.join(", "), "工作, 管理员", false, 1400);
  generatorTags.input.classList.add("generator-config-control");
  generatorTags.input.addEventListener("input", () => {
    state.generatorDraft.tags = parseTags(generatorTags.input.value);
  });
  addSensitiveTextActions(generatorTags, "标签");
  metadataCard.append(generatorTitle.wrapper, metaTwo, generatorUrl.wrapper, generatorTags.wrapper);
  columns.append(optionsCard, metadataCard);
  body.append(columns);
  dialog.append(body);

  const footer = makeElement("footer", "dialog-footer generator-footer");
  const leftActions = makeElement("div", "dialog-footer-left");
  const regenerate = makeButton("重新生成", "button button-secondary", requestGeneratedPassword, "refresh");
  regenerate.id = "regenerate-button";
  const copyOnly = makeButton("仅复制，不保存", "button button-ghost", () => copySecret(state.generatorResult?.password ?? ""), "copy");
  copyOnly.id = "generator-copy-only";
  leftActions.append(regenerate, copyOnly);
  const primary = makeButton(
    state.generatorSource === "entry" ? "应用到当前条目" : "生成并保存",
    "button button-primary",
    () => applyGeneratedPassword(primary),
    state.generatorSource === "entry" ? "check" : "shield",
  );
  primary.id = "generator-primary";
  footer.append(leftActions, primary);
  dialog.append(footer);
  overlay.append(dialog);
  region.append(overlay);
  generatorFocusRelease = installDialogFocusTrap(dialog, () => closeGenerator());
  updateGeneratorOutput();
  window.setTimeout(() => generatorTitle.input.focus(), 0);
}

function generatorToggle(
  id: string,
  title: string,
  description: string,
  key: keyof Omit<GeneratorOptions, "length">,
): HTMLElement {
  const label = makeElement("label", "generator-option");
  label.htmlFor = id;
  const input = makeElement("input") as HTMLInputElement;
  input.id = id;
  input.type = "checkbox";
  input.checked = state.generatorOptions[key];
  input.classList.add("generator-config-control");
  const box = makeElement("span", "check-box");
  box.append(icon("check", 13));
  const copy = makeElement("span", "option-copy");
  copy.append(makeElement("strong", "", title), makeElement("span", "", description));
  label.append(input, box, copy);
  input.addEventListener("change", () => {
    state.generatorOptions[key] = input.checked;
    scheduleGenerate();
  });
  return label;
}

function bindGeneratorInput(input: HTMLInputElement, key: keyof Omit<GeneratorDraft, "tags">): void {
  input.addEventListener("input", () => {
    state.generatorDraft[key] = input.value;
    clearFieldError(input.id);
  });
}

function scheduleGenerate(): void {
  if (generatorDebounce) window.clearTimeout(generatorDebounce);
  generatorDebounce = window.setTimeout(() => void requestGeneratedPassword(), 140);
}

async function requestGeneratedPassword(): Promise<void> {
  if (!state.generatorOpen || !state.status.unlocked || state.generatorApplying) return;
  const requestId = ++generatorRequestId;
  const selectedClasses = [
    state.generatorOptions.lowercase,
    state.generatorOptions.uppercase,
    state.generatorOptions.digits,
    state.generatorOptions.symbols,
  ].filter(Boolean).length;
  const error = document.querySelector<HTMLElement>("#generator-option-error");
  if (!selectedClasses) {
    if (error) error.textContent = "至少选择一种字符类型。";
    state.generatorBusy = false;
    state.generatorResult = null;
    updateGeneratorOutput();
    return;
  }
  if (state.generatorOptions.requireEach && state.generatorOptions.length < selectedClasses) {
    if (error) error.textContent = "密码长度不能小于已选择的字符类型数量。";
    state.generatorBusy = false;
    state.generatorResult = null;
    updateGeneratorOutput();
    return;
  }
  if (error) error.textContent = "";
  const epoch = state.epoch;
  state.generatorBusy = true;
  updateGeneratorOutput();
  try {
    const result = await invokeCommand<GeneratedPassword>("generate_password", { options: { ...state.generatorOptions } });
    if (epoch !== state.epoch || requestId !== generatorRequestId || !state.generatorOpen || !state.status.unlocked) {
      result.password = "";
      return;
    }
    if (state.generatorResult) state.generatorResult.password = "";
    state.generatorResult = result;
    state.generatorBusy = false;
    hideGeneratorPassword();
    updateGeneratorOutput();
  } catch {
    if (epoch !== state.epoch || requestId !== generatorRequestId) return;
    state.generatorBusy = false;
    state.generatorResult = null;
    updateGeneratorOutput();
    if (error) error.textContent = "无法生成密码，请重试。";
  }
}

function updateGeneratorOutput(): void {
  const input = document.querySelector<HTMLInputElement>("#generated-password");
  const entropy = document.querySelector<HTMLElement>("#generator-entropy");
  const bar = document.querySelector<HTMLElement>("#generator-entropy-bar span");
  const regenerate = document.querySelector<HTMLButtonElement>("#regenerate-button");
  const reveal = document.querySelector<HTMLButtonElement>("#generator-reveal");
  const copy = document.querySelector<HTMLButtonElement>("#generator-copy");
  const copyOnly = document.querySelector<HTMLButtonElement>("#generator-copy-only");
  const primary = document.querySelector<HTMLButtonElement>("#generator-primary");
  const close = document.querySelector<HTMLButtonElement>("#generator-close");
  const interactionBusy = state.generatorBusy || state.generatorApplying;
  const resultReady = Boolean(state.generatorResult) && !interactionBusy;
  if (input) {
    input.value = state.generatorResult?.password ?? "";
    input.placeholder = state.generatorBusy ? "正在生成…" : "等待生成";
  }
  if (entropy) {
    entropy.textContent = state.generatorBusy
      ? "正在生成…"
      : state.generatorResult
        ? `${Math.round(state.generatorResult.entropyBits)} bits · 字符池 ${state.generatorResult.poolSize}`
        : "无法生成";
  }
  if (bar) {
    const bits = state.generatorResult?.entropyBits ?? 0;
    bar.dataset.level = String(bits >= 128 ? 5 : bits >= 96 ? 4 : bits >= 64 ? 3 : bits >= 40 ? 2 : bits > 0 ? 1 : 0);
  }
  if (regenerate) regenerate.disabled = interactionBusy;
  if (reveal) reveal.disabled = !resultReady;
  if (copy) copy.disabled = !resultReady;
  if (copyOnly) copyOnly.disabled = !resultReady;
  if (primary) primary.disabled = !resultReady;
  if (close) close.disabled = interactionBusy;
  const dialog = document.querySelector<HTMLElement>(".generator-dialog");
  dialog?.setAttribute("aria-busy", String(interactionBusy));
  dialog
    ?.querySelectorAll<HTMLInputElement | HTMLButtonElement>(".generator-config-control")
    .forEach((control) => {
      control.disabled = state.generatorApplying;
    });
}

function toggleGeneratorVisibility(): void {
  if (state.generatorVisible) {
    hideGeneratorPassword();
    return;
  }
  hideAllManagedSensitiveInputs();
  hidePassword();
  hideNotes();
  state.generatorVisible = true;
  const input = document.querySelector<HTMLInputElement>("#generated-password");
  if (input) input.type = "text";
  const button = document.querySelector<HTMLButtonElement>("#generator-reveal");
  if (button) {
    clearNode(button);
    button.append(icon("eyeOff"));
    button.setAttribute("aria-label", "隐藏生成的密码");
    button.setAttribute("aria-pressed", "true");
    button.title = "隐藏生成的密码";
  }
  if (generatorRevealTimeout) window.clearTimeout(generatorRevealTimeout);
  generatorRevealTimeout = window.setTimeout(hideGeneratorPassword, Math.max(1, state.settings.passwordRevealSeconds) * 1000);
}

function hideGeneratorPassword(): void {
  state.generatorVisible = false;
  if (generatorRevealTimeout) window.clearTimeout(generatorRevealTimeout);
  generatorRevealTimeout = null;
  const input = document.querySelector<HTMLInputElement>("#generated-password");
  if (input) input.type = "password";
  const button = document.querySelector<HTMLButtonElement>("#generator-reveal");
  if (button) {
    clearNode(button);
    button.append(icon("eye"));
    button.setAttribute("aria-label", "显示生成的密码");
    button.setAttribute("aria-pressed", "false");
    button.title = "显示生成的密码";
  }
}

async function applyGeneratedPassword(button: HTMLButtonElement): Promise<void> {
  const result = state.generatorResult;
  if (!result || state.generatorBusy || state.generatorApplying) return;
  if (!state.generatorDraft.title.trim()) {
    setFieldError("generator-app", "请输入应用名称。", true);
    return;
  }
  if (state.generatorDraft.tags.length > 20) {
    showToast("最多可保存 20 个标签。", "warning");
    return;
  }
  if (state.generatorSource === "entry" && state.draft) {
    state.draft.title = state.generatorDraft.title;
    state.draft.username = state.generatorDraft.username;
    state.draft.purpose = state.generatorDraft.purpose;
    state.draft.url = state.generatorDraft.url;
    state.draft.tags = [...state.generatorDraft.tags];
    state.draft.password = result.password;
    closeGenerator();
    renderMainShell();
    showToast("已应用新密码，保存条目后才会写入保险库。", "info");
    return;
  }

  const input: EntryInput = {
    title: state.generatorDraft.title,
    username: state.generatorDraft.username,
    password: result.password,
    url: state.generatorDraft.url,
    purpose: state.generatorDraft.purpose,
    notes: "",
    tags: [...state.generatorDraft.tags],
    favorite: false,
  };
  const epoch = state.epoch;
  const stayInSettings = state.view === "settings";
  let committed = false;
  state.generatorApplying = true;
  setBusy(button, true, "正在加密保存…");
  updateGeneratorOutput();
  try {
    const summary = await invokeCommand<EntrySummary>("save_entry", { input });
    committed = true;
    if (epoch !== state.epoch || !state.status.unlocked) return;
    recordLocalSyncMutation();
    closeGenerator(true);
    if (!stayInSettings) {
      state.view = "all";
      state.conflictsOnly = false;
    }
    state.status.itemCount += 1;
    await loadVaultOverview(epoch).catch(() => undefined);
    await refreshSyncStatusAfterMutation(epoch);
    if (stayInSettings) {
      renderMainShell();
      const backupNeedsAttention = currentAutoBackupNeedsAttention();
      showToast(
        backupNeedsAttention
          ? "密码和应用信息已保存，但无法确认当前版本的自动备份。请检查备份状态并手动导出。"
          : "密码和应用信息已保存。未提交的安全设置仍保留；可在全部条目中查看新条目。",
        backupNeedsAttention ? "warning" : "success",
      );
      return;
    }
    const listRefreshed = await loadEntries(true, epoch, false, false);
    const detailOpened = await selectEntry(summary.id);
    const backupNeedsAttention = currentAutoBackupNeedsAttention();
    showToast(
      !listRefreshed
        ? "密码和应用信息已保存，但列表刷新失败。请重试读取后核对条目。"
        : backupNeedsAttention
          ? "密码和应用信息已保存，但无法确认当前版本的自动备份。请在设置中检查备份状态并手动导出。"
        : detailOpened
          ? "密码和应用信息已一起加密保存。"
          : "密码和应用信息已保存；请从条目列表打开新条目核对。",
      listRefreshed && detailOpened && !backupNeedsAttention ? "success" : "warning",
    );
  } catch (error) {
    if (committed) {
      if (epoch !== state.epoch || !state.status.unlocked) return;
      if (state.generatorOpen) closeGenerator(true);
      if (!stayInSettings) {
        state.view = "all";
        state.conflictsOnly = false;
      }
      await loadVaultOverview(epoch).catch(() => undefined);
      await refreshSyncStatusAfterMutation(epoch);
      if (!stayInSettings) {
        state.entries = [];
        state.listLoading = false;
        state.listError = true;
      }
      renderMainShell();
      showToast(
        stayInSettings
          ? "密码和应用信息已保存，但界面刷新失败。请到全部条目核对，避免重复创建。"
          : "密码和应用信息已保存，但界面刷新失败。请点击“重试读取”后核对条目，避免重复创建。",
        "warning",
        7200,
      );
      return;
    }
    state.generatorApplying = false;
    setBusy(button, false);
    updateGeneratorOutput();
    presentEntrySaveFailure(error, "generator");
  }
}

function closeGenerator(force = false): void {
  if (!force && (state.generatorBusy || state.generatorApplying)) return;
  hideAllManagedSensitiveInputs();
  state.generatorOpen = false;
  state.generatorVisible = false;
  state.generatorBusy = false;
  state.generatorApplying = false;
  generatorRequestId += 1;
  if (generatorDebounce) window.clearTimeout(generatorDebounce);
  if (generatorRevealTimeout) window.clearTimeout(generatorRevealTimeout);
  generatorDebounce = null;
  generatorRevealTimeout = null;
  if (state.generatorResult) state.generatorResult.password = "";
  state.generatorResult = null;
  state.generatorDraft.title = "";
  state.generatorDraft.username = "";
  state.generatorDraft.purpose = "";
  state.generatorDraft.url = "";
  state.generatorDraft.tags.length = 0;
  state.generatorDraft = emptyGeneratorDraft();
  const region = document.querySelector<HTMLElement>("#modal-region");
  region?.querySelector(".generator-overlay")?.remove();
  deactivateModal();
  const release = generatorFocusRelease;
  generatorFocusRelease = null;
  release?.();
}

function describeWebDavBackupFailure(error: unknown, phase: "test" | "save" | "upload" | "list" | "download" | "disable"): string {
  const message = typeof error === "string" ? error : error instanceof Error ? error.message : "";
  if (message.startsWith("WebDAV 备份：") && message.length <= 240) return message;
  if (message === "尚未在此设备配置 WebDAV 备份。") return message;
  const fallback: Record<typeof phase, string> = {
    test: "无法验证 WebDAV 目录。请检查 HTTPS 地址、证书、账号及目录读写权限后重试。",
    save: "无法保存 WebDAV 备份设置。原有配置未被替换，请检查连接后重试。",
    upload: "远端上传未能确认。请保留本机备份，检查网络和服务器后重试；远端可能已经收到这份快照。",
    list: "无法读取远端备份列表。请检查连接及目录读取权限后重试。",
    download: "无法下载所选远端备份。本机保险库未被替换，请重试或选择其他备份。",
    disable: "无法停用本机 WebDAV 备份配置，请重试。",
  };
  return describeWebDavNetworkFailure(error, fallback[phase]);
}

async function configureWebDavBackup(): Promise<void> {
  if (!state.status.unlocked) return;
  if (state.securityOperation !== null || state.syncOperation !== null) return;
  const operationEpoch = state.epoch;
  state.securityOperation = "backup";
  setSecurityMutationControlsDisabled(true);
  try {
    const current = state.webdavBackupStatusError
      ? { ...state.webdavBackupStatus, configured: false }
      : state.webdavBackupStatus;
    const saved = await showWebDavBackupConfig(current, operationEpoch);
    if (!saved || operationEpoch !== state.epoch || !state.status.unlocked) return;
    backupStatusRequestId += 1;
    state.webdavBackupStatus = saved;
    state.webdavBackupStatusError = false;
    state.backupOperationError = null;
    renderMainShell();
    showToast(saved.automatic
      ? "WebDAV 备份设置已保存。后台将检查首次上传，请核对“最近上传”状态。"
      : "WebDAV 备份设置已保存。点击“立即上传加密备份”可创建首份远端副本。", "success", 6500);
  } finally {
    if (operationEpoch === state.epoch && state.securityOperation === "backup") {
      state.securityOperation = null;
      setSecurityMutationControlsDisabled(false);
    }
  }
}

function showWebDavBackupConfig(current: WebDavBackupStatus, operationEpoch: number): Promise<WebDavBackupStatus | null> {
  return new Promise((resolve) => {
    const region = document.querySelector<HTMLElement>("#modal-region");
    if (!region || hasOpenModal()) { resolve(null); return; }
    const ids = nextModalIds("webdav-backup-config");
    const overlay = makeElement("div", "modal-overlay confirm-overlay");
    const dialog = makeElement("form", "confirm-dialog confirm-dialog-wide webdav-dialog") as HTMLFormElement;
    dialog.noValidate = true;
    dialog.setAttribute("role", "dialog");
    dialog.setAttribute("aria-modal", "true");
    dialog.setAttribute("aria-labelledby", ids.title);
    dialog.setAttribute("aria-describedby", ids.description);
    const badge = makeElement("div", "status-icon");
    badge.append(icon("archive", 23));
    const heading = makeElement("h2", "", current.configured ? "修改 WebDAV 备份设置" : "配置 WebDAV 备份");
    heading.id = ids.title;
    const body = makeElement("p", "", "填写已存在的 HTTPS 目录。连接验证会测试读取、写入与清理权限；保存后，应用专用密码会加密保存在本机。");
    body.id = ids.description;
    const endpoint = createTextField("backup-webdav-endpoint", "WebDAV 目录地址", "", "https://cloud.example.com/backups/", true, 2048);
    endpoint.input.value = current.endpoint ?? "";
    addSensitiveTextActions(endpoint, "WebDAV 地址");
    endpoint.wrapper.append(makeElement("p", "field-help", "必须是已存在的 HTTPS 目录，以 / 结尾；请勿将账号或密码写入地址。"));
    const username = createTextField("backup-webdav-username", "用户名", "", "WebDAV 用户名", true, 500);
    username.input.value = current.username ?? "";
    addSensitiveTextActions(username, "WebDAV 用户名");
    const password = createPasswordField("backup-webdav-password", "应用专用密码", current.configured ? "留空则沿用已保存密码" : "输入 WebDAV 应用专用密码", "off");
    password.input.maxLength = 4096;
    password.wrapper.append(makeElement("p", "field-help", current.configured
      ? "地址和用户名不变时，可沿用已加密保存的密码；更换账号时需重新输入。"
      : "建议使用服务端可单独撤销的应用专用密码。"));
    const fields = makeElement("div", "webdav-fields");
    fields.append(endpoint.wrapper, username.wrapper, password.wrapper);
    const automaticLabel = makeElement("label", "webdav-backup-automatic");
    const automatic = makeElement("input") as HTMLInputElement;
    automatic.type = "checkbox";
    automatic.checked = current.configured ? Boolean(current.automatic) : true;
    automaticLabel.append(automatic, makeElement("span", "", "保存后自动上传最新加密备份"));
    const automaticHelp = makeElement("p", "field-help webdav-backup-automatic-help", "短时间连续保存会合并为一次上传，每次上传新增历史文件。未完成的上传会在下次解锁时重试；不会自动下载或合并其他设备的修改。");
    const error = makeElement("p", "form-error webdav-form-error");
    error.setAttribute("role", "alert");
    const feedback = makeElement("p", "field-help webdav-backup-feedback");
    feedback.setAttribute("role", "status");
    for (const input of [endpoint.input, username.input, password.input, automatic]) {
      input.addEventListener("input", () => { error.textContent = ""; feedback.textContent = ""; });
    }
    const actions = makeElement("div", "confirm-actions webdav-backup-dialog-actions");
    let settled = false;
    let busy = false;
    let release: () => void = () => undefined;
    const clearInputs = () => {
      endpoint.input.value = "";
      username.input.value = "";
      password.input.value = "";
      hideAllManagedSensitiveInputs();
    };
    const finish = (value: WebDavBackupStatus | null) => {
      if (settled) return;
      settled = true;
      clearInputs();
      overlay.remove();
      deactivateModal();
      release();
      resolve(value);
    };
    if (!activateModal(() => finish(null))) { clearInputs(); resolve(null); return; }
    const cancel = makeButton("取消", "button button-ghost", () => { if (!busy) finish(null); });
    const test = makeButton("测试连接", "button button-secondary", () => void submit("test"), "refresh");
    const save = makeButton("验证并保存", "button button-primary", () => undefined, "check");
    save.type = "submit";
    const setFormBusy = (value: boolean, label: string) => {
      busy = value;
      dialog.setAttribute("aria-busy", value ? "true" : "false");
      for (const control of [endpoint.input, username.input, password.input, automatic, cancel, test]) control.disabled = value;
      setBusy(save, value, label);
    };
    const submit = async (kind: "test" | "save") => {
      if (settled || busy || operationEpoch !== state.epoch || !state.status.unlocked) return;
      error.textContent = "";
      feedback.textContent = "";
      const address = endpoint.input.value.trim();
      const endpointError = validateWebDavEndpointInput(address);
      if (endpointError) { error.textContent = endpointError; endpoint.input.focus(); return; }
      if (!username.input.value.trim()) { error.textContent = "请输入用户名。"; username.input.focus(); return; }
      const reuseSavedPassword = current.configured
        && address === current.endpoint
        && username.input.value.trim() === current.username;
      if (!password.input.value && !reuseSavedPassword) {
        error.textContent = "地址或用户名已更改，请输入应用专用密码。";
        password.input.focus();
        return;
      }
      const credentials: WebDavCredentials = {
        endpoint: address,
        username: username.input.value.trim(),
        appPassword: password.input.value,
      };
      setFormBusy(true, kind === "test" ? "正在测试…" : "正在验证并保存…");
      try {
        if (kind === "test") {
          await invokeCommand<void>("webdav_backup_test_config", { credentials });
          if (!settled && operationEpoch === state.epoch) feedback.textContent = "连接验证通过。";
        } else {
          const result = await invokeCommand<WebDavBackupStatus>("webdav_backup_save_config", {
            credentials, automatic: automatic.checked,
          });
          if (!settled && operationEpoch === state.epoch) finish(result);
        }
      } catch (caught) {
        if (!settled && operationEpoch === state.epoch) error.textContent = describeWebDavBackupFailure(caught, kind);
      } finally {
        credentials.appPassword = "";
        if (!settled && operationEpoch === state.epoch) setFormBusy(false, "验证并保存");
      }
    };
    dialog.addEventListener("submit", (event) => { event.preventDefault(); void submit("save"); });
    actions.append(cancel, test, save);
    dialog.append(badge, heading, body, fields, automaticLabel, automaticHelp, error, feedback, actions);
    overlay.append(dialog);
    region.append(overlay);
    release = installDialogFocusTrap(dialog, () => { if (!busy) finish(null); });
    window.setTimeout(() => { if (dialog.isConnected) (current.endpoint ? password.input : endpoint.input).focus(); }, 0);
  });
}

async function uploadWebDavBackup(): Promise<void> {
  if (!state.status.unlocked || !state.webdavBackupStatus.configured) return;
  if (state.securityOperation !== null || state.syncOperation !== null) return;
  const operationEpoch = state.epoch;
  state.securityOperation = "backup";
  setSecurityMutationControlsDisabled(true);
  const closeProgress = showRestoreProgress("正在上传加密备份…", "本机保险库不会被修改。上传完成后请核对远端备份状态。");
  try {
    await invokeCommand<WebDavBackupItem>("webdav_backup_upload");
    if (operationEpoch !== state.epoch || !state.status.unlocked) return;
    state.backupOperationError = null;
    await refreshWebDavBackupStatus(operationEpoch);
    if (operationEpoch === state.epoch) showToast("加密备份已上传至 WebDAV。", "success");
  } catch (caught) {
    if (operationEpoch !== state.epoch) return;
    state.backupOperationError = describeWebDavBackupFailure(caught, "upload");
    showToast(state.backupOperationError, "error", 8000);
  } finally {
    closeProgress();
    if (operationEpoch === state.epoch && state.securityOperation === "backup") {
      state.securityOperation = null;
      setSecurityMutationControlsDisabled(false);
      if (state.view === "settings") renderMainShell();
    }
  }
}

async function disableWebDavBackup(): Promise<void> {
  if (!state.status.unlocked || (!state.webdavBackupStatus.configured && !state.webdavBackupStatusError)) return;
  if (state.securityOperation !== null || state.syncOperation !== null) return;
  const confirmed = await showConfirm(
    "停用本机 WebDAV 备份？",
    "本机保存的连接配置将被删除，自动上传会停止。远端已有的加密备份不会删除。",
    "停用本机备份",
    true,
  );
  if (!confirmed || state.securityOperation !== null || state.syncOperation !== null) return;
  const operationEpoch = state.epoch;
  state.securityOperation = "backup";
  setSecurityMutationControlsDisabled(true);
  const closeProgress = showRestoreProgress(
    "正在停用 WebDAV 备份…",
    "正在等待已经开始的上传结束；远端已有的备份文件不会删除。",
  );
  try {
    await invokeCommand<void>("webdav_backup_disable");
    if (operationEpoch !== state.epoch || !state.status.unlocked) return;
    backupStatusRequestId += 1;
    state.webdavBackupStatus = { configured: false };
    state.webdavBackupStatusError = false;
    state.backupOperationError = null;
    renderMainShell();
    showToast("本机 WebDAV 备份已停用；远端文件仍保留。", "success");
  } catch (caught) {
    if (operationEpoch !== state.epoch) return;
    state.backupOperationError = describeWebDavBackupFailure(caught, "disable");
    renderMainShell();
    showToast(state.backupOperationError, "error", 7200);
  } finally {
    closeProgress();
    if (operationEpoch === state.epoch && state.securityOperation === "backup") {
      state.securityOperation = null;
      setSecurityMutationControlsDisabled(false);
    }
  }
}

async function exportBackup(button: HTMLButtonElement): Promise<void> {
  if (state.syncOperation !== null || state.securityOperation !== null) return;
  setBusy(button, true, "正在导出…");
  try {
    const result = await withTrustedSystemInteraction(
      () => invokeCommand<string | null>("export_backup"),
    );
    if (typeof result === "string" && result.length > 0) {
      state.backupOperationError = null;
      if (state.status.unlocked) {
        await loadVaultOverview().catch(() => undefined);
        if (state.status.unlocked) renderMainShell();
      }
      showToast("加密备份已导出。", "success");
    }
  } catch (error) {
    const failure = describeBackupFailure("export", error);
    state.backupOperationError = failure.message;
    if (state.status.unlocked && state.view === "settings") renderMainShell();
    showToast(failure.message, failure.tone, 7200);
  } finally {
    setBusy(button, false);
  }
}

function showWebDavBackupPicker(operationEpoch: number): Promise<RestoreSelection | null> {
  return new Promise((resolve) => {
    const region = document.querySelector<HTMLElement>("#modal-region");
    if (!region || hasOpenModal()) { resolve(null); return; }
    const needsCredentials = !state.status.unlocked || !state.webdavBackupStatus.configured || state.webdavBackupStatusError;
    const ids = nextModalIds("webdav-backup-picker");
    const overlay = makeElement("div", "modal-overlay confirm-overlay");
    const dialog = makeElement("section", "confirm-dialog confirm-dialog-wide webdav-backup-picker");
    dialog.setAttribute("role", "dialog");
    dialog.setAttribute("aria-modal", "true");
    dialog.setAttribute("aria-labelledby", ids.title);
    dialog.setAttribute("aria-describedby", ids.description);
    const badge = makeElement("div", "status-icon");
    badge.append(icon("download", 23));
    const heading = makeElement("h2", "", "选择 WebDAV 加密备份");
    heading.id = ids.title;
    const body = makeElement("p", "", needsCredentials
      ? "输入备份目录凭据，选择要下载的备份。恢复后可将这组凭据加密保存在本机，用于继续自动备份。"
      : "先下载所选备份，再使用创建备份时的主密码验证内容；确认前不会替换当前保险库。");
    body.id = ids.description;
    dialog.append(badge, heading, body);

    const endpoint = needsCredentials
      ? createTextField("restore-webdav-endpoint", "WebDAV 目录地址", "", "https://cloud.example.com/backups/", true, 2048)
      : null;
    const username = needsCredentials
      ? createTextField("restore-webdav-username", "用户名", "", "WebDAV 用户名", true, 500)
      : null;
    const password = needsCredentials
      ? createPasswordField("restore-webdav-password", "应用专用密码", "输入 WebDAV 应用专用密码", "off")
      : null;
    if (endpoint && username && password) {
      addSensitiveTextActions(endpoint, "WebDAV 地址");
      addSensitiveTextActions(username, "WebDAV 用户名");
      password.input.maxLength = 4096;
      endpoint.wrapper.append(makeElement("p", "field-help", "请输入已存在的 HTTPS 目录，以 / 结尾。"));
      const fields = makeElement("div", "webdav-fields");
      fields.append(endpoint.wrapper, username.wrapper, password.wrapper);
      dialog.append(fields);
    }
    const saveConnectionLabel = needsCredentials ? makeElement("label", "webdav-backup-automatic") : null;
    const saveConnection = needsCredentials ? makeElement("input") as HTMLInputElement : null;
    if (saveConnectionLabel && saveConnection) {
      saveConnection.type = "checkbox";
      saveConnection.checked = true;
      saveConnectionLabel.append(saveConnection, makeElement("span", "", "恢复成功后保存此备份连接，并启用自动备份"));
      dialog.append(saveConnectionLabel, makeElement("p", "field-help webdav-backup-automatic-help", "凭据只会在确认恢复后加密保存到此设备。取消恢复或验证失败时不会保存；双向同步仍需单独配置。"));
    }

    const error = makeElement("p", "form-error webdav-form-error");
    error.setAttribute("role", "alert");
    const progress = makeElement("p", "field-help webdav-backup-feedback");
    progress.setAttribute("role", "status");
    const list = makeElement("div", "webdav-backup-list");
    const actions = makeElement("div", "confirm-actions webdav-backup-dialog-actions");
    let release: () => void = () => undefined;
    let settled = false;
    let busy = false;
    let listed: WebDavBackupItem[] = [];
    let visibleCount = 100;
    const clearInputs = () => {
      if (endpoint) endpoint.input.value = "";
      if (username) username.input.value = "";
      if (password) password.input.value = "";
      hideAllManagedSensitiveInputs();
      listed = [];
    };
    const finish = (selection: RestoreSelection | null) => {
      if (settled) return;
      settled = true;
      clearInputs();
      overlay.remove();
      deactivateModal();
      release();
      resolve(selection);
    };
    if (!activateModal(() => finish(null))) { clearInputs(); resolve(null); return; }
    const cancel = makeButton("取消", "button button-ghost", () => { if (!busy) finish(null); });
    const refresh = makeButton("读取备份列表", "button button-secondary", () => void loadList(), "refresh");
    const setFormBusy = (value: boolean, label: string) => {
      busy = value;
      dialog.setAttribute("aria-busy", value ? "true" : "false");
      for (const control of dialog.querySelectorAll<HTMLInputElement | HTMLButtonElement>("input, button")) {
        control.disabled = value;
      }
      setBusy(refresh, value, label);
    };
    const readCredentials = (): WebDavCredentials | null => {
      if (!endpoint || !username || !password) return null;
      const address = endpoint.input.value.trim();
      const endpointError = validateWebDavEndpointInput(address);
      if (endpointError) { error.textContent = endpointError; endpoint.input.focus(); return null; }
      if (!username.input.value.trim()) { error.textContent = "请输入用户名。"; username.input.focus(); return null; }
      if (!password.input.value) { error.textContent = "请输入应用专用密码。"; password.input.focus(); return null; }
      return { endpoint: address, username: username.input.value.trim(), appPassword: password.input.value };
    };
    const renderList = () => {
      clearNode(list);
      if (!listed.length) {
        list.append(makeElement("p", "webdav-backup-empty", "目录中没有可列出的 CipherNest 加密备份。"));
        return;
      }
      const shown = listed.slice(0, visibleCount);
      for (const item of shown) {
        const row = makeElement("div", "webdav-backup-item");
        const copy = makeElement("div", "webdav-backup-item-copy");
        copy.append(
          makeElement("strong", "", formatFullDate(item.updatedAt)),
          makeElement("span", "", `第 ${item.generation.toLocaleString("zh-CN")} 代 · ${formatFileSize(item.fileSize)} · 保险库 ${item.vaultIdShort}`),
          makeElement("small", "", item.fileName),
        );
        row.append(copy, makeButton("下载并验证", "button button-ghost", () => void prepare(item), "download"));
        list.append(row);
      }
      if (listed.length > shown.length) {
        list.append(makeButton(`显示更多（剩余 ${listed.length - shown.length} 份）`, "button button-ghost", () => {
          visibleCount += 100;
          renderList();
        }, "chevron"));
      }
    };
    const loadList = async () => {
      if (settled || busy || operationEpoch !== state.epoch) return;
      error.textContent = "";
      progress.textContent = "";
      const credentials = needsCredentials ? readCredentials() : null;
      if (needsCredentials && !credentials) return;
      setFormBusy(true, "正在读取…");
      progress.textContent = "正在读取远端备份列表…";
      try {
        const result = needsCredentials
          ? await invokeCommand<WebDavBackupItem[]>("webdav_backup_list_with_credentials", { credentials })
          : await invokeCommand<WebDavBackupItem[]>("webdav_backup_list");
        if (settled || operationEpoch !== state.epoch) return;
        listed = result;
        visibleCount = 100;
        progress.textContent = `找到 ${result.length.toLocaleString("zh-CN")} 份加密备份。`;
        renderList();
      } catch (caught) {
        if (!settled && operationEpoch === state.epoch) {
          listed = [];
          clearNode(list);
          progress.textContent = "";
          error.textContent = describeWebDavBackupFailure(caught, "list");
        }
      } finally {
        if (credentials) credentials.appPassword = "";
        if (!settled && operationEpoch === state.epoch) setFormBusy(false, "读取备份列表");
      }
    };
    const prepare = async (item: WebDavBackupItem) => {
      if (settled || busy || operationEpoch !== state.epoch || !listed.includes(item)) return;
      error.textContent = "";
      const credentials = needsCredentials ? readCredentials() : null;
      if (needsCredentials && !credentials) return;
      setFormBusy(true, "正在下载…");
      progress.textContent = "正在下载所选加密备份…";
      try {
        const selection = needsCredentials
          ? await invokeCommand<RestoreSelection>("webdav_backup_prepare_restore_with_credentials", {
            credentials, fileName: item.fileName,
            saveConnectionAfterRestore: Boolean(saveConnection?.checked),
          })
          : await invokeCommand<RestoreSelection>("webdav_backup_prepare_restore", { fileName: item.fileName });
        if (!settled && operationEpoch === state.epoch) finish(selection);
      } catch (caught) {
        if (!settled && operationEpoch === state.epoch) {
          error.textContent = describeWebDavBackupFailure(caught, "download");
          progress.textContent = "";
        }
      } finally {
        if (credentials) credentials.appPassword = "";
        if (!settled && operationEpoch === state.epoch) setFormBusy(false, "读取备份列表");
      }
    };
    const invalidateList = () => {
      listed = [];
      clearNode(list);
      error.textContent = "";
      progress.textContent = "凭据已修改，请重新读取备份列表。";
    };
    if (endpoint && username && password) {
      for (const input of [endpoint.input, username.input, password.input]) input.addEventListener("input", invalidateList);
    }
    actions.append(cancel, refresh);
    dialog.append(error, progress, list, actions);
    overlay.append(dialog);
    region.append(overlay);
    release = installDialogFocusTrap(dialog, () => { if (!busy) finish(null); });
    window.setTimeout(() => {
      if (!dialog.isConnected) return;
      if (endpoint) endpoint.input.focus();
      else { refresh.focus(); void loadList(); }
    }, 0);
  });
}

async function restoreBackup(source: "local" | "webdav" = "local"): Promise<void> {
  if (state.securityOperation !== null || state.syncOperation !== null) return;
  if (blockEntryActionWhileMutating()) return;
  if (state.status.unlocked && hasUnsavedDraft()) {
    const continueRestore = await showConfirm(
      "当前条目有未保存修改",
      "恢复会完整替换当前保险库，这些未保存内容不会包含在恢复后的数据中。是否继续选择备份？",
      "继续选择备份",
      true,
    );
    if (!continueRestore || state.securityOperation !== null) return;
  }

  const operationEpoch = state.epoch;
  state.securityOperation = "restore";
  setSecurityMutationControlsDisabled(true);
  let masterPassword: string | null = null;
  let restoreApplied = false;
  let restorePhase: BackupPhase = "select";
  const wasUnlocked = state.status.unlocked;
  try {
    const selection = source === "webdav"
      ? await showWebDavBackupPicker(operationEpoch)
      : await withTrustedSystemInteraction(
        () => invokeCommand<RestoreSelection | null>("select_backup_for_restore"),
      );
    if (operationEpoch !== state.epoch || !selection) return;

    masterPassword = await askMasterPassword(
      "验证加密备份",
      `已选择“${selection.fileName}”（${formatFileSize(selection.fileSize)}）。请输入创建这份备份时使用的主密码；验证不会修改当前保险库。`,
      "验证并查看内容概览",
    );
    if (masterPassword === null || operationEpoch !== state.epoch) return;

    restorePhase = "inspect";
    const closeInspectionProgress = showRestoreProgress("正在验证并解密备份…");
    let preview: RestorePreview;
    try {
      const inspectRequest = invokeCommand<RestorePreview>("inspect_selected_backup", {
        token: selection.token,
        masterPassword,
      });
      masterPassword = "";
      preview = await inspectRequest;
    } finally {
      closeInspectionProgress();
    }
    if (operationEpoch !== state.epoch) return;

    const confirmed = await showRestorePreview(selection, preview);
    if (!confirmed || operationEpoch !== state.epoch) return;

    restorePhase = "apply";
    const closeApplyProgress = showRestoreProgress(
      "正在安全替换保险库…",
      "已确认的备份正在提交。此阶段不能保证取消；完成后请核对保险库内容。",
      wasUnlocked,
    );
    try {
      await invokeCommand<VaultStatus>("apply_selected_backup", { token: selection.token });
    } finally {
      closeApplyProgress();
    }
    restoreApplied = true;
    if (operationEpoch !== state.epoch) return;
    state.epoch += 1;
    const refreshed = await bootstrap();
    if (refreshed && !state.listError) {
      state.backupOperationError = null;
      showToast(
        state.webdavBackupStatusError
          ? "加密备份已恢复；备份连接状态未能读取，请在设置中检查。双向同步需单独配置。"
          : state.webdavBackupStatus.configured
            ? "加密备份已恢复；本机 WebDAV 备份连接已保留。双向同步需单独配置。"
            : "加密备份已恢复；此设备尚未保存 WebDAV 备份连接。双向同步需单独配置。",
        "success",
        7200,
      );
    } else if (refreshed) {
      showToast("备份已提交，但条目列表未能读取。请点击“重试读取”，核对恢复后的内容。", "warning", 9000);
    } else {
      showToast("恢复提交已返回，但无法确认重新读取的结果。请保留原备份，重试读取并核对条目。", "warning", 9000);
    }
  } catch (error) {
    if (operationEpoch !== state.epoch) return;
    const failure = describeBackupFailure(restorePhase, error);
    const message = typeof error === "string" ? error : error instanceof Error ? error.message : "";
    if (restorePhase === "apply" && message !== RESTORE_TARGET_CHANGED) {
      state.epoch += 1;
      state.status.unlocked = false;
      clearSensitiveState(true);
      renderLoading();
      await Promise.allSettled([
        invokeCommand<void>("clear_owned_clipboard"),
        invokeCommand<void>("lock_vault"),
      ]);
      const lockedStatus = await invokeCommand<VaultStatus>("vault_status").catch(() => null);
      if (!lockedStatus || lockedStatus.unlocked) {
        renderFatal();
        showToast("恢复结果无法确认，且无法确认保险库已锁定。请关闭应用，保留备份并检查数据目录。", "error", 9000);
        return;
      }
      await bootstrap();
      showToast(`${failure.message} 已结束当前编辑会话，请重新解锁并核对保险库。`, "warning", 9000);
      return;
    }
    state.backupOperationError = failure.message;
    if (wasUnlocked && state.view === "settings") renderMainShell();
    showToast(failure.message, failure.tone, 7200);
    if (!wasUnlocked) renderGate();
  } finally {
    masterPassword = "";
    hideAllManagedSensitiveInputs();
    if (!restoreApplied) {
      try {
        await invokeCommand<void>("cancel_pending_restore");
      } catch {
        // Pending restore data also expires in Rust; cancellation is best-effort here.
      }
    }
    if (operationEpoch === state.epoch && state.securityOperation === "restore") {
      state.securityOperation = null;
      setSecurityMutationControlsDisabled(false);
    }
  }
}

async function manualLock(): Promise<void> {
  if (!state.status.unlocked) return;
  if (
    state.syncOperation !== null
    || state.securityOperation !== null
    || state.entryMutation !== null
  ) {
    await performLock("保险库界面已锁定。请重新解锁后核对进行中操作的结果。", true);
    return;
  }
  if (hasUnsavedDraft()) {
    const choice = await showUnsavedLockDialog();
    if (choice === "cancel") return;
    if (choice === "save") {
      const saved = await saveCurrentEntry();
      if (!saved) return;
    }
  }
  await performLock("保险库已锁定。", true);
}

async function performLock(message: string, notify: boolean): Promise<void> {
  if (!state.status.unlocked) return;
  const automaticBackupEnabled = state.webdavBackupStatus.configured && state.webdavBackupStatus.automatic;
  state.epoch += 1;
  state.status.unlocked = false;
  clearSensitiveState(true);
  renderGate();
  try {
    await invokeCommand<void>("clear_owned_clipboard");
  } catch {
    // Locking must continue even when clipboard ownership cannot be confirmed.
  }
  try {
    await invokeCommand<void>("lock_vault");
  } catch {
    // The backend may have locked before a later cleanup step returned an error.
  }
  const lockedStatus = await invokeCommand<VaultStatus>("vault_status").catch(() => null);
  if (!lockedStatus || lockedStatus.unlocked) {
    renderFatal();
    showToast("无法确认保险库已锁定。请关闭应用，保留备份并检查数据目录。", "error", 9000);
    return;
  }
  if (notify) showToast(
    automaticBackupEnabled ? `${message} 如有待上传的远端备份，下次解锁后会继续尝试。` : message,
    "info",
  );
}

function clearSensitiveState(clearMetadata: boolean): void {
  backupStatusRequestId += 1;
  syncStatusRequestId += 1;
  remoteContentRefreshQueued = false;
  state.securityOperation = null;
  state.syncOperation = null;
  state.backupOperationError = null;
  state.syncStatusUncertain = false;
  state.webdavRetry = null;
  hideAllManagedSensitiveInputs();
  hidePassword();
  hideGeneratorPassword();
  hideNotes();
  dismissActiveModal();
  closeGenerator(true);
  stopClipboardTimer();
  clipboardDeadline = 0;
  if (autoLockTimeout) window.clearTimeout(autoLockTimeout);
  autoLockTimeout = null;
  clearEntryDraft();
  state.query = "";
  state.conflictsOnly = false;
  state.visibleEntryCount = ENTRY_PAGE_SIZE;
  state.entryListKey = "";
  state.report = null;
  state.visibleIssueCount = ENTRY_PAGE_SIZE;
  state.reportLoading = false;
  state.reportError = false;
  state.listLoading = false;
  state.listError = false;
  if (clearMetadata) {
    state.entries = [];
    state.status.itemCount = 0;
    state.overview = { ...EMPTY_OVERVIEW };
    state.webdavBackupStatus = { configured: false };
    state.webdavBackupStatusError = false;
    state.syncStatus = {
      configured: state.syncStatus.configured,
      pendingLocalChanges: false,
    };
  }
}

async function handleLifecycleLock(): Promise<void> {
  if (!state.status.unlocked) return;
  state.epoch += 1;
  state.status.unlocked = false;
  clearSensitiveState(true);
  renderGate();
  showToast("系统已恢复运行，保险库已自动锁定。", "info", 4200);
}

function scheduleAutoLock(): void {
  if (autoLockTimeout) window.clearTimeout(autoLockTimeout);
  if (!state.status.unlocked || state.settings.autoLockMinutes <= 0) return;
  autoLockTimeout = window.setTimeout(() => {
    void performLock(`保险库已因 ${state.settings.autoLockMinutes} 分钟无操作而锁定。`, true);
  }, state.settings.autoLockMinutes * 60_000);
}

function recordActivity(): void {
  if (!state.status.unlocked) return;
  scheduleAutoLock();
  const now = Date.now();
  if (now - lastActivitySent < 10_000) return;
  lastActivitySent = now;
  void invokeCommand<void>("touch_activity").catch(() => undefined);
}

async function handleFocusChange(focused: boolean): Promise<void> {
  hideAllManagedSensitiveInputs();
  hidePassword();
  hideGeneratorPassword();
  hideNotes();
  if (!state.status.unlocked) return;
  if (trustedSystemInteractionDepth > 0) return;
  try {
    const locked = await invokeCommand<boolean>("handle_focus_change", { focused });
    if (locked) {
      await performLock("保险库已因窗口失焦或会话超时而锁定。", false);
      return;
    }
    if (!focused || trustedSystemInteractionDepth > 0) return;
    const status = await invokeCommand<VaultStatus>("vault_status");
    if (!status.unlocked) {
      await performLock("保险库会话已超时。", false);
    } else {
      state.status = status;
      recordActivity();
    }
  } catch {
    if (state.status.unlocked) {
      await performLock("无法确认保险库会话状态，已安全锁定。", true);
    }
  }
}

function focusSearchAtEnd(): void {
  window.setTimeout(() => {
    const search = document.querySelector<HTMLInputElement>("#vault-search");
    if (!search) return;
    search.focus();
    search.setSelectionRange(search.value.length, search.value.length);
  }, 0);
}

function parseTags(value: string): string[] {
  const seen = new Set<string>();
  const tags: string[] = [];
  for (const raw of value.split(/[，,]/)) {
    const tag = raw.trim().slice(0, 50);
    const key = tag.toLocaleLowerCase("zh-CN");
    if (!tag || seen.has(key)) continue;
    seen.add(key);
    tags.push(tag);
  }
  return tags.slice(0, 21);
}

function firstCharacter(value: string): string {
  return Array.from(value.trim())[0]?.toLocaleUpperCase("zh-CN") ?? "?";
}

function titleHueClass(value: string): string {
  let hash = 0;
  for (const character of value) hash = (hash * 31 + character.codePointAt(0)!) % 8;
  return `avatar-hue-${hash}`;
}

function securityFlagSummary(flags: string[]): string {
  const labels: Record<string, string> = { weak: "弱密码", reused: "重复使用", stale: "长期未更换" };
  return flags.map((flag) => labels[flag] ?? "需要检查").join("、");
}

function formatCompactDate(value: number): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  const now = new Date();
  if (date.toDateString() === now.toDateString()) return date.toLocaleTimeString("zh-CN", { hour: "2-digit", minute: "2-digit" });
  return date.toLocaleDateString("zh-CN", { month: "numeric", day: "numeric" });
}

function formatFullDate(value: string | number): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString("zh-CN", { year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" });
}

function formatFileSize(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return "大小未知";
  if (bytes < 1024) return `${Math.round(bytes)} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(bytes < 10 * 1024 ? 1 : 0)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(bytes < 10 * 1024 * 1024 ? 1 : 0)} MB`;
}

function shortcutLabel(key: string): string {
  return `${/Mac|iPhone|iPad/.test(navigator.platform) ? "⌘" : "Ctrl"}+${key}`;
}

function shortcutTitle(key: string): string {
  return `快捷键 ${shortcutLabel(key)}`;
}

function installDialogFocusTrap(dialog: HTMLElement, close: () => void): () => void {
  const previous = document.activeElement as HTMLElement | null;
  if (!dialog.hasAttribute("tabindex")) dialog.tabIndex = -1;
  const keydown = (event: KeyboardEvent) => {
    if (!dialog.isConnected) {
      document.removeEventListener("keydown", keydown, true);
      return;
    }
    if (event.key === "Escape") {
      event.preventDefault();
      event.stopPropagation();
      close();
      return;
    }
    if (event.key !== "Tab") return;
    const focusable = Array.from(dialog.querySelectorAll<HTMLElement>("button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex='-1'])"));
    if (!focusable.length) {
      event.preventDefault();
      dialog.focus();
      return;
    }
    const first = focusable[0]!;
    const last = focusable[focusable.length - 1]!;
    if (!dialog.contains(document.activeElement)) {
      event.preventDefault();
      (event.shiftKey ? last : first).focus();
    } else if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  };
  document.addEventListener("keydown", keydown, true);
  return () => {
    document.removeEventListener("keydown", keydown, true);
    previous?.focus();
  };
}

function showConfirm(title: string, description: string, confirmLabel: string, danger = false): Promise<boolean> {
  return new Promise((resolve) => {
    const region = document.querySelector<HTMLElement>("#modal-region");
    if (!region || hasOpenModal()) {
      resolve(false);
      return;
    }
    const ids = nextModalIds("confirm");
    const overlay = makeElement("div", "modal-overlay confirm-overlay");
    const dialog = makeElement("section", "confirm-dialog");
    dialog.setAttribute("role", "alertdialog");
    dialog.setAttribute("aria-modal", "true");
    dialog.setAttribute("aria-labelledby", ids.title);
    dialog.setAttribute("aria-describedby", ids.description);
    const badge = makeElement("div", danger ? "status-icon status-icon-danger" : "status-icon");
    badge.append(icon(danger ? "alert" : "shield", 23));
    const heading = makeElement("h2", "", title);
    heading.id = ids.title;
    const body = makeElement("p", "", description);
    body.id = ids.description;
    const actions = makeElement("div", "confirm-actions");
    let release: () => void = () => undefined;
    let settled = false;
    const finish = (value: boolean) => {
      if (settled) return;
      settled = true;
      overlay.remove();
      deactivateModal();
      release();
      resolve(value);
    };
    if (!activateModal(() => finish(false))) {
      resolve(false);
      return;
    }
    const cancel = makeButton("取消", "button button-ghost", () => finish(false));
    const confirm = makeButton(confirmLabel, danger ? "button button-danger" : "button button-primary", () => finish(true), danger ? "trash" : "check");
    actions.append(cancel, confirm);
    dialog.append(badge, heading, body, actions);
    overlay.append(dialog);
    region.append(overlay);
    release = installDialogFocusTrap(dialog, () => finish(false));
    window.setTimeout(() => {
      if (dialog.isConnected) cancel.focus();
    }, 0);
  });
}

function showUnsavedLockDialog(): Promise<"save" | "discard" | "cancel"> {
  return new Promise((resolve) => {
    const region = document.querySelector<HTMLElement>("#modal-region");
    if (!region || hasOpenModal()) {
      resolve("cancel");
      return;
    }
    const ids = nextModalIds("unsaved-lock");
    const overlay = makeElement("div", "modal-overlay confirm-overlay");
    const dialog = makeElement("section", "confirm-dialog confirm-dialog-wide");
    dialog.setAttribute("role", "alertdialog");
    dialog.setAttribute("aria-modal", "true");
    dialog.setAttribute("aria-labelledby", ids.title);
    dialog.setAttribute("aria-describedby", ids.description);
    const badge = makeElement("div", "status-icon status-icon-warning");
    badge.append(icon("alert", 23));
    const heading = makeElement("h2", "", "锁定前保存修改？");
    heading.id = ids.title;
    const body = makeElement("p", "", "当前条目有未保存内容。自动锁定不会等待确认；这次你可以先保存。");
    body.id = ids.description;
    dialog.append(badge, heading, body);
    const actions = makeElement("div", "confirm-actions confirm-actions-three");
    let release: () => void = () => undefined;
    let settled = false;
    const finish = (value: "save" | "discard" | "cancel") => {
      if (settled) return;
      settled = true;
      overlay.remove();
      deactivateModal();
      release();
      resolve(value);
    };
    if (!activateModal(() => finish("cancel"))) {
      resolve("cancel");
      return;
    }
    const cancel = makeButton("取消", "button button-ghost", () => finish("cancel"));
    const discard = makeButton("放弃并锁定", "button button-danger-ghost", () => finish("discard"));
    const save = makeButton("保存并锁定", "button button-primary", () => finish("save"), "lock");
    actions.append(cancel, discard, save);
    dialog.append(actions);
    overlay.append(dialog);
    region.append(overlay);
    release = installDialogFocusTrap(dialog, () => finish("cancel"));
    window.setTimeout(() => {
      if (dialog.isConnected) save.focus();
    }, 0);
  });
}

function askMasterPassword(
  title: string,
  description: string,
  confirmLabel: string,
  fieldLabel = "备份主密码",
  placeholder = "输入此备份的主密码",
): Promise<string | null> {
  return new Promise((resolve) => {
    const region = document.querySelector<HTMLElement>("#modal-region");
    if (!region || hasOpenModal()) {
      resolve(null);
      return;
    }
    const ids = nextModalIds("master-password");
    const overlay = makeElement("div", "modal-overlay confirm-overlay");
    const dialog = makeElement("form", "confirm-dialog secret-dialog") as HTMLFormElement;
    dialog.setAttribute("role", "dialog");
    dialog.setAttribute("aria-modal", "true");
    dialog.setAttribute("aria-labelledby", ids.title);
    dialog.setAttribute("aria-describedby", ids.description);
    dialog.noValidate = true;
    const badge = makeElement("div", "status-icon");
    badge.append(icon("archive", 23));
    const heading = makeElement("h2", "", title);
    heading.id = ids.title;
    const body = makeElement("p", "", description);
    body.id = ids.description;
    dialog.append(badge, heading, body);
    const field = createPasswordField("sensitive-master-password", fieldLabel, placeholder, "current-password");
    const error = makeElement("p", "form-error");
    error.setAttribute("role", "alert");
    dialog.append(field.wrapper, error);
    const actions = makeElement("div", "confirm-actions");
    let release: () => void = () => undefined;
    let settled = false;
    const finish = (value: string | null) => {
      if (settled) return;
      settled = true;
      field.input.value = "";
      hideAllManagedSensitiveInputs();
      overlay.remove();
      deactivateModal();
      release();
      resolve(value);
    };
    if (!activateModal(() => finish(null))) {
      resolve(null);
      return;
    }
    const cancel = makeButton("取消", "button button-ghost", () => finish(null));
    const confirm = makeButton(confirmLabel, "button button-primary", () => undefined, "upload");
    confirm.type = "submit";
    actions.append(cancel, confirm);
    dialog.append(actions);
    dialog.addEventListener("submit", (event) => {
      event.preventDefault();
      if (!field.input.value) {
        error.textContent = `请输入${fieldLabel}。`;
        field.input.focus();
        return;
      }
      const value = field.input.value;
      finish(value);
    });
    overlay.append(dialog);
    region.append(overlay);
    release = installDialogFocusTrap(dialog, () => finish(null));
    window.setTimeout(() => {
      if (dialog.isConnected) field.input.focus();
    }, 0);
  });
}

function validateWebDavEndpointInput(value: string): string | null {
  let endpoint: URL;
  try {
    endpoint = new URL(value);
  } catch {
    return "请输入完整的 WebDAV HTTPS 目录地址。";
  }
  if (endpoint.protocol !== "https:") return "为避免凭据泄露，只允许 HTTPS 地址。";
  if (endpoint.username || endpoint.password) return "请不要把用户名或密码写进地址。";
  if (endpoint.search || endpoint.hash) return "WebDAV 目录地址不能包含查询参数或片段。";
  if (!endpoint.pathname.endsWith("/")) return "目录地址必须以 / 结尾。";
  return null;
}

function askWebDavConnection(mode: "create", prefill?: WebDavRetryHint | null): Promise<WebDavCredentials | null>;
function askWebDavConnection(mode: "join", prefill?: WebDavRetryHint | null): Promise<WebDavJoinDetails | null>;
function askWebDavConnection(
  mode: "create" | "join",
  prefill?: WebDavRetryHint | null,
): Promise<WebDavCredentials | WebDavJoinDetails | null> {
  return new Promise((resolve) => {
    const region = document.querySelector<HTMLElement>("#modal-region");
    if (!region || hasOpenModal()) {
      resolve(null);
      return;
    }
    const ids = nextModalIds("webdav-connection");
    const overlay = makeElement("div", "modal-overlay confirm-overlay");
    const dialog = makeElement("form", "confirm-dialog confirm-dialog-wide webdav-dialog") as HTMLFormElement;
    dialog.setAttribute("role", "dialog");
    dialog.setAttribute("aria-modal", "true");
    dialog.setAttribute("aria-labelledby", ids.title);
    dialog.setAttribute("aria-describedby", ids.description);
    dialog.noValidate = true;
    const badge = makeElement("div", "status-icon");
    badge.append(icon(mode === "create" ? "plus" : "download", 23));
    const heading = makeElement("h2", "", mode === "create" ? "创建 WebDAV 同步空间" : "加入已有 WebDAV 同步空间");
    heading.id = ids.title;
    const body = makeElement(
      "p",
      "",
      mode === "create"
        ? "使用你已有的空 WebDAV 目录。CipherNest 会验证服务器的条件写入与强 ETag 行为，再创建首个加密快照。"
        : "输入与另一台设备相同的目录、账号和恢复码。应用会先读取只读概览，不会立即覆盖本机内容。",
    );
    body.id = ids.description;

    const endpoint = createTextField("webdav-endpoint", "WebDAV 目录地址", "", "https://cloud.example.com/remote.php/dav/files/name/CipherNest/", true, 2048);
    endpoint.input.value = prefill?.endpoint ?? "";
    addSensitiveTextActions(endpoint, "WebDAV 地址");
    endpoint.wrapper.append(makeElement("p", "field-help", "必须是已存在的 HTTPS 目录，并以 / 结尾；请勿在地址中嵌入凭据。"));
    const portHint = makeElement("p", "field-help", "5005 在一些 WebDAV 服务中是 HTTP 端口。请确认此端口确实启用了 HTTPS；实际端口以服务器设置为准。");
    portHint.hidden = true;
    portHint.setAttribute("aria-live", "polite");
    endpoint.wrapper.append(portHint);
    endpoint.input.addEventListener("input", () => {
      try {
        portHint.hidden = new URL(endpoint.input.value.trim()).port !== "5005";
      } catch {
        portHint.hidden = true;
      }
    });
    const username = createTextField("webdav-username", "用户名", "", "WebDAV 用户名", true, 500);
    username.input.value = prefill?.username ?? "";
    addSensitiveTextActions(username, "WebDAV 用户名");
    const appPassword = createPasswordField("webdav-app-password", "应用专用密码", "输入 WebDAV 应用专用密码", "off");
    appPassword.input.maxLength = 4096;
    appPassword.wrapper.append(makeElement("p", "field-help", "建议在服务端单独创建、可随时撤销的应用专用密码。它会加密保存在本机同步配置中。"));
    const recovery = mode === "join"
      ? createPasswordField("webdav-recovery-code", "同步恢复码", "输入另一台设备保存的恢复码", "off")
      : null;
    if (recovery) {
      recovery.input.maxLength = 2048;
      recovery.wrapper.append(makeElement("p", "field-help", "恢复码是解密远端快照的关键，请勿通过同一 WebDAV 目录传递。"));
    }
    const fields = makeElement("div", "webdav-fields");
    fields.append(endpoint.wrapper, username.wrapper, appPassword.wrapper);
    if (recovery) fields.append(recovery.wrapper);
    const error = makeElement("p", "form-error webdav-form-error");
    error.setAttribute("role", "alert");
    error.textContent = prefill?.message ?? "";
    const actions = makeElement("div", "confirm-actions");

    let release: () => void = () => undefined;
    let settled = false;
    const clearInputs = () => {
      endpoint.input.value = "";
      username.input.value = "";
      appPassword.input.value = "";
      if (recovery) recovery.input.value = "";
      hideAllManagedSensitiveInputs();
    };
    const finish = (value: WebDavCredentials | WebDavJoinDetails | null) => {
      if (settled) return;
      settled = true;
      clearInputs();
      overlay.remove();
      deactivateModal();
      release();
      resolve(value);
    };
    if (!activateModal(() => finish(null))) {
      clearInputs();
      resolve(null);
      return;
    }
    const cancel = makeButton("取消", "button button-ghost", () => finish(null));
    const confirm = makeButton(mode === "create" ? "验证并创建" : "读取远端概览", "button button-primary", () => undefined, mode === "create" ? "plus" : "download");
    confirm.type = "submit";
    actions.append(cancel, confirm);
    dialog.append(badge, heading, body, fields, error, actions);
    dialog.addEventListener("submit", (event) => {
      event.preventDefault();
      const endpointValue = endpoint.input.value.trim();
      const endpointError = validateWebDavEndpointInput(endpointValue);
      if (endpointError) {
        error.textContent = endpointError;
        endpoint.input.focus();
        return;
      }
      if (!username.input.value.trim()) {
        error.textContent = "请输入 WebDAV 用户名。";
        username.input.focus();
        return;
      }
      if (!appPassword.input.value) {
        error.textContent = "请输入 WebDAV 应用专用密码。";
        appPassword.input.focus();
        return;
      }
      if (recovery && !recovery.input.value.trim()) {
        error.textContent = "请输入同步恢复码。";
        recovery.input.focus();
        return;
      }
      const credentials: WebDavCredentials = {
        endpoint: endpointValue,
        username: username.input.value.trim(),
        appPassword: appPassword.input.value,
      };
      finish(recovery
        ? { credentials, recoveryCode: recovery.input.value.trim() }
        : credentials);
    });
    overlay.append(dialog);
    region.append(overlay);
    release = installDialogFocusTrap(dialog, () => finish(null));
    window.setTimeout(() => {
      if (dialog.isConnected) endpoint.input.focus();
    }, 0);
  });
}

function showRecoveryCodeDialog(code: string, requireSaved: boolean, title: string): Promise<void> {
  return new Promise((resolve) => {
    const region = document.querySelector<HTMLElement>("#modal-region");
    if (!region || hasOpenModal()) {
      resolve();
      return;
    }
    const ids = nextModalIds("recovery-code");
    const overlay = makeElement("div", "modal-overlay confirm-overlay");
    const dialog = makeElement("section", "confirm-dialog confirm-dialog-wide recovery-code-dialog");
    dialog.setAttribute("role", "dialog");
    dialog.setAttribute("aria-modal", "true");
    dialog.setAttribute("aria-labelledby", ids.title);
    dialog.setAttribute("aria-describedby", ids.description);
    const badge = makeElement("div", "status-icon status-icon-warning");
    badge.append(icon("key", 23));
    const heading = makeElement("h2", "", title);
    heading.id = ids.title;
    const body = makeElement(
      "p",
      "",
      requireSaved
        ? "这是本次创建流程唯一一次自动展示。请离线保存；丢失后，新设备无法解密服务器上的数据。"
        : "任何拿到此恢复码和 WebDAV 文件的人都可以尝试解密同步数据。查看完成后请立即重新隐藏。",
    );
    body.id = ids.description;

    const codeWrap = makeElement("div", "secret-field recovery-code-field");
    const input = makeElement("input", "input secret-input") as HTMLInputElement;
    input.type = "password";
    input.value = code;
    input.readOnly = true;
    input.autocomplete = "off";
    input.spellcheck = false;
    input.setAttribute("aria-label", "WebDAV 同步恢复码");
    const actionsInField = makeElement("div", "secret-actions");
    let managedField: ManagedSensitiveInput;
    const reveal = iconButton("显示恢复码", "eye", () => {
      if (input.type === "password") revealManagedSensitiveInput(managedField);
      else hideManagedSensitiveInput(managedField);
    });
    reveal.setAttribute("aria-pressed", "false");
    const copy = iconButton("复制恢复码", "copy", () => copySecret(input.value, "恢复码"));
    managedField = { input, button: reveal, label: "恢复码", timeout: null };
    actionsInField.append(reveal, copy);
    codeWrap.append(input, actionsInField);

    const warning = makeElement("div", "inline-notice inline-notice-warning recovery-code-warning");
    warning.append(icon("alert", 17), makeElement("p", "", "不要把恢复码保存在同一个 WebDAV 目录，也不要截图上传到云相册。"));
    const error = makeElement("p", "form-error");
    error.setAttribute("role", "alert");
    const modalActions = makeElement("div", "confirm-actions");
    let saved: HTMLInputElement | null = null;
    if (requireSaved) {
      const savedLabel = makeElement("label", "recovery-saved-check");
      saved = makeElement("input") as HTMLInputElement;
      saved.type = "checkbox";
      savedLabel.append(saved, makeElement("span", "", "我已将恢复码保存在 WebDAV 之外的安全位置"));
      dialog.append(badge, heading, body, codeWrap, warning, savedLabel, error);
    } else {
      dialog.append(badge, heading, body, codeWrap, warning, error);
    }

    let release: () => void = () => undefined;
    let settled = false;
    const finish = () => {
      if (settled) return;
      settled = true;
      hideManagedSensitiveInput(managedField);
      input.value = "";
      overlay.remove();
      deactivateModal();
      release();
      resolve();
    };
    const attemptFinish = () => {
      if (requireSaved && !saved?.checked) {
        error.textContent = "请先确认恢复码已经安全保存。";
        saved?.focus();
        return;
      }
      finish();
    };
    if (!activateModal(finish)) {
      input.value = "";
      resolve();
      return;
    }
    const done = makeButton(requireSaved ? "已保存，完成" : "关闭", "button button-primary", attemptFinish, "check");
    if (saved) {
      done.disabled = true;
      saved.addEventListener("change", () => {
        done.disabled = !saved?.checked;
        error.textContent = "";
      });
    }
    modalActions.append(done);
    dialog.append(modalActions);
    overlay.append(dialog);
    region.append(overlay);
    release = installDialogFocusTrap(dialog, attemptFinish);
    window.setTimeout(() => {
      if (dialog.isConnected) (saved ?? reveal).focus();
    }, 0);
  });
}

function showWebDavJoinPreview(preview: WebDavRemotePreview, localItemCount: number): Promise<WebDavJoinMode | null> {
  return new Promise((resolve) => {
    const region = document.querySelector<HTMLElement>("#modal-region");
    if (!region || hasOpenModal()) {
      resolve(null);
      return;
    }
    const ids = nextModalIds("webdav-preview");
    const overlay = makeElement("div", "modal-overlay confirm-overlay");
    const dialog = makeElement("section", "confirm-dialog confirm-dialog-wide webdav-preview-dialog");
    dialog.setAttribute("role", "alertdialog");
    dialog.setAttribute("aria-modal", "true");
    dialog.setAttribute("aria-labelledby", ids.title);
    dialog.setAttribute("aria-describedby", ids.description);
    const badge = makeElement("div", "status-icon status-icon-warning");
    badge.append(icon("shield", 23));
    const heading = makeElement("h2", "", "核对远端同步空间");
    heading.id = ids.title;
    const body = makeElement("p", "", "远端快照已通过恢复码和完整性验证，但尚未写入本机。请选择首次加入方式。");
    body.id = ids.description;
    const details = makeElement("dl", "restore-preview-grid");
    const appendDetail = (label: string, value: string) => {
      const item = makeElement("div", "restore-preview-item");
      item.append(makeElement("dt", "", label), makeElement("dd", "", value));
      details.append(item);
    };
    appendDetail("远端条目", `${preview.itemCount.toLocaleString("zh-CN")} 项`);
    appendDetail("远端更新时间", formatFullDate(preview.updatedAt));
    appendDetail("远端序列", `#${preview.sequence.toLocaleString("zh-CN")}`);
    appendDetail("同步 ID", preview.syncIdShort);

    const tofu = makeElement("div", "inline-notice inline-notice-warning webdav-tofu-warning");
    tofu.append(
      icon("alert", 17),
      makeElement("p", "", preview.checkpointTrusted
        ? "此快照延续了本机已经信任的检查点。"
        : "首次加入（TOFU）：此设备没有旧检查点，无法独立证明服务器给出的是最新版本。请与另一台可信设备核对同步 ID 和序列。"),
    );

    let mode: WebDavJoinMode = preview.localHasHistory ? "merge" : "remote";
    const choices = makeElement("fieldset", "webdav-join-choices");
    if (preview.localHasHistory) {
      const legend = makeElement("legend", "", localItemCount > 0
        ? `本机已有 ${localItemCount.toLocaleString("zh-CN")} 个条目及删除历史`
        : "本机已有删除历史");
      choices.append(legend);
      const addChoice = (value: WebDavJoinMode, label: string, description: string, checked: boolean) => {
        const choice = makeElement("label", "webdav-join-choice");
        const radio = makeElement("input") as HTMLInputElement;
        radio.type = "radio";
        radio.name = "webdav-join-mode";
        radio.value = value;
        radio.checked = checked;
        radio.addEventListener("change", () => {
          if (radio.checked) mode = value;
        });
        const copy = makeElement("span");
        copy.append(makeElement("strong", "", label), makeElement("small", "", description));
        choice.append(radio, copy);
        choices.append(choice);
      };
      addChoice("merge", "合并（推荐）", "保留双方修改；同一条目冲突时创建带标记的副本。", true);
      addChoice("remote", "以远端替换本机", "忽略本机条目及删除历史；下一步还会再次危险确认。", false);
    } else {
      choices.append(makeElement("p", "webdav-empty-join", "本机保险库为空，将使用远端快照作为首次内容。"));
    }

    const modalActions = makeElement("div", "confirm-actions");
    let release: () => void = () => undefined;
    let settled = false;
    const finish = (value: WebDavJoinMode | null) => {
      if (settled) return;
      settled = true;
      overlay.remove();
      deactivateModal();
      release();
      resolve(value);
    };
    if (!activateModal(() => finish(null))) {
      resolve(null);
      return;
    }
    const cancel = makeButton("取消", "button button-ghost", () => finish(null));
    const confirm = makeButton("按此方式加入", "button button-primary", () => finish(mode), "check");
    modalActions.append(cancel, confirm);
    dialog.append(badge, heading, body, details, tofu, choices, modalActions);
    overlay.append(dialog);
    region.append(overlay);
    release = installDialogFocusTrap(dialog, () => finish(null));
    window.setTimeout(() => {
      if (dialog.isConnected) cancel.focus();
    }, 0);
  });
}

function showRestoreProgress(
  label: string,
  description = "请稍候。操作可能已进入不可取消的阶段；完成后请核对保险库状态。",
  allowImmediateLock = true,
): () => void {
  const region = document.querySelector<HTMLElement>("#modal-region");
  if (!region || hasOpenModal()) return () => undefined;
  const ids = nextModalIds("restore-progress");
  const overlay = makeElement("div", "modal-overlay confirm-overlay");
  const dialog = makeElement("section", "confirm-dialog restore-progress-dialog");
  dialog.setAttribute("role", "dialog");
  dialog.setAttribute("aria-modal", "true");
  dialog.setAttribute("aria-labelledby", ids.title);
  dialog.setAttribute("aria-describedby", ids.description);
  dialog.setAttribute("aria-busy", "true");
  const spinner = makeElement("div", "spinner");
  spinner.setAttribute("aria-hidden", "true");
  const heading = makeElement("h2", "", label);
  heading.id = ids.title;
  const body = makeElement("p", "", description);
  body.id = ids.description;
  dialog.append(spinner, heading, body);
  if (allowImmediateLock && state.status.unlocked) {
    const actions = makeElement("div", "confirm-actions restore-progress-actions");
    actions.append(makeButton(
      "立即锁定界面",
      "button button-ghost",
      () => performLock("保险库界面已锁定。请重新解锁后核对操作结果。", true),
      "lock",
    ));
    dialog.append(actions);
  }
  overlay.append(dialog);

  let release: () => void = () => undefined;
  let closed = false;
  const close = () => {
    if (closed) return;
    closed = true;
    overlay.remove();
    deactivateModal();
    release();
  };
  if (!activateModal(close)) return () => undefined;
  region.append(overlay);
  release = installDialogFocusTrap(dialog, () => undefined);
  window.setTimeout(() => {
    if (dialog.isConnected) dialog.focus();
  }, 0);
  return close;
}

function showRestorePreview(selection: RestoreSelection, preview: RestorePreview): Promise<boolean> {
  return new Promise((resolve) => {
    const region = document.querySelector<HTMLElement>("#modal-region");
    if (!region || hasOpenModal()) {
      resolve(false);
      return;
    }
    const ids = nextModalIds("restore-preview");
    const overlay = makeElement("div", "modal-overlay confirm-overlay");
    const dialog = makeElement("section", "confirm-dialog confirm-dialog-wide restore-preview-dialog");
    dialog.setAttribute("role", "alertdialog");
    dialog.setAttribute("aria-modal", "true");
    dialog.setAttribute("aria-labelledby", ids.title);
    dialog.setAttribute("aria-describedby", ids.description);

    const badge = makeElement("div", "status-icon status-icon-warning");
    badge.append(icon("archive", 23));
    const heading = makeElement("h2", "", "确认替换当前保险库");
    heading.id = ids.title;
    const body = makeElement(
      "p",
      "",
      "备份已通过完整性与主密码验证。请核对以下只读概览；继续后，当前保险库会被这份备份完整替换。",
    );
    body.id = ids.description;

    const details = makeElement("dl", "restore-preview-grid");
    const appendDetail = (label: string, value: string) => {
      const item = makeElement("div", "restore-preview-item");
      item.append(makeElement("dt", "", label), makeElement("dd", "", value));
      details.append(item);
    };
    appendDetail("备份文件", preview.fileName);
    appendDetail("文件大小", formatFileSize(selection.fileSize));
    appendDetail("条目数量", `${preview.itemCount.toLocaleString("zh-CN")} 项`);
    appendDetail("备份更新时间", formatFullDate(preview.updatedAt));
    appendDetail("数据代次", preview.generation.toLocaleString("zh-CN"));
    appendDetail("保险库标识", preview.vaultIdShort);

    const warning = makeElement("div", "inline-notice inline-notice-warning restore-preview-warning");
    warning.append(
      icon("alert", 17),
      makeElement(
        "p",
        "",
        "未保存修改不会被保留；本机双向同步配置与检查点会清除。已保存的备份连接会保留；临时连接仅在选择保存时保留。恢复后请核对保险库和远端设置。",
      ),
    );

    const actions = makeElement("div", "confirm-actions");
    let release: () => void = () => undefined;
    let settled = false;
    const finish = (value: boolean) => {
      if (settled) return;
      settled = true;
      overlay.remove();
      deactivateModal();
      release();
      resolve(value);
    };
    if (!activateModal(() => finish(false))) {
      resolve(false);
      return;
    }
    const cancel = makeButton("取消", "button button-ghost", () => finish(false));
    const confirm = makeButton("替换当前保险库", "button button-danger", () => finish(true), "upload");
    actions.append(cancel, confirm);
    dialog.append(badge, heading, body, details, warning, actions);
    overlay.append(dialog);
    region.append(overlay);
    release = installDialogFocusTrap(dialog, () => finish(false));
    window.setTimeout(() => {
      if (dialog.isConnected) cancel.focus();
    }, 0);
  });
}

function handleGlobalShortcut(event: KeyboardEvent): void {
  if (event.key === "Escape" && compactNavigationMedia.matches && state.mobileNavOpen) {
    event.preventDefault();
    setMobileNavOpen(false, true);
    return;
  }
  if (!state.status.unlocked || !(event.ctrlKey || event.metaKey) || event.altKey) return;
  const key = event.key.toLocaleLowerCase();
  if (!["n", "g", "f", "s", "l"].includes(key)) return;
  if (event.repeat && key !== "f") return;
  event.preventDefault();
  if (key === "l") {
    if (hasOpenModal()) dismissActiveModal();
    void manualLock();
    return;
  }
  if (hasOpenModal()) return;
  if (key === "n") void createNewEntry();
  else if (key === "g") openGenerator("standalone");
  else if (key === "f") {
    if (state.view !== "all" && state.view !== "favorites") {
      void switchView("all").then(focusSearchAtEnd);
    } else focusSearchAtEnd();
  } else if (key === "s") {
    if (state.entryMutation === null && state.draft && hasUnsavedDraft()) void saveCurrentEntry();
  }
}

ensureLayers();
void listen("ciphernest://vault-locked", () => void handleLifecycleLock());
void listen("ciphernest://webdav-backup-status", () => {
  if (state.status.unlocked) void refreshWebDavBackupStatus(state.epoch);
});
void listen("ciphernest://webdav-sync-status", () => {
  if (state.status.unlocked) void refreshWebDavSyncStatus(state.epoch);
});
void listen("ciphernest://vault-content-changed", () => {
  if (state.status.unlocked) void refreshAfterAutoSyncedContent();
});
document.addEventListener("keydown", handleGlobalShortcut);
document.addEventListener("pointerdown", recordActivity, { passive: true });
document.addEventListener("keydown", recordActivity, { passive: true });
document.addEventListener("input", recordActivity, { passive: true });
document.addEventListener("wheel", recordActivity, { passive: true });
window.addEventListener("blur", () => void handleFocusChange(false));
window.addEventListener("focus", () => void handleFocusChange(true));
document.addEventListener("visibilitychange", () => {
  if (document.hidden) {
    hideAllManagedSensitiveInputs();
    hidePassword();
    hideGeneratorPassword();
    hideNotes();
  }
});
window.addEventListener("beforeunload", () => {
  clearSensitiveState(true);
  void invokeCommand<void>("clear_owned_clipboard");
});
compactNavigationMedia.addEventListener("change", () => {
  if (!state.status.unlocked) return;
  setMobileNavOpen(false);
});
compactSettingsMedia.addEventListener("change", () => {
  reflowSettingsLayout();
});

void bootstrap();
