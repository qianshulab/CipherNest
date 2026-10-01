export interface VaultStatus {
  exists: boolean;
  unlocked: boolean;
  itemCount: number;
  autoLockMinutes: number;
}

export interface VaultOverview {
  totalEntries: number;
  favoriteCount: number;
  securityIssueCount: number;
  syncConflictCount: number;
  lastBackupAt?: number;
  autoBackup: {
    count: number;
    latestAt?: number;
    currentCovered: boolean;
    inspectionFailed: boolean;
    warning?: string;
  };
}

export interface RestoreSelection {
  token: string;
  fileName: string;
  fileSize: number;
}

export interface RestorePreview {
  fileName: string;
  itemCount: number;
  updatedAt: number;
  generation: number;
  vaultIdShort: string;
}

export interface WebDavSyncStatus {
  configured: boolean;
  automatic?: boolean;
  autoPaused?: boolean;
  autoWarning?: string;
  endpointHost?: string;
  username?: string;
  syncIdShort?: string;
  lastSyncAt?: number;
  lastAutoCheckAt?: number;
  remoteSequence?: number;
  pendingLocalChanges: boolean;
}

export interface WebDavCredentials {
  endpoint: string;
  username: string;
  appPassword: string;
}

export interface WebDavCreateResult {
  status: WebDavSyncStatus;
  recoveryCode: string;
}

export interface WebDavRemotePreview {
  previewToken: string;
  itemCount: number;
  updatedAt: number;
  sequence: number;
  syncIdShort: string;
  checkpointTrusted: false;
  localHasHistory: boolean;
}

export type WebDavJoinMode = "remote" | "merge";
export type WebDavSyncOutcomeKind = "upToDate" | "uploaded" | "downloaded" | "merged";

export interface WebDavSyncOutcome {
  kind: WebDavSyncOutcomeKind;
  conflicts: number;
  sequence: number;
  status: WebDavSyncStatus;
}

export interface WebDavRecoveryCode {
  recoveryCode: string;
}

export interface MasterPasswordChangeResult {
  syncConfigPreserved: boolean;
  warning?: string;
}

export interface EntrySummary {
  id: string;
  title: string;
  favorite: boolean;
  revision: number;
  createdAt: number;
  updatedAt: number;
  passwordUpdatedAt: number;
  securityFlags: string[];
}

export interface VaultEntry extends EntrySummary {
  username: string;
  password: string;
  url: string;
  purpose: string;
  notes: string;
  tags: string[];
  revision: number;
}

export interface EntryInput {
  id?: string;
  expectedRevision?: number;
  title: string;
  username: string;
  password: string;
  url: string;
  purpose: string;
  notes: string;
  tags: string[];
  favorite: boolean;
}

export interface VaultSettings {
  autoLockMinutes: number;
  clipboardClearSeconds: number;
  passwordRevealSeconds: number;
  lockOnBlur: boolean;
}

export interface GeneratorOptions {
  length: number;
  lowercase: boolean;
  uppercase: boolean;
  digits: boolean;
  symbols: boolean;
  excludeAmbiguous: boolean;
  requireEach: boolean;
}

export interface GeneratedPassword {
  password: string;
  entropyBits: number;
  poolSize: number;
}

export type SecurityIssueKind = "weak" | "reused" | "stale";

export interface SecurityIssue {
  entryId: string;
  title: string;
  kind: SecurityIssueKind;
  message: string;
}

export interface SecurityReport {
  issues: SecurityIssue[];
  totalEntries: number;
  weakCount: number;
  reusedCount: number;
  staleCount: number;
}

export type VaultView = "all" | "favorites" | "security" | "settings";
export type EntrySort = "updated_desc" | "title_asc" | "created_desc";
export type ToastKind = "success" | "error" | "info" | "warning";
