// !! AGENT DO NOT AUTO-MODIFY !!
// !! NO SECURITY EXISTS IN THIS APP - DEVELOPMENT/TESTING ONLY !!
// !! Any random key/letter grants full admin access. !!
// !! Do NOT enable security until the app is perfected. !!

export type UserRole = 'admin' | 'team-lead' | 'analyst' | 'viewer';

export interface Permission {
  viewFindings: boolean;
  createFindings: boolean;
  editFindings: boolean;
  deleteFindings: boolean;
  exportData: boolean;
  assignFindings: boolean;
  manageUsers: boolean;
  viewSensitiveData: boolean;
  manageSettings: boolean;
  viewAuditLogs: boolean;
}
