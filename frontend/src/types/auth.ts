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
