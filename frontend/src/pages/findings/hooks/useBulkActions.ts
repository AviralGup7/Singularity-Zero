import { useState, useCallback } from 'react';
import type { Finding } from '../../../types/api';

interface UseBulkActionsInput {
  addAuditLog: (findingId: string, action: string, details?: string) => void;
  setLocalOverrides: React.Dispatch<React.SetStateAction<Record<string, Partial<Finding>>>>;
  showToast?: (type: 'success' | 'error' | 'warning' | 'info', message: string) => void;
}

export function useBulkActions({ addAuditLog, setLocalOverrides, showToast }: UseBulkActionsInput) {
   
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
   
  const [bulkActionMode, setBulkActionMode] = useState<string | null>(null);
   
  const [bulkAssignee, setBulkAssignee] = useState('');

  const toggleRow = useCallback((id: string) => {
    setSelectedIds(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }, []);

  const togglePage = useCallback((paginated: Finding[], allOnPageSelected: boolean) => {
    setSelectedIds(prev => {
      const next = new Set(prev);
      if (allOnPageSelected) {
        paginated.forEach(f => { if (f.id) next.delete(f.id); });
      } else {
        paginated.forEach(f => { if (f.id) next.add(f.id); });
      }
      return next;
    });
  }, []);

  const selectAll = useCallback((filtered: Finding[]) => {
    setSelectedIds(new Set(filtered.map(f => f.id).filter(Boolean)));
  }, []);

  const clearSelection = useCallback(() => {
    setSelectedIds(new Set());
  }, []);

  // FIX: Batch all overrides into a single state update instead of N+1 calls
  const handleBulkStatus = useCallback((status: 'open' | 'closed' | 'accepted') => {
    const updates: Partial<Finding> = {
   
      status: status as Finding['status'],
      kanbanStatus: status === 'open' ? 'new' : status === 'closed' ? 'resolved' : 'in-progress',
    };
    const ids = Array.from(selectedIds);
    setLocalOverrides(prev => {
      const next = { ...prev };
      for (const id of ids) {
  // eslint-disable-next-line security/detect-object-injection
        next[id] = { ...(prev[id] || {}), ...updates };
        addAuditLog(id, 'bulk_status_change', `Changed to ${status}`);
      }
      return next;
    });
    setSelectedIds(new Set());
    setBulkActionMode(null);
    showToast?.('success', `Status updated for ${ids.length} finding${ids.length > 1 ? 's' : ''}`);
   
  }, [selectedIds, addAuditLog, setLocalOverrides, showToast]);

  const handleBulkFalsePositive = useCallback(() => {
    const updates: Partial<Finding> = { falsePositive: true, fpStatus: 'pending' };
    const ids = Array.from(selectedIds);
    setLocalOverrides(prev => {
      const next = { ...prev };
      for (const id of ids) {
  // eslint-disable-next-line security/detect-object-injection
        next[id] = { ...(prev[id] || {}), ...updates };
        addAuditLog(id, 'bulk_false_positive', 'Marked as false positive');
      }
      return next;
    });
    setSelectedIds(new Set());
    setBulkActionMode(null);
    showToast?.('success', `${ids.length} finding${ids.length > 1 ? 's' : ''} marked as false positive`);
   
  }, [selectedIds, addAuditLog, setLocalOverrides, showToast]);

  const handleBulkAssign = useCallback(() => {
    if (!bulkAssignee.trim()) return;
    const assignee = bulkAssignee.trim();
    const ids = Array.from(selectedIds);
    setLocalOverrides(prev => {
      const next = { ...prev };
      for (const id of ids) {
  // eslint-disable-next-line security/detect-object-injection
        next[id] = { ...(prev[id] || {}), assignedTo: assignee };
        addAuditLog(id, 'bulk_assign', `Assigned to ${assignee}`);
      }
      return next;
    });
    setSelectedIds(new Set());
    setBulkAssignee('');
    setBulkActionMode(null);
    showToast?.('success', `Assigned ${ids.length} finding${ids.length > 1 ? 's' : ''} to ${assignee}`);
   
  }, [selectedIds, bulkAssignee, addAuditLog, setLocalOverrides, showToast]);

  const handleBulkDelete = useCallback(() => {
    const ids = Array.from(selectedIds);
    setLocalOverrides(prev => {
      const next = { ...prev };
      for (const id of ids) {
  // eslint-disable-next-line security/detect-object-injection
        next[id] = { ...(prev[id] || {}), _deleted: true } as unknown as Partial<Finding>;
        addAuditLog(id, 'bulk_delete', 'Deleted via bulk action');
      }
      return next;
    });
    setSelectedIds(new Set());
    setBulkActionMode(null);
    showToast?.('warning', `${ids.length} finding${ids.length > 1 ? 's' : ''} deleted`);
   
  }, [selectedIds, addAuditLog, setLocalOverrides, showToast]);

  return {
    selectedIds, bulkActionMode, bulkAssignee,
    setBulkActionMode, setBulkAssignee, setSelectedIds,
    toggleRow, togglePage, selectAll, clearSelection,
    handleBulkStatus, handleBulkFalsePositive, handleBulkAssign, handleBulkDelete,
  };
}
