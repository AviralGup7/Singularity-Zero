import { useCallback, useEffect, useMemo, useState } from 'react';
import type { Finding } from '@/types/api';
import { bulkUpdateFindings } from '@/api/client';
import { useToast } from '@/hooks/useToast';
import { FindingsTableView } from './FindingsTableView';
import { FindingsFpDialogs } from './FindingsFpDialogs';
import { dedupeFindings } from '../hooks/useFindingsTable';
import { clampFindingsPage } from '../findingsViewMode';
import { userInitials } from '@/utils/userChrome';

type TableSortKey = 'severity' | 'type' | 'target' | 'status' | 'date' | 'bounty_value';

const TABLE_SORT_KEYS = new Set<string>(['severity', 'type', 'target', 'status', 'date', 'bounty_value']);
const PAGE_SIZE = 20;

function hashToColor(str: string): string {
  let hash = 0;
  for (let i = 0; i < str.length; i += 1) {
    hash = str.charCodeAt(i) + ((hash << 5) - hash);
  }
  return `hsl(${Math.abs(hash) % 360} 70% 45%)`;
}

function getInitials(name: string): string {
  return userInitials(name);
}

interface FindingsTablePaneProps {
  findings: Finding[];
  selectedIds: Set<string>;
  onToggleSelect: (id: string) => void;
  onSelectAll: () => void;
  onClearSelection: () => void;
  onOpenDetail: (finding: Finding) => void;
  bulkActionMode: string | null;
  setBulkActionMode: (mode: string | null) => void;
  bulkAssignee: string;
  setBulkAssignee: (name: string) => void;
  handleBulkStatus: (status: 'open' | 'closed' | 'accepted') => void;
  handleBulkFalsePositive: () => void;
  handleBulkAssign: () => void;
  handleBulkDelete: () => void;
  sortKey: string;
  sortDir: 'asc' | 'desc';
  onSort: (key: TableSortKey) => void;
}

export function FindingsTablePane({
  findings,
  selectedIds,
  onToggleSelect,
  onSelectAll,
  onClearSelection,
  onOpenDetail,
  bulkActionMode,
  setBulkActionMode,
  bulkAssignee,
  setBulkAssignee,
  handleBulkStatus,
  handleBulkFalsePositive,
  handleBulkAssign,
  handleBulkDelete,
  sortKey,
  sortDir,
  onSort,
}: FindingsTablePaneProps) {
  const toast = useToast();
  const [page, setPage] = useState(1);
  const [expandedDuplicates, setExpandedDuplicates] = useState<Set<string>>(new Set());
  const [fpDialogFinding, setFpDialogFinding] = useState<Finding | null>(null);
  const [fpJustification, setFpJustification] = useState('');
  const [fpReviewDialog, setFpReviewDialog] = useState<Finding | null>(null);
  const [fpReviewComment, setFpReviewComment] = useState('');

  const uniqueFindings = useMemo(() => dedupeFindings(findings), [findings]);
  const tableSortKey: TableSortKey = TABLE_SORT_KEYS.has(sortKey) ? (sortKey as TableSortKey) : 'severity';
  const totalPages = Math.max(1, Math.ceil(uniqueFindings.length / PAGE_SIZE));
  const safePage = clampFindingsPage(page, totalPages);

  useEffect(() => {
    if (page !== safePage) setPage(safePage);
  }, [page, safePage]);
  const paginated = useMemo(
    () => uniqueFindings.slice((safePage - 1) * PAGE_SIZE, safePage * PAGE_SIZE),
    [uniqueFindings, safePage],
  );
  const allOnPageSelected = paginated.length > 0 && paginated.every((finding) => selectedIds.has(finding.id));
  const uniqueAssignees = useMemo(() => {
    const names = uniqueFindings.map((finding) => finding.assignedTo).filter((name): name is string => Boolean(name));
    return [...new Set(names)].sort();
  }, [uniqueFindings]);

  const togglePage = useCallback(() => {
    const ids = paginated.map((finding) => finding.id);
    if (allOnPageSelected) {
      ids.forEach((id) => {
        if (selectedIds.has(id)) onToggleSelect(id);
      });
      return;
    }
    ids.forEach((id) => {
      if (!selectedIds.has(id)) onToggleSelect(id);
    });
  }, [allOnPageSelected, onToggleSelect, paginated, selectedIds]);

  const toggleDuplicateExpand = useCallback((id: string) => {
    setExpandedDuplicates((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }, []);

  const getDuplicateById = useCallback(
    (id: string) => findings.find((finding) => finding.id === id) ?? uniqueFindings.find((finding) => finding.id === id),
    [findings, uniqueFindings],
  );

  const handleAssign = useCallback(async (findingId: string, assignee: string) => {
    try {
      await bulkUpdateFindings([findingId], { assignedTo: assignee || undefined });
      toast.success(assignee ? `Assigned to ${assignee}` : 'Unassigned');
    } catch {
      toast.error('Failed to assign finding');
    }
  }, [toast]);

  const onMarkFalsePositive = useCallback(async () => {
    if (!fpDialogFinding || !fpJustification.trim()) return;
    try {
      await bulkUpdateFindings([fpDialogFinding.id], {
        falsePositive: true,
        fpStatus: 'pending',
        fpJustification: fpJustification.trim(),
      });
      toast.success('Marked as false positive');
      setFpDialogFinding(null);
      setFpJustification('');
    } catch {
      toast.error('Failed to mark false positive');
    }
  }, [fpDialogFinding, fpJustification, toast]);

  const onFpReview = useCallback(async (finding: Finding, decision: 'approved' | 'rejected') => {
    try {
      await bulkUpdateFindings([finding.id], {
        fpStatus: decision,
        falsePositive: decision === 'approved',
      });
      toast.success(decision === 'approved' ? 'FP approved' : 'FP rejected');
      setFpReviewDialog(null);
      setFpReviewComment('');
    } catch {
      toast.error('Failed to review false positive');
    }
  }, [fpReviewComment, toast]);

  return (
    <div className="h-full overflow-auto px-4 pb-24">
      <FindingsTableView
        paginated={paginated}
        filtered={uniqueFindings}
        page={safePage}
        pageSize={PAGE_SIZE}
        sortKey={tableSortKey}
        sortDir={sortDir}
        selectedIds={selectedIds}
        expandedDuplicates={expandedDuplicates}
        allOnPageSelected={allOnPageSelected}
        uniqueAssignees={uniqueAssignees}
        bulkActionMode={bulkActionMode}
        bulkAssignee={bulkAssignee}
        handleSort={onSort}
        toggleRow={onToggleSelect}
        togglePage={togglePage}
        selectAll={onSelectAll}
        clearSelection={onClearSelection}
        onPageChange={setPage}
        toggleDuplicateExpand={toggleDuplicateExpand}
        getDuplicateById={getDuplicateById}
        handleAssign={handleAssign}
        setFpDialogFinding={setFpDialogFinding}
        setFpReviewDialog={setFpReviewDialog}
        handleOpenDetail={onOpenDetail}
        hashToColor={hashToColor}
        getInitials={getInitials}
        setBulkActionMode={setBulkActionMode}
        setBulkAssignee={setBulkAssignee}
        handleBulkStatus={handleBulkStatus}
        handleBulkFalsePositive={handleBulkFalsePositive}
        handleBulkAssign={handleBulkAssign}
        handleBulkDelete={handleBulkDelete}
      />
      <FindingsFpDialogs
        fpDialogFinding={fpDialogFinding}
        fpJustification={fpJustification}
        setFpJustification={setFpJustification}
        onMarkFalsePositive={onMarkFalsePositive}
        onCloseFpDialog={() => { setFpDialogFinding(null); setFpJustification(''); }}
        fpReviewDialog={fpReviewDialog}
        fpReviewComment={fpReviewComment}
        setFpReviewComment={setFpReviewComment}
        onFpReview={onFpReview}
        onCloseFpReview={() => { setFpReviewDialog(null); setFpReviewComment(''); }}
      />
    </div>
  );
}
