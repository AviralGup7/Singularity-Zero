import { useCallback, useMemo, useRef, useState } from 'react';
import type { Finding } from '@/types/api';
import { bulkUpdateFindings, updateFinding } from '@/api/client';
import { useToast } from '@/hooks/useToast';
import { FindingsFpDialogs } from './FindingsFpDialogs';
import {
  FindingsKanbanView,
  bucketKanbanFindings,
  resolveKanbanColumn,
  type KanbanColumn,
} from './FindingsKanbanView';

function hashToColor(str: string): string {
  let hash = 0;
  for (let i = 0; i < str.length; i += 1) {
    hash = str.charCodeAt(i) + ((hash << 5) - hash);
  }
  return `hsl(${Math.abs(hash) % 360} 70% 45%)`;
}

function getInitials(name: string): string {
  return name
    .split(/\s+/)
    .map((part) => part[0] ?? '')
    .join('')
    .slice(0, 2)
    .toUpperCase() || '?';
}

interface FindingsKanbanPaneProps {
  findings: Finding[];
  onOpenDetail: (finding: Finding) => void;
}

export function FindingsKanbanPane({ findings, onOpenDetail }: FindingsKanbanPaneProps) {
  const toast = useToast();
  const [overrides, setOverrides] = useState<Record<string, KanbanColumn>>({});
  const [dragged, setDragged] = useState<Finding | null>(null);
  const draggedRef = useRef<Finding | null>(null);
  const [expandedDuplicates, setExpandedDuplicates] = useState<Set<string>>(new Set());
  const [fpDialogFinding, setFpDialogFinding] = useState<Finding | null>(null);
  const [fpJustification, setFpJustification] = useState('');
  const [fpReviewDialog, setFpReviewDialog] = useState<Finding | null>(null);
  const [fpReviewComment, setFpReviewComment] = useState('');

  const boardFindings = useMemo(
    () => findings.map((finding) => (
      overrides[finding.id]
        ? { ...finding, kanbanStatus: overrides[finding.id] }
        : finding
    )),
    [findings, overrides],
  );

  const kanbanFindings = useMemo(
    () => bucketKanbanFindings(boardFindings),
    [boardFindings],
  );

  const uniqueAssignees = useMemo(() => {
    const names = findings.map((finding) => finding.assignedTo).filter((name): name is string => Boolean(name));
    return [...new Set(names)].sort();
  }, [findings]);

  const toggleDuplicateExpand = useCallback((id: string) => {
    setExpandedDuplicates((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }, []);

  const getDuplicateById = useCallback(
    (id: string) => findings.find((finding) => finding.id === id),
    [findings],
  );

  const handleAssign = useCallback(async (findingId: string, assignee: string) => {
    try {
      await bulkUpdateFindings([findingId], { assignedTo: assignee || undefined });
      toast.success(assignee ? `Assigned to ${assignee}` : 'Unassigned');
    } catch {
      toast.error('Failed to assign finding');
    }
  }, [toast]);

  const handleDragStart = useCallback((finding: Finding) => {
    draggedRef.current = finding;
    setDragged(finding);
  }, []);

  const handleDragOver = useCallback((event: React.DragEvent) => {
    event.preventDefault();
  }, []);

  const handleDrop = useCallback(async (column: KanbanColumn) => {
    const active = draggedRef.current ?? dragged;
    if (!active) return;
    const previous = resolveKanbanColumn({ ...active, kanbanStatus: overrides[active.id] ?? active.kanbanStatus });
    if (previous === column) {
      draggedRef.current = null;
      setDragged(null);
      return;
    }
    setOverrides((prev) => ({ ...prev, [active.id]: column }));
    draggedRef.current = null;
    setDragged(null);
    try {
      await updateFinding(active.id, { kanbanStatus: column });
      toast.success(`Moved to ${column.replace(/_/g, ' ')}`);
    } catch {
      setOverrides((prev) => {
        const next = { ...prev };
        if (previous) next[active.id] = previous;
        else delete next[active.id];
        return next;
      });
      toast.error('Failed to update board status');
    }
  }, [dragged, overrides, toast]);

  const onMarkFalsePositive = useCallback(async () => {
    if (!fpDialogFinding || !fpJustification.trim()) return;
    try {
      await bulkUpdateFindings([fpDialogFinding.id], {
        falsePositive: true,
        fpStatus: 'pending',
        fpJustification: fpJustification.trim(),
      });
      setOverrides((prev) => ({ ...prev, [fpDialogFinding.id]: 'needs_validation' }));
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
      setOverrides((prev) => ({
        ...prev,
        [finding.id]: decision === 'approved' ? 'not_interested' : 'needs_validation',
      }));
      toast.success(decision === 'approved' ? 'FP approved' : 'FP rejected');
      setFpReviewDialog(null);
      setFpReviewComment('');
    } catch {
      toast.error('Failed to review false positive');
    }
  }, [toast]);

  return (
    <div className="h-full overflow-auto px-4 pb-24">
      <FindingsKanbanView
        kanbanFindings={kanbanFindings}
        uniqueAssignees={uniqueAssignees}
        handleDragStart={handleDragStart}
        handleDragOver={handleDragOver}
        handleDrop={handleDrop}
        handleAssign={handleAssign}
        toggleDuplicateExpand={toggleDuplicateExpand}
        getDuplicateById={getDuplicateById}
        expandedDuplicates={expandedDuplicates}
        setFpDialogFinding={setFpDialogFinding}
        setFpReviewDialog={setFpReviewDialog}
        hashToColor={hashToColor}
        getInitials={getInitials}
        onOpenDetail={onOpenDetail}
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
