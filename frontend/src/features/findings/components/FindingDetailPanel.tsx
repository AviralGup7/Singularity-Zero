import { useEffect, useState, useMemo, useRef, useCallback } from 'react';
import { Zap } from 'lucide-react';
import { motion } from 'framer-motion';
import type { Finding, RemediationSuggestion, EvidenceItem, AttackChain } from '@/types/api';
import { getFindingRemediation, getFindingById } from '@/api/client';
import { useToast } from '@/hooks/useToast';
import { EvidenceDisplay } from './EvidenceDisplay';
import { AttackChainVisualizer } from '@/components/AttackChainVisualizer';
import { FindingComments } from './FindingComments';
import { RequestResponseViewer } from '@/components/RequestResponseViewer';
import { ChainOfCustodyViewer } from '@/components/common/ChainOfCustodyViewer';
import { useTriageCollaboration } from '@/hooks/useTriageCollaboration';
import { exportFinding  } from '@/utils/findingExport';
import type {ReportFormat} from '@/utils/findingExport';
import { SubmitToPlatformDialog } from './SubmitToPlatformDialog';
import { DetailHeader } from './FindingDetailPanel/DetailHeader';
import { DetailFooter } from './FindingDetailPanel/DetailFooter';
import { DetailTabs, buildTabs } from './FindingDetailPanel/DetailTabs';
import { useOptionalFeatures } from '@/hooks/useOptionalFeatures';
import { ThreatIntelPanel } from './ThreatIntelPanel';
import { CVSSDetail } from './CVSSDetail';
import { PIIControls } from './PIIControls';
import { isPIIVisible } from '@/utils/piiRedactor';
import { sanitizePiiFromVisibility } from '@/utils/piiVisibility';
import { confidencePercent } from '@/utils/normalizeScale';
import { displayNumericOrNA } from '@/utils/displayValue';
import { parseFindingTimestamp } from '@/utils/findingTime';
import { RemediationTracker } from './RemediationTracker';
import { BountyPanel } from './FindingDetailPanel/BountyPanel';
import { RiskPanel } from './FindingDetailPanel/RiskPanel';
import { remediationCache, prefetchRemediation } from './FindingDetailPanel/helpers';
import type {DetailTab, ExtendedEvidence} from './FindingDetailPanel/helpers';

export { remediationCache, prefetchRemediation };

export interface FindingDetailPanelProps {
  finding: Finding;
  onClose: () => void;
}

export function FindingDetailPanel({
  finding: initialFinding,
  onClose,
}: FindingDetailPanelProps) {
  const [finding, setFinding] = useState<Finding>(initialFinding);
  const dialogRef = useRef<HTMLDivElement>(null);
  const previousFocusRef = useRef<HTMLElement | null>(null);

  useEffect(() => {
    let cancelled = false;
    getFindingById(initialFinding.id)
      .then((fresh: Finding | null | undefined) => {
        if (!cancelled && fresh) setFinding(fresh);
      })
      .catch(() => {});
    return () => { cancelled = true; };
  }, [initialFinding.id]);

  useEffect(() => {
    previousFocusRef.current = document.activeElement as HTMLElement;
    const dialog = dialogRef.current;
    if (dialog) {
      const firstFocusable = dialog.querySelector<HTMLElement>(
        'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])',
      );
      firstFocusable?.focus();
    }
    return () => {
      previousFocusRef.current?.focus();
    };
  }, []);

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === 'Escape') {
        onClose();
        return;
      }
      if (e.key !== 'Tab') return;
      const dialog = dialogRef.current;
      if (!dialog) return;
      const focusableElements = dialog.querySelectorAll<HTMLElement>(
        'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
      );
      if (focusableElements.length === 0) return;
      const first = focusableElements[0];
      const last = focusableElements[focusableElements.length - 1];
      if (e.shiftKey) {
        if (document.activeElement === first) {
          e.preventDefault();
          last.focus();
        }
      } else {
        if (document.activeElement === last) {
          e.preventDefault();
          first.focus();
        }
      }
    },
    [onClose],
  );

  const [detailTab, setDetailTab] = useState<DetailTab>('csi');
  const [bountyValue, setBountyValue] = useState(finding.bounty_value || 0);
  const [bountySource, setBountySource] = useState<string>(finding.bounty_source || 'estimate');
  const [bountyCurrency, setBountyCurrency] = useState(finding.bounty_currency || 'USD');
  const [alreadyReported, setAlreadyReported] = useState(finding.already_reported || false);
  const [savingBounty, setSavingBounty] = useState(false);
  const [sanitizePII, setSanitizePII] = useState(() => sanitizePiiFromVisibility(isPIIVisible()));
  const [remediation, setRemediation] = useState<RemediationSuggestion[]>([]);
  const [loadingRemediation, setLoadingRemediation] = useState(false);
  const [submitDialogOpen, setSubmitDialogOpen] = useState(false);
  const toast = useToast();
  const features = useOptionalFeatures();

  useEffect(() => {
    setBountyValue(finding.bounty_value || 0);
    setBountySource(finding.bounty_source || 'estimate');
    setBountyCurrency(finding.bounty_currency || 'USD');
    setAlreadyReported(finding.already_reported || false);
  }, [finding]);

  const handleSaveBounty = async () => {
    setSavingBounty(true);
    try {
      const { updateFinding } = await import('../../../api/findings');
      await updateFinding(finding.id, {
        bounty_value: bountyValue,
        bounty_source: bountySource as 'hackerone' | 'bugcrowd' | 'intigriti' | 'synack' | 'estimate' | 'manual',
        bounty_currency: bountyCurrency,
        already_reported: alreadyReported,
      });
      toast.success('Bounty details saved successfully');
    } catch {
      toast.error('Failed to save bounty details');
    } finally {
      setSavingBounty(false);
    }
  };

  useEffect(() => {
    const handleEsc = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', handleEsc);
    return () => window.removeEventListener('keydown', handleEsc);
  }, [onClose]);

  useEffect(() => {
    if (!finding.id) return;
    if (remediationCache.has(finding.id)) {
      setRemediation(remediationCache.get(finding.id) || []);
      setLoadingRemediation(false);
      return;
    }
    let mounted = true;
    Promise.resolve().then(() => {
      if (mounted) setLoadingRemediation(true);
    });
    getFindingRemediation(finding.id)
      .then((res: { suggestions: RemediationSuggestion[] }) => {
        if (mounted) {
          const suggestions = res.suggestions || [];
          remediationCache.set(finding.id, suggestions);
          setRemediation(suggestions);
          setLoadingRemediation(false);
        }
      })
      .catch(() => {
        if (mounted) {
          setRemediation([]);
          setLoadingRemediation(false);
        }
      });
    return () => { mounted = false; };
  }, [finding.id]);

  const isLogicBreach = finding.type?.startsWith('logic_breach');
  const evidence = finding.evidence as ExtendedEvidence | undefined;
  const runId = String(
    finding.metadata?.run_name || finding.metadata?.job_id || finding.target || 'global',
  );
  const triage = useTriageCollaboration(runId, finding.id);
  const triageStatus = triage.state?.status || finding.lifecycle_state || 'open';

  const recordWorkflowAction = async (
    action: 'finding_escalated' | 'finding_closed' | 'finding_reopened' | 'finding_false_positive',
    payload: Record<string, unknown>,
    successMessage: string,
    errorMessage: string,
  ) => {
    try {
      await triage.sendAction(action, payload);
      toast.success(successMessage);
    } catch {
      toast.error(errorMessage);
    }
  };

  const handleMergeDuplicates = async () => {
    const dupIds = (finding.duplicates || []).filter(Boolean);
    if (dupIds.length === 0) {
      toast.warning('No duplicates to merge');
      return;
    }
    const ok =
      typeof window !== 'undefined'
        ? window.confirm(
            `Merge ${dupIds.length} duplicate(s) into this finding? The duplicates will be marked as resolved duplicates.`,
          )
        : true;
    if (!ok) return;
      const { updateFinding } = await import('../../../api/findings');
    let failed = 0;
    for (const dupId of dupIds) {
      try {
        await updateFinding(dupId, {
          falsePositive: true,
          fpStatus: 'approved',
          fpJustification: `Merged into primary ${finding.id}`,
        });
      } catch {
        failed += 1;
      }
    }
    if (failed === 0) {
      toast.success(`Merged ${dupIds.length} duplicate(s) into this finding`);
    } else {
      toast.warning(`Merged ${dupIds.length - failed}; ${failed} failed`);
    }
  };

  const handleDismissAsDuplicate = async () => {
    if (!finding.id) return;
    const ok =
      typeof window !== 'undefined'
        ? window.confirm(
            'Mark this finding as a duplicate and dismiss? It will be hidden from default triage queues.',
          )
        : true;
    if (!ok) return;
      const { updateFinding } = await import('../../../api/findings');
    try {
      await updateFinding(finding.id, {
        falsePositive: true,
        fpStatus: 'approved',
        fpJustification: 'Marked as duplicate by analyst',
      });
      toast.success('Finding dismissed as duplicate');
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Unable to dismiss as duplicate');
    }
  };

  const handlePromoteToIndependent = async () => {
    if (!finding.id) return;
    const ok =
      typeof window !== 'undefined'
        ? window.confirm(
            'Promote this finding to an independent (non-duplicate) entry? The link to its previous primary will be removed.',
          )
        : true;
    if (!ok) return;
      const { updateFinding } = await import('../../../api/findings');
    try {
      await updateFinding(finding.id, { duplicates: [], kanbanStatus: 'new' });
      toast.success('Finding promoted to independent');
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Unable to promote finding');
    }
  };

  const handleExport = async (format: ReportFormat) => {
    try {
      exportFinding(finding, format);
      toast.success(`Exported as ${format.toUpperCase()}`);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Export failed');
    }
  };

  const chainSimulation: AttackChain | null =
    (finding.metadata?.chain_simulation as AttackChain) || evidence?.chain_simulation || null;

  const evidenceItems: EvidenceItem[] = finding.evidence
    ? [
        {
          id: `ev-${finding.id}`,
          timestamp: new Date(parseFindingTimestamp(finding.timestamp) || Date.now()).toISOString(),
          source: 'System Correlation Scanner',
          description: finding.title,
          raw_data: JSON.stringify(finding.evidence, null, 2),
          data_type: 'json',
        },
      ]
    : [];

  const rawPocText = useMemo(() => {
    const severityLabel = finding.severity.toUpperCase();
    const targetUrl = finding.url || finding.host || finding.target || '';
    const description = finding.description || '';
    const pocSteps = finding.proof_of_concept || finding.poc || 'No automated reproduction script recorded.';

    let reqResDump = '';
    if (finding.request_response && finding.request_response.length > 0) {
      reqResDump = finding.request_response
        .map((pair: { request: { body: string; headers: Record<string, string>; method: string; url: string }; response: { body: string; headers: Record<string, string>; status: number } }, idx: number) => {
          let reqBody = pair.request.body || '';
          let resBody = pair.response.body || '';
          let headersStr = Object.entries(pair.request.headers || {})
            .map(([k, v]) => `${k}: ${v}`)
            .join('\n');
          let resHeadersStr = Object.entries(pair.response.headers || {})
            .map(([k, v]) => `${k}: ${v}`)
            .join('\n');

          if (sanitizePII) {
            const sanitizeHeaders = (str: string) =>
              str.replace(
                /(?:cookie|authorization|token|api-key|session-id|passwd|password):\s*[^\r\n]+/gi,
                (m) => {
                  const parts = m.split(':');
                  return `${parts[0]}: [REDACTED_BY_RESEARCHER]`;
                },
              );
            headersStr = sanitizeHeaders(headersStr);
            resHeadersStr = sanitizeHeaders(resHeadersStr);
            reqBody = sanitizeHeaders(reqBody);
            resBody = sanitizeHeaders(resBody);
          }

          return `### HTTP Transaction #${idx + 1}
#### Request
\`\`\`http
${pair.request.method} ${pair.request.url} HTTP/1.1
${headersStr}

${reqBody}
\`\`\`

#### Response
\`\`\`http
HTTP/1.1 ${pair.response.status}
${resHeadersStr}

${resBody.slice(0, 1000)}${resBody.length > 1000 ? '\n... [TRUNCATED] ...' : ''}
\`\`\``;
        })
        .join('\n\n');
    }

    return `# [VULNERABILITY REPORT] ${finding.title}

## Executive Summary
- **Vulnerability Type**: ${finding.type}
- **Severity**: ${severityLabel}
- **CVSS Score**: ${finding.cvss_v4_score ?? finding.cvss_score ?? 'N/A'}
- **Target URL**: ${targetUrl}

## Vulnerability Description
${description}

## Proof of Concept / Reproduction Steps
${pocSteps}

${reqResDump ? `## HTTP Request/Response Evidence\n${reqResDump}` : ''}

## Remediation Guidance
Ensure inputs are strictly validated and output is properly encoded. Apply context-aware mitigation logic.`;
  }, [finding, sanitizePII]);

  const [reviewerId] = useState<string>(() => {
    try {
      return localStorage.getItem('analyst_reviewer_id') || 'analyst';
    } catch {
      return 'analyst';
    }
  });

  const tabs = buildTabs(chainSimulation, isLogicBreach);

  return (
    <div
      className="fixed inset-0 z-[8500] flex items-center justify-center bg-panel backdrop-blur-md p-4"
      onClick={onClose}
      onKeyDown={(e) => { if (e.key === 'Escape') onClose(); }}
      role="presentation"
    >
      <motion.div
        ref={dialogRef}
        initial={{ opacity: 0, scale: 0.9, y: 20 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        className="w-full max-w-4xl max-h-[90vh] bg-bg border border-line rounded-3xl shadow-overlay-lg overflow-hidden flex flex-col"
        onClick={(e: React.MouseEvent) => e.stopPropagation()}
        onKeyDown={handleKeyDown}
        role="dialog"
        aria-modal="true"
        aria-labelledby="finding-detail-title"
      >
        <DetailHeader
          finding={finding}
          onExport={handleExport}
          onSubmit={() => setSubmitDialogOpen(true)}
          onClose={onClose}
        />

        <div className="flex-1 overflow-y-auto p-8 space-y-8 scrollbar-cyber">
          <div className="grid grid-cols-4 gap-4">
            {[
              { label: 'CSI Index', value: displayNumericOrNA(finding.csi_score), cls: 'text-accent' },
              { label: 'Confidence', value: `${confidencePercent(finding.confidence)}%`, cls: 'text-text-primary' },
              { label: 'State', value: triageStatus, cls: 'text-text uppercase' },
              {
                label: 'Severity',
                value: finding.severity,
                cls: finding.severity === 'critical' ? 'text-bad' : 'text-accent',
              },
            ].map((stat) => (
              <div key={stat.label} className="glass-panel p-4 rounded-xl">
                <div className="text-[9px] font-black text-muted uppercase mb-1 tracking-widest">{stat.label}</div>
                <div className={`text-2xl font-black ${stat.cls}`}>
                  {stat.label === 'State' ? (
                    <span className="text-sm font-black">{stat.value}</span>
                  ) : (
                    stat.value
                  )}
                </div>
              </div>
            ))}
          </div>

          <DetailTabs tabs={tabs} activeTab={detailTab} onTabChange={setDetailTab} />

          <div className="min-h-[300px]">
            {detailTab === 'bounty' && (
              <BountyPanel
                finding={finding}
                bountyValue={bountyValue}
                bountyCurrency={bountyCurrency}
                bountySource={bountySource}
                alreadyReported={alreadyReported}
                sanitizePII={sanitizePII}
                savingBounty={savingBounty}
                onBountyValueChange={setBountyValue}
                onBountyCurrencyChange={setBountyCurrency}
                onBountySourceChange={setBountySource}
                onAlreadyReportedChange={setAlreadyReported}
                onSanitizePIIChange={setSanitizePII}
                onSaveBounty={handleSaveBounty}
                onCopyReport={() => {
                  navigator.clipboard.writeText(rawPocText);
                  toast.success('Sanitized markdown report copied to clipboard!');
                }}
              />
            )}

            {detailTab === 'csi' && (
              <div className="space-y-6">
                {features.piiControls && (
                  <PIIControls
                    className="mb-2"
                    onChange={(visible) => setSanitizePII(sanitizePiiFromVisibility(visible))}
                  />
                )}
                <p className="text-sm text-text/80 leading-relaxed italic border-l-2 border-accent/20 pl-4">
                  {finding.description}
                </p>
                {features.threatIntel && (
                  <ThreatIntelPanel
                    cveId={finding.cve || (finding.metadata?.cve_id as string | undefined)}
                    cweId={finding.cwe || (finding.metadata?.cwe_id as string | undefined)}
                  />
                )}
                {features.cvssDetails && <CVSSDetail finding={finding} />}
                {features.remediationTracker && (
                  <RemediationTracker
                    entries={[{
                      id: finding.id,
                      findingType: finding.type,
                      severity: finding.severity,
                      target: finding.target || finding.host || '',
                      detectedAt: String(finding.timestamp ?? ''),
                      status: finding.status === 'closed' ? 'remediated' : finding.status === 'accepted' ? 'accepted' : 'open',
                    }]}
                  />
                )}
                {loadingRemediation ? (
                  <div className="flex items-center gap-2 text-[10px] text-accent animate-pulse uppercase tracking-widest">
                    <div className="w-2 h-2 rounded-full bg-accent" />
                    Fetching Remediation intelligence...
                  </div>
                ) : remediation.length > 0 ? (
                  <div className="grid gap-2">
                    <div className="text-[9px] font-black text-muted uppercase tracking-widest">
                      Remediation Signals
                    </div>
                    {remediation.slice(0, 3).map((item) => (
                      <div key={item.id} className="p-3 bg-surface-2 border border-line rounded-xl">
                        <div className="text-xs font-bold text-text">{item.title}</div>
                        {item.rationale && (
                          <p className="text-[10px] text-muted mt-1">{item.rationale}</p>
                        )}
                      </div>
                    ))}
                  </div>
                ) : null}
              </div>
            )}

            {detailTab === 'logic' && (
              <div className="space-y-4 font-mono text-[11px]">
                <div className="p-4 bg-bad/10 border border-bad/20 rounded-xl mb-4">
                  <p className="text-bad font-black uppercase mb-1">State Machine Divergence Detected</p>
                  <p className="text-text/70">
                    Differential analysis revealed significant identical behavior across distinct contexts.
                  </p>
                </div>
                <pre className="p-6 bg-panel rounded-2xl border border-line text-accent overflow-x-auto whitespace-pre-wrap">
                  {finding.logic_diff || 'No structural diff recorded for this signal.'}
                </pre>
              </div>
            )}

            {detailTab === 'risk' && <RiskPanel finding={finding} reviewerId={reviewerId} />}

            {detailTab === 'evidence' && <EvidenceDisplay evidence={evidenceItems} />}

            {detailTab === 'custody' && (
              <div className="glass-panel p-6 rounded-2xl border border-line">
                <ChainOfCustodyViewer evidenceId={finding.id} source="evidenceChain" />
              </div>
            )}

            {detailTab === 'request' && (
              <RequestResponseViewer pairs={finding.request_response || []} />
            )}

            {detailTab === 'activity' && (
              <div className="space-y-4">
                <div className="text-[10px] text-muted uppercase tracking-widest font-black">Triage Activity</div>
                {triage.state?.chain && (
                  <div className="glass-panel p-4 rounded-xl border border-line text-[10px] font-mono text-muted">
                    Audit chain: {triage.state.chain.valid ? 'verified' : 'invalid'} ·{' '}
                    {triage.state.chain.entries} entries · hash{' '}
                    {triage.state.chain.latest_hash.slice(0, 16)}…
                  </div>
                )}
                {triage.presence.length === 0 ? (
                  <p className="text-[10px] text-muted">No other analysts currently viewing this finding.</p>
                ) : (
                  <ul className="space-y-2">
                    {triage.presence.map((p) => (
                      <li key={p.analyst_id} className="text-xs text-text/80 flex items-center gap-2">
                        <span className="pulse-dot" aria-hidden="true" />
                        <span className="font-mono">{p.analyst_id}</span>
                        <span className="text-muted">
                          — {(p.cursor as { area?: string } | undefined)?.area || 'viewing'}
                        </span>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            )}

            {detailTab === 'comments' && (
              <div className="glass-panel p-6 rounded-2xl border border-line">
                <FindingComments findingId={finding.id} targetName={finding.target} runId={runId} />
              </div>
            )}

            {detailTab === 'simulation' && chainSimulation && (
              <div className="space-y-6">
                <div className="p-4 bg-accent/5 border border-accent/20 rounded-2xl flex items-center gap-4">
                  <div className="h-10 w-10 rounded-full bg-accent/10 grid place-items-center text-accent">
                    <Zap size={20} />
                  </div>
                  <div>
                    <h4 className="text-sm font-black uppercase tracking-widest">
                      Automated Kill-Chain Simulation
                    </h4>
                    <p className="text-[10px] text-muted leading-relaxed">
                      System correlation identified a potential multi-stage attack path based on this finding.
                    </p>
                  </div>
                </div>
                <AttackChainVisualizer chains={[chainSimulation]} />
              </div>
            )}
          </div>
        </div>

        <DetailFooter
          target={finding.target || ''}
          url={finding.url}
          triageStatus={triageStatus}
          duplicates={finding.duplicates || []}
          onReplay={() => {
            const runName = finding.metadata?.run_name || finding.metadata?.job_id || '';
            const replayId = finding.metadata?.replay_id || evidence?.replay?.id || '';
            window.location.href = `/replay?target=${finding.target}&run=${runName}&replay_id=${replayId}&finding=${finding.id}`;
          }}
          onCockpitView={() => {
            window.location.href = `/cockpit?target=${finding.target}&focus=${finding.id}`;
          }}
          onForensicProbe={async () => {
            if (!finding.target || !finding.url) {
              toast.error('Missing target or URL for forensic probing');
              return;
            }
            try {
              const { cockpitApi } = await import('@/api/cockpit');
              await cockpitApi.triggerProbe(finding.target, finding.url);
              toast.success('Manual forensic probe launched');
            } catch {
              toast.error('Probe sequence failed');
            }
          }}
          onEscalate={() =>
            recordWorkflowAction(
              'finding_escalated',
              { severity: finding.severity, confidence: finding.confidence, reason: 'Manual analyst escalation' },
              'Finding escalated for review',
              'Unable to escalate finding',
            )
          }
          onClose={() =>
            recordWorkflowAction(
              'finding_closed',
              { resolution: 'Manual analyst closure', previous_state: triageStatus },
              'Finding closed for the team',
              'Unable to close finding',
            )
          }
          onReopen={() =>
            recordWorkflowAction(
              'finding_reopened',
              { previous_state: triageStatus, reason: 'Manual analyst reopen' },
              'Finding reopened',
              'Unable to reopen finding',
            )
          }
          onFalsePositive={() =>
            recordWorkflowAction(
              'finding_false_positive',
              {
                category: String(finding.metadata?.category || finding.type || finding.metadata?.module || 'manual_triage'),
                status_code: finding.metadata?.response_status || finding.metadata?.status_code,
                description: finding.description,
                evidence: JSON.stringify(finding.evidence || {}),
              },
              'False-positive pattern shared with the mesh',
              'Unable to record false-positive triage',
            )
          }
          onMergeDuplicates={handleMergeDuplicates}
          onDismissAsDuplicate={handleDismissAsDuplicate}
          onPromoteToIndependent={handlePromoteToIndependent}
        />
      </motion.div>

      <SubmitToPlatformDialog
        runId={runId}
        findingId={finding.id}
        findingTitle={finding.title}
        open={submitDialogOpen}
        onClose={() => setSubmitDialogOpen(false)}
        onSubmitted={(res) => {
          if (res.submitted && res.url) {
            toast.success(`Submitted to ${res.platform}: ${res.url}`);
          } else if (res.submitted) {
            toast.success(`Draft saved to ${res.platform}`);
          } else {
            toast.error(`Submission to ${res.platform} failed: ${res.error || 'unknown error'}`);
          }
        }}
      />
    </div>
  );
}
