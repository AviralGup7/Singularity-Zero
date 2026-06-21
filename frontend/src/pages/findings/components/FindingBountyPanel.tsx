import { useState, useMemo, useEffect } from 'react';
import { Link } from 'react-router-dom';
import type { Finding } from '@/types/api';
import { useToast } from '@/hooks/useToast';
import { useScopeStore } from '@/stores/scopeStore';
import { classifyAgainstScope } from '@/utils/scopeParser';

interface FindingBountyPanelProps {
  finding: Finding;
  onUpdateFinding: (updated: Partial<Finding>) => void;
}

function estimateBounty(score: number, epss: number, criticality: number): { min: number; max: number } {
  let min = 0;
  let max = 0;
  if (score >= 9.0) {
    min = 2000;
    max = 10000;
  } else if (score >= 7.0) {
    min = 500;
    max = 2000;
  } else if (score >= 4.0) {
    min = 100;
    max = 500;
  } else if (score > 0) {
    min = 50;
    max = 100;
  }

  let multiplier = 1.0;
  if (epss > 0.1) multiplier += 0.2;
  if (criticality > 1.0) multiplier += (criticality - 1.0);

  return {
    min: Math.round(min * multiplier),
    max: Math.round(max * multiplier),
  };
}

export function FindingBountyPanel({ finding, onUpdateFinding }: FindingBountyPanelProps) {
  const toast = useToast();
  const [bountyValue, setBountyValue] = useState(finding.bounty_value || 0);
  const [bountySource, setBountySource] = useState<string>(finding.bounty_source || 'estimate');
  const [bountyCurrency, setBountyCurrency] = useState(finding.bounty_currency || 'USD');
  const [alreadyReported, setAlreadyReported] = useState(finding.already_reported || false);
  const [savingBounty, setSavingBounty] = useState(false);
  const [sanitizePII, setSanitizePII] = useState(true);

  useEffect(() => {
    setBountyValue(finding.bounty_value || 0);
    setBountySource(finding.bounty_source || 'estimate');
    setBountyCurrency(finding.bounty_currency || 'USD');
    setAlreadyReported(finding.already_reported || false);
  }, [finding]);

  const parsedScope = useScopeStore((s) => s.parsed);
  const scopeClassification = useMemo(() => {
    const asset = finding.url || finding.host || finding.target || '';
    return classifyAgainstScope(asset, parsedScope);
  }, [finding, parsedScope]);

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
      onUpdateFinding({
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

  const rawPocText = useMemo(() => {
    const severityLabel = finding.severity.toUpperCase();
    const targetUrl = finding.url || finding.host || finding.target || '';
    const description = finding.description || '';
    const pocSteps = finding.proof_of_concept || finding.poc || 'No automated reproduction script recorded.';
    
    let reqResDump = '';
    if (finding.request_response && finding.request_response.length > 0) {
      reqResDump = finding.request_response.map((pair, idx) => {
        let reqBody = pair.request.body || '';
        let resBody = pair.response.body || '';
        
        let headersStr = Object.entries(pair.request.headers || {})
          .map(([k, v]) => `${k}: ${v}`)
          .join('\n');
          
        let resHeadersStr = Object.entries(pair.response.headers || {})
          .map(([k, v]) => `${k}: ${v}`)
          .join('\n');

        if (sanitizePII) {
          const sanitizeHeaders = (str: string) => str.replace(/(?:cookie|authorization|token|api-key|session-id|passwd|password):\s*[^\r\n]+/gi, (m) => {
            const parts = m.split(':');
            return `${parts[0]}: [REDACTED_BY_RESEARCHER]`;
          });
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
      }).join('\n\n');
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

  return (
    <div className="space-y-6" data-testid="finding-bounty-panel">
      {/* Scope Status */}
      <div className="glass-panel border border-white/5 rounded-xl p-4">
        <div className="text-[10px] font-black uppercase tracking-widest text-muted mb-2">Scope Compliance Rules</div>
        {scopeClassification.status === 'in_scope' ? (
          <div className="p-3 bg-ok/10 border border-ok/20 rounded-lg text-xs text-ok flex flex-col gap-1">
            <span className="font-bold">✓ IN SCOPE</span>
            <span className="text-[10px] text-text/80 leading-normal">
              Matches pattern: <code className="bg-black/40 px-1 rounded">{scopeClassification.matchingEntry?.pattern}</code>
            </span>
            {scopeClassification.matchingEntry?.notes && (
              <p className="text-[9px] text-muted italic mt-1">Notes: {scopeClassification.matchingEntry.notes}</p>
            )}
          </div>
        ) : scopeClassification.status === 'out_of_scope' ? (
          <div className="p-3 bg-bad/10 border border-bad/20 rounded-lg text-xs text-bad flex flex-col gap-1 animate-pulse">
            <span className="font-bold">⚠️ OUT OF SCOPE WARNING</span>
            <span className="text-[10px] text-text/80 leading-normal">
              Matches pattern: <code className="bg-black/40 px-1 rounded text-bad">{scopeClassification.matchingEntry?.pattern}</code>
            </span>
            <p className="text-[9px] text-muted italic mt-1">Caution: Submission of this asset may result in negative reputation or ban.</p>
          </div>
        ) : (
          <div className="p-3 bg-zinc-900/40 border border-white/5 rounded-lg text-xs text-muted flex flex-col gap-1">
            <span className="font-bold">? NO SCOPE DATA IMPORTED</span>
            <span className="text-[10px] text-muted leading-normal">
              Verify with the target's program policy manually before submitting.
            </span>
          </div>
        )}
      </div>

      {/* Bounty Payout Estimator & Manual override */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="glass-panel border border-white/5 rounded-xl p-4 space-y-4">
          <div>
            <div className="text-[10px] font-black uppercase tracking-widest text-muted mb-1">CVSS-to-Bounty Estimator</div>
            <div className="text-sm font-semibold text-text">Estimated Payout Range:</div>
            {(() => {
              const score = finding.cvss_v4_score ?? finding.cvss_score ?? 0;
              const epss = finding.threat_intel?.epss_score ?? finding.epss_score ?? 0;
              const criticality = finding.asset_criticality ?? 1.0;
              const range = estimateBounty(score, epss, criticality);
              return (
                <div className="mt-2 flex items-baseline gap-2">
                  <span className="text-3xl font-black text-accent">${range.min.toLocaleString()}</span>
                  <span className="text-muted text-xs font-mono">—</span>
                  <span className="text-3xl font-black text-accent">${range.max.toLocaleString()}</span>
                  <span className="text-[10px] font-mono text-muted uppercase">USD</span>
                </div>
              );
            })()}
            <div className="text-[9px] text-muted font-mono mt-2 leading-relaxed">
              EPSS Multiplier: {(finding.threat_intel?.epss_score ?? finding.epss_score ?? 0) > 0.1 ? '1.20x (+20% Wild Activity)' : '1.00x'} <br />
              Asset Multiplier: {finding.asset_criticality ? `${finding.asset_criticality.toFixed(2)}x` : '1.00x'}
            </div>
          </div>

          <div className="pt-2 border-t border-white/5 space-y-3">
            <div className="text-[10px] font-black uppercase tracking-widest text-muted">Bounty Custom Details</div>
            <div className="grid grid-cols-3 gap-2">
              <label className="block text-[10px] text-muted">
                Amount ($)
                <input
                  type="number"
                  value={bountyValue}
                  onChange={(e) => setBountyValue(Number(e.target.value))}
                  className="w-full mt-1 bg-white/5 border border-white/10 rounded-lg py-1.5 px-2 text-xs font-mono text-text focus:border-accent/50 outline-none"
                />
              </label>
              <label className="block text-[10px] text-muted">
                Currency
                <input
                  type="text"
                  value={bountyCurrency}
                  onChange={(e) => setBountyCurrency(e.target.value)}
                  className="w-full mt-1 bg-white/5 border border-white/10 rounded-lg py-1.5 px-2 text-xs font-mono text-text focus:border-accent/50 outline-none uppercase"
                />
              </label>
              <label className="block text-[10px] text-muted">
                Platform
                <select
                  value={bountySource}
                  onChange={(e) => setBountySource(e.target.value)}
                  className="w-full mt-1 bg-[#151515] border border-white/10 rounded-lg py-1.5 px-2 text-xs font-mono text-text focus:border-accent/50 outline-none"
                >
                  <option value="estimate">Estimate</option>
                  <option value="hackerone">HackerOne</option>
                  <option value="bugcrowd">Bugcrowd</option>
                  <option value="intigriti">Intigriti</option>
                  <option value="synack">Synack</option>
                  <option value="manual">Manual</option>
                </select>
              </label>
            </div>
            <div className="flex justify-between items-center gap-4 pt-1">
              <label className="flex items-center gap-2 text-[10px] text-muted cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={alreadyReported}
                  onChange={(e) => setAlreadyReported(e.target.checked)}
                  className="accent-accent"
                />
                Already Submitted
              </label>
              <button
                type="button"
                onClick={handleSaveBounty}
                disabled={savingBounty}
                className="px-3 py-1.5 rounded-lg bg-accent/20 border border-accent/40 text-accent font-black text-[9px] uppercase tracking-widest hover:bg-accent/30 transition-all cursor-pointer disabled:opacity-50"
              >
                {savingBounty ? 'Saving...' : 'Save Details'}
              </button>
            </div>
          </div>
        </div>

        {/* Proof of Concept Exporter */}
        <div className="glass-panel border border-white/5 rounded-xl p-4 flex flex-col justify-between">
          <div className="space-y-3">
            <div className="text-[10px] font-black uppercase tracking-widest text-muted">POC Report Builder</div>
            <p className="text-[10px] text-muted leading-relaxed">
              Export reproduction packages, evidence lists, and HTTP dumps formatted as bug-bounty markdown reports.
            </p>
            <label className="flex items-center gap-2 text-[10px] text-muted cursor-pointer select-none pt-1">
              <input
                type="checkbox"
                checked={sanitizePII}
                onChange={(e) => setSanitizePII(e.target.checked)}
                className="accent-accent"
              />
              Mask PII (Authorization, Cookies)
            </label>
          </div>
          <div className="flex gap-2 mt-4 pt-3 border-t border-white/5">
            <button
              type="button"
              className="flex-1 px-3 py-2 rounded-lg bg-accent text-black font-black text-[10px] uppercase tracking-widest hover:bg-accent-dim transition-all cursor-pointer flex items-center justify-center gap-1 shadow-[0_0_15px_rgba(0,255,65,0.2)]"
              onClick={() => {
                navigator.clipboard.writeText(rawPocText);
                toast.success('Sanitized markdown report copied to clipboard!');
              }}
            >
              Copy Report (MD)
            </button>
            <Link
              to={`/reports/builder?finding=${finding.id}`}
              className="flex-1 px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-white font-black text-[10px] uppercase tracking-widest hover:bg-white/10 transition-all cursor-pointer flex items-center justify-center gap-1"
            >
              Report Bundle
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}
