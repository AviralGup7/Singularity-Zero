import type { Finding } from '@/types/api';

export type ReportFormat = 'markdown' | 'html' | 'json';

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function safe(s: string | number | undefined | null): string {
  if (s === undefined || s === null) return 'N/A';
  return String(s);
}

function formatRequest(req: { method?: string; url?: string; headers?: Record<string, string>; body?: string } | undefined): string {
  if (!req) return 'N/A';
  const headerLines = Object.entries(req.headers || {})
    .map(([k, v]) => `${k}: ${v}`)
    .join('\n');
  return `${req.method || 'GET'} ${req.url || '/'} HTTP/1.1\n${headerLines}\n\n${req.body || ''}`;
}

function formatResponse(res: { status?: number; headers?: Record<string, string>; body?: string } | undefined): string {
  if (!res) return 'N/A';
  const headerLines = Object.entries(res.headers || {})
    .map(([k, v]) => `${k}: ${v}`)
    .join('\n');
  return `HTTP/1.1 ${res.status || 200}\n${headerLines}\n\n${res.body || ''}`;
}

function csiLevel(finding: Finding): string {
  const score = finding.csi_score ?? 0;
  if (score >= 80) return 'Critical';
  if (score >= 60) return 'High';
  if (score >= 40) return 'Medium';
  if (score >= 20) return 'Low';
  return 'Info';
}

function downloadBlob(filename: string, content: string, mime: string) {
  if (typeof document === 'undefined') return;
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export function buildMarkdownReport(finding: Finding): string {
  const cvss = finding.cvss ?? finding.cvss_score ?? 'N/A';
  const lines: string[] = [];
  lines.push(`# ${safe(finding.title)}`);
  lines.push('');
  lines.push(`**Severity:** ${safe(finding.severity).toUpperCase()}`);
  lines.push(`**Target:** ${safe(finding.target)}`);
  lines.push(`**Type:** ${safe(finding.type)}`);
  lines.push(`**CVSS:** ${safe(cvss)}`);
  lines.push(`**CSI Score:** ${safe(finding.csi_score)} (${csiLevel(finding)})`);
  lines.push(`**Confidence:** ${Math.round((finding.confidence ?? 0) * 100)}%`);
  lines.push(`**Status:** ${safe(finding.status)}`);
  if (finding.bounty_value) {
    lines.push(`**Bounty:** $${finding.bounty_value.toLocaleString()}${finding.bounty_currency ? ' ' + finding.bounty_currency : ''}`);
  }
  lines.push(`**Discovered:** ${safe(finding.timestamp)}`);
  lines.push(`**Finding ID:** ${safe(finding.id)}`);
  lines.push('');
  lines.push('## Description');
  lines.push('');
  lines.push(finding.description || 'No description provided.');
  lines.push('');
  if (finding.proof_of_concept || finding.poc) {
    lines.push('## Proof of Concept');
    lines.push('');
    lines.push('```');
    lines.push(safe(finding.proof_of_concept || finding.poc));
    lines.push('```');
    lines.push('');
  }
  if (finding.remediation && finding.remediation.length > 0) {
    lines.push('## Remediation');
    lines.push('');
    finding.remediation.forEach((r, idx) => {
      lines.push(`${idx + 1}. ${r}`);
    });
    lines.push('');
  }
  if (finding.request_response && finding.request_response.length > 0) {
    lines.push('## Payloads (Request / Response)');
    lines.push('');
    finding.request_response.slice(0, 3).forEach((pair, idx) => {
      lines.push(`### Pair ${idx + 1}`);
      lines.push('```http');
      lines.push(formatRequest(pair.request));
      lines.push('---');
      lines.push(formatResponse(pair.response));
      lines.push('```');
      lines.push('');
    });
  }
  return lines.join('\n');
}

export function buildHtmlReport(finding: Finding): string {
  const cvss = finding.cvss ?? finding.cvss_score ?? 'N/A';
  const facts: Array<[string, string]> = [
    ['Severity', safe(finding.severity).toUpperCase()],
    ['Target', safe(finding.target)],
    ['Type', safe(finding.type)],
    ['CVSS', safe(cvss)],
    ['CSI Score', `${safe(finding.csi_score)} (${csiLevel(finding)})`],
    ['Confidence', `${Math.round((finding.confidence ?? 0) * 100)}%`],
    ['Status', safe(finding.status)],
    ['Discovered', safe(finding.timestamp)],
    ['Finding ID', safe(finding.id)],
  ];
  if (finding.bounty_value) {
    facts.push(['Bounty', `$${finding.bounty_value.toLocaleString()}${finding.bounty_currency ? ' ' + finding.bounty_currency : ''}`]);
  }
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>${escapeHtml(safe(finding.title))}</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; max-width: 880px; margin: 32px auto; padding: 0 24px; color: #1a1a1a; line-height: 1.55; }
  h1 { border-bottom: 2px solid #2563eb; padding-bottom: 8px; }
  .sev-critical { color: #b91c1c; font-weight: 700; }
  .sev-high { color: #c2410c; font-weight: 700; }
  .sev-medium { color: #b45309; font-weight: 700; }
  .sev-low { color: #1d4ed8; font-weight: 700; }
  .sev-info { color: #475569; font-weight: 700; }
  table.facts { width: 100%; border-collapse: collapse; margin: 16px 0 24px; }
  table.facts th, table.facts td { text-align: left; padding: 8px 12px; border: 1px solid #e5e7eb; font-size: 14px; }
  table.facts th { background: #f8fafc; width: 30%; }
  pre { background: #0f172a; color: #e2e8f0; padding: 16px; border-radius: 6px; overflow-x: auto; font-size: 13px; }
  h2 { margin-top: 32px; }
  .meta { color: #64748b; font-size: 13px; }
</style>
</head>
<body>
  <h1>${escapeHtml(safe(finding.title))}</h1>
  <p class="meta"><span class="sev-${escapeHtml(safe(finding.severity).toLowerCase())}">${escapeHtml(safe(finding.severity).toUpperCase())}</span> &middot; ${escapeHtml(safe(finding.type))} on ${escapeHtml(safe(finding.target))}</p>
  <table class="facts">
    <tbody>
      ${facts.map(([k, v]) => `<tr><th>${escapeHtml(k)}</th><td>${escapeHtml(v)}</td></tr>`).join('')}
    </tbody>
  </table>
  <h2>Description</h2>
  <p>${escapeHtml(finding.description || 'No description provided.')}</p>
  ${finding.proof_of_concept || finding.poc ? `<h2>Proof of Concept</h2><pre>${escapeHtml(safe(finding.proof_of_concept || finding.poc))}</pre>` : ''}
  ${finding.remediation && finding.remediation.length > 0
    ? `<h2>Remediation</h2><ol>${finding.remediation.map(r => `<li>${escapeHtml(r)}</li>`).join('')}</ol>`
    : ''}
  ${finding.request_response && finding.request_response.length > 0
    ? `<h2>Payloads (Request / Response)</h2>${finding.request_response.slice(0, 3).map((pair, idx) => `<h3>Pair ${idx + 1}</h3><pre>${escapeHtml(formatRequest(pair.request))}\n---\n${escapeHtml(formatResponse(pair.response))}</pre>`).join('')}`
    : ''}
</body>
</html>`;
}

export function buildJsonReport(finding: Finding): string {
  return JSON.stringify(finding, null, 2);
}

export function exportFinding(finding: Finding, format: ReportFormat): void {
  const safeId = String(finding.id || 'finding').replace(/[^a-zA-Z0-9._-]/g, '_');
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const base = `finding-${safeId}-${stamp}`;
  if (format === 'markdown') {
    downloadBlob(`${base}.md`, buildMarkdownReport(finding), 'text/markdown;charset=utf-8');
  } else if (format === 'html') {
    downloadBlob(`${base}.html`, buildHtmlReport(finding), 'text/html;charset=utf-8');
  } else {
    downloadBlob(`${base}.json`, buildJsonReport(finding), 'application/json;charset=utf-8');
  }
}

export const exportFindingAsMarkdown = (finding: Finding) => exportFinding(finding, 'markdown');
export const exportFindingAsHtml = (finding: Finding) => exportFinding(finding, 'html');
export const exportFindingAsJson = (finding: Finding) => exportFinding(finding, 'json');

export interface ReportMeta {
  title?: string;
  author?: string;
  scope?: string;
  generatedAt?: string;
}

function severityRank(sev: string | undefined): number {
  switch ((sev || '').toLowerCase()) {
    case 'critical': return 5;
    case 'high':     return 4;
    case 'medium':   return 3;
    case 'low':      return 2;
    case 'info':     return 1;
    default:         return 0;
  }
}

function sortedFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => severityRank(b.severity) - severityRank(a.severity));
}

export function buildMarkdownReportBundle(findings: Finding[], meta: ReportMeta = {}): string {
  const list = sortedFindings(findings);
  const lines: string[] = [];
  const title = meta.title || `Pentest Report — ${new Date().toISOString().split('T')[0]}`;
  lines.push(`# ${title}`);
  lines.push('');
  lines.push(`**Generated:** ${meta.generatedAt || new Date().toISOString()}`);
  if (meta.author) lines.push(`**Author:** ${meta.author}`);
  if (meta.scope) lines.push(`**Scope:** ${meta.scope}`);
  lines.push(`**Findings:** ${list.length}`);
  lines.push('');
  lines.push('## Executive Summary');
  lines.push('');
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  list.forEach(f => {
    const k = (f.severity || 'info').toLowerCase() as keyof typeof counts;
    // eslint-disable-next-line security/detect-object-injection
    if (k in counts) counts[k] += 1;
  });
  lines.push(`- Critical: ${counts.critical}`);
  lines.push(`- High: ${counts.high}`);
  lines.push(`- Medium: ${counts.medium}`);
  lines.push(`- Low: ${counts.low}`);
  lines.push(`- Info: ${counts.info}`);
  lines.push('');
  lines.push('## Table of Contents');
  list.forEach((f, idx) => {
    lines.push(`${idx + 1}. [${safe(f.title)}](#finding-${idx + 1})`);
  });
  lines.push('');
  list.forEach((f, idx) => {
    lines.push('---');
    lines.push('');
    lines.push(`<a id="finding-${idx + 1}"></a>`);
    lines.push(`## ${idx + 1}. ${safe(f.title)}`);
    lines.push('');
    lines.push(`**Severity:** ${safe(f.severity).toUpperCase()}`);
    lines.push(`**Target:** ${safe(f.target)}`);
    lines.push(`**Type:** ${safe(f.type)}`);
    lines.push(`**CVSS:** ${safe(f.cvss ?? f.cvss_score)}`);
    lines.push(`**CSI Score:** ${safe(f.csi_score)} (${csiLevel(f)})`);
    lines.push(`**Confidence:** ${Math.round((f.confidence ?? 0) * 100)}%`);
    lines.push(`**Status:** ${safe(f.status)}`);
    lines.push(`**Finding ID:** ${safe(f.id)}`);
    lines.push('');
    lines.push(f.description || 'No description provided.');
    if (f.proof_of_concept || f.poc) {
      lines.push('');
      lines.push('### Proof of Concept');
      lines.push('```');
      lines.push(safe(f.proof_of_concept || f.poc));
      lines.push('```');
    }
    if (f.remediation && f.remediation.length > 0) {
      lines.push('');
      lines.push('### Remediation');
      f.remediation.forEach((r, rIdx) => lines.push(`${rIdx + 1}. ${r}`));
    }
    lines.push('');
  });
  return lines.join('\n');
}

export function buildHtmlReportBundle(findings: Finding[], meta: ReportMeta = {}): string {
  const list = sortedFindings(findings);
  const title = meta.title || `Pentest Report — ${new Date().toISOString().split('T')[0]}`;
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  list.forEach(f => {
    const k = (f.severity || 'info').toLowerCase() as keyof typeof counts;
    // eslint-disable-next-line security/detect-object-injection
    if (k in counts) counts[k] += 1;
  });
  const findingsHtml = list.map((f, idx) => {
    const cvss = f.cvss ?? f.cvss_score ?? 'N/A';
    return `<article class="finding" id="finding-${idx + 1}">
      <h2>${idx + 1}. ${escapeHtml(safe(f.title))}</h2>
      <p class="meta">
        <span class="sev sev-${escapeHtml(safe(f.severity).toLowerCase())}">${escapeHtml(safe(f.severity).toUpperCase())}</span>
        &middot; ${escapeHtml(safe(f.type))} on ${escapeHtml(safe(f.target))}
        &middot; CVSS ${escapeHtml(safe(cvss))}
        &middot; CSI ${escapeHtml(safe(f.csi_score))} (${escapeHtml(csiLevel(f))})
      </p>
      <table class="facts"><tbody>
        <tr><th>Confidence</th><td>${Math.round((f.confidence ?? 0) * 100)}%</td></tr>
        <tr><th>Status</th><td>${escapeHtml(safe(f.status))}</td></tr>
        <tr><th>Finding ID</th><td><code>${escapeHtml(safe(f.id))}</code></td></tr>
        ${f.bounty_value ? `<tr><th>Bounty</th><td>$${f.bounty_value.toLocaleString()}${f.bounty_currency ? ' ' + escapeHtml(f.bounty_currency) : ''}</td></tr>` : ''}
      </tbody></table>
      <h3>Description</h3>
      <p>${escapeHtml(f.description || 'No description provided.')}</p>
      ${f.proof_of_concept || f.poc ? `<h3>Proof of Concept</h3><pre>${escapeHtml(safe(f.proof_of_concept || f.poc))}</pre>` : ''}
      ${f.remediation && f.remediation.length > 0
        ? `<h3>Remediation</h3><ol>${f.remediation.map(r => `<li>${escapeHtml(r)}</li>`).join('')}</ol>`
        : ''}
    </article>`;
  }).join('\n');
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>${escapeHtml(title)}</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; max-width: 980px; margin: 32px auto; padding: 0 24px; color: #1a1a1a; line-height: 1.55; }
  h1 { border-bottom: 3px solid #2563eb; padding-bottom: 8px; }
  h2 { margin-top: 32px; border-bottom: 1px solid #e5e7eb; padding-bottom: 4px; }
  .summary { display: flex; gap: 12px; flex-wrap: wrap; margin: 16px 0; }
  .summary .pill { padding: 4px 12px; border-radius: 999px; font-size: 12px; font-weight: 600; }
  .summary .pill--critical { background: #fee2e2; color: #b91c1c; }
  .summary .pill--high { background: #ffedd5; color: #c2410c; }
  .summary .pill--medium { background: #fef3c7; color: #b45309; }
  .summary .pill--low { background: #dbeafe; color: #1d4ed8; }
  .summary .pill--info { background: #e2e8f0; color: #475569; }
  .finding { margin: 32px 0; padding: 16px 20px; border: 1px solid #e5e7eb; border-radius: 8px; background: #fff; }
  .finding h2 { margin-top: 0; border: 0; }
  .meta { color: #64748b; font-size: 13px; margin: 0 0 12px; }
  .sev-critical { color: #b91c1c; font-weight: 700; }
  .sev-high { color: #c2410c; font-weight: 700; }
  .sev-medium { color: #b45309; font-weight: 700; }
  .sev-low { color: #1d4ed8; font-weight: 700; }
  .sev-info { color: #475569; font-weight: 700; }
  table.facts { width: 100%; border-collapse: collapse; margin: 12px 0 16px; }
  table.facts th, table.facts td { text-align: left; padding: 6px 10px; border: 1px solid #e5e7eb; font-size: 13px; }
  table.facts th { background: #f8fafc; width: 30%; }
  pre { background: #0f172a; color: #e2e8f0; padding: 14px; border-radius: 6px; overflow-x: auto; font-size: 12px; }
  .toc a { text-decoration: none; color: #2563eb; }
  .toc li { margin: 2px 0; }
</style>
</head>
<body>
  <h1>${escapeHtml(title)}</h1>
  <p class="meta">
    Generated: ${escapeHtml(meta.generatedAt || new Date().toISOString())}
    ${meta.author ? `&middot; Author: ${escapeHtml(meta.author)}` : ''}
    ${meta.scope ? `&middot; Scope: ${escapeHtml(meta.scope)}` : ''}
  </p>
  <h2>Executive Summary</h2>
  <div class="summary">
    <span class="pill pill--critical">${counts.critical} Critical</span>
    <span class="pill pill--high">${counts.high} High</span>
    <span class="pill pill--medium">${counts.medium} Medium</span>
    <span class="pill pill--low">${counts.low} Low</span>
    <span class="pill pill--info">${counts.info} Info</span>
  </div>
  <h2>Table of Contents</h2>
  <ol class="toc">
    ${list.map((f, idx) => `<li><a href="#finding-${idx + 1}">${escapeHtml(safe(f.title))}</a></li>`).join('')}
  </ol>
  <h2>Findings</h2>
  ${findingsHtml}
</body>
</html>`;
}

export function buildJsonReportBundle(findings: Finding[], meta: ReportMeta = {}): string {
  return JSON.stringify(
    {
      meta: {
        title: meta.title || `Pentest Report — ${new Date().toISOString().split('T')[0]}`,
        author: meta.author,
        scope: meta.scope,
        generatedAt: meta.generatedAt || new Date().toISOString(),
        findingCount: findings.length,
      },
      findings: sortedFindings(findings),
    },
    null,
    2,
  );
}

export function exportReportBundle(findings: Finding[], format: ReportFormat, meta: ReportMeta = {}): void {
  if (findings.length === 0) return;
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const base = `report-${stamp}`;
  if (format === 'markdown') {
    downloadBlob(`${base}.md`, buildMarkdownReportBundle(findings, meta), 'text/markdown;charset=utf-8');
  } else if (format === 'html') {
    downloadBlob(`${base}.html`, buildHtmlReportBundle(findings, meta), 'text/html;charset=utf-8');
  } else {
    downloadBlob(`${base}.json`, buildJsonReportBundle(findings, meta), 'application/json;charset=utf-8');
  }
}
