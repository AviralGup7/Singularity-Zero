/**
 * Strategy-pattern exporters for findings. Each exporter implements a single
 * method (`export`) that takes the selection and returns a `Blob` (or
 * initiates a download). The UI layer (`useExporters`) is a thin wrapper
 * that lets the operator pick an exporter from a dropdown.
 *
 * Existing CSV/JSON export continues to work via the `csv`/`json`
 * strategies, which mirror the legacy `useExport` behavior exactly. The
 * new `jira`, `hackerone`, `bugcrowd`, `intigriti`, `synack`, `burp`,
 * and `postman` strategies emit structured documents the operator can
 * drop straight into those platforms:
 *
 *   - Jira:    CSV header matches Jira's bulk-create import format
 *   - HackerOne: Markdown report template with the platform's required
 *                sections (Title, Severity, Weakness, Summary, Steps,
 *                Impact, Remediation)
 *   - Bugcrowd: Markdown with the platform's submission fields
 *                (Category, Description, Reproduction Steps, Impact,
 *                Remediation Plan)
 *   - Intigriti: Markdown with the platform's required sections
 *                (Description, Steps, Impact, Remediation, Mitigation)
 *   - Synack:   Markdown matching Synack's submission template
 *                (Vulnerability Description, Reproduction Steps,
 *                Business Impact, Suggested Fix)
 *   - Burp:    XML in Burp's findings-list format (Issues → Issue → ...)
 *   - Postman: JSON v2.1 collection with the report attached as a body
 *
 * Integrations stay strategy-local: no network calls are made from the
 * exporter. The operator saves the file and uploads it through the
 * platform's own importer. This keeps the surface area small and
 * reviewable.
 */

import type { Finding } from '@/types/api';

export type ExporterFormat =
  | 'csv'
  | 'json'
  | 'jira'
  | 'hackerone'
  | 'bugcrowd'
  | 'intigriti'
  | 'synack'
  | 'burp'
  | 'postman';

export interface ExporterContext {
  findings: Finding[];
  filename: string;
  /** When true, the operator has explicitly opted in to include PII fields. */
  includePII?: boolean;
  /** Optional metadata for the run/scan/program. */
  context?: {
    target?: string;
    program?: string;
    jobId?: string;
  };
}

export interface ExportArtifact {
  blob: Blob;
  filename: string;
  mime: string;
}

export type ExporterFn = (ctx: ExporterContext) => ExportArtifact;

const PII_KEYS = ['email', 'phone', 'ssn', 'password', 'token', 'api_key', 'secret', 'ip_address', 'username'];

function stripPII(rows: Record<string, unknown>[]): Record<string, unknown>[] {
  return rows.map((row) => {
    const cleaned: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(row)) {
      if (PII_KEYS.some((pii) => k.toLowerCase().includes(pii))) {
        Reflect.set(cleaned, k, '[REDACTED]');
      } else {
        Reflect.set(cleaned, k, v);
      }
    }
    return cleaned;
  });
}

function toRecords(findings: Finding[], includePII: boolean): Record<string, unknown>[] {
  const records = findings.map((f) => ({
    id: f.id,
    type: f.type,
    title: f.title,
    description: f.description,
    severity: f.severity,
    confidence: f.confidence,
    url: f.url,
    host: f.host,
    target: f.target,
    cve: f.cve,
    cwe: f.cwe,
    cvss_score: f.cvss_score,
    status: f.status,
    bounty_value: f.bounty_value,
    bounty_currency: f.bounty_currency,
    timestamp: f.timestamp,
  }));
  return includePII ? records : stripPII(records);
}

function csvEscape(value: unknown): string {
  const s = value === null || value === undefined ? '' : String(value);
  if (s.includes(',') || s.includes('"') || s.includes('\n')) {
    return `"${s.replace(/"/g, '""')}"`;
  }
  return s;
}

const csvExporter: ExporterFn = ({ findings, filename, includePII }) => {
  const records = toRecords(findings, Boolean(includePII));
  if (records.length === 0) {
    return { blob: new Blob([''], { type: 'text/csv' }), filename: `${filename}.csv`, mime: 'text/csv' };
  }
  const headers = Array.from(new Set(records.flatMap((r) => Object.keys(r))));
  const lines = [
    headers.join(','),
    ...records.map((r) => headers.map((h) => {
      // `h` came from `Object.keys(r)` of the same record, so it is safe.
      // eslint-disable-next-line security/detect-object-injection
      return csvEscape(r[h]);
    }).join(',')),
  ];
  return {
    blob: new Blob([lines.join('\n')], { type: 'text/csv' }),
    filename: `${filename}.csv`,
    mime: 'text/csv',
  };
};

const jsonExporter: ExporterFn = ({ findings, filename, includePII, context }) => {
  const records = toRecords(findings, Boolean(includePII));
  const payload = {
    generated_at: new Date().toISOString(),
    context: context ?? {},
    findings: records,
  };
  return {
    blob: new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' }),
    filename: `${filename}.json`,
    mime: 'application/json',
  };
};

/**
 * Jira bulk-create CSV. Header order matches Jira's "Import CSV" wizard
 * (https://support.atlassian.com/cloud-ims/docs/import-issues-from-csv/).
 */
const jiraExporter: ExporterFn = ({ findings, filename }) => {
  const rows = findings.map((f) => ({
    Summary: f.title,
    'Issue Type': 'Bug',
    Priority: priorityForJira(f.severity),
    Description: jiraDescription(f),
    'Security Level': 'Bug Bounty',
    Labels: ['bug-bounty', `severity-${f.severity}`, f.type || 'unknown'].filter(Boolean).join(' '),
    Assignee: f.assignedTo ?? '',
    'Due Date': '',
    'Custom Field (Bounty Value)': f.bounty_value ?? '',
    'Custom Field (CVSS)': f.cvss_score ?? '',
    'Custom Field (CVE)': f.cve ?? '',
  }));
  const headers = Object.keys(rows[0] ?? { Summary: '' });
  const lines = [
    headers.join(','),
    ...rows.map((r) => headers.map((h) => csvEscape(r[h as keyof typeof r])).join(',')),
  ];
  return {
    blob: new Blob([lines.join('\n')], { type: 'text/csv' }),
    filename: `${filename}-jira.csv`,
    mime: 'text/csv',
  };
};

function priorityForJira(severity: Finding['severity']): string {
  switch (severity) {
    case 'critical': return 'Highest';
    case 'high': return 'High';
    case 'medium': return 'Medium';
    case 'low': return 'Low';
    default: return 'Lowest';
  }
}

function jiraDescription(f: Finding): string {
  return [
    f.description || '',
    '',
    `Target: ${f.target ?? '—'}`,
    `URL: ${f.url ?? '—'}`,
    `CVE: ${f.cve ?? '—'}`,
    `CWE: ${f.cwe ?? '—'}`,
    `CVSS: ${f.cvss_score ?? '—'}`,
    `Confidence: ${Math.round(f.confidence * 100)}%`,
  ].join('\n');
}

/**
 * HackerOne report format. We emit Markdown with the platform's required
 * sections (Title, Severity, Weakness, Summary, Steps To Reproduce, Impact,
 * Remediation). Operators can paste this directly into a new report.
 */
const hackeroneExporter: ExporterFn = ({ findings, filename, context }) => {
  const lines: string[] = [];
  lines.push(`# Bug Bounty Submission — ${context?.target ?? 'Multiple Targets'}`);
  lines.push('');
  lines.push(`_Generated ${new Date().toISOString()} from ${context?.program ?? 'this program'}_`);
  lines.push('');
  for (const f of findings) {
    lines.push('---');
    lines.push('');
    lines.push(`## ${f.title}`);
    lines.push('');
    lines.push(`**Severity:** ${f.severity}  `);
    lines.push(`**Weakness:** ${f.type}  `);
    if (f.cve) lines.push(`**CVE:** ${f.cve}  `);
    if (f.cvss_score != null) lines.push(`**CVSS:** ${f.cvss_score}  `);
    lines.push('');
    lines.push('### Summary');
    lines.push('');
    lines.push(f.description || '_No description provided._');
    lines.push('');
    lines.push('### Steps To Reproduce');
    lines.push('');
    lines.push('1. Navigate to the affected URL below');
    lines.push(`2. Use the request/response pair provided`);
    lines.push('3. Observe the behaviour described above');
    lines.push('');
    lines.push('### Impact');
    lines.push('');
    lines.push(f.description || 'See summary.');
    lines.push('');
    if (f.url) {
      lines.push(`**Affected URL:** ${f.url}`);
    }
    if (f.target) {
      lines.push(`**Target:** ${f.target}`);
    }
    lines.push('');
    lines.push('### Remediation');
    lines.push('');
    lines.push('Triage with the engineering team to determine the appropriate fix for this class of issue.');
    lines.push('');
  }
  return {
    blob: new Blob([lines.join('\n')], { type: 'text/markdown' }),
    filename: `${filename}-hackerone.md`,
    mime: 'text/markdown',
  };
};

/**
 * Burp Suite "Find issues" report XML. Operators can import this directly
 * into Burp's Target > Issues tab.
 */
const burpExporter: ExporterFn = ({ findings, filename }) => {
  const items = findings.map((f) => {
    const evidence = f.evidence ?? {};
    return `    <issue>
      <serialNumber>${escapeXml(f.id)}</serialNumber>
      <type>${escapeXml(f.type)}</type>
      <name><![CDATA[${f.title}]]></name>
      <host>${escapeXml(f.host ?? '')}</host>
      <path><![CDATA[${f.url ?? ''}]]></path>
      <severity>${escapeXml(f.severity)}</severity>
      <confidence>${escapeXml(String(f.confidence))}</confidence>
      <issueBackground><![CDATA[${f.description ?? ''}]]></issueBackground>
      <remediationBackground><![CDATA[]]></remediationBackground>
      <issueDetail><![CDATA[${evidence.match ?? evidence.proof ?? ''}]]></issueDetail>
      <remediationDetail><![CDATA[]]></remediationDetail>
    </issue>`;
  }).join('\n');
  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<issues>
${items}
</issues>
`;
  return {
    blob: new Blob([xml], { type: 'application/xml' }),
    filename: `${filename}-burp.xml`,
    mime: 'application/xml',
  };
};

function escapeXml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

/**
 * Bugcrowd submission format. Markdown with the platform's required
 * fields (Category, Description, Reproduction Steps, Impact,
 * Remediation Plan). Operators paste this directly into Bugcrowd's
 * submission wizard.
 */
const bugcrowdExporter: ExporterFn = ({ findings, filename, context }) => {
  const lines: string[] = [];
  lines.push(`# Bug Bounty Submission — ${context?.target ?? 'Multiple Targets'}`);
  lines.push('');
  lines.push(`_Generated ${new Date().toISOString()} from ${context?.program ?? 'this program'}_`);
  lines.push('');
  for (const f of findings) {
    lines.push('---');
    lines.push('');
    lines.push(`## ${f.title}`);
    lines.push('');
    lines.push(`**Category:** ${f.type || 'other'}  `);
    lines.push(`**Severity:** ${f.severity}  `);
    if (f.cvss_score != null) lines.push(`**CVSS Score:** ${f.cvss_score}  `);
    lines.push('');
    lines.push('### Description');
    lines.push('');
    lines.push(f.description || '_No description provided._');
    lines.push('');
    lines.push('### Reproduction Steps');
    lines.push('');
    lines.push('1. Navigate to the affected URL below');
    lines.push(`2. Use the request/response pair provided`);
    lines.push('3. Observe the behaviour described above');
    lines.push('');
    lines.push('### Impact');
    lines.push('');
    lines.push(f.description || 'See description above.');
    lines.push('');
    if (f.url) {
      lines.push(`**Affected URL:** ${f.url}`);
    }
    if (f.target) {
      lines.push(`**Target:** ${f.target}`);
    }
    lines.push('');
    lines.push('### Remediation Plan');
    lines.push('');
    lines.push('Triage with the engineering team to determine the appropriate fix for this class of issue.');
    lines.push('');
  }
  return {
    blob: new Blob([lines.join('\n')], { type: 'text/markdown' }),
    filename: `${filename}-bugcrowd.md`,
    mime: 'text/markdown',
  };
};

/**
 * Intigriti submission format. Markdown with the platform's required
 * sections (Description, Steps To Reproduce, Impact, Remediation,
 * Mitigation). Operators paste this directly into Intigriti's
 * submission form.
 */
const intigritiExporter: ExporterFn = ({ findings, filename, context }) => {
  const lines: string[] = [];
  lines.push(`# Bug Bounty Submission — ${context?.target ?? 'Multiple Targets'}`);
  lines.push('');
  lines.push(`_Generated ${new Date().toISOString()} from ${context?.program ?? 'this program'}_`);
  lines.push('');
  for (const f of findings) {
    lines.push('---');
    lines.push('');
    lines.push(`## ${f.title}`);
    lines.push('');
    lines.push(`**Severity:** ${f.severity}  `);
    lines.push(`**Weakness:** ${f.type}  `);
    if (f.cve) lines.push(`**CVE:** ${f.cve}  `);
    if (f.cvss_score != null) lines.push(`**CVSS:** ${f.cvss_score}  `);
    lines.push('');
    lines.push('### Description');
    lines.push('');
    lines.push(f.description || '_No description provided._');
    lines.push('');
    lines.push('### Steps To Reproduce');
    lines.push('');
    lines.push('1. Navigate to the affected URL below');
    lines.push(`2. Use the request/response pair provided`);
    lines.push('3. Observe the behaviour described above');
    lines.push('');
    lines.push('### Impact');
    lines.push('');
    lines.push(f.description || 'See description above.');
    lines.push('');
    if (f.url) {
      lines.push(`**Affected URL:** ${f.url}`);
    }
    lines.push('');
    lines.push('### Remediation');
    lines.push('');
    lines.push('Triage with the engineering team to determine the appropriate fix for this class of issue.');
    lines.push('');
    lines.push('### Mitigation');
    lines.push('');
    lines.push('Apply the remediation described above; if a patch cannot be deployed immediately, consider rate-limiting or blocking the affected endpoint as a temporary mitigation.');
    lines.push('');
  }
  return {
    blob: new Blob([lines.join('\n')], { type: 'text/markdown' }),
    filename: `${filename}-intigriti.md`,
    mime: 'text/markdown',
  };
};

/**
 * Synack submission format. Markdown matching Synack's submission
 * template (Vulnerability Description, Reproduction Steps, Business
 * Impact, Suggested Fix).
 */
const synackExporter: ExporterFn = ({ findings, filename, context }) => {
  const lines: string[] = [];
  lines.push(`# Bug Bounty Submission — ${context?.target ?? 'Multiple Targets'}`);
  lines.push('');
  lines.push(`_Generated ${new Date().toISOString()} from ${context?.program ?? 'this program'}_`);
  lines.push('');
  for (const f of findings) {
    lines.push('---');
    lines.push('');
    lines.push(`## ${f.title}`);
    lines.push('');
    lines.push(`**Severity:** ${f.severity}  `);
    lines.push(`**Vulnerability Category:** ${f.type}  `);
    if (f.cvss_score != null) lines.push(`**CVSS:** ${f.cvss_score}  `);
    lines.push('');
    lines.push('### Vulnerability Description');
    lines.push('');
    lines.push(f.description || '_No description provided._');
    lines.push('');
    lines.push('### Reproduction Steps');
    lines.push('');
    lines.push('1. Navigate to the affected URL below');
    lines.push(`2. Use the request/response pair provided`);
    lines.push('3. Observe the behaviour described above');
    lines.push('');
    lines.push('### Business Impact');
    lines.push('');
    lines.push(f.description || 'See description above.');
    lines.push('');
    if (f.url) {
      lines.push(`**Affected URL:** ${f.url}`);
    }
    if (f.target) {
      lines.push(`**Target:** ${f.target}`);
    }
    lines.push('');
    lines.push('### Suggested Fix');
    lines.push('');
    lines.push('Triage with the engineering team to determine the appropriate fix for this class of issue.');
    lines.push('');
  }
  return {
    blob: new Blob([lines.join('\n')], { type: 'text/markdown' }),
    filename: `${filename}-synack.md`,
    mime: 'text/markdown',
  };
};

/**
 * Postman v2.1 collection with one request per finding. The body contains
 * the request/response pair, the URL is the affected endpoint, and the
 * request name is the finding title. Operators can drop this into
 * Postman and re-execute each finding to validate.
 */
const postmanExporter: ExporterFn = ({ findings, filename }) => {
  const items = findings.map((f, i) => {
    const req = f.request_response?.[0];
    const url = f.url ?? '';
    const method = (req?.request?.method ?? 'GET').toUpperCase();
    return {
      name: f.title || `Finding ${i + 1}`,
      request: {
        method,
        header: Object.entries(req?.request?.headers ?? {}).map(([k, v]) => ({ key: k, value: v })),
        url: {
          raw: url,
          protocol: url.startsWith('https') ? 'https' : 'http',
          host: [f.host ?? url.split('/')[2] ?? 'example.com'],
          path: url.split('/').slice(3).filter(Boolean),
        },
        body: req?.request?.body
          ? { mode: 'raw', raw: req.request.body }
          : undefined,
      },
      response: req ? [{
        name: f.title || `Finding ${i + 1}`,
        originalRequest: undefined,
        status: String(req.response?.status ?? ''),
        code: req.response?.status ?? 0,
        _postman_previewlanguage: 'raw',
        header: Object.entries(req.response?.headers ?? {}).map(([k, v]) => ({ key: k, value: v })),
        body: req.response?.body ?? '',
      }] : [],
    };
  });
  const collection = {
    info: {
      _postman_id: crypto.randomUUID(),
      name: filename,
      schema: 'https://schema.getpostman.com/json/collection/v2.1.0/collection.json',
    },
    item: items,
  };
  return {
    blob: new Blob([JSON.stringify(collection, null, 2)], { type: 'application/json' }),
    filename: `${filename}-postman.json`,
    mime: 'application/json',
  };
};

export const EXPORTERS: Record<ExporterFormat, { label: string; description: string; ext: string; export: ExporterFn }> = {
  csv: { label: 'CSV', description: 'Spreadsheet-friendly flat list', ext: 'csv', export: csvExporter },
  json: { label: 'JSON', description: 'Structured findings dump', ext: 'json', export: jsonExporter },
  jira: { label: 'Jira CSV', description: 'Jira bulk-import compatible', ext: 'csv', export: jiraExporter },
  hackerone: { label: 'HackerOne', description: 'Markdown report with required H1 sections', ext: 'md', export: hackeroneExporter },
  bugcrowd: { label: 'Bugcrowd', description: 'Markdown report with Bugcrowd submission fields', ext: 'md', export: bugcrowdExporter },
  intigriti: { label: 'Intigriti', description: 'Markdown report matching Intigriti submission format', ext: 'md', export: intigritiExporter },
  synack: { label: 'Synack', description: 'Markdown report matching Synack submission format', ext: 'md', export: synackExporter },
  burp: { label: 'Burp Suite', description: 'Burp issues XML', ext: 'xml', export: burpExporter },
  postman: { label: 'Postman', description: 'Re-executable request collection', ext: 'json', export: postmanExporter },
};
