export interface CVEInfo {
  id: string;
  description: string;
  published: string;
  modified: string;
  cvssV3?: number;
  severity?: string;
  url: string;
}

export interface CWEInfo {
  id: string;
  name: string;
  description: string;
  url: string;
}

export interface EPSSInfo {
  cve: string;
  epss: number;
  percentile: number;
}

export interface ThreatIntelData {
  cve?: CVEInfo | null;
  cwe?: CWEInfo | null;
  epss?: EPSSInfo | null;
}

const THREAT_INTEL_CACHE_KEY = 'cyber-pipeline-threat-intel';
const CACHE_TTL_MS = 24 * 60 * 60 * 1000;

interface CacheEntry<T> {
  data: T;
  timestamp: number;
}

function getCached<T>(key: string): T | null {
  try {
    const raw = localStorage.getItem(`${THREAT_INTEL_CACHE_KEY}:${key}`);
    if (!raw) return null;
    const entry: CacheEntry<T> = JSON.parse(raw);
    if (Date.now() - entry.timestamp > CACHE_TTL_MS) {
      localStorage.removeItem(`${THREAT_INTEL_CACHE_KEY}:${key}`);
      return null;
    }
    return entry.data;
  } catch {
    return null;
  }
}

function setCached<T>(key: string, data: T): void {
  try {
    const entry: CacheEntry<T> = { data, timestamp: Date.now() };
    localStorage.setItem(`${THREAT_INTEL_CACHE_KEY}:${key}`, JSON.stringify(entry));
  } catch {
    console.warn('Failed to cache threat intel data');
  }
}

export async function lookupCVE(cveId: string): Promise<CVEInfo | null> {
  const cached = getCached<CVEInfo>(`cve:${cveId}`);
  if (cached) return cached;

  // FIX: Attempt real NVD API lookup, fall back to placeholder
  try {
    const response = await fetch(`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cveId}`);
    if (response.ok) {
      const json = await response.json();
      if (json.vulnerabilities?.length > 0) {
        const vuln = json.vulnerabilities[0].cve;
        const cveInfo: CVEInfo = {
          id: cveId,
          description: vuln.descriptions?.find((d: { lang: string }) => d.lang === 'en')?.value || `Vulnerability ${cveId}`,
          published: vuln.published || new Date().toISOString(),
          modified: vuln.lastModified || new Date().toISOString(),
          url: `https://nvd.nist.gov/vuln/detail/${cveId}`,
        };
        setCached(`cve:${cveId}`, cveInfo);
        return cveInfo;
      }
    }
  } catch {
    // NVD API unavailable, fall through to placeholder
  }

  const cveInfo: CVEInfo = {
    id: cveId,
    description: `Vulnerability ${cveId} - lookup via NVD API for details`,
    published: new Date().toISOString(),
    modified: new Date().toISOString(),
    url: `https://nvd.nist.gov/vuln/detail/${cveId}`,
  };

  setCached(`cve:${cveId}`, cveInfo);
  return cveInfo;
}

export async function lookupCWE(cweId: string): Promise<CWEInfo | null> {
  const cached = getCached<CWEInfo>(`cwe:${cweId}`);
  if (cached) return cached;

  const cweNames: Record<string, string> = {
    'CWE-79': 'Cross-site Scripting (XSS)',
    'CWE-89': 'SQL Injection',
    'CWE-20': 'Improper Input Validation',
    'CWE-287': 'Improper Authentication',
    'CWE-352': 'Cross-Site Request Forgery (CSRF)',
    'CWE-434': 'Unrestricted Upload of File with Dangerous Type',
    'CWE-611': 'XML External Entity (XXE)',
    'CWE-78': 'OS Command Injection',
    'CWE-22': 'Path Traversal',
    'CWE-862': 'Missing Authorization',
  };

  const cweInfo: CWEInfo = {
    id: cweId,
    name: cweNames[cweId] || `Weakness ${cweId}`,
    description: `See CWE database for full details on ${cweId}`,
    url: `https://cwe.mitre.org/data/definitions/${cweId.replace('CWE-', '')}.html`,
  };

  setCached(`cwe:${cweId}`, cweInfo);
  return cweInfo;
}

export async function lookupEPSS(cveId: string): Promise<EPSSInfo | null> {
  const cached = getCached<EPSSInfo>(`epss:${cveId}`);
  if (cached) return cached;

  // FIX: Attempt real EPSS API lookup instead of returning fake random data
  try {
    const response = await fetch(`https://api.first.org/data/v1/epss?cve=${cveId}`);
    if (response.ok) {
      const json = await response.json();
      if (json.data?.length > 0) {
        const epssData = json.data[0];
        const epssInfo: EPSSInfo = {
          cve: cveId,
          epss: parseFloat(epssData.epss || '0'),
          percentile: parseFloat(epssData.percentile || '0') * 100,
        };
        setCached(`epss:${cveId}`, epssInfo);
        return epssInfo;
      }
    }
  } catch {
    // EPSS API unavailable, fall through to placeholder
  }

  // Mark as unavailable rather than returning fake data
  const epssInfo: EPSSInfo = {
    cve: cveId,
    epss: -1, // -1 indicates unavailable
    percentile: -1,
  };

  setCached(`epss:${cveId}`, epssInfo);
  return epssInfo;
}

export async function getThreatIntel(cveId?: string, cweId?: string): Promise<ThreatIntelData> {
  const result: ThreatIntelData = {};

  if (cveId) {
    const [cve, epss] = await Promise.all([
      lookupCVE(cveId),
      lookupEPSS(cveId),
    ]);
    result.cve = cve;
    result.epss = epss;
  }

  if (cweId) {
    result.cwe = await lookupCWE(cweId);
  }

  return result;
}

export function getEPSSLabel(epss: number): string {
  if (epss < 0) return 'N/A'; // FIX: Handle unavailable EPSS
  if (epss >= 0.5) return 'Very High';
  if (epss >= 0.2) return 'High';
  if (epss >= 0.1) return 'Medium';
  if (epss >= 0.05) return 'Low';
  return 'Very Low';
}

export function getEPSSColor(epss: number): string {
  if (epss < 0) return 'var(--muted)'; // FIX: Handle unavailable EPSS
  if (epss >= 0.5) return 'var(--severity-critical)';
  if (epss >= 0.2) return 'var(--severity-high)';
  if (epss >= 0.1) return 'var(--severity-medium)';
  if (epss >= 0.05) return 'var(--severity-low)';
  return 'var(--muted)';
}
