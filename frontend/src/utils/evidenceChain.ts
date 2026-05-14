async function sha256(data: string): Promise<string> {
  const encoder = new TextEncoder();
  const buffer = encoder.encode(data);
  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

export interface CustodyEntry {
  id: string;
  evidenceId: string;
  action: 'created' | 'accessed' | 'modified' | 'exported' | 'deleted';
  user: string;
  timestamp: string;
  hashBefore?: string;
  hashAfter?: string;
  details: string;
}

export interface EvidenceRecord {
  id: string;
  findingId: string;
  data: string;
  hash: string;
  createdAt: string;
  createdBy: string;
  custodyChain: CustodyEntry[];
}

const EVIDENCE_STORAGE_KEY = 'cyber-pipeline-evidence-chain';

function loadEvidence(): EvidenceRecord[] {
  try {
    const raw = sessionStorage.getItem(EVIDENCE_STORAGE_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}

function saveEvidence(records: EvidenceRecord[]): void {
  try {
    sessionStorage.setItem(EVIDENCE_STORAGE_KEY, JSON.stringify(records));
  } catch (e) {
    console.warn('Failed to save evidence records:', e);
  }
}

export async function createEvidenceRecord(
  findingId: string,
  data: string,
  user = 'anonymous'
): Promise<EvidenceRecord> {
  const hash = await sha256(data);
  const record: EvidenceRecord = {
    id: `evidence-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    findingId,
    data,
    hash,
    createdAt: new Date().toISOString(),
    createdBy: user,
    custodyChain: [
      {
        id: `custody-${Date.now()}`,
        evidenceId: '',
        action: 'created',
        user,
        timestamp: new Date().toISOString(),
        hashAfter: hash,
        details: 'Evidence created and hashed',
      },
    ],
  };

  const records = loadEvidence();
  records.push(record);
  saveEvidence(records);

  return record;
}

export async function logEvidenceAccess(
  evidenceId: string,
  user = 'anonymous',
  details = 'Evidence accessed for review'
): Promise<void> {
  const records = loadEvidence();
  const record = records.find(r => r.id === evidenceId);
  if (!record) return;

  const entry: CustodyEntry = {
    id: `custody-${Date.now()}`,
    evidenceId,
    action: 'accessed',
    user,
    timestamp: new Date().toISOString(),
    details,
  };

  record.custodyChain.push(entry);
  saveEvidence(records);
}

export async function logEvidenceModification(
  evidenceId: string,
  newData: string,
  user = 'anonymous',
  details = 'Evidence modified'
): Promise<void> {
  const records = loadEvidence();
  const record = records.find(r => r.id === evidenceId);
  if (!record) return;

  const hashBefore = record.hash;
  const hashAfter = await sha256(newData);

  record.data = newData;
  record.hash = hashAfter;

  const entry: CustodyEntry = {
    id: `custody-${Date.now()}`,
    evidenceId,
    action: 'modified',
    user,
    timestamp: new Date().toISOString(),
    hashBefore,
    hashAfter,
    details,
  };

  record.custodyChain.push(entry);
  saveEvidence(records);
}

export async function verifyEvidenceIntegrity(evidenceId: string): Promise<{ valid: boolean; message: string }> {
  const records = loadEvidence();
  const record = records.find(r => r.id === evidenceId);
  if (!record) {
    return { valid: false, message: 'Evidence record not found' };
  }

  const currentHash = await sha256(record.data);
  if (currentHash === record.hash) {
    return { valid: true, message: 'Evidence integrity verified' };
  }
  return { valid: false, message: 'Evidence integrity compromised - hash mismatch!' };
}

export function getEvidenceByFinding(findingId: string): EvidenceRecord[] {
  return loadEvidence().filter(r => r.findingId === findingId);
}

export function getCustodyChain(evidenceId: string): CustodyEntry[] {
  const records = loadEvidence();
  const record = records.find(r => r.id === evidenceId);
  return record ? record.custodyChain : [];
}
