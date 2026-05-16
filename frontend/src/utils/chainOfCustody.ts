export interface CustodyEntry {
  id: string;
  evidenceId: string;
  action: 'created' | 'accessed' | 'modified' | 'transferred' | 'deleted';
  user: string;
  timestamp: string;
  hash: string;
  previousHash?: string;
  details: Record<string, unknown>;
}

export interface EvidenceRecord {
  id: string;
  name: string;
  type: string;
  created: string;
  hash: string;
  custodyChain: CustodyEntry[];
  metadata: Record<string, unknown>;
}

const CUSTODY_STORAGE_KEY = 'cyber-pipeline-chain-of-custody';

async function computeHash(data: string): Promise<string> {
  const encoder = new TextEncoder();
  const buffer = encoder.encode(data);
  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
}

export async function createEvidenceRecord(
  name: string,
  type: string,
  content: string,
  user = 'anonymous',
  metadata: Record<string, unknown> = {}
): Promise<EvidenceRecord> {
  const hash = await computeHash(content);
  const now = new Date().toISOString();

  const custodyEntry: CustodyEntry = {
    id: `custody-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    evidenceId: '',
    action: 'created',
    user,
    timestamp: now,
    hash,
    details: { name, type, ...metadata },
  };

  const record: EvidenceRecord = {
    id: `evidence-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    name,
    type,
    created: now,
    hash,
    custodyChain: [],
    metadata,
  };

  custodyEntry.evidenceId = record.id;
  record.custodyChain.push(custodyEntry);

  saveEvidenceRecord(record);
  return record;
}

export async function recordEvidenceAccess(
  evidenceId: string,
  user = 'anonymous',
  details: Record<string, unknown> = {}
): Promise<void> {
  const records = getAllEvidenceRecords();
  const record = records.find((r) => r.id === evidenceId);
  if (!record) return;

   
  const lastEntry = record.custodyChain[record.custodyChain.length - 1];
  const entry: CustodyEntry = {
    id: `custody-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    evidenceId,
    action: 'accessed',
    user,
    timestamp: new Date().toISOString(),
    hash: record.hash,
    previousHash: lastEntry?.hash,
    details,
  };

  record.custodyChain.push(entry);
  saveEvidenceRecord(record);
}

export async function recordEvidenceModification(
  evidenceId: string,
  newContent: string,
  user = 'anonymous',
  details: Record<string, unknown> = {}
): Promise<string> {
  const records = getAllEvidenceRecords();
  const record = records.find((r) => r.id === evidenceId);
  if (!record) return '';

  const newHash = await computeHash(newContent);
   
  const lastEntry = record.custodyChain[record.custodyChain.length - 1];

  const entry: CustodyEntry = {
    id: `custody-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    evidenceId,
    action: 'modified',
    user,
    timestamp: new Date().toISOString(),
    hash: newHash,
    previousHash: lastEntry?.hash,
    details,
  };

  record.hash = newHash;
  record.custodyChain.push(entry);
  saveEvidenceRecord(record);
  return newHash;
}

export async function recordEvidenceTransfer(
  evidenceId: string,
  toUser: string,
  user = 'anonymous',
  details: Record<string, unknown> = {}
): Promise<void> {
  const records = getAllEvidenceRecords();
  const record = records.find((r) => r.id === evidenceId);
  if (!record) return;

   
  const lastEntry = record.custodyChain[record.custodyChain.length - 1];
  const entry: CustodyEntry = {
    id: `custody-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    evidenceId,
    action: 'transferred',
    user,
    timestamp: new Date().toISOString(),
    hash: record.hash,
    previousHash: lastEntry?.hash,
    details: { toUser, ...details },
  };

  record.custodyChain.push(entry);
  saveEvidenceRecord(record);
}

export function getAllEvidenceRecords(): EvidenceRecord[] {
  try {
    const raw = sessionStorage.getItem(CUSTODY_STORAGE_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}

export function getEvidenceRecord(id: string): EvidenceRecord | null {
  return getAllEvidenceRecords().find((r) => r.id === id) || null;
}

export function getCustodyChain(evidenceId: string): CustodyEntry[] {
  const record = getEvidenceRecord(evidenceId);
  return record ? record.custodyChain : [];
}

function saveEvidenceRecord(record: EvidenceRecord): void {
  try {
    const records = getAllEvidenceRecords();
    const idx = records.findIndex((r) => r.id === record.id);
    if (idx >= 0) {
      records[idx] = record;
    } else {
      records.push(record);
    }
    sessionStorage.setItem(CUSTODY_STORAGE_KEY, JSON.stringify(records));
  } catch (e) {
    console.warn('Failed to save evidence record:', e);
  }
}

export async function verifyEvidenceIntegrity(
  evidenceId: string,
  content: string
): Promise<boolean> {
  const record = getEvidenceRecord(evidenceId);
  if (!record) return false;

  const computedHash = await computeHash(content);
  return computedHash === record.hash;
}

export function deleteEvidenceRecord(evidenceId: string, user = 'anonymous'): void {
  const records = getAllEvidenceRecords();
  const record = records.find((r) => r.id === evidenceId);
  if (record) {
   
    const lastEntry = record.custodyChain[record.custodyChain.length - 1];
    record.custodyChain.push({
      id: `custody-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      evidenceId,
      action: 'deleted',
      user,
      timestamp: new Date().toISOString(),
      hash: record.hash,
      previousHash: lastEntry?.hash,
      details: {},
    });
  }
  sessionStorage.setItem(
    CUSTODY_STORAGE_KEY,
    JSON.stringify(records.filter((r) => r.id !== evidenceId))
  );
}
