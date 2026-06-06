import { motion, AnimatePresence } from 'framer-motion';
import { Icon } from '@/components/Icon';

const CATEGORY_METADATA: Record<string, { name: string; desc: string; severity: 'critical' | 'high' | 'medium' | 'low'; remediation: string }> = {
  idor: {
    name: 'Insecure Direct Object Reference (IDOR)',
    desc: 'Occurs when an application uses user-supplied input to access objects directly without proper authorization checks.',
    severity: 'high',
    remediation: 'Implement indirect reference maps or strict row-level Access Control Lists (ACLs) verifying that the authenticated session owns the requested object identifier.',
  },
  ssrf: {
    name: 'Server-Side Request Forgery (SSRF)',
    desc: 'Allows an attacker to abuse server functionality to make requests to internal-only resources, cloud metadata APIs, or local network endpoints.',
    severity: 'critical',
    remediation: 'Implement strict IP/domain blocklists (blocking RFC1918 ranges) or, preferably, a strict whitelist of allowed destination endpoints. Resolve DNS queries and validate destination IPs before socket connection.',
  },
  xss: {
    name: 'Cross-Site Scripting (XSS)',
    desc: "Allows execution of untrusted scripts in a user's browser session, facilitating session hijacking, DOM tampering, or phishing redirections.",
    severity: 'high',
    remediation: 'Use context-aware HTML entity encoding on all user-supplied data in templates, enforce strong Content Security Policies (CSP), and utilize modern frameworks (React/Vue/Angular) which auto-encode outputs.',
  },
  open_redirect: {
    name: 'Open Redirect',
    desc: 'Enables attackers to leverage trusted domains to redirect users to malicious landing pages, often used to bypass email security filter checks.',
    severity: 'medium',
    remediation: 'Avoid accepting absolute redirect paths as parameters. Use relative paths only, or validate redirect destinations against a strict domain whitelist.',
  },
  token_leak: {
    name: 'Token & Session Exposure',
    desc: 'Unauthorized disclosure of authorization credentials, bearer tokens, or session identifiers in HTTP responses, scripts, or application logs.',
    severity: 'high',
    remediation: 'Strip high-entropy security tokens from logging buffers, store session identifiers in secure HttpOnly cookies, and never transmit sensitive keys via query parameters.',
  },
  access_control: {
    name: 'Broken Access Control',
    desc: 'Failure to restrict access permissions across vertical (admin vs user) or horizontal (tenant vs tenant) structural boundaries.',
    severity: 'high',
    remediation: 'Adopt a default-deny routing policy, perform centralized authorization checks on every endpoint, and enforce parameter-level ownership verification.',
  },
  authentication_bypass: {
    name: 'Authentication Bypass',
    desc: 'Mechanisms or endpoints that let an attacker access protected logic without proving identity or validating signatures.',
    severity: 'critical',
    remediation: 'Centralize routing authentication checks using trusted middleware, validate cryptographically signed tokens (JWTs) using secure algorithms, and reject methods overrides.',
  },
  broken_authentication: {
    name: 'Broken Authentication',
    desc: 'Weaknesses in session management or credential validation allowing credential brute forcing or token fixation.',
    severity: 'high',
    remediation: 'Enforce high password complexity, apply strict rate limiting on authentication routes, and invalidate previous sessions upon logout or password reset.',
  },
  business_logic: {
    name: 'Business Logic Flaws',
    desc: 'Bypassing operational constraints or transaction workflows by mutating schemas, parameter payloads, or sequencing steps.',
    severity: 'high',
    remediation: 'Enforce transactional state machine validation on the backend, run mathematical sanity checks on quantities (preventing negative values), and avoid relying on client-side state parameters.',
  },
  payment: {
    name: 'Payment Flow Weaknesses',
    desc: 'Bypassing financial checkout flows, callback signature validations, or transaction amounts.',
    severity: 'high',
    remediation: 'Validate payment webhooks using cryptographic signature checks, check unit prices against internal database tables during checkout rather than accepting client-provided prices, and enforce single-use tokens.',
  },
  sensitive_data: {
    name: 'Sensitive Data Exposure',
    desc: 'Transmission of unencrypted personally identifiable information (PII), credentials, or system diagnostic messages.',
    severity: 'high',
    remediation: 'Encrypt sensitive data both in transit (TLS 1.3) and at rest (AES-256), redact personal identifiers in output pipelines, and set strict security headers.',
  },
  misconfiguration: {
    name: 'Security Misconfiguration',
    desc: 'Improperly hardened servers, loose CORS controls, missing cookie flags, or exposed development consoles.',
    severity: 'medium',
    remediation: 'Disable directory listing, strip production server signatures (Server, X-Powered-By), enforce secure Cookie flags (HttpOnly, Secure, SameSite=Lax), and restrict HTTP methods.',
  },
  cors: {
    name: 'CORS Misconfiguration',
    desc: 'Overly permissive Cross-Origin Resource Sharing rules allowing arbitrary web pages to read authenticated data.',
    severity: 'medium',
    remediation: 'Never reflect Origin headers directly alongside Access-Control-Allow-Credentials. Use a strict, static domain whitelist for cors cross-communication.',
  },
  session: {
    name: 'Session Management Issues',
    desc: 'Long session lifetimes, missing invalidation hooks, or session identifier predictability.',
    severity: 'high',
    remediation: 'Generate high-entropy session identifiers, support backend token revocation, enforce maximum session timeouts, and regenerate tokens upon state change.',
  },
  anomaly: {
    name: 'Telemetry Anomalies',
    desc: 'Atypical response payload lengths or latency variations which might indicate server fuzzing or information leak side channels.',
    severity: 'medium',
    remediation: 'Apply uniform latency padding where security checks occur, rate-limit excessive request variance, and monitor backend resource usage metrics.',
  },
  behavioral_deviation: {
    name: 'WAF / IPS Detection Bypasses',
    desc: 'Vulnerabilities exposed due to evasion techniques mapping behavioral limits.',
    severity: 'medium',
    remediation: 'Ensure consistent input validation irrespective of payload length, maintain dynamic IP blocklists, and evaluate heuristic threat patterns.',
  },
  redirect: {
    name: 'Redirect Chains & Loops',
    desc: 'Uncontrolled redirect patterns triggering authentication loops or cross-site referral leaks.',
    severity: 'medium',
    remediation: 'Restrict OAuth redirect URLs to precise whitelisted client routes and validate state parameters to prevent referral interception.',
  },
  server_side_injection: {
    name: 'Server-Side Injection (RCE/SQLi)',
    desc: 'Direct execution of arbitrary template expressions, SQL databases queries, or shell commands via unvalidated parameter entry.',
    severity: 'critical',
    remediation: 'Use parameterized queries / ORMs exclusively, sandbox template compiler runtimes, and never execute system shell strings using user parameters.',
  },
  race_condition: {
    name: 'Race Condition (Concurrency Flaws)',
    desc: 'Executing multiple overlapping parallel requests to double spend credits, duplicate account links, or bypass transaction locks.',
    severity: 'high',
    remediation: 'Use transactional locks, atomic database transactions (e.g. SELECT FOR UPDATE), or distributed key locks (Redis/Redlock) to serialize access to highly sensitive resources.',
  },
  csrf: {
    name: 'Cross-Site Request Forgery (CSRF)',
    desc: 'Inducing a user browser to perform actions on their behalf on an authenticated web app.',
    severity: 'medium',
    remediation: 'Use anti-CSRF token verification on state-changing requests, and configure cookies with Strict/Lax SameSite constraints.',
  },
  ssti: {
    name: 'Server-Side Template Injection (SSTI)',
    desc: 'Injecting expressions inside template engines which then run with full backend sandbox permissions.',
    severity: 'critical',
    remediation: 'Disable dynamic template rendering on user input, or use completely sandboxed templating environments with restricted modules access.',
  },
  ai_surface: {
    name: 'AI/ML Surface Exposure',
    desc: 'Abusing LLM models to leak system prompts, access sandboxed actions, or inject model weights commands.',
    severity: 'medium',
    remediation: 'Perform strict pre-prompt sanitization, isolate AI endpoints workflows, and treat LLM outputs as untrusted parameters.',
  },
  exposure: {
    name: 'Information Leakage & File Exposure',
    desc: 'Leaking raw environment parameters, backup volumes, active GraphQL schemas, or debug stack traces.',
    severity: 'medium',
    remediation: 'Block direct access to server directory backups (.bak, .git, .env), disable verbose stack traces in production environment, and restrict GraphQL introspection schemas.',
  },
};

export type ActiveMitigation = {
  module: string;
  category: string;
  missing: string[];
};

interface MitigationModalProps {
  activeMitigation: ActiveMitigation | null;
  selectedTarget: string;
  onClose: () => void;
  onCopyPatch: (patch: string) => void;
  copied: boolean;
}

export function MitigationModal({ activeMitigation, selectedTarget, onClose, onCopyPatch, copied }: MitigationModalProps) {
  if (!activeMitigation) return null;

  const meta =
    CATEGORY_METADATA[activeMitigation.category] || {
      name: activeMitigation.category.toUpperCase() + ' Vulnerability',
      desc: 'A detected security validation gap within the module scanning matrix.',
      remediation: 'Configure scanner rules or implement strict code validation logic.',
      severity: 'high',
    };
  const targetName = selectedTarget === 'all' ? 'target_name' : selectedTarget;
  const runCmd = `python -m src.pipeline.run --target ${targetName} --mode custom --modules ${activeMitigation.module}`;
  const patchJson = JSON.stringify(
    {
      target: targetName,
      enabled_modules: [activeMitigation.module],
    },
    null,
    2
  );

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-in fade-in duration-300">
      <motion.div
        initial={{ opacity: 0, y: 50, scale: 0.95 }}
        animate={{ opacity: 1, y: 0, scale: 1 }}
        exit={{ opacity: 0, y: 50, scale: 0.95 }}
        className="relative w-full max-w-2xl bg-panel border border-white/10 rounded-2xl overflow-hidden shadow-2xl"
      >
        <div className="absolute top-0 right-0 w-48 h-48 bg-accent/5 -rotate-45 translate-x-24 -translate-y-24 pointer-events-none" />

        <div className="p-6 border-b border-white/5 flex items-center justify-between">
          <div>
            <span
              className={`text-[10px] font-bold px-2 py-0.5 rounded uppercase ${
                meta.severity === 'critical'
                  ? 'bg-bad/20 text-bad border border-bad/30'
                  : meta.severity === 'high'
                  ? 'bg-warn/20 text-warn border border-warn/30'
                  : 'bg-accent/20 text-accent border border-accent/30'
              }`}
            >
              {meta.severity} severity
            </span>
            <h3 className="text-xl font-bold text-text mt-2">{meta.name}</h3>
          </div>
          <button
            onClick={() => {
              onClose();
            }}
            className="p-1.5 hover:bg-white/5 rounded-lg transition-colors text-muted hover:text-text"
          >
            <Icon name="x" size={20} />
          </button>
        </div>

        <div className="p-6 space-y-6 max-h-[70vh] overflow-y-auto">
          <div className="space-y-2">
            <div className="text-[10px] text-muted font-bold uppercase tracking-wider">Deficiency Analysis</div>
            <p className="text-sm text-muted/90 leading-relaxed text-left">{meta.desc}</p>
          </div>

          {activeMitigation.missing.length > 0 && (
            <div className="space-y-3 text-left">
              <div className="text-[10px] text-muted font-bold uppercase tracking-wider">Unverified Edge Cases</div>
              <div className="grid grid-cols-1 gap-2">
                {activeMitigation.missing.map((check, i) => (
                  <div
                    key={i}
                    className="flex items-start gap-3 bg-black/40 border border-white/5 p-2.5 rounded-lg text-xs font-mono text-muted"
                  >
                    <span className="text-accent">•</span>
                    <span className="text-left">{check}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          <div className="space-y-2 text-left">
            <div className="text-[10px] text-muted font-bold uppercase tracking-wider">Secure Coding Remediation</div>
            <div className="bg-accent/5 border border-accent/10 rounded-xl p-4 text-sm text-text leading-relaxed flex items-start gap-3">
              <Icon name="info" size={18} className="text-accent mt-0.5 flex-shrink-0" />
              <p className="text-left">{meta.remediation}</p>
            </div>
          </div>

          <div className="space-y-2 text-left">
            <div className="text-[10px] text-muted font-bold uppercase tracking-wider flex items-center gap-1.5">
              <Icon name="terminal" size={12} className="text-muted" />
              Ad-Hoc Execution Command
            </div>
            <div className="relative bg-black/60 rounded-lg p-3 border border-white/10 font-mono text-xs text-ok overflow-x-auto text-left select-all">
              {runCmd}
            </div>
          </div>

          <div className="space-y-2 text-left">
            <div className="flex items-center justify-between">
              <div className="text-[10px] text-muted font-bold uppercase tracking-wider">Orchestrator Config Patch</div>
              <button
                onClick={() => onCopyPatch(patchJson)}
                className="text-[10px] text-accent hover:underline font-bold uppercase tracking-wider flex items-center gap-1"
              >
                <Icon name="copy" size={12} />
                {copied ? 'Copied!' : 'Copy Patch'}
              </button>
            </div>
            <pre className="bg-black/60 rounded-lg p-3 border border-white/10 font-mono text-xs text-text overflow-x-auto text-left text-muted/95">
              {patchJson}
            </pre>
          </div>
        </div>

        <div className="p-4 border-t border-white/5 bg-white/[0.01] flex justify-end gap-3">
          <button
            onClick={() => onClose()}
            className="btn btn-secondary px-4 py-2 text-xs font-bold uppercase tracking-wider"
          >
            Close Guide
          </button>
        </div>
      </motion.div>
    </div>
  );
}
