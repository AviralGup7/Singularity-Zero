import { useState } from 'react';
import { CopyButton } from './CopyButton';

interface SubdomainResult {
  domain: string;
  resolved: boolean;
  ip?: string;
  source: string;
}
   
// ... [rest of interfaces same]
interface UrlDiscoveryResult {
  url: string;
  statusCode: number;
  title: string;
  tech?: string[];
}

interface ParameterResult {
  url: string;
  parameters: string[];
  method: string;
}

interface ReconResultsProps {
  target: string;
  subdomains?: SubdomainResult[];
  urls?: UrlDiscoveryResult[];
  parameters?: ParameterResult[];
}

   
export function ReconResults({ target, subdomains = [], urls = [], parameters = [] }: ReconResultsProps) {
   
  const [expandedSections, setExpandedSections] = useState<Set<string>>(new Set(['subdomains']));

  const toggleSection = (section: string) => {
    setExpandedSections(prev => {
      const next = new Set(prev);
      if (next.has(section)) next.delete(section);
      else next.add(section);
      return next;
    });
  };

  const isExpanded = (section: string) => expandedSections.has(section);

  const getSubdomainsText = () => (subdomains || []).map(s => s.domain).join('\n');
  const getUrlsText = () => (urls || []).map(u => u.url).join('\n');

  return (
    <div className="recon-results space-y-4">
      <h3 className="recon-results-title text-xl font-bold mb-4">Recon Results: {target}</h3>

      <details
        className="recon-section bg-panel border border-white/5 rounded-xl overflow-hidden"
        open={isExpanded('subdomains')}
        onToggle={e => {
          const el = e.target as HTMLDetailsElement;
          if (el.open) toggleSection('subdomains');
          else setExpandedSections(prev => { const n = new Set(prev); n.delete('subdomains'); return n; });
        }}
      >
        <summary className="recon-section-header p-4 bg-white/5 cursor-pointer hover:bg-white/10 transition-colors flex items-center justify-between">
          <div className="flex items-center gap-3">
            <span className="recon-section-icon">🌐</span>
            <span className="recon-section-label font-bold uppercase tracking-wider text-sm">Subdomain Enumeration</span>
            <span className="recon-section-count bg-accent/20 text-accent px-2 py-0.5 rounded-full text-[10px]">{(subdomains || []).length}</span>
          </div>
          {subdomains.length > 0 && (
            <div onKeyDown={(e) => e.key === "Enter" && (e.target as HTMLElement).click()} onClick={e => e.stopPropagation()}>
              <CopyButton text={getSubdomainsText()} />
            </div>
          )}
        </summary>
        <div className="recon-section-content p-4">
          {subdomains.length === 0 ? (
            <div className="recon-empty italic text-muted text-sm">No subdomains found.</div>
          ) : (
            <div className="max-h-96 overflow-y-auto scrollbar-cyber">
              <table className="recon-table w-full text-left text-xs">
                <thead className="sticky top-0 bg-panel shadow-sm">
                  <tr className="text-muted border-b border-white/5 uppercase tracking-tighter">
                    <th className="py-2">Subdomain</th>
                    <th className="py-2">Status</th>
                    <th className="py-2">IP</th>
                    <th className="py-2">Source</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/5">
                  {(subdomains || []).map((sd, idx) => (
   
                    <tr key={idx} className="hover:bg-white/[0.02]">
                      <td className="py-2 font-bold text-text">{sd?.domain ?? '—'}</td>
                      <td className="py-2">
                        <span className={`px-1.5 py-0.5 rounded-[4px] font-bold text-[9px] uppercase ${sd?.resolved ? 'bg-ok/10 text-ok' : 'bg-muted/10 text-muted'}`}>
                          {sd?.resolved ? 'Resolved' : 'Unresolved'}
                        </span>
                      </td>
                      <td className="py-2 font-mono text-muted">{sd?.ip ?? '—'}</td>
                      <td className="py-2 text-muted">{sd?.source ?? '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </details>

      <details
        className="recon-section bg-panel border border-white/5 rounded-xl overflow-hidden"
        open={isExpanded('urls')}
        onToggle={e => {
          const el = e.target as HTMLDetailsElement;
          if (el.open) toggleSection('urls');
          else setExpandedSections(prev => { const n = new Set(prev); n.delete('urls'); return n; });
        }}
      >
        <summary className="recon-section-header p-4 bg-white/5 cursor-pointer hover:bg-white/10 transition-colors flex items-center justify-between">
          <div className="flex items-center gap-3">
            <span className="recon-section-icon">🔗</span>
            <span className="recon-section-label font-bold uppercase tracking-wider text-sm">URL Discovery</span>
            <span className="recon-section-count bg-accent/20 text-accent px-2 py-0.5 rounded-full text-[10px]">{(urls || []).length}</span>
          </div>
          {urls.length > 0 && (
            <div onKeyDown={(e) => e.key === "Enter" && (e.target as HTMLElement).click()} onClick={e => e.stopPropagation()}>
              <CopyButton text={getUrlsText()} />
            </div>
          )}
        </summary>
        <div className="recon-section-content p-4">
          {urls.length === 0 ? (
            <div className="recon-empty italic text-muted text-sm">No URLs discovered.</div>
          ) : (
            <div className="max-h-96 overflow-y-auto scrollbar-cyber">
              <table className="recon-table w-full text-left text-xs">
                <thead className="sticky top-0 bg-panel shadow-sm">
                  <tr className="text-muted border-b border-white/5 uppercase tracking-tighter">
                    <th className="py-2">URL</th>
                    <th className="py-2">Status</th>
                    <th className="py-2">Title</th>
                    <th className="py-2">Tech</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/5">
                  {(urls || []).map((url, idx) => (
   
                    <tr key={idx} className="hover:bg-white/[0.02]">
                      <td className="py-2 text-accent truncate max-w-md" title={url?.url ?? '—'}>{url?.url ?? '—'}</td>
                      <td className="py-2">
                        <span className={`font-mono font-bold ${url?.statusCode >= 200 && url?.statusCode < 300 ? 'text-ok' : url?.statusCode >= 400 ? 'text-bad' : 'text-warn'}`}>
                          {url?.statusCode ?? 0}
                        </span>
                      </td>
                      <td className="py-2 truncate max-w-xs">{url?.title ?? '—'}</td>
                      <td className="py-2">
                        {url?.tech && url.tech.length > 0 ? (
                          <div className="flex flex-wrap gap-1">
                            {url.tech.map((t, i) => (
   
                              <span key={i} className="bg-white/5 px-1.5 py-0.5 rounded text-[9px] border border-white/5">{t}</span>
                            ))}
                          </div>
                        ) : '—'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </details>

      <details
        className="recon-section bg-panel border border-white/5 rounded-xl overflow-hidden"
        open={isExpanded('parameters')}
        onToggle={e => {
          const el = e.target as HTMLDetailsElement;
          if (el.open) toggleSection('parameters');
          else setExpandedSections(prev => { const n = new Set(prev); n.delete('parameters'); return n; });
        }}
      >
        <summary className="recon-section-header p-4 bg-white/5 cursor-pointer hover:bg-white/10 transition-colors flex items-center gap-3">
          <span className="recon-section-icon">🔧</span>
          <span className="recon-section-label font-bold uppercase tracking-wider text-sm">Parameter Extraction</span>
          <span className="recon-section-count bg-accent/20 text-accent px-2 py-0.5 rounded-full text-[10px]">{(parameters || []).length}</span>
        </summary>
        <div className="recon-section-content p-4">
          {parameters.length === 0 ? (
            <div className="recon-empty italic text-muted text-sm">No parameters extracted.</div>
          ) : (
            <div className="max-h-96 overflow-y-auto scrollbar-cyber space-y-2">
              {(parameters || []).map((param, idx) => (
                <div key={idx} className="recon-param-item bg-white/5 p-3 rounded-lg border border-white/5 group">
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <span className="bg-accent/10 text-accent px-1.5 py-0.5 rounded font-black text-[9px] uppercase tracking-widest">{param?.method ?? '—'}</span>
                      <span className="text-xs text-text/80 truncate font-mono">{param?.url ?? '—'}</span>
                    </div>
                    <CopyButton text={param?.url || ''} />
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    {(param?.parameters || []).map((p, i) => (
   
                      <span key={i} className="bg-black/40 text-accent/80 border border-accent/20 px-2 py-0.5 rounded text-[10px] font-mono group-hover:border-accent/40 transition-colors">{p}</span>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </details>
    </div>
  );
}

