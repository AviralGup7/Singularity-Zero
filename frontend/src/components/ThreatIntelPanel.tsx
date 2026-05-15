import { useState, useEffect } from 'react';
import { getThreatIntel, getEPSSLabel, getEPSSColor, type ThreatIntelData } from '@/utils/threatIntelligence';

interface ThreatIntelPanelProps {
  cveId?: string;
  cweId?: string;
}

export function ThreatIntelPanel({ cveId, cweId }: ThreatIntelPanelProps) {
  const [data, setData] = useState<ThreatIntelData | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!cveId && !cweId) return;
    let mounted = true;
    
    Promise.resolve().then(() => {
      if (mounted) setLoading(true);
    });
    
    getThreatIntel(cveId, cweId).then((result) => {
      if (mounted) {
        setData(result);
        setLoading(false);
      }
    }).catch(() => {
      if (mounted) setLoading(false);
    });
    
    return () => { mounted = false; };
  }, [cveId, cweId]);

  if (!cveId && !cweId) return null;
  if (loading) return <div className="text-[var(--muted)] text-xs font-mono">Loading threat intel...</div>;
  if (!data) return null;

  return (
    <div className="threat-intel-section">
      <h4 className="threat-intel-title">Threat Intelligence</h4>
      <div className="threat-intel-grid">
        {data.cve && (
          <div className="threat-intel-item">
            <div className="threat-intel-label">CVE</div>
            <div className="threat-intel-value">
              <a href={data.cve.url} target="_blank" rel="noopener noreferrer" className="threat-intel-link">
                {data.cve.id}
              </a>
            </div>
            {data.cve.cvssV3 && (
              <div className="text-xs text-[var(--muted)]">
                CVSS v3: {data.cve.cvssV3} ({data.cve.severity})
              </div>
            )}
          </div>
        )}

        {data.cwe && (
          <div className="threat-intel-item">
            <div className="threat-intel-label">CWE</div>
            <div className="threat-intel-value">
              <a href={data.cwe.url} target="_blank" rel="noopener noreferrer" className="threat-intel-link">
                {data.cwe.id}: {data.cwe.name}
              </a>
            </div>
          </div>
        )}

        {data.epss && (
          <div className="threat-intel-item">
            <div className="threat-intel-label">EPSS</div>
            <div className="threat-intel-value">
              <span style={{ color: getEPSSColor(data.epss.epss) }}>
                {(data.epss.epss * 100).toFixed(2)}%
              </span>
              {' '}
              <span className="text-xs text-[var(--muted)]">
                ({getEPSSLabel(data.epss.epss)})
              </span>
            </div>
            <div className="text-xs text-[var(--muted)]">
              Percentile: {data.epss.percentile}%
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
