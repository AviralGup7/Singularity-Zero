import { useEffect, useState } from 'react';
import { APP_VERSION } from '@/config';
import '@/styles/system/pages/night-city.css';

function pad(n: number) {
  return String(n).padStart(2, '0');
}

export interface NightCityHudProps {
  sector?: string;
  district?: string;
  jobTitle?: string;
  jobObjective?: string;
  ready?: boolean;
}

export function NightCityHud({
  sector = 'OPS',
  district = 'SECURITY CONSOLE',
  jobTitle = 'PIPELINE LIVE',
  jobObjective = 'Triage findings. Keep scans live.',
  ready = true,
}: NightCityHudProps) {
  const [now, setNow] = useState(() => new Date());
  const [booting, setBooting] = useState(true);

  useEffect(() => {
    const id = window.setInterval(() => setNow(new Date()), 1000);
    const boot = window.setTimeout(() => setBooting(false), 1700);
    return () => {
      window.clearInterval(id);
      window.clearTimeout(boot);
    };
  }, []);

  const stamp = `${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`;
  const hpPips = ready ? 5 : 2;
  const stPips = ready ? 3 : 1;

  return (
    <>
      <div className="nc-world" aria-hidden="true">
        <img src="/night-city/skyline.jpg" alt="" />
      </div>

      <div className="nc-hud" aria-hidden="true">
        <div className="nc-hud-scan" />

        <div className="nc-hud-vitals">
          <div className="nc-bar nc-bar--hp">
            {Array.from({ length: hpPips }, (_, i) => (
              <span key={`hp-${i}`} />
            ))}
          </div>
          <div className="nc-bar nc-bar--st">
            {Array.from({ length: stPips }, (_, i) => (
              <span key={`st-${i}`} />
            ))}
          </div>
          <div className="nc-hud-ammo">
            {APP_VERSION}
            <small>{ready ? 'LIVE' : 'DEGRADED'}</small>
          </div>
        </div>

        <div className="nc-hud-map">
          <div className="nc-minimap">
            <img src="/night-city/circuit.jpg" alt="" />
            <i />
            <i />
            <i />
            <b />
          </div>
          <div className="nc-district">
            <em>{sector}</em>
            <strong>{district}</strong>
          </div>
        </div>

        <div className="nc-hud-job">
          <div className="nc-job-tag">MAIN JOB</div>
          <div className="nc-job-title">{jobTitle}</div>
          <div className="nc-job-obj">{jobObjective}</div>
        </div>

        <div className="nc-hud-keys">
          <div>
            <span>Command Palette</span>
            <kbd>⌘K</kbd>
          </div>
          <div>
            <span>New Scan</span>
            <kbd>2</kbd>
          </div>
        </div>

        <div className="nc-hud-slots">
          <i />
          <i />
          <i />
        </div>

        <div className="nc-hud-clock">{stamp}</div>
      </div>

      <div className={`nc-boot${booting ? ' nc-boot--on' : ''}`}>
        <img className="nc-boot-art" src="/night-city/loading.jpg" alt="" />
        <img className="nc-boot-ring" src="/night-city/hud-ring.jpg" alt="" />
        <span className="nc-boot-label">LINKING CONSOLE</span>
      </div>
    </>
  );
}
