import { useEffect, useState } from 'react';

function pad(n: number) {
  return String(n).padStart(2, '0');
}

export function NightCityHud() {
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

  return (
    <div className="nc-hud" aria-hidden="true">
      <div className="nc-world" />
      <div className="nc-hud-scan" />

      <div className={`nc-boot${booting ? ' nc-boot--on' : ''}`}>
        <img className="nc-boot-art" src="/night-city/loading.jpg" alt="" />
        <img className="nc-boot-ring" src="/night-city/hud-ring.jpg" alt="" />
        <span className="nc-boot-label">LINKING NEURALWARE</span>
      </div>

      <div className="nc-hud-vitals">
        <div className="nc-bar nc-bar--hp">
          <span />
          <span />
          <span />
          <span />
          <span />
        </div>
        <div className="nc-bar nc-bar--st">
          <span />
          <span />
          <span />
        </div>
        <div className="nc-hud-ammo">
          2077
          <small>OPTICS</small>
        </div>
      </div>

      <div className="nc-hud-map">
        <div className="nc-minimap">
          <i />
          <i />
          <i />
          <b />
        </div>
        <div className="nc-district">
          <em>THE GLEN</em>
          <strong>WATSON</strong>
        </div>
      </div>

      <div className="nc-hud-job">
        <div className="nc-job-tag">MAIN JOB</div>
        <div className="nc-job-title">NOCTURNE OP55N1</div>
        <div className="nc-job-obj">Meet Hanako at Embers.</div>
      </div>

      <div className="nc-hud-keys">
        <div>
          <span>Draw Weapon</span>
          <kbd>ALT</kbd>
        </div>
        <div>
          <span>Crouch</span>
          <kbd>C</kbd>
        </div>
      </div>

      <div className="nc-hud-slots">
        <i />
        <i />
        <i />
      </div>

      <div className="nc-hud-clock">{stamp}</div>
    </div>
  );
}
