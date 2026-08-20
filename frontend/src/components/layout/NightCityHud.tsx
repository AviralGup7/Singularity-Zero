import { useEffect, useState } from 'react';

function pad(n: number) {
  return String(n).padStart(2, '0');
}

export function NightCityHud() {
  const [now, setNow] = useState(() => new Date());

  useEffect(() => {
    const id = window.setInterval(() => setNow(new Date()), 1000);
    return () => window.clearInterval(id);
  }, []);

  const stamp = `${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`;
  const date = `${now.getFullYear()}.${pad(now.getMonth() + 1)}.${pad(now.getDate())}`;

  return (
    <div className="nc-hud" aria-hidden="true">
      <div className="nc-hud-vignette" />
      <div className="nc-hud-scan" />
      <div className="nc-hud-noise" />
      <span className="nc-c nc-c--tl" />
      <span className="nc-c nc-c--tr" />
      <span className="nc-c nc-c--bl" />
      <span className="nc-c nc-c--br" />
      <div className="nc-hud-top">
        <span className="nc-hud-mark">ナイトシティ</span>
        <span className="nc-hud-brand">NIGHT CITY</span>
        <span className="nc-hud-district">WATSON // LITTLE CHINA</span>
        <span className="nc-hud-clock">
          {date}  {stamp}
        </span>
      </div>
      <div className="nc-hud-ticker">
        <div className="nc-hud-ticker-track">
          NETWATCH TRACE · NEGATIVE · BIOMONITOR STABLE · OPTICS ONLINE · KERENZIKOV READY ·
          STREETCRED 000 · WANTED LEVEL 0 · N54 NEWS · CORPSEC QUIET · AFTERLIFE OPEN ·
          SAMURAI ON AIR · RELIC INTEGRITY 98.4% · NO TRAUMA TEAM PING ·
        </div>
      </div>
    </div>
  );
}
