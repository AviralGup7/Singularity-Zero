import{yn as b}from"./react-vendor-B_0K7QAp.js";import{t as x}from"./toastDispatcher-BBkf3OTJ.js";function f(e,r,o){if(typeof document>"u")return;const n=document.getElementById("error-overlay");n&&n.remove();const t=document.createElement("div");t.id="error-overlay",t.style.cssText=`
    position: fixed; top: 0; left: 0; right: 0; bottom: 0;
    background: rgba(0,0,0,0.85); z-index: 99999;
    display: flex; align-items: center; justify-content: center;
    padding: 2rem; overflow: auto;
  `;const a=document.createElement("div");a.style.cssText=`
    padding: 1rem 1.5rem; border-bottom: 1px solid #30363d;
    display: flex; align-items: center; justify-content: space-between;
  `;const l=document.createElement("h2");l.style.cssText="color: #f85149; margin: 0; font-size: 1.1rem;",l.textContent=`⚠️ ${e}`;const s=document.createElement("button");s.textContent="✕ Close",s.style.cssText=`
    background: #21262d; border: 1px solid #30363d; color: #8b949e;
    padding: 0.25rem 0.75rem; border-radius: 4px; cursor: pointer;
  `,s.addEventListener("click",()=>t.remove()),a.appendChild(l),a.appendChild(s);const i=document.createElement("div");i.style.cssText="padding: 1.5rem;";const c=document.createElement("div");c.style.cssText=`
    background: #0d1117; border: 1px solid #30363d; border-radius: 6px;
    padding: 1rem; margin-bottom: 1rem;
  `;const m=document.createElement("p");m.style.cssText="color: #f85149; margin: 0 0 0.5rem; font-weight: 600;",m.textContent="Error Details:";const p=document.createElement("pre");p.style.cssText=`
    color: #c9d1d9; margin: 0; font-size: 0.85rem;
    white-space: pre-wrap; word-break: break-word;
    font-family: 'Consolas', 'Monaco', monospace;
  `,p.textContent=r,c.appendChild(m),c.appendChild(p),i.appendChild(c);const u=document.createElement("div");u.style.cssText="margin-top: 1rem; padding-top: 1rem; border-top: 1px solid #30363d;";const g=document.createElement("p");g.style.cssText="color: #8b949e; font-size: 0.8rem; margin: 0;",g.textContent="💡 Tip: Check the browser console (F12) for more details.",u.appendChild(g),i.appendChild(u);const d=document.createElement("div");d.style.cssText=`
    background: #161b22; border: 1px solid #f85149; border-radius: 8px;
    max-width: 800px; width: 100%; max-height: 90vh; overflow: auto;
    box-shadow: 0 0 40px rgba(248,81,73,0.3);
  `,d.appendChild(a),d.appendChild(i),t.appendChild(d),document.body.appendChild(t)}var h=!1;async function y(){if("serviceWorker"in navigator){const e=await navigator.serviceWorker.getRegistrations();await Promise.all(e.map(r=>r.unregister()))}if("caches"in window){const e=await caches.keys();await Promise.all(e.filter(r=>r.startsWith("cyberpipe-")).map(r=>caches.delete(r)))}}function C(){y().catch(e=>{console.warn("[SW] Legacy cleanup failed:",e)})}function T(){b(async()=>{const{onCLS:e,onLCP:r,onFCP:o,onTTFB:n}=await import("./web-vitals-BJ1eIB6D.js");return{onCLS:e,onLCP:r,onFCP:o,onTTFB:n}},[]).then(({onCLS:e,onLCP:r,onFCP:o,onTTFB:n})=>{const t=a=>{};e(t),r(t),o(t),n(t)}).catch(()=>{})}function k(){h||(h=!0,window.addEventListener("error",e=>{if(console.error("[GlobalError]",e.error||e.message),e.target!==window&&e.target instanceof Element){const r=e.target.tagName;(r==="SCRIPT"||r==="LINK")&&f("Resource Load Error",`Failed to load ${r}`);return}x(`Runtime Error: ${e.message}`,"error"),f("JavaScript Error",e.error?.message||e.message||"Unknown error",e.error?.stack)},!0),window.addEventListener("unhandledrejection",e=>{const r=e.reason,o=r?.message||r?.toString?.()||"",n=String(o).toLowerCase();n==="canceled"||n==="abort"||r?.name==="CanceledError"||r?.name==="AbortError"||(console.error("[UnhandledRejection]",e.reason),x(`Async Failure: ${o}`,"error"),f("Async Error",o,r?.stack))}))}export{y as clearLegacyServiceWorkers,T as initWebVitals,C as registerServiceWorker,k as setupGlobalErrorTracking};
