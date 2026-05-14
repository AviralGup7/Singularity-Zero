RUN_REPORT_STYLES = """
:root{--bg:#07111f;--panel:#0d1b2a;--text:#e5eef7;--muted:#91a4b8;--accent:#7dd3fc;--ok:#34d399;--warn:#f59e0b;--bad:#f87171}
*{box-sizing:border-box}
body{font-family:Segoe UI,Arial,sans-serif;background:radial-gradient(circle at top,#12304a 0%,#07111f 52%);color:var(--text);margin:0;padding:24px}
h1,h2,h3{margin:0 0 12px}main{max-width:1200px;margin:0 auto}.muted{color:var(--muted)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin:16px 0 24px}
.card{background:rgba(13,27,42,.92);border:1px solid rgba(148,163,184,.18);border-radius:20px;padding:14px}
.value{font-size:1.6rem;font-weight:700;margin-top:6px}.label{color:#cbd5e1;text-transform:capitalize}
.meta{color:var(--muted);font-size:.9rem;margin-top:8px}
section{background:rgba(13,27,42,.92);border:1px solid rgba(148,163,184,.18);border-radius:20px;padding:18px;margin-top:18px}
ul{margin:0;padding-left:20px}li{margin:8px 0;word-break:break-word}
.shots{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:14px}
.shot{background:#0b1220;border:1px solid #334155;border-radius:16px;overflow:hidden}
.shot img{display:block;width:100%;height:190px;object-fit:cover;background:#020617}
.shot-url{padding:10px;font-size:.9rem;word-break:break-all}a{color:var(--accent)}
.action-row{display:flex;gap:10px;flex-wrap:wrap;margin-top:10px}
.action-btn{background:#16324a;border:0;border-radius:14px;color:var(--text);padding:10px 14px;cursor:pointer;font-weight:600}
.action-btn:hover{filter:brightness(1.06)}
.ui-badge{display:inline-flex;align-items:center;justify-content:center;padding:6px 10px;border-radius:999px;background:rgba(148,163,184,.16);color:var(--text);border:1px solid rgba(148,163,184,.2);font-size:.78rem;text-transform:uppercase;letter-spacing:.04em}
.ui-badge.ok{background:rgba(52,211,153,.12);color:var(--ok);border-color:rgba(52,211,153,.22)}
.ui-badge.warn{background:rgba(245,158,11,.12);color:var(--warn);border-color:rgba(245,158,11,.22)}
.ui-badge.bad{background:rgba(248,113,113,.12);color:var(--bad);border-color:rgba(248,113,113,.22)}
.finding-card{list-style:none;margin:0 0 12px;padding:14px;border-radius:16px;background:rgba(9,19,31,.72);border:1px solid rgba(148,163,184,.16)}
.finding-head{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:8px}
.finding-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:10px;margin-top:10px}
.finding-metric{background:#0a1827;border:1px solid rgba(148,163,184,.12);border-radius:14px;padding:10px 12px}
.finding-metric strong{display:block;font-size:.82rem;color:var(--muted);font-weight:600;margin-bottom:4px}
.table-wrap{overflow-x:auto;margin-top:14px}
.collapsed-block{margin-top:8px}
.collapsed-block summary{cursor:pointer;color:var(--accent);font-weight:600}
section pre{white-space:pre-wrap;word-break:break-word;background:#0a1827;border:1px solid rgba(148,163,184,.12);border-radius:12px;padding:10px;max-height:42vh;overflow:auto;margin-top:8px}
section code{font-family:Consolas,Monaco,monospace;font-size:.86rem}
.report-table{width:100%;border-collapse:collapse;min-width:880px}
.report-table th,.report-table td{padding:12px 10px;border-bottom:1px solid rgba(148,163,184,.12);text-align:left;vertical-align:top}
.report-table th{color:#cbd5e1;font-size:.82rem;text-transform:uppercase;letter-spacing:.04em}
.report-table tbody tr:hover{background:rgba(125,211,252,.05)}
.report-modal-backdrop{position:fixed;inset:0;background:rgba(2,6,23,.72);display:flex;align-items:center;justify-content:center;padding:20px;z-index:9999}
.report-modal-backdrop[hidden]{display:none !important}
.report-modal{width:min(760px,100%);background:#081524;border:1px solid rgba(148,163,184,.18);border-radius:20px;padding:20px;box-shadow:0 30px 80px rgba(0,0,0,.45)}
.report-modal h3{margin-bottom:8px}
.report-modal pre{white-space:pre-wrap;word-break:break-word;background:#0a1827;border:1px solid rgba(148,163,184,.12);border-radius:16px;padding:14px;max-height:52vh;overflow:auto;color:var(--text)}
.report-modal-actions{display:flex;justify-content:flex-end;gap:10px;margin-top:14px}
.export-bar{display:flex;gap:10px;flex-wrap:wrap;margin:14px 0;align-items:center}
.export-label{color:var(--muted);font-size:.9rem;font-weight:600}
.export-btn{background:#16324a;border:0;border-radius:14px;color:var(--text);padding:10px 14px;cursor:pointer;font-weight:600;text-decoration:none;font-size:.88rem}
.export-btn:hover{filter:brightness(1.06)}
.export-row{display:flex;gap:10px;flex-wrap:wrap;margin-top:12px}
.export-row .export-btn{background:#1e3a52;padding:8px 12px;font-size:.82rem}
.export-bar{display:flex;gap:10px;flex-wrap:wrap;margin:14px 0;align-items:center}
.export-label{color:var(--muted);font-size:.9rem;font-weight:600}
.export-btn{background:#16324a;border:0;border-radius:14px;color:var(--text);padding:10px 14px;cursor:pointer;font-weight:600;text-decoration:none;font-size:.88rem}
.export-btn:hover{filter:brightness(1.06)}
.export-row{display:flex;gap:10px;flex-wrap:wrap;margin-top:12px}
.export-row .export-btn{background:#1e3a52;padding:8px 12px;font-size:.82rem}
"""

REPORT_SCRIPT = """
const apiChecklistModal = (() => {
  const backdrop = document.createElement('div');
  backdrop.className = 'report-modal-backdrop';
  backdrop.hidden = true;
  backdrop.innerHTML = `
    <div class="report-modal" role="dialog" aria-modal="true" aria-labelledby="api-checklist-title">
      <h3 id="api-checklist-title">Authorized API Key Review</h3>
      <p class="muted" id="api-checklist-context"></p>
      <pre id="api-checklist-body"></pre>
      <div class="report-modal-actions">
        <button type="button" class="action-btn" id="copy-api-checklist">Copy Checklist</button>
        <button type="button" class="action-btn" id="close-api-checklist">Close</button>
      </div>
    </div>
  `;
  document.body.appendChild(backdrop);

  const context = backdrop.querySelector('#api-checklist-context');
  const body = backdrop.querySelector('#api-checklist-body');
  const closeButton = backdrop.querySelector('#close-api-checklist');
  const copyButton = backdrop.querySelector('#copy-api-checklist');

  const hide = () => {
    backdrop.hidden = true;
  };

  closeButton.addEventListener('click', hide);
  backdrop.addEventListener('click', (event) => {
    if (event.target === backdrop) {
      hide();
    }
  });
  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && !backdrop.hidden) {
      hide();
    }
  });
  copyButton.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(body.textContent || '');
      copyButton.textContent = 'Copied';
      window.setTimeout(() => { copyButton.textContent = 'Copy Checklist'; }, 1200);
    } catch (error) {
      copyButton.textContent = 'Copy Failed';
      window.setTimeout(() => { copyButton.textContent = 'Copy Checklist'; }, 1200);
    }
  });

  return {
    show(title, checklist) {
      context.textContent = title;
      body.textContent = checklist;
      copyButton.textContent = 'Copy Checklist';
      backdrop.hidden = false;
    },
  };
})();

document.querySelectorAll('.copy-review-brief').forEach((button) => {
  button.addEventListener('click', async () => {
    const brief = button.getAttribute('data-review-brief') || '';
    try {
      await navigator.clipboard.writeText(brief);
      button.textContent = 'Copied';
      window.setTimeout(() => { button.textContent = 'Copy Review Note'; }, 1200);
    } catch (error) {
      button.textContent = 'Copy Failed';
      window.setTimeout(() => { button.textContent = 'Copy Review Note'; }, 1200);
    }
  });
});

document.querySelectorAll('.copy-proof-script').forEach((button) => {
  button.addEventListener('click', async () => {
    const script = button.getAttribute('data-proof-script') || '';
    const defaultLabel = button.getAttribute('data-default-label') || 'Copy Proof';
    try {
      await navigator.clipboard.writeText(script);
      button.textContent = 'Copied';
      window.setTimeout(() => { button.textContent = defaultLabel; }, 1200);
    } catch (error) {
      button.textContent = 'Copy Failed';
      window.setTimeout(() => { button.textContent = defaultLabel; }, 1200);
    }
  });
});

document.querySelectorAll('.open-review-url').forEach((button) => {
  button.addEventListener('click', () => {
    const url = button.getAttribute('data-review-url');
    if (url) {
      window.open(url, '_blank', 'noopener,noreferrer');
    }
  });
});

document.querySelectorAll('.replay-variant').forEach((button) => {
  button.addEventListener('click', async () => {
    const replayUrl = button.getAttribute('data-replay-url');
    if (!replayUrl) {
      return;
    }
    const originalText = button.textContent;
    button.textContent = 'Replaying...';
    try {
      const response = await fetch(replayUrl, { headers: { 'Accept': 'application/json' } });
      const payload = await response.json();
      if (!response.ok) {
        throw new Error(payload.error || 'Replay failed');
      }
      const summary = [
        `auth ${payload.auth_mode || 'inherit'}`,
        `status ${payload.status_code}`,
        `final ${payload.final_url || payload.requested_url}`,
        `similarity ${payload.body_similarity}`,
      ].join(' | ');
      button.textContent = 'Replay Ready';
      button.setAttribute('title', summary);
      window.setTimeout(() => { button.textContent = originalText; }, 1600);
    } catch (error) {
      button.textContent = 'Replay Failed';
      window.setTimeout(() => { button.textContent = originalText; }, 1600);
    }
  });
});

document.querySelectorAll('.show-api-key-checklist').forEach((button) => {
  button.addEventListener('click', () => {
    const target = button.getAttribute('data-target-label') || 'Unknown target';
    const exposureType = button.getAttribute('data-exposure-type') || 'API key exposure';
    const checklist = button.getAttribute('data-review-checklist') || '';
    apiChecklistModal.show(`${exposureType} on ${target}`, checklist);
  });
});
"""

INDEX_STYLES = """
body{font-family:Segoe UI,Arial,sans-serif;background:#020617;color:#e2e8f0;margin:0;padding:24px}
main{max-width:1200px;margin:0 auto}.run{background:#0f172a;border:1px solid #334155;border-radius:16px;padding:18px;margin-bottom:16px}
.counts{display:flex;flex-wrap:wrap;gap:10px;margin:14px 0}.chip{background:#111827;border:1px solid #334155;border-radius:999px;padding:8px 12px;color:#cbd5e1}
a{color:#7dd3fc}.muted{color:#94a3b8}
.export-row{display:flex;gap:10px;flex-wrap:wrap;margin-top:12px}
.export-btn{background:#1e3a52;border:0;border-radius:14px;color:#7dd3fc;padding:8px 12px;cursor:pointer;font-weight:600;text-decoration:none;font-size:.82rem}
.export-btn:hover{filter:brightness(1.06)}
"""
