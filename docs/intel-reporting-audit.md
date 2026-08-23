# Intel + reporting audit

**Date:** 2026-08-23  
**Question:** are the intel and reporting modules useful, or debt that can drag the system? Which parts are underdeveloped or wrong?  
**This file is the audit.** Do not spawn a sibling plan unless product asks to implement.

**Verdict in one line:** `src.reporting` is a real pipeline stage (keep). `src.intelligence` is mixed — some of it is on the scan path and useful, some is a rubber-stamp CVE table and a GitHub-sized MITRE download that *can* drag a scan. `src.intel` is an offline console facade that never talks to the live feeds. Do not merge the three.

---

## Evidence grades

| Grade | Meaning |
|---|---|
| **LIVE** | On a dashboard / scan / API / console path |
| **TEST-ONLY** | Tests or a helper only tests call |
| **DEAD** | Defined in `src/`, no production caller |
| **UNDERDEVELOPED** | Intended API exists; incomplete vs its own comments |
| **WRONG** | Behavior contradicts the claim, or is unsafe / inverted |
| **UNCERTAIN** | Not fully proven; do not delete or merge on this alone |

---

## 1. Three packages, three jobs

Same noun. Different owners. Same rule as resilience / sandbox: do **not** collapse them.

| ID | Location | Classif. | Useful? | Drag? |
|---|---|---|---|---|
| **IN-shell** | `src/intel/*` | **LIVE** console only | Offline IOC classify + manual vote store. Comment says it is the “pipeline stage contract.” Pipeline never imports it. | None on scan. |
| **IG-feeds** | `src/intelligence/feeds/*` | **LIVE** on enrichment | Real HTTP clients (VT, OTX, MISP, Shodan, NVD, MITRE). | Yes if enrichment runs: NVD keyword search + **full MITRE enterprise-attack.json**. |
| **IG-correlator** | `src/intelligence/threat_intel.py` | **LIVE** | IOC lookup when keys exist. Sync `enrich_findings_with_intel` is a **hardcoded category→CVE table**. | Low CPU. High *correctness* drag. |
| **IG-corr-engine** | `src/intelligence/correlation/engine.py` | **LIVE** enrichment | In-process attack-chain / multi-vector / compound risk. | Small. |
| **IG-aeve-corr** | `src/intelligence/correlation/attack_chain_correlator.py` | **LIVE** via AEVE only | Separate correlator. Not the enrichment one. | None on default scan. |
| **IG-campaign** | `src/intelligence/campaigns/` + `chain_proposal.py` + `graph/` | **LIVE** enrichment | Graph + campaign summary written into ctx / report. Heuristic, not Kuzu GNN. | Moderate (in-process). |
| **IG-severity** | `src/intelligence/severity_model.py` | **LIVE** merge + recon + report | Cheap logreg + priors. Trains from telemetry DB if present; else static weights. | Small SQLite open. Overwrites `severity` / `score`. |
| **IG-risk** | `src/intelligence/risk/*` | **LIVE** dashboard + optional blend | Lifecycle / priority / EPSS / KEV / modern risk. | Dashboard. EPSS/KEV on reporting enrich. |
| **IG-swarm** | `src/intelligence/swarm/` | **DEAD** | File says “RESEARCH PROTOTYPE — not wired.” Zero `src/` callers. | Import cost only if imported. |
| **AN-intel** | `src/analysis/intelligence/` | **LIVE** analysis | Finding merge, endpoint scoring, specs. **Not** TI. | Scan analysis cost (belongs there). |
| **RP-stage** | `src/reporting/pipeline.py` + `pages.py` + `html.py` | **LIVE** `run_reporting` | HTML/JSON run report, `run_summary.json`, `findings.json`. **This is the product artifact.** | End-of-scan I/O. Needed. |
| **RP-sarif** | `src/reporting/sarif_exporter.py` | **LIVE** `sarif_export` | CI `report.sarif`. | Small. |
| **RP-export** | `src/reporting/export_findings.py` | **LIVE** `/api/.../export` | CSV/JSON download. | Small. |
| **RP-compliance** | mapping / attestation / pdf / maturity | **LIVE** report + `/api/reports/*` | Heuristic control overlay + optional PDF. | PDF needs `reportlab` (not a core dep → 503). |
| **RP-sla** | `src/reporting/sla_tracker.py` | **LIVE** reporting + `/sla/trending` | Age vs 14/30/90 day tables; can fire notifications. | Trending walks every `findings.json`. |
| **RP-platforms** | `src/reporting/platforms/*` | **LIVE** if operator submits | httpx clients. Opt-in. | None until POST submit. |
| **RP-exporters** | `src/reporting/exporters.py` | **TEST-ONLY** | Lists `platforms/*.py` stems. Comment “Pipeline reporting is the only caller” is **false**. | None. |
| **RP-intel-txt** | `src/intel/report.py` | **DEAD** in `src/` outside intel | Plain-text “intel findings=N”. | None. |
| **RP-ai** | `/api/reports/ai-summary` | **LIVE** 501 | Frontend still calls it. Module removed. | 501 on click. |

---

## 2. Runtime call-flow (traced)

### 2.1 Intel (two stacks that do not meet)

```
src.intel  (offline)
  FeedAggregator.lookup  → only _manual seeds
  configured_feed_keys() → env peek (VT_API_KEY, OTX_API_KEY, …)
  NEVER constructs VirusTotalClient / OTXClient / MISPClient

  callers in src/:
    console.runtime.intel = FeedAggregator()
    console INTEL_LOOKUP / INTEL_SEED
    frontend bridge intel.lookup / intel.seed  → /api/console/intel

  callers in pipeline / dashboard routers: NONE

src.intelligence  (live TI)
  enrichment stage  (pipeline, name in UI: "intelligence")
    CVSS enrich
    correlate_findings / multi-vector / compound_risk     # correlation.engine
    ChainProposalEngine
    async with CVESyncClient + MitreAttackMapper:
         for top N findings (default 25):
            NVD keywordSearch(finding.title)
            mitre.get_techniques_by_tactic(finding.category)  # "xss" ≠ TA0002
            ThreatIntelCorrelator.match_ioc_async(host)       # VT/OTX/MISP if keys
    build_threat_graph + build_attack_campaigns

  reporting.build_summary
    ThreatIntelCorrelator.enrich_findings_with_intel()
         correlate_cve(category)  # HARDCODED table
         attach EPSS + CISA KEV for those CVE ids

  finding merge / recon scoring
    enrich_findings_with_model_severity()

  dashboard
    /api/risk*  → risk.remediation_priority / finding_lifecycle
    cockpit nodes → load_lateral_movement_graph

  AEVE
    VulnCorrelationEngine   # third correlator
```

`src.intel` docstring: “Live HTTP clients stay in intelligence.feeds.” True. It also claims to be the discoverable pipeline contract. **False** — enrichment imports `src.intelligence.feeds` directly.

### 2.2 Reporting

```
DAG: reporting → sarif_export → report_distribution (default SKIP)

run_reporting
  screenshots + artifact diff
  plugin builders (endpoint intel, VRT, next steps, …)
  build_summary  → compliance_mapping + optional TI table
  RemediationPatchGenerator
  persist findings.json / run_summary.json
  SLATracker.auto_escalate_overdue  (notifications)
  generate_run_report → report.html / report.json / attestation*

dashboard
  GET /api/reports/library
  GET /api/reports/compliance/pdf     # reportlab or 503
  GET /api/reports/sla/trending
  GET /api/reports/ai-summary         # always 501
  GET /api/reports/platforms
  POST /api/reports/runs/{run}/findings/{id}/submit
  export CSV/JSON

distribution
  enabled=false by default
```

---

## 3. What is actually useful

1. **`run_reporting` + `generate_run_report` + persist** — the scan’s deliverable. Keep.
2. **SARIF + CSV/JSON export** — CI and operator download. Keep.
3. **`intelligence.correlation.engine` on enrichment** — in-process, no network, writes chains into analysis_results. Keep.
4. **Severity model** — real enough as a prior blender; does not need XGBoost despite `architecture.md`. Keep, but do not treat `severity` overwrite as gospel when the DB is empty (static weights).
5. **Feed *clients*** — VT/OTX/MISP/NVD/Shodan look like real httpx wrappers. Worth keeping **as libraries**. Do not pretend they run unless keys + enrichment are on.
6. **Campaign / threat graph / chain proposals** — heuristic, but they feed the HTML report. Keep as report sections, not as “GNN path prediction.”
7. **Platform submit API** — opt-in, gated on `ready`. Useful *if* credentials exist. Frontend `platforms.ts` is wired.
8. **`src.intel` IOC classify + console seed** — small, honest offline tool. Useful as a console command. Not a TI platform.

---

## 4. What is debt (does not always drag *runtime*)

| Item | Why debt | Safe delete / freeze? |
|---|---|---|
| `src.intel` sold as pipeline contract | Never imported by pipeline | Keep as console facade **or** make enrichment use it. Do not leave the lie. |
| `src.intel.report` | No production caller | Yes. |
| `intelligence.swarm` | Explicit prototype, unused | Yes, or quarantine. |
| `reporting.exporters.list_exporter_platforms` | Filename listing | Harmless. Do not grow it into a second platform layer. |
| AI executive summary | Frontend calls 501 | Remove UI or restore module. |
| Second/third `correlate_findings` | `src.intel` vs `intelligence.correlation` vs AEVE engine | Do not merge blindly. Different math. |
| Docs (`architecture.md` ML XGBoost / Kuzu GCN / Production TI) | Overclaim | Honesty pass. |

---

## 5. Underdeveloped

| Item | What’s missing |
|---|---|
| IN-shell ↔ IG-feeds | Facade never constructs a client. `unavailable_feeds()` only checks env names. |
| VT env names | `src.intel` + `feeds/virustotal.py` + recon: `VT_API_KEY`. `threat_intel.match_ioc_async`: **`VIRUSTOTAL_API_KEY`**. Lifespan labels `VIRUSTOTAL_API_KEY`. Operator can set the documented VT key and still skip VT on the scan path. |
| MITRE mapping | Enrichment calls `get_techniques_by_tactic(finding.category)`. Categories are `xss` / `idor`. Tactics are `TA0002` / `initial-access`. Result is usually **[]**. Mapper itself can load the real STIX file. |
| CVE keyword search | `search_cves(keyword=finding.title)` against NVD. Titles like “Reflected XSS” attach whatever NVD ranks, not “this host’s CVE.” |
| EPSS / KEV | Attached only to the **hardcoded** CVE list (or enrichment NVD hits if someone wired them — sync path uses the table). Empty table category ⇒ no EPSS. |
| Platform HackerOne URL | POST `{base}/v1/hacktivity/teams/{handle}/reports`. Official HackerOne report create is historically `/v1/reports` with program relationship. **UNCERTAIN** — treat as unproven until a live 201. |
| `exporters.py` | Not used by `run_reporting`. |
| Compliance PDF | `reportlab` is mypy-ignored, not a core dependency. |
| Report distribution | Real SMTP path; default off. Fine. |
| Swarm “LLM-powered agent” | No LLM. Sync gossip only. |

---

## 6. Wrong

### 6.1 Category → CVE table is not correlation — **certain**

`ThreatIntelCorrelator._cve_knowledge_base` maps:

| Category | Sample CVE | Problem |
|---|---|---|
| `command_injection` | **CVE-2021-44228** (Log4Shell) | Not command injection. |
| `sql_injection` | CVE-2024-27956 etc. | Specific third-party bugs, not “this finding is that CVE.” |
| every listed category | 2–3 fixed IDs | Docstring: “high-fidelity matching CVE entries.” |

`build_summary` always runs this (unless every finding already has a `threat_intel` dict). Findings get `cve_correlations: ["CVE-2021-44228", …]` and then EPSS/KEV for **those** IDs. UI “Threat Intelligence” / EPSS can show Log4Shell odds on a local cmdi finding.

### 6.2 SLA trending counts `verified` as remediated — **certain**

`GET /api/reports/sla/trending`:

```python
is_remediated = status in {"remediated", "resolved", "verified"}
```

In this product `verified` / AEVE `verified_tp` means **still exploitable**. MTTR and “remediated_count” inflate. Missing timestamps fall back to `time.time()`, so duration can be ~0.

### 6.3 AI summary still advertised — **certain**

Handler raises `501 "AI executive summary module removed."` `frontend/src/api/reports.ts` still GETs `/api/reports/ai-summary`.

### 6.4 Two VirusTotal keys — **certain**

Scan-path IOC uses `VIRUSTOTAL_API_KEY`. Client module and `src.intel` advertise `VT_API_KEY`. Recon passive DNS uses `VT_API_KEY`. Same vendor, two knobs.

### 6.5 Docs vs code — **certain**

`architecture.md` still calls resilience `src/resilience/circuit_breaker.py` (deleted) and TI/ML “Production XGBoost.” Severity model is in-process logreg. Threat graph is dict nodes/edges, not Kuzu GCN.

---

## 7. Does it drag the system?

| Path | Drag |
|---|---|
| Default scan, no TI keys | **Yes, possible network drag.** Enrichment still `async with CVESyncClient + MitreAttackMapper` and hits NVD + **downloads MITRE `enterprise-attack.json`** (large) once per mapper context, then queries by the wrong tactic id. Failures are caught per finding; the download/timeout still burns wall clock (default 8s/finding, 25 findings, concurrency 5). |
| Default scan, reporting | Real I/O: HTML, JSON, optional screenshots, SLA notify. **Product cost.** Sync CVE table is CPU-cheap and **truth-expensive**. |
| Default dashboard | Report library / export: useful. SLA trending: full tree walk. Platform list: constructs all 13 clients from env. |
| Console intel lookup | In-memory. Always “unavailable” for VT/OTX/MISP/Shodan unless env set — and even then lookup still won’t HTTP. |
| `FEATURE` / swarm | No. |
| Platform submit | Only on explicit POST with credentials. |

The dangerous drag is **belief + enrichment I/O**: operators see CVE/MITRE/EPSS fields and MITRE/NVD latency on every intelligence stage, even when mapping is empty or invented.

---

## 8. Same noun vs different domain

Do **not** merge:

| Domain | Why not one module |
|---|---|
| Offline IOC + console votes (`src.intel`) | No HTTP. Manual seed. |
| HTTP TI clients (`intelligence.feeds`) | Keys, rate limits, Retry-After (already its own breaker). |
| In-scan finding merge (`analysis.intelligence`) | Detector output, not feeds. |
| Severity prior (`intelligence.severity_model`) | Local telemetry, not VT. |
| HTML/SARIF report (`src.reporting`) | Artifact writer. |
| Bug-bounty push (`reporting.platforms`) | Opt-in egress to third parties. |
| Swarm | Unwired research. |

`src.intel.correlation.correlate_findings(findings, aggregator)` ≠ `intelligence.correlation.engine.correlate_findings(findings)`.

---

## 9. What “done” would mean (do not implement on a bare continue)

Product order still wins: real scan + restart proof before theater.

If product later picks a slice:

1. **Honesty (cheap, default recommendation)**  
   - Label `src.intel` “console offline votes,” not pipeline TI.  
   - One VT env name.  
   - Stop attaching the hardcoded CVE table (or rename field `example_cves_for_category`, never `cve_correlations`).  
   - Do not count `verified` as remediated.  
   - 501-or-delete AI summary on the frontend.  
   - Docs: enrichment may call NVD/MITRE; swarm is dead; severity is not XGBoost.
2. **Stop scan drag:** skip MITRE/NVD unless `analysis.threat_intel` (or similar) is on **and** a key/allow-network flag is set. Cache MITRE STIX on disk. Map categories → technique IDs, not tactic IDs.
3. **Do not** wire `src.intel.FeedAggregator` as a fake front for VT “to unify packages.”
4. **Do not** rewrite reporting HTML / SSE / theater in this program.

---

## 10. Open / UNCERTAIN

- Whether any deployment already depends on `cve_correlations` IDs in downstream tickets.
- Whether HackerOne/Bugcrowd URLs return 201 against current APIs.
- Whether `includeIntelligence` scan-profile toggle actually skips the enrichment stage (UI flag exists; not re-traced here).
- Completeness of EPSS/KEV clients without network in this sandbox.
- Whether `load_lateral_movement_graph` reads the enrichment threat_graph or a different file.

If a later slice depends on one of these, re-trace that path first.
