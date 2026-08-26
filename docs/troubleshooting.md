# Troubleshooting

Decision tree and recovery model: [FAILURE_MODES.md](FAILURE_MODES.md) and flowchart **F-018**. This page is the short operator index.

## Scan will not start

| Symptom | Check |
|---|---|
| Exit 3 immediately | `attach_pipeline_authority` failed (fail-closed). Authority runtime must attach. |
| `AuthorityNotAttached` in unit tests | Expected: orchestrator properties do not construct a private `StateAuthority`. |
| Doctor exit 2 / 3 / 5 | `cstp system doctor` — missing binaries, `.env`, or invalid config. |
| Lock collision exit 1 | Another scan holds the run lock. |

## Zero findings

| Stage / exit | Meaning |
|---|---|
| COMPLETED + exit 0 | Genuine clean or under policy. |
| COMPLETED + exit 4 | Degraded / SKIPPED_FAILED probes. Not a clean bill of health. |
| FAILED + exit 3 | Fatal recon or target down. |
| COMPLETED + exit 2 | Findings exceeded policy (not a failure of the job SM). |

`"open"` is **not** a finding lifecycle alias. Dashboard open/closed is `ticket_status`. Report PDF uses `surface == REPORTABLE`.

## Authority / settlement

- HMAC receipts: set `AUTHORITY_SIGNING_KEY` (else `APP_SECRET_KEY`). Process-local random key will not verify after restart.
- FAILED stage still settles. Settlement **status** for a failed attempt is `REJECTED` (wal_id present; no `FINDING_CREATED`).
- Fenced partition (`I37`) refuses `settle_stage_output` and HuntBudget reserve.
- Outbox append failure: **do not emit** on EventBus. Replay later.

## Dashboard 429 on `/api/findings/`

Prefix limit is 60 req/min when security is enabled, 180 when disabled. Timeline queries should send a stable `paramsKey` and a 5s TTL. Do not `bypassCache` on the GET success path.

## Resume vs fresh

Dashboard default `force_fresh=True` appends `--force-fresh-run`. Resume only when the job sets `force_fresh=False`. I35 recovery then walks FrontierWAL + `apply_authority_recovery` on the partition plane.

## WebSocket / SSE

Real paths (not the abbreviated chart names):

- SSE: `GET /api/jobs/{job_id}/progress/stream`
- Logs WS: `/ws/logs/{job_id}`
- Triage WS: `/ws/triage/{run_id}`

Origin validation runs **before** the `DASHBOARD_AUTH_DISABLED` admin bypass.

## Tests hang locally

Do not run the full suite. `timeout = 20` in `pyproject.toml`. Fail-fast recon tests stay skipped.
