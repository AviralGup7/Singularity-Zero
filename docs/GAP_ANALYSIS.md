# Gap Analysis: Cyber Security Test Pipeline

| Gap | Severity | Status | Owner/Track |
|:---|:---|:---|:---|
| Manifest entries with no backing engine implementation: xpath, xxe, nosql, ldap, cors, trace, options, hpp, http_smuggling, json, response_diff | High | Open | Architecture/Exploit Engines |
| No multi-node actor migration (Ghost-Actor Mesh is single-node pykka only) | Critical | Open | Architecture/Actor Mesh |
| WASM sandbox (AEVE) not connected to wasmtime runtime in exploit engines | High | Open | Execution/AEVE |
| No real DRL evasion (PPO) — only HMM-based evasion; no torch/stable-baselines3 dep | High | Open | Learning/Evasion |
| No Jira/ServiceNow/DefectDojo ticket creation wired to pipeline output | Medium | Open | Integration/Ticketing |
| No VirusTotal or AlienVault OTX feeds (MISP only) | High | Open | Intelligence/Feeds |
| detection/ is a thin facade over analysis/ — merge is unresolved | High | Open | Architecture/Modules |
| analysis/checks/active and analysis/checks/passive excluded from coverage (now being addressed) | High | In Progress | Testing/Coverage |
| Coverage threshold was 5% per module (being raised to 70%) | High | In Progress | Testing/Coverage |
| No credential test matrix for multi-role scanning | High | Open | Analysis/Auth Testing |
| GraphQL mutation / alias-stacking / persisted-query-hijacking not in active engine catalog | High | Open | Exploit Engines/GraphQL |
| secrets_scanner.py was just added but not yet wired into the passive analysis pipeline | High | Open | Pipeline/Analysis |
| No TLS certificate pinning in exploit engine targets | Medium | Open | Execution/Targets |
| GNN model (hidden_dim=128 after fix) still unconnected to Kuzu | High | Open | Learning/Graph Engine |
| Ghost-VFS not implemented as described (Python bytearray heap memory; true encrypted RAM isolation not available) | Medium | Open | Architecture/Memory |
| Collaborative AI Swarm (Red Team Mesh) — no LLM backend or multi-node consensus harness | Medium | Open | Architecture/Swarm |
| Supply chain & pipeline integrity — template cryptographic verification not enforced at startup | Medium | Open | Platform Hardening |
| No sandbox container orchestration — sandbox service layer exists but orchestration is limited | Medium | Open | Infrastructure/Containers |
