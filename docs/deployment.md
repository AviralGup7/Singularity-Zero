# Deployment & Infrastructure (Singularity-Zero)

This guide provides structured deployment metadata and environment configuration for orchestrating the Neural-Mesh in production.

---

## 🔧 Environment Configuration

The pipeline relies on environment variables for infrastructure binding. 
> **SOURCE OF TRUTH**: See [Environment Variables Reference](environment-variables.md).

**CRITICAL ADDITION**: The mesh requires a shared HMAC secret.
- `MESH_SECRET`: Mandatory for authenticating the Gossip protocol. If mismatched, nodes will silently drop packets.

---

## 🚢 Orchestration Modes

### 1. Neural-Mesh (Distributed Actor Model)
The Neural-Mesh enables P2P collaboration, task migration, and CRDT state sync.

**Discovery & Network Protocols:**
- **Gossip Protocol (UDP)**: Port `9008` (Default port `8000` + `1008` offset) must be open across the internal VPC for UDP traffic.
- **Serialization**: `MessagePack` over Redis Pub/Sub for high-throughput zero-copy transfers.
- **Leader Election**: Automated via Deterministic Bully Algorithm.

```yaml
# deploy_config.yaml
mode: neural-mesh
components:
  - role: actor_node
    replicas: auto
    scaling_policy: resource-aware
    anti_forensics: enabled
    capabilities: [browser, heavy_compute, nuclei]
```

### 2. Single-Node (Docker Compose)
For isolated environments, use the optimized stack:
```bash
docker-compose -f docker-compose.optimized.yml up -d
```

---

## 🛡️ Anti-Forensic Requirements (Ghost-VFS)
When running with `anti_forensic_mode: true` (Ghost Mode), the container requires significantly more RAM as all output artifacts, screenshots, and findings are stored in AES-256-GCM encrypted memory buffers.

- Ensure Docker/K8s memory limits are set to at least **1.5x** the expected capacity.
- Do not mount host volumes to `/app/output` if true deniability is required.

---

## 🛠️ Health & Readiness Protocols

Agents should monitor these endpoints for deployment health:
- **Mesh Health**: `GET /api/health` (verify `mesh.length >= 1` and status is `alive`).
- **Cockpit Telemetry**: View live Gossip stats on the `/mesh` dashboard.
