# Deployment & Infrastructure (Singularity-Zero)

This guide provides structured deployment metadata and environment configuration for orchestrating the Neural-Mesh in production.

---

## 🔧 Environment Configuration

The pipeline relies on environment variables for infrastructure binding. 
> **SOURCE OF TRUTH**: See [Environment Variables Reference](environment-variables.md).

**CRITICAL ADDITION**: The mesh requires a shared HMAC secret.
- `MESH_SECRET`: Mandatory for authenticating the Gossip protocol. If mismatched, nodes will silently drop packets.
  
  > [!WARNING]
  > **Mesh Security Warning**: Never use weak defaults or hardcoded values for `MESH_SECRET`. Generate a high-entropy secret in production using:
  > ```bash
  > openssl rand -hex 32
  > ```
  
- `MESH_BIND_INTERFACE`: Restricts the gossip server to bind only to a specific network interface (e.g., a private VPC network adapter) rather than `0.0.0.0` (all interfaces). This significantly reduces the network exposure.
  
  > [!TIP]
  > **Network Security Best Practices**: Gossip UDP traffic (port 9008) is not wire-encrypted out of the box and relies entirely on HMAC-SHA256 signatures for authentication.
  > - **Recommendation**: Run all inter-node gossip traffic over a secure **WireGuard overlay network** or **IPsec VPN tunnel** across your internal VPC.
  > - Restrict communication to private network interfaces using the `MESH_BIND_INTERFACE` environment variable in the node configuration.

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

## 🔒 Production Security Hardening & Isolation

To support multi-tenant isolation and supply chain security in production:

### 1. Multi-Tenant Key Namespacing & Scaling
- Upstream reverse proxies, gateways, and load balancers must pass through the `X-Tenant-ID` header to FastAPI dashboard servers.
  
  > For architecture details and context propagation logic, see [Architecture - Multi-Tenant Isolation](architecture.md#1-multi-tenant-key-namespacing-playbook-pub-sub-isolation) and [API Reference - Global Security Headers](api-reference.md#global-security-governance-headers).

### 2. Double-Submit CSRF Verification
- All mutating endpoints enforce stateless double-submit cookie matching. Upstream HTTP reverse proxies must preserve cookies.
  
  > For exact cookie properties, exemptions, and header matching requirements, see [API Reference - Global Security Headers](api-reference.md#global-security-governance-headers).

### 3. Gated Deployment Pipelines (CI/CD)
- CD pipelines must run the automated security verification quality gate checks before launching deployments.
  
  > See [Automated Quality Gates & Pipeline Security Verification](testing.md#automated-quality-gates-pipeline-security-verification) for the complete execution syntax and descriptions.

---

## 🛠️ Health & Readiness Protocols

Agents should monitor these endpoints for deployment health:
- **Mesh Health**: `GET /api/health` (verify `mesh.length >= 1` and status is `alive`).
- **Cockpit Telemetry**: View live Gossip stats on the `/mesh` dashboard.
