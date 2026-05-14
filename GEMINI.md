# Cyber Security Test Pipeline - AI Agent Directives
> **CRITICAL: This file contains foundational architectural mandates for autonomous agents operating in the Singularity-Zero codebase. These instructions OVERRIDE all general workflow defaults.**

## 🌌 The Singularity-Zero Architecture

You are operating within a **Frontier-Level Autonomous Security Engine**. The codebase utilizes advanced distributed systems paradigms, hardware acceleration, and anti-forensic storage.

### 1. State Management is CRDT-Based
- **NEVER** perform deep-merges or list appends manually on pipeline state.
- **MANDATE**: All findings, URLs, and subdomains are stored in `NeuralState` using **Vector-Clocked Last-Write-Wins (LWW) Sets** (`src/core/frontier/state.py`).
- Stages must emit `StageOutput` containing a `state_delta`. The Orchestrator automatically handles the CRDT conflict resolution.

### 2. Actor-Based Execution
- The pipeline executes tasks using **Location-Transparent Actors** (`src/core/frontier/ghost_actor.py`).
- **NEVER** assume a task will finish on the same machine it started on. State must be perfectly serializable via `msgpack` so actors can migrate mid-execution.

### 3. Hardware Acceleration & Type Safety
- **MANDATE**: Use the hardware accelerators in `src/core/frontier/` (e.g., `vectorized_url_filter` in NumPy) for operations involving >1000 items.
- **MANDATE**: Every internal service function in `src/pipeline/services/services/` MUST be decorated with `@beartype` for recursive runtime type-checking.

### 4. Anti-Forensic Storage (Ghost-VFS)
- **NEVER** write directly to the physical disk (`open(..., 'w')`) for security artifacts.
- **MANDATE**: Always use `PipelineOutputStore.write_text()`. If `anti_forensic_mode` is enabled, the store routes the data to a volatile, AES-GCM encrypted RAM drive (`src/core/frontier/ghost_vfs.py`).

### 5. Advanced Evasion & Intelligence
- The pipeline utilizes a **Polymorphic Chameleon** (`src/core/frontier/chameleon.py`) to bypass behavioral WAFs. Do not hardcode static User-Agents or headers.
- Findings are evaluated using **Semantic Deduplication** (Cosine Similarity) and the **Differential Logic Prober** (Levenshtein distance). Avoid writing rigid Regex deduplication logic.

---

## 🤖 AI Workflow Protocols

When tasked with modifying this codebase:

1. **Research Phase**:
   - Understand that you are modifying a distributed mesh. Code changes in one stage must serialize correctly across the cluster.
   - Read the relevant `src/core/frontier/` modules before attempting to fix performance bottlenecks.
2. **Strategy Phase**:
   - Ensure your proposed solution adheres to the CRDT replacement rule and uses the `StageInput` immutable contract.
3. **Execution Phase**:
   - Apply surgical changes. Use `@beartype` on new service endpoints. Use Zod in the frontend for API contracts.
4. **Validation Phase**:
   - Run type checking: `mypy .`
   - Run linting: `ruff check . --fix`
   - If UI changes were made, verify Zod schema integrity in `frontend/src/api/schemas.ts`.
5. **Git Protocol**:
   - **MANDATE**: Perform occasional pushes to the remote GitHub repository (e.g., after significant feature completions or bug fixes) to ensure work is backed up and synchronized.
