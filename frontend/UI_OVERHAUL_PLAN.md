# UI/UX Architectural Overhaul Plan: 'The Silent Bug Purge'

This plan outlines a series of major structural changes to the Cyber Security Test Pipeline frontend to eliminate silent synchronization bugs, solve performance bottlenecks at scale, and modernize the user experience.

---

## 🏗️ Phase 1: State & Synchronization Overhaul (The 'Action Buffer' Engine)

**Problem**: The UI currently fights between three data sources (REST Polling, WebSockets, and SSE). Inconsistent timestamp generation and loose merging logic lead to 'state flicker' where UI elements (like progress bars) jump backwards or revert to old states.

**Overhaul Actions**:
1.  **Unified State Reducer**: Replace multiple `useState` calls in `useJobMonitor` with a single, high-performance `useReducer` or a structured state object.
2.  **Clock-Skew Correction**: Implement a `serverTimeOffset` calculation on app startup. All frontend timestamps must be normalized to backend time before comparison.
3.  **The Action Buffer**: Implement a non-blocking event queue that buffers high-frequency WebSocket/SSE events and commits them to React state in atomic batches (every 100ms) to prevent re-render thrashing.
4.  **Source Precedence**: Enforce strict precedence: `SSE/WS Event > Manual Refetch > REST Polling`.

## 🚀 Phase 2: High-Performance Rendering (Massive Data Virtualization)

**Problem**: Scanning large targets produces 100k+ log lines and 5k+ findings. The current implementation renders these into standard DOM nodes, causing the browser to freeze or crash during 'mining' and 'analysis' phases.

**Overhaul Actions**:
1.  **Log Virtualization**: Implement `react-virtuoso` for the live terminal and log viewer. Support rendering 1 million lines with zero lag.
2.  **Finding Heatmap Virtualization**: Move the findings grid to a virtualized component.
3.  **Off-Main-Thread Parsing**: Move complex finding merging and ranking heuristics into a **Web Worker** to keep the UI thread responsive at 60 FPS.

## 📊 Phase 3: Visual Intelligence (Instanced Threat Visualization)

**Problem**: The 3D Security Cockpit uses one Three.js object per endpoint. Performance degrades exponentially beyond 500 nodes.

**Overhaul Actions**:
1.  **Instanced Rendering**: Refactor the Cockpit to use `THREE.InstancedMesh`. This allows rendering 50,000 nodes in a single draw call.
2.  **GPU Layout Calculation**: Offload node positions to a Fragment Shader (GPGPU) or a highly optimized worker-based force-directed layout engine.
3.  **Real-time Bloom & Post-processing**: Add high-impact 'Cyber' aesthetics (bloom, scanlines, chromatic aberration) that scale with target severity.

## 🛡️ Phase 4: Resilience & Silent Error Capture

**Problem**: Network interruptions often result in empty states or infinite loading spinners without informing the user.

**Overhaul Actions**:
1.  **Z-Index 10000 Toast Hub**: A centralized, priority-aware notification hub that captures all `unhandledrejection` events and API failures.
2.  **Aggressive Reconnection Policy**: Implement jittered exponential backoff for BOTH WebSocket and SSE, with a 'Manual Override' UI when the backend is unreachable.
3.  **Contract Guards**: Use Zod to validate all incoming API payloads. If a backend change breaks the contract, show a 'Compatibility Warning' instead of crashing silently.

## 🧹 Phase 5: Architectural Cleanup

**Overhaul Actions**:
1.  **Legacy Purge**: Remove all references to `src/dashboard/static/ui`.
2.  **Theming Unification**: Move all hardcoded cyber-green (`#00ff41`) and dark-bg (`#0a0a0a`) colors into a unified TailwindCSS design token set.
3.  **Focus & Accessibility**: Ensure full keyboard navigation (`Tab`, `Space`, `Enter`) for the entire dashboard to support 'speed-scanning' workflows.
