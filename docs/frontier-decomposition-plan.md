# Frontier Decomposition Plan

## Goal

Split `core/frontier` into three packages based on dependency analysis:

```text
core/frontier/          → Pure algorithms (CRDT, bloom, actor model)
infrastructure/frontier/ → Distributed infrastructure (Redis, mesh, encryption)
execution/frontier/     → Domain-specific (chameleon, WASM)
```

## Current State

| Category | Modules | Count |
|----------|---------|-------|
| Pure Core | bloom, chameleon_evasion, drl_evasion, ghost_actor, ghost_actor_state, marshaller, mesh_limiter, policies, proc_pool, ring_bus, shared_memory, state, state_validation, tracing_manager, vfs_isolation | 15 |
| Infrastructure-Dependent | bloom_mesh, ghost_actor_coordinator, ghost_actor_registry, ghost_vfs, vault, vfs_mounts, wal | 7 |
| Domain-Dependent | chameleon, wasm | 2 |

## Phase 1: Create Package Structure

```bash
mkdir -p src/infrastructure/frontier
mkdir -p src/execution/frontier
```

## Phase 2: Move Infrastructure Modules

### Files to Move

| Source | Destination | Reason |
|--------|-------------|--------|
| `core/frontier/bloom_mesh.py` | `infrastructure/frontier/bloom_mesh.py` | Depends on Redis, Metrics |
| `core/frontier/ghost_actor_registry.py` | `infrastructure/frontier/ghost_actor_registry.py` | Depends on Redis |
| `core/frontier/ghost_actor_coordinator.py` | `infrastructure/frontier/ghost_actor_coordinator.py` | Depends on Mesh |
| `core/frontier/ghost_vfs.py` | `infrastructure/frontier/ghost_vfs.py` | Depends on Encryption |
| `core/frontier/vault.py` | `infrastructure/frontier/vault.py` | Depends on Encryption |
| `core/frontier/vfs_mounts.py` | `infrastructure/frontier/vfs_mounts.py` | Depends on Encryption |
| `core/frontier/wal.py` | `infrastructure/frontier/wal.py` | Depends on Redis |

### Import Updates Required

For each moved file, update:
1. Internal imports within the file
2. All files that import from the moved module

### Compatibility Shim (Optional)

To avoid breaking existing imports, add re-exports in `core/frontier/__init__.py`:

```python
# Backward compatibility - will be removed in future version
def _deprecated_import(old_name, new_module):
    import warnings
    warnings.warn(f"Import from core.frontier.{old_name} is deprecated, use {new_module}", DeprecationWarning)
    return __import__(new_module)

# Add lazy imports for moved modules
```

## Phase 3: Move Domain Modules

### Files to Move

| Source | Destination | Reason |
|--------|-------------|--------|
| `core/frontier/chameleon.py` | `execution/frontier/chameleon.py` | Depends on execution.active_manifest, learning.integration |
| `core/frontier/chameleon_evasion.py` | `execution/frontier/chameleon_evasion.py` | Used only by chameleon.py |
| `core/frontier/wasm.py` | `execution/frontier/wasm.py` | Depends on execution.active_manifest, execution.isolated |

### Import Updates Required

1. `core/frontier/__init__.py` - Remove chameleon exports
2. `core/frontier/chameleon.py` - Update all imports
3. `execution/__init__.py` - Add frontier exports if needed

## Phase 4: Add Import-Linter Rules

Update `.import-linter`:

```ini
[importlinter:contract:6]
name = "Core must not depend on infrastructure"
type = forbidden
source_modules = src.core
forbidden_modules = src.infrastructure

[importlinter:contract:7]
name = "Core must not depend on execution"
type = forbidden
source_modules = src.core
forbidden_modules = src.execution

[importlinter:contract:8]
name = "Core must not depend on learning"
type = forbidden
source_modules = src.core
forbidden_modules = src.learning
```

## Phase 5: Update All Import References

### Files That Import from `core/frontier`

Search for all imports and update:

```bash
grep -r "from src.core.frontier" src/ --include="*.py"
```

Key files to update:
- `src/pipeline/self_healing/controller.py`
- `src/infrastructure/queue/worker_lite.py`
- `src/infrastructure/execution_engine/*.py`
- `src/dashboard/fastapi/lifespan.py`
- Any other files importing from frontier

## Execution Order

1. Create package directories
2. Move infrastructure modules (lowest risk)
3. Update imports for moved infrastructure modules
4. Add compatibility shims
5. Run import-linter to verify
6. Move domain modules (higher risk)
7. Update imports for moved domain modules
8. Update __init__.py files
9. Run full test suite
10. Remove compatibility shims (optional, can keep for transition)

## Success Criteria

- `core/frontier` has zero imports from `infrastructure`, `execution`, `learning`
- All moved modules work from new locations
- Import-linter passes all contracts
- No circular dependencies introduced

## Risk Assessment

| Phase | Risk | Mitigation |
|-------|------|------------|
| Move infrastructure | Low | Add compatibility shims |
| Move domain | Medium | Test thoroughly, keep shims longer |
| Add linter rules | Low | Add after moves complete |

## Estimated Effort

- Phase 1-2: 1-2 hours
- Phase 3: 2-3 hours
- Phase 4: 30 minutes
- Phase 5: 2-4 hours (depends on number of import sites)
- Testing: 2-3 hours

Total: ~8-12 hours
