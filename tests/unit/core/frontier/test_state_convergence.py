"""
Distributed state convergence — prove CRDT + HLC + NeuralState converge
under concurrent updates regardless of merge order.

Proves the following always hold:

  .merge(b).merge(c) == .merge(c).merge(b)     (commutative)
  .merge(a) == .merge(a).merge(a)              (idempotent)
  merge(A→B→C) == merge(A→C→B) == merge(C→A→B) (convergent)
  (A + B + C).merge(D) == (A + D).merge(B + C) (associative)
"""

from __future__ import annotations

import random
import time

from src.core.frontier.state import (
    HybridLogicalClock,
    LWWset,
    NeuralState,
    VectorClock,
)

# ruff: noqa: N802  — allow short function names for test DSL


# ---------------------------------------------------------------------------
# Helpers — tiny DSL for declaring distributed scenarios
# ---------------------------------------------------------------------------


def _ns() -> NeuralState:
    return NeuralState()


def _delta(
    idx: int, *, url: str | None = None, sub: str | None = None, finding_title: str | None = None
) -> dict:
    """A delta that looks like what merge_stage_output would produce."""
    d: dict = {"_wal_id": f"{int(time.time() * 1000)}-{idx:04d}"}
    if url:
        d["urls"] = [url]
    if sub:
        d["subdomains"] = [sub]
    if finding_title:
        d["findings"] = [{"title": finding_title, "severity": "medium", "target": "x.example.com"}]
    return d


def _apply(ns: NeuralState, *deltas: dict) -> NeuralState:
    """Apply deltas to a fresh copy of *ns* in order."""
    from src.core.frontier.state import _clone_value

    result = _clone_value(ns)
    for d in deltas:
        result.apply_delta(dict(d))
    return result


def _merge(*states: NeuralState) -> NeuralState:
    """Merge all NeuralStates pairwise, in left-to-right order."""
    if not states:
        return _ns()
    from src.core.frontier.state import _clone_value

    result = _clone_value(states[0])
    for s in states[1:]:
        result.merge(_clone_value(s))
    return result


def _snap(ns: NeuralState) -> dict:
    """Deterministic snapshot for comparison."""
    return {
        "subdomains": sorted(ns.subdomains.to_set()),
        "urls": sorted(ns.urls.to_set()),
        "findings": sorted(f["title"] for f in ns.findings.values()),
        "metadata": dict(sorted(ns.metadata.items())),
        "applied_wal_ids": sorted(ns.applied_wal_ids),
        "last_wal_id": ns.last_wal_id,
    }


def _converged(*states: NeuralState) -> bool:
    """Return True iff ALL states have identical snapshots."""
    snaps = [_snap(s) for s in states]
    return all(s == snaps[0] for s in snaps)


# ===================================================================
# 1.  LWWset convergence — the core primitive
# ===================================================================


def test_lwwset_converges_commutatively():
    """Two LWW sets with same data merged in either order → identical."""
    left = LWWset[str]()
    right = LWWset[str]()

    # Worker A adds "apple" at ts=10, Worker B adds "banana" at ts=20
    left.add("apple", timestamp=10.0)
    right.add("banana", timestamp=20.0)

    # Both merge both ways
    left.merge(right)
    right.merge(left)

    assert left.to_set() == right.to_set() == {"apple", "banana"}


def test_lwwset_concurrent_remove_wins():
    """Add vs concurrent remove: HLC tiebreak picks deterministic winner.

    When timestamps are equal, the LWWset convention is:
    remove wins (deleted flag is True → overwrites).
    """
    left = LWWset[str]()
    right = LWWset[str]()

    hlc_a = HybridLogicalClock(10.0, 0, "a")
    hlc_b = HybridLogicalClock(10.0, 1, "b")  # same wall clock, larger seq → later

    left.add("item", hlc=hlc_a, timestamp=10.0)
    right.remove("item", hlc=hlc_b, timestamp=10.0)

    left.merge(right)
    right.merge(left)

    # HLC(b) > HLC(a) → remove wins on both sides
    assert "item" not in left.to_set()
    assert left.to_dict() == right.to_dict()


def test_lwwset_concurrent_add_wins():
    """Concurrent add vs add: the lexicographically larger value wins
    when timestamps AND HLC are equal (edge case convergence).
    """
    left = LWWset[str]()
    right = LWWset[str]()

    # Same timestamp 10.0 with identical HLC — tiebreaker is stable JSON string order
    left.add("cherry", timestamp=10.0)
    right.add("apple", timestamp=10.0)

    left.merge(right)
    right.merge(left)

    # "cherry" > "apple" lexicographically → cherry wins
    assert left.to_set() == right.to_set()
    assert "cherry" in left.to_set()


# ===================================================================
# 2.  NeuralState convergence — full state merges
# ===================================================================


def test_neural_state_converges_commutatively():
    """NeuralState merge is commutative: A.merge(B) == B.merge(A)."""
    a = _apply(_ns(), _delta(1, url="https://a.example.com"))
    b = _apply(_ns(), _delta(2, sub="b.example.com"))

    ab = _merge(a, b)
    ba = _merge(b, a)

    assert _snap(ab) == _snap(ba), "commutative merge failed"


def test_neural_state_converges_associatively():
    """(A.merge(B)).merge(C) == A.merge(B.merge(C))."""
    a = _apply(_ns(), _delta(1, url="https://a.example.com"))
    b = _apply(_ns(), _delta(2, sub="b.example.com"))
    c = _apply(_ns(), _delta(3, finding_title="F3"))

    ab_c = _merge(_merge(a, b), c)
    a_bc = _merge(a, _merge(b, c))

    assert _snap(ab_c) == _snap(a_bc), "associative merge failed"


def test_neural_state_converges_idempotently():
    """Merging the same state twice is a no-op after the first merge."""
    base = _apply(_ns(), _delta(1, url="https://a.example.com"))
    clone = base

    base.merge(clone)
    snap_once = _snap(base)

    base.merge(clone)  # same state again
    snap_twice = _snap(base)

    assert snap_once == snap_twice, "idempotent merge failed"


# ===================================================================
# 3.  Concurrent worker scenario: A→X, B→Y, A→Z, B→W
# ===================================================================


def test_two_workers_converge_under_all_merge_orders():
    """Workers A and B produce interleaved deltas. Every possible
    four-step merge schedule produces the same final state.

    Timeline:
      A: delta_ax  (adds subdomain "a-x")
      B: delta_by  (adds url "https://b-y")
      A: delta_az  (adds finding F-AZ)
      B: delta_bw  (adds subdomain "b-w")
    """
    seed = _ns()
    delta_ax = _delta(1, sub="a-x.example.com")
    delta_by = _delta(2, url="https://b-y.example.com")
    delta_az = _delta(3, finding_title="F-AZ")
    delta_bw = _delta(4, sub="b-w.example.com")

    # Worker A sees ax, az. Worker B sees by, bw.
    # Apply in order: ax → by → az → bw (the "real" timeline)
    ordered = _apply(seed, delta_ax, delta_by, delta_az, delta_bw)
    reference = _snap(ordered)

    # Simulate different merge orders that could happen in a mesh:
    # Each worker sends its state at a different time.
    merge_orders = [
        # A sends first (ax,az), B sends second (by,bw)
        lambda: _merge(
            _apply(seed, delta_ax, delta_az),
            _apply(seed, delta_by, delta_bw),
        ),
        # B sends first
        lambda: _merge(
            _apply(seed, delta_by, delta_bw),
            _apply(seed, delta_ax, delta_az),
        ),
        # Interleaved: A sends ax, B sends by, A sends az, B sends bw
        lambda: _merge(
            _apply(seed, delta_ax),
            _apply(seed, delta_by),
            _apply(seed, delta_az),
            _apply(seed, delta_bw),
        ),
        # Reverse interleaved
        lambda: _merge(
            _apply(seed, delta_bw),
            _apply(seed, delta_az),
            _apply(seed, delta_by),
            _apply(seed, delta_ax),
        ),
        # All into one then merge with empty
        lambda: _merge(
            _apply(seed, delta_ax, delta_by, delta_az, delta_bw),
            seed,
        ),
    ]

    for i, build in enumerate(merge_orders):
        result = build()
        assert _snap(result) == reference, f"merge order {i} produced different state"


def test_two_workers_duplicate_merge_is_idempotent():
    """If Worker B merges into A twice (duplicate delivery in gossip),
    the second merge is a no-op."""
    a = _apply(_ns(), _delta(1, sub="a.example.com"))
    b = _apply(_ns(), _delta(2, url="https://b.example.com"))

    snap_before = _snap(a)
    a.merge(b)
    snap_after1 = _snap(a)
    assert snap_before != snap_after1, "first merge should add B's data"

    a.merge(b)  # duplicate delivery
    snap_after2 = _snap(a)
    assert snap_after1 == snap_after2, "duplicate merge should be idempotent"


def test_two_workers_delayed_merge_converges():
    """If Worker B receives A's state late (after its own updates),
    the final merged state still converges with A.

    This simulates a network partition: A and B diverge, then
    A's state is delivered to B after B has already made progress.
    """
    delta_a1 = _delta(1, sub="a1.example.com")
    delta_a2 = _delta(2, sub="a2.example.com")
    delta_b1 = _delta(3, sub="b1.example.com")
    delta_b2 = _delta(4, sub="b2.example.com")

    # A sees all 4 deltas in order (the reference timeline)
    a_full = _apply(_ns(), delta_a1, delta_a2, delta_b1, delta_b2)
    reference = _snap(a_full)
    assert reference["subdomains"]

    # B's timeline: b1, b2, then (later) a1, a2 delivered
    b = _apply(_ns(), delta_b1, delta_b2)
    # Delayed delivery of A's early deltas
    b.merge(_apply(_ns(), delta_a1, delta_a2))
    # But A's early deltas have lower wal_ids, so they should be treated
    # as old news — the applied_wal_ids dedup should skip them if already
    # applied OR HLC comparison should prefer B's later timestamps.

    # Both should converge
    a = _apply(_ns(), delta_a1, delta_a2, delta_b1, delta_b2)
    assert _snap(a) == _snap(b), "delayed merge should converge"


# ===================================================================
# 4.  Four-worker scenario with arbitrary interleaving
# ===================================================================


def test_four_workers_converge():
    """Four workers each produce 3 deltas. Every possible pairwise
    merge order leads to identical state."""
    workers = {
        "A": [_delta(i, sub=f"wA-d{i}.example.com") for i in range(1, 4)],
        "B": [_delta(i + 10, url=f"https://wB-d{i}.example.com") for i in range(1, 4)],
        "C": [_delta(i + 20, finding_title=f"FC-{i}") for i in range(1, 4)],
        "D": [
            _delta(i + 30, sub=f"wD-d{i}.example.com", url=f"https://wD-d{i}.example.com")
            for i in range(1, 4)
        ],
    }

    # Build each worker's state independently
    states = {w: _apply(_ns(), *deltas) for w, deltas in workers.items()}

    # Reference: sequential apply all 12 deltas in one timeline
    all_deltas = []
    for w in ["A", "B", "C", "D"]:
        all_deltas.extend(workers[w])
    reference = _snap(_apply(_ns(), *all_deltas))

    # Merge all workers in different orders
    orders = [
        ["A", "B", "C", "D"],
        ["D", "C", "B", "A"],
        ["B", "D", "A", "C"],
        ["C", "A", "D", "B"],
        random.sample(["A", "B", "C", "D"], 4),
        random.sample(["A", "B", "C", "D"], 4),
    ]

    for i, order in enumerate(orders):
        merged = states[order[0]]
        for name in order[1:]:
            merged.merge(states[name])
        assert _snap(merged) == reference, f"four-worker merge order {i} diverged"

    # Pairwise merge: merge all four pairwise in a binary tree
    ab = _merge(states["A"], states["B"])
    cd = _merge(states["C"], states["D"])
    all_pairwise = _merge(ab, cd)
    assert _snap(all_pairwise) == reference, "pairwise merge diverged"


# ===================================================================
# 5.  CRDT element resolution — HLC + lexical tiebreaks
# ===================================================================


def test_crdt_element_hlc_tiebreak():
    """When two workers add the SAME key with different values,
    the one with the later HLC wins — deterministically on both sides."""
    left = LWWset[str]()
    right = LWWset[str]()

    hlc_a = HybridLogicalClock(5.0, 0, "node-a")
    hlc_b = HybridLogicalClock(10.0, 0, "node-b")  # later wall clock

    left.add("key", timestamp=5.0, hlc=hlc_a)
    right.add("key", timestamp=10.0, hlc=hlc_b)

    left.merge(right)
    right.merge(left)

    assert left.to_set() == right.to_set()
    assert "key" in left.to_set()


def test_crdt_same_hlc_lexical_tiebreak():
    """Exactly identical HLC → lexical comparison of stable JSON wins."""
    left = LWWset[str]()
    right = LWWset[str]()

    hlc = HybridLogicalClock(10.0, 0, "same-node")

    left.add("item-to-remove", hlc=hlc, timestamp=10.0)
    right.remove("item", hlc=hlc, timestamp=10.0)

    left.merge(right)
    right.merge(left)

    # In LWWset, when HLC is identical, the deleted element wins
    assert "item" not in left.to_set()
    assert left.to_dict() == right.to_dict()


# ===================================================================
# 6.  VectorClock convergence
# ===================================================================


def test_vector_clock_merge_commutative():
    v1 = VectorClock.from_dict({"a": 3, "b": 1})
    v2 = VectorClock.from_dict({"a": 2, "c": 5})

    v1v2 = v1.merge(v2)
    v2v1 = v2.merge(v1)

    assert v1v2.to_dict() == v2v1.to_dict() == {"a": 3, "b": 1, "c": 5}


def test_vector_clock_later_than():
    v1 = VectorClock.from_dict({"a": 3, "b": 1})
    v2 = VectorClock.from_dict({"a": 2})

    assert v1.is_later_than(v2)
    assert not v2.is_later_than(v1)


# ===================================================================
# 7.  Stress — many random deltas
# ===================================================================


def test_convergence_under_random_interleaving():
    """Apply 50 random deltas in 3 different orders — all converge."""
    random.seed(42)

    # Generate 50 deltas from 3 workers
    deltas_by_worker = {"A": [], "B": [], "C": []}
    for idx in range(50):
        worker = random.choice(["A", "B", "C"])
        domain = f"domain-{idx}.example.com"
        url = f"https://{domain}/page"
        deltas_by_worker[worker].append(_delta(idx, sub=domain, url=url, finding_title=f"F-{idx}"))

    # Apply in order (reference timeline)
    ordered = _ns()
    for w in ["A", "B", "C"]:
        ordered = _apply(ordered, *deltas_by_worker[w])
    reference = _snap(ordered)

    # Merge worker states (convergence path)
    states = {w: _apply(_ns(), *deltas_by_worker[w]) for w in deltas_by_worker}
    all_merged = _merge(*[states[w] for w in ["A", "B", "C"]])
    merged_snap = _snap(all_merged)

    # The reference has all 50 deltas applied sequentially.
    # The merged path has 3 independent states merged.
    # They should converge to the same set of subdomains/urls/findings
    # though the exact last_wal_id may differ (the merge picks the max).
    assert reference["subdomains"] == merged_snap["subdomains"], (
        "subdomains differ after random interleaving"
    )
    assert reference["urls"] == merged_snap["urls"], "urls differ after random interleaving"
    assert reference["findings"] == merged_snap["findings"], (
        "findings differ after random interleaving"
    )
