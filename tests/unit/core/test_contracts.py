"""Unit tests verifying explicit contracts and runtime checkability in src/core/contracts/."""

from src.core.contracts.bidder import (
    BidContract,
    BidWeightsContract,
)
from src.core.contracts.executor import (
    ExecutionResultContract,
)
from src.core.contracts.resource_manager import (
    BudgetEnforcerContract,
    ResourceGuardContract,
)
from src.core.contracts.scheduler import (
    AdaptiveCoordinatorContract,
    PriorityQueueContract,
)
from src.decision.adaptive_scan import AdaptiveScanCoordinator
from src.decision.hunt_budget import HuntBudgetEnforcer
from src.decision.models import ScanResult
from src.decision.priority_queue import CorrelationPriorityQueue
from src.infrastructure.resource_guard import ResourceGuard
from src.infrastructure.scheduling.bidding import BidWeights, bid_for_target


class TestCoreContracts:
    def test_priority_queue_contract_conformance(self):
        pq = CorrelationPriorityQueue.from_urls(["https://example.com/api"])
        assert isinstance(pq, PriorityQueueContract)

    def test_adaptive_coordinator_contract_conformance(self):
        async def dummy_probe(url):
            return []

        coord = AdaptiveScanCoordinator(["https://example.com"], dummy_probe)
        assert isinstance(coord, AdaptiveCoordinatorContract)

    def test_bid_contracts(self):
        bid = bid_for_target(url="https://example.com", base_priority=10.0, current_priority=10.0)
        assert isinstance(bid, BidContract)
        weights = BidWeights()
        assert isinstance(weights, BidWeightsContract)

    def test_resource_manager_contracts(self):
        guard = ResourceGuard()
        assert isinstance(guard, ResourceGuardContract)
        enforcer = HuntBudgetEnforcer()
        assert isinstance(enforcer, BudgetEnforcerContract)

    def test_models_conformance(self):
        res = ScanResult(target="https://example.com", success=True)
        assert isinstance(res, ExecutionResultContract)
