import pytest

from src.core.frontier.mesh_limiter import MeshRateLimiter


def test_mesh_rate_limiter_rejects_non_positive_limits():
    with pytest.raises(ValueError, match="global_rps_limit"):
        MeshRateLimiter(global_rps_limit=0)


def test_mesh_rate_limiter_clamps_tokens_when_mesh_grows():
    limiter = MeshRateLimiter(global_rps_limit=10.0)

    limiter.update_mesh_size(5)

    stats = limiter.get_stats()
    assert stats["local_share"] == 2.0
    assert stats["current_tokens"] == 2.0
