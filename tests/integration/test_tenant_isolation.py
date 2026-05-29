from src.core.tenant_context import TenantContext
from src.dashboard.fastapi.routers.targets import is_target_owned_by_tenant


def test_tenant_context_scoping():
    """Verify TenantContext thread-safe/async-safe variable scoping and reset behavior."""
    assert TenantContext.get_current_tenant() is None

    # Test nested scopes
    with TenantContext.scope("tenant_alpha"):
        assert TenantContext.get_current_tenant() == "tenant_alpha"

        with TenantContext.scope("tenant_beta"):
            assert TenantContext.get_current_tenant() == "tenant_beta"

        assert TenantContext.get_current_tenant() == "tenant_alpha"

    assert TenantContext.get_current_tenant() is None


def test_target_owned_by_tenant_helper():
    """Verify target ownership helper matches prefix or falls back correctly."""
    # Active tenant checks
    assert is_target_owned_by_tenant("tenant1_my_target", "tenant1") is True
    assert is_target_owned_by_tenant("tenant2_my_target", "tenant1") is False

    # Default tenant checks
    assert is_target_owned_by_tenant("my_target_without_prefix", "default") is True
    assert is_target_owned_by_tenant("my_target_without_prefix", None) is True
    assert is_target_owned_by_tenant("tenant1_my_target", "default") is False
    assert is_target_owned_by_tenant("default_my_target", "default") is True


def test_redis_key_prefixing_isolated():
    """Simulate key prefixing logic to ensure separate partitions in Redis commands."""

    class FakeRedisClient:
        def __init__(self):
            self.command_history = []

        def execute_command(self, command: str, *args, **kwargs):
            # Emulate execute_command prefixing logic
            tenant_id = TenantContext.get_current_tenant()
            if tenant_id and len(args) > 0:
                key = args[0]
                if isinstance(key, str):
                    if not key.startswith(f"{tenant_id}:"):
                        args = (f"{tenant_id}:{key}",) + args[1:]
            self.command_history.append((command, args))
            return "OK"

    client = FakeRedisClient()

    # Outside tenant context
    client.execute_command("SET", "global_config", "value")
    assert client.command_history[-1] == ("SET", ("global_config", "value"))

    # Inside tenant context
    with TenantContext.scope("tenant_xyz"):
        client.execute_command("SET", "my_keys", "secret_value")
        assert client.command_history[-1] == ("SET", ("tenant_xyz:my_keys", "secret_value"))

        # Already prefixed should not be double prefixed
        client.execute_command("SET", "tenant_xyz:my_keys", "secret_value")
        assert client.command_history[-1] == ("SET", ("tenant_xyz:my_keys", "secret_value"))
