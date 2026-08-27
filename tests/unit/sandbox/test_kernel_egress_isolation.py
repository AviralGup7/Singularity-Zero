import unittest
from src.sandbox.seccomp_filter import (
    SeccompPolicy,
    KernelEgressNamespace,
    get_default_seccomp_policy,
)
from src.sandbox.process_sandbox import (
    ProcessSandbox,
    SandboxResourceLimits,
)


class TestKernelLevelEgressIsolation(unittest.TestCase):
    def test_seccomp_policy_network_syscall_blocking(self) -> None:
        # Default policy with network allowed
        policy_net = get_default_seccomp_policy(allow_network=True)
        self.assertTrue(policy_net.is_syscall_allowed("connect"))
        self.assertTrue(policy_net.is_syscall_allowed("socket"))
        self.assertFalse(policy_net.is_syscall_allowed("ptrace"))

        # Policy with network blocked
        policy_no_net = get_default_seccomp_policy(allow_network=False)
        self.assertFalse(policy_no_net.is_syscall_allowed("connect"))
        self.assertFalse(policy_no_net.is_syscall_allowed("socket"))
        self.assertFalse(policy_no_net.is_syscall_allowed("bind"))
        self.assertFalse(policy_no_net.is_syscall_allowed("ptrace"))

    def test_process_sandbox_isolated_execution(self) -> None:
        sandbox = ProcessSandbox(
            limits=SandboxResourceLimits(max_memory_mb=64, timeout_seconds=5.0, allow_network=False)
        )
        res = sandbox.run(["python", "-c", "print('sandbox_ok')"])
        self.assertTrue(res.success)
        self.assertEqual(res.stdout.strip(), "sandbox_ok")


if __name__ == "__main__":
    unittest.main()
