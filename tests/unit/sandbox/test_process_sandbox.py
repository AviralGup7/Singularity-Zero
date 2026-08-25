import os
import sys
import unittest

from src.sandbox.process_sandbox import (
    ProcessSandbox,
    SandboxExecutionResult,
    SandboxResourceLimits,
)


class TestProcessSandbox(unittest.TestCase):
    def test_environment_scrubbing(self):
        os.environ["AWS_SECRET_ACCESS_KEY"] = "super_secret_aws"
        os.environ["DATABASE_URL"] = "postgres://root:pwd@localhost/db"
        os.environ["JWT_SECRET"] = "jwt_token_secret"

        sandbox = ProcessSandbox()
        clean_env = sandbox.scrub_environment()

        self.assertNotIn("AWS_SECRET_ACCESS_KEY", clean_env)
        self.assertNotIn("DATABASE_URL", clean_env)
        self.assertNotIn("JWT_SECRET", clean_env)
        self.assertIn("PATH", clean_env)

    def test_sandboxed_command_execution(self):
        sandbox = ProcessSandbox(limits=SandboxResourceLimits(timeout_seconds=5.0))
        result = sandbox.run([sys.executable, "-c", "print('hello from sandbox')"])

        self.assertIsInstance(result, SandboxExecutionResult)
        self.assertEqual(result.exit_code, 0)
        self.assertIn("hello from sandbox", result.stdout)
        self.assertFalse(result.timed_out)

    def test_sandbox_timeout(self):
        sandbox = ProcessSandbox(limits=SandboxResourceLimits(timeout_seconds=0.5))
        result = sandbox.run([sys.executable, "-c", "import time; time.sleep(2.0)"])

        self.assertTrue(result.timed_out)
        self.assertNotEqual(result.exit_code, 0)
