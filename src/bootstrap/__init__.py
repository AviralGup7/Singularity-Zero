"""Bootstrap package — composition root for cross-package protocol registration.

This package exists outside of any layer (core, infrastructure, pipeline, etc.)
so it can import from all of them without violating architecture contracts.
"""
