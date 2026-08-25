"""Live platform-push clients for HackerOne, Bugcrowd, Intigriti, Synack, and newer platforms.

Each client wraps the platform's submission API as an async
``submit`` method that returns a structured :class:`SubmissionResult`.
The clients use ``httpx`` (already a project dependency) for HTTP
transport; authentication is read from environment variables or the
constructor arguments so credentials never appear in the source tree.

All clients are *opt-in* — they make a live network call only when
``submit()`` is invoked.
"""

from src.reporting.platforms import (  # noqa: F401  # re-exported
    AppleClient,
    AWSClient,
    BugcrowdClient,
    DefectDojoClient,
    GoogleVRPClient,
    GovDefenseClient,
    HackerOneClient,
    IntigritiClient,
    JiraClient,
    MetaClient,
    MozillaClient,
    MSRCAgent,
    OpenBugBountyClient,
    ServiceNowClient,
    SubmissionEnvelope,
    SubmissionResult,
    SynackClient,
    YesWeHackClient,
    _BaseClient,
    build_default_clients,
    to_envelope,
)

__all__ = [
    "BugcrowdClient",
    "HackerOneClient",
    "IntigritiClient",
    "SubmissionResult",
    "SynackClient",
    "YesWeHackClient",
    "OpenBugBountyClient",
    "GoogleVRPClient",
    "MetaClient",
    "AppleClient",
    "AWSClient",
    "MSRCAgent",
    "MozillaClient",
    "GovDefenseClient",
    "JiraClient",
    "ServiceNowClient",
    "DefectDojoClient",
    "SubmissionEnvelope",
    "build_default_clients",
]
