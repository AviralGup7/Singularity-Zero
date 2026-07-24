from __future__ import annotations

from src.reporting.platforms.apple import AppleClient
from src.reporting.platforms.aws import AWSClient
from src.reporting.platforms.base import (
    SubmissionEnvelope,
    SubmissionResult,
    _BaseClient,
    to_envelope,
)
from src.reporting.platforms.bugcrowd import BugcrowdClient
from src.reporting.platforms.bugzilla import MozillaClient
from src.reporting.platforms.googlevrp import GoogleVRPClient
from src.reporting.platforms.govdefense import GovDefenseClient
from src.reporting.platforms.hackerone import HackerOneClient
from src.reporting.platforms.intigriti import IntigritiClient
from src.reporting.platforms.meta import MetaClient
from src.reporting.platforms.msrc import MSRCAgent
from src.reporting.platforms.openbugbounty import OpenBugBountyClient
from src.reporting.platforms.synack import SynackClient
from src.reporting.platforms.yeswehack import YesWeHackClient


def build_default_clients() -> dict[str, _BaseClient]:
    return {
        "hackerone": HackerOneClient(),
        "bugcrowd": BugcrowdClient(),
        "intigriti": IntigritiClient(),
        "synack": SynackClient(),
        "yeswehack": YesWeHackClient(),
        "openbugbounty": OpenBugBountyClient(),
        "googlevrp": GoogleVRPClient(),
        "meta": MetaClient(),
        "apple": AppleClient(),
        "aws": AWSClient(),
        "msrc": MSRCAgent(),
        "mozilla": MozillaClient(),
        "govdefense": GovDefenseClient(),
    }


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
    "SubmissionEnvelope",
    "_BaseClient",
    "to_envelope",
    "build_default_clients",
]
