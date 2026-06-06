import json
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch
from src.analysis.plugins import PASSIVE_CHECK_NAMES
from src.dashboard.configuration import apply_runtime_overrides, load_template
from src.dashboard.constants import ANALYSIS_CHECK_OPTIONS
from src.dashboard.fastapi.validation import is_within_directory
from src.dashboard.form_specs import RUNTIME_NUMERIC_CONTROLS, NumericControlSpec
from src.dashboard.job_store import JobStore
from src.dashboard.pipeline_jobs import create_job_record
from src.dashboard.scope_utils import build_scope_entries, normalize_base_url, root_domain
from src.dashboard.services import DashboardHandler, DashboardServices
from src.pipeline.storage import load_config



class DummyProcess:
    def __init__(self) -> None:
        self.terminated = False
        self.pid = 4242

    def terminate(self) -> None:
        self.terminated = True