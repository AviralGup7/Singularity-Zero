from src.analysis.passive.detectors.detector_anomaly import anomaly_detector
from src.analysis.passive.detectors.detector_business_logic import business_logic_tampering_detector
from src.analysis.passive.detectors.detector_clickjacking import clickjacking_detector
from src.analysis.passive.detectors.detector_csrf import csrf_protection_checker
from src.analysis.passive.detectors.detector_idor import idor_candidate_finder
from src.analysis.passive.detectors.detector_logging import (
    logging_security_detector as logging_failure_detector,
)
from src.analysis.passive.detectors.detector_oauth import oauth_misconfiguration_detector
from src.analysis.passive.detectors.detector_open_redirect import open_redirect_detector
from src.analysis.passive.detectors.detector_ssrf import ssrf_candidate_finder
from src.analysis.passive.detectors.detector_ssti import ssti_surface_detector
from src.analysis.passive.detectors.detector_token import token_leak_detector
from src.analysis.passive.detectors.detector_upload import file_upload_surface_detector
from src.analysis.passive.detectors.detector_xxe import xxe_surface_detector

__all__ = [
    "anomaly_detector",
    "business_logic_tampering_detector",
    "clickjacking_detector",
    "csrf_protection_checker",
    "file_upload_surface_detector",
    "idor_candidate_finder",
    "logging_failure_detector",
    "oauth_misconfiguration_detector",
    "open_redirect_detector",
    "ssrf_candidate_finder",
    "ssti_surface_detector",
    "token_leak_detector",
    "xxe_surface_detector",
]
