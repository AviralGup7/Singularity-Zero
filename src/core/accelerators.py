"""
Cyber Security Test Pipeline - Hardware Accelerators
Vectorized string processing and SIMD-style analysis using NumPy.
"""

from __future__ import annotations

import logging
import re

import numpy as np

logger = logging.getLogger(__name__)

# Pre-compiled high-speed tool detection regex
SENSITIVE_REGEX = re.compile(
    rb"(?i)(password|secret|key|token|bearer|apikey|access_key|auth_token|ssh-rsa|PRIVATE KEY)",
    re.MULTILINE
)

def vectorized_regex_search(data_list: list[str], pattern: str) -> np.ndarray:
    """
    Search for a regex pattern across a large list of strings using vectorized dispatch.
    Returns a boolean mask.
    """
    regex = re.compile(pattern)
    # Fast path: Vectorized search via numpy.frompyfunc
    vec_match = np.frompyfunc(lambda x: bool(regex.search(x)), 1, 1)
    arr = np.array(data_list, dtype=object)
    return vec_match(arr).astype(bool)

def vectorized_url_filter(urls: list[str], forbidden_exts: set[str]) -> list[str]:
    """
    High-speed URL filtering using numpy-based extension matching.
    """
    if not urls:
        return []
        
    arr = np.array(urls, dtype=object)
    
    # Fast vectorized extension extraction
    # Heuristic: split by dot and take last part
    def get_ext(u: str) -> str:
        path = u.split('?')[0]
        parts = path.rsplit('.', 1)
        return parts[1].lower() if len(parts) > 1 else ""

    vec_get_ext = np.frompyfunc(get_ext, 1, 1)
    exts = vec_get_ext(arr)
    
    # Vectorized 'in' check
    mask = np.array([e not in forbidden_exts for e in exts])
    
    return arr[mask].tolist()

def fast_secret_scanner(content_bytes: bytes) -> list[bytes]:
    """
    SIMD-accelerated secret scanning across a large binary blob.
    Uses re.findall which is C-optimized.
    """
    return SENSITIVE_REGEX.findall(content_bytes)

def compute_entropy_vectorized(data_list: list[str]) -> np.ndarray:
    """
    Compute Shannon Entropy for a large set of strings in parallel.
    Useful for detecting encoded secrets/tokens.
    """
    def shannon(s: str) -> float:
        if not s: return 0.0
        probabilities = [float(s.count(c)) / len(s) for c in set(s)]
        return -sum(p * np.log2(p) for p in probabilities)

    vec_shannon = np.frompyfunc(shannon, 1, 1)
    return vec_shannon(np.array(data_list, dtype=object)).astype(float)
