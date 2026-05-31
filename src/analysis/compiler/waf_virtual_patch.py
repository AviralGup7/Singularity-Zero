"""
Purple-Team WAF Virtual Patch Compiler.
Automatically translates successful exploitation fingerprints into precise ModSecurity WAF rules or eBPF network filters.
"""

from __future__ import annotations

import re
from typing import Any

from src.core.logging.trace_logging import get_pipeline_logger

logger = get_pipeline_logger(__name__)


class VirtualPatchCompiler:
    """Compiles attack fingerprints into WAF and eBPF filters."""

    def __init__(self, target_domain: str | None = None) -> None:
        self.target_domain = target_domain

    def compile_modsecurity_rule(self, fingerprint: dict[str, Any], rule_id: int = 1000000) -> str:
        """Translate fingerprint into a ModSecurity virtual patch."""
        path = fingerprint.get("path", "/")
        payload = fingerprint.get("payload", "")
        method = fingerprint.get("method", "GET")

        # Escape for ModSecurity SecRule regex
        safe_path = re.escape(path)
        safe_payload = re.escape(payload)

        rule = (
            f'SecRule REQUEST_METHOD "^{method}$" "id:{rule_id},phase:1,t:none,deny,status:403,'
            f"msg:'Virtual Patch: Exploit fingerprint matched',chain\"\n"
            f'  SecRule REQUEST_URI "^{safe_path}" "chain"\n'
            f'  SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@contains {safe_payload}"\n'
        )
        return rule

    def compile_ebpf_filter(self, fingerprint: dict[str, Any]) -> str:
        """Translate fingerprint into an eBPF network filter program (BCC/C syntax)."""
        payload = fingerprint.get("payload", "")
        if not payload:
            return "// No payload to filter"

        hex_payload = ", ".join(f"0x{c.encode().hex()}" for c in payload)
        length = len(payload)

        ebpf_c = f"""
#include <uapi/linux/ptrace.h>
#include <linux/skbuff.h>

// Auto-compiled eBPF filter for Payload: {payload}
int filter_malicious_payload(struct __sk_buff *skb) {{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // Pattern to match
    unsigned char pattern[] = {{{hex_payload}}};
    int pattern_len = {length};

    // Basic linear search (prototype for eBPF payload inspection)
    // Warning: Unrolled loops are required for BPF verifier in real implementations.
    #pragma unroll
    for (int i = 0; i < 256; i++) {{
        if (data + i + pattern_len > data_end) {{
            break;
        }}

        int matched = 1;
        #pragma unroll
        for (int j = 0; j < pattern_len; j++) {{
            unsigned char *ptr = data + i + j;
            if (*ptr != pattern[j]) {{
                matched = 0;
                break;
            }}
        }}

        if (matched == 1) {{
            // Drop packet
            return 0; // TC_ACT_SHOT equivalent
        }}
    }}

    return 1; // TC_ACT_OK
}}
        """.strip()

        return ebpf_c

    def generate_patches(
        self, exploitation_result: dict[str, Any], base_rule_id: int = 1000000
    ) -> dict[str, str]:
        """Generate all virtual patches for a given successful exploitation."""
        fingerprint = exploitation_result.get("fingerprint", {})
        if not fingerprint:
            # Fallback to the raw result if it acts as the fingerprint
            fingerprint = exploitation_result

        return {
            "modsecurity": self.compile_modsecurity_rule(fingerprint, base_rule_id),
            "ebpf": self.compile_ebpf_filter(fingerprint),
        }
