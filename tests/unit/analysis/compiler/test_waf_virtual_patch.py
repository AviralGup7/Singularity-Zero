"""Tests for the Purple-Team WAF Virtual Patch Compiler."""

import pytest
from src.analysis.compiler.waf_virtual_patch import VirtualPatchCompiler

def test_compile_modsecurity_rule():
    compiler = VirtualPatchCompiler()
    fingerprint = {
        "method": "POST",
        "path": "/api/v1/login",
        "payload": "1' OR '1'='1"
    }
    
    rule = compiler.compile_modsecurity_rule(fingerprint, 12345)
    
    import re
    assert 'SecRule REQUEST_METHOD "^POST$"' in rule
    assert 'id:12345' in rule
    assert 'SecRule REQUEST_URI "^/api/v1/login"' in rule
    assert f'@contains {re.escape("1\' OR \'1\'=\'1")}' in rule

def test_compile_ebpf_filter():
    compiler = VirtualPatchCompiler()
    fingerprint = {
        "payload": "<script>alert(1)</script>"
    }
    
    ebpf_c = compiler.compile_ebpf_filter(fingerprint)
    
    assert 'filter_malicious_payload' in ebpf_c
    assert '0x3c, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x3e, 0x61, 0x6c, 0x65, 0x72, 0x74, 0x28, 0x31, 0x29, 0x3c, 0x2f, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x3e' in ebpf_c
    assert 'int pattern_len = 25;' in ebpf_c

def test_generate_patches_empty_payload():
    compiler = VirtualPatchCompiler()
    patches = compiler.generate_patches({"method": "GET", "path": "/admin"})
    
    assert "modsecurity" in patches
    assert "ebpf" in patches
    assert patches["ebpf"] == "// No payload to filter"
