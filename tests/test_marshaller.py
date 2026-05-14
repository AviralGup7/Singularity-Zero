import pytest
from src.core.frontier.marshaller import FrontierMarshaller, mesh_marshal, mesh_unmarshal

def test_marshaller_roundtrip():
    data = {"findings": [{"id": 1, "severity": "HIGH"}], "status": "active"}
    
    marshaller = FrontierMarshaller()
    packed = marshaller.pack(data)
    assert isinstance(packed, bytes)
    
    unpacked = marshaller.unpack(packed)
    assert unpacked == data

def test_mesh_helpers_roundtrip():
    data = [1, 2, "three", {"four": 5}]
    packed = mesh_marshal(data)
    assert isinstance(packed, bytes)
    
    unpacked = mesh_unmarshal(packed)
    assert unpacked == data
