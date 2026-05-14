"""Constants and payloads for deserialization probing."""

import re

from src.analysis.plugins import AnalysisPluginSpec

__all__ = [
    "DESERIALIZATION_PROBE_SPEC",
    "SERIALIZATION_PATH_PATTERNS",
    "SERIALIZATION_CONTENT_TYPES",
    "JAVA_MARKERS",
    "PYTHON_MARKERS",
    "PHP_MARKERS",
    "RUBY_MARKERS",
    "DOTNET_MARKERS",
    "JAVA_PAYLOAD",
    "PYTHON_PAYLOAD",
    "PHP_PAYLOAD",
    "RUBY_PAYLOAD",
    "DOTNET_PAYLOAD",
    "DESERIALIZATION_ERRORS",
    "VULNERABLE_INDICATORS",
    "STACK_TRACE_PATTERNS",
    "SERIAL_PARAM_NAMES",
]

DESERIALIZATION_PROBE_SPEC = AnalysisPluginSpec(
    key="deserialization_probe",
    label="Deserialization Probe",
    description="Send crafted serialized objects to parameters that look like serialized data to test for insecure deserialization.",
    group="active",
    slug="deserialization_probe",
    enabled_by_default=True,
)

SERIALIZATION_PATH_PATTERNS = (
    "/api/",
    "/rpc/",
    "/soap/",
    "/xmlrpc/",
    "/graphql",
    "/serialize/",
    "/deserialize/",
    "/deser/",
    "/serial/",
    "/object/",
    "/import/",
    "/export/",
    "/load/",
    "/unmarshal/",
    "/marshal/",
    "/decode/",
    "/parse/",
)

SERIALIZATION_CONTENT_TYPES = (
    "application/x-java-serialized-object",
    "application/x-python-pickle",
    "application/x-php-serialize",
    "application/x-ruby-marshal",
    "application/x-protobuf",
    "application/x-msgpack",
    "application/x-thrift",
    "application/soap+xml",
    "text/xml",
    "application/xml",
)

JAVA_MARKERS = [
    re.compile(r"aced0005", re.IGNORECASE),
    re.compile(r"rO0AB", re.IGNORECASE),
    re.compile(r"\bjava\.io\.ObjectInputStream\b", re.IGNORECASE),
    re.compile(r"\bjava\.io\.ObjectOutputStream\b", re.IGNORECASE),
    re.compile(r"\bObjectInputStream\b.*\breadObject\b", re.IGNORECASE),
]

PYTHON_MARKERS = [
    re.compile(r"\(lp0\\n", re.IGNORECASE),
    re.compile(r"[Ss]'[^']*'\n", re.IGNORECASE),
    re.compile(r"cos\\n", re.IGNORECASE),
    re.compile(r"i__main__", re.IGNORECASE),
    re.compile(r"\bpickle\b.*\bload\b", re.IGNORECASE),
    re.compile(r"\bcPickle\b", re.IGNORECASE),
    re.compile(r"__reduce__", re.IGNORECASE),
]

PHP_MARKERS = [
    re.compile(r'\b[Oa]:\d+:"'),
    re.compile(r'\bs:\d+:"'),
    re.compile(r"\bi:\d+;"),
    re.compile(r"\bb:[01];"),
    re.compile(r"N;"),
    re.compile(r"\bunserialize\b", re.IGNORECASE),
    re.compile(r"\bserialize\b", re.IGNORECASE),
    re.compile(r"__wakeup", re.IGNORECASE),
    re.compile(r"__destruct", re.IGNORECASE),
]

RUBY_MARKERS = [
    re.compile(r"MARSHAL", re.IGNORECASE),
    re.compile(r"\x04\x08", re.IGNORECASE),
    re.compile(r"\bMarshal\.load\b", re.IGNORECASE),
    re.compile(r"\bMarshal\.dump\b", re.IGNORECASE),
    re.compile(r"YAML\.load", re.IGNORECASE),
    re.compile(r"Psych\.load", re.IGNORECASE),
]

DOTNET_MARKERS = [
    re.compile(r"__type", re.IGNORECASE),
    re.compile(r"__assembly", re.IGNORECASE),
    re.compile(r"BinaryFormatter", re.IGNORECASE),
    re.compile(r"ObjectStateFormatter", re.IGNORECASE),
    re.compile(r"LosFormatter", re.IGNORECASE),
    re.compile(r"NetDataContractSerializer", re.IGNORECASE),
    re.compile(r"System\.Diagnostics\.Process", re.IGNORECASE),
]

JAVA_PAYLOAD = "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAAAeHQAAHRlc3Q="

PYTHON_PAYLOAD = "cos\nsystem\n(S'echo VULNERABLE'\ntR."

PHP_PAYLOAD = 'O:8:"stdClass":1:{s:4:"test";s:13:"VULNERABLE";}'

RUBY_PAYLOAD = b"\x04\x08o:\x0eActiveRecord::Base\x00"

DOTNET_PAYLOAD = '{"$type":"System.Diagnostics.Process, System", "StartInfo":{"FileName":"echo","Arguments":"VULNERABLE"}}'

DESERIALIZATION_ERRORS = [
    re.compile(r"invalid\s+(stream|class|type)\s+header", re.IGNORECASE),
    re.compile(r"unexpected\s+(bytes|token)\s+in\s+(serialized|pickle)", re.IGNORECASE),
    re.compile(r"ObjectInputStream", re.IGNORECASE),
    re.compile(r"pickle\.UnpicklingError", re.IGNORECASE),
    re.compile(r"unserialize\(\)\s+error", re.IGNORECASE),
    re.compile(r"Marshal\.load", re.IGNORECASE),
    re.compile(r"JsonSerializationException", re.IGNORECASE),
    re.compile(r"TypeResolve", re.IGNORECASE),
    re.compile(r"SerializationException", re.IGNORECASE),
    re.compile(r"ClassNotFoundException", re.IGNORECASE),
    re.compile(r"InvalidClassException", re.IGNORECASE),
    re.compile(r"NotSerializableException", re.IGNORECASE),
    re.compile(r"java\.io\.IOException.*readObject", re.IGNORECASE),
    re.compile(r"yaml\.constructor", re.IGNORECASE),
    re.compile(r"unsafe\s+deserialization", re.IGNORECASE),
    re.compile(r"deserialization\s+(error|failed|exception)", re.IGNORECASE),
]

VULNERABLE_INDICATORS = [
    re.compile(r"\bVULNERABLE\b"),
    re.compile(r"\bDESER\b"),
    re.compile(r"\bPROBE_OK\b"),
    re.compile(r"\bINJECTED\b"),
]

STACK_TRACE_PATTERNS = [
    re.compile(r"at\s+[\w.$]+\(", re.IGNORECASE),
    re.compile(r"Traceback\s+\(most\s+recent\s+call\s+last\)", re.IGNORECASE),
    re.compile(r"File\s+\"[^\"]+\", line \d+", re.IGNORECASE),
    re.compile(r"Exception\s+in\s+thread", re.IGNORECASE),
    re.compile(r"Caused\s+by:", re.IGNORECASE),
]

SERIAL_PARAM_NAMES = {
    "data",
    "payload",
    "object",
    "serialized",
    "serialized_data",
    "pickle",
    "marshal",
    "encode",
    "encoded",
    "input",
    "body",
    "request",
    "params",
    "state",
    "session_data",
    "cache",
    "config",
    "settings",
    "token",
    "jwt",
}
