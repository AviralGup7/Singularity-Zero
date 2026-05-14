#!/usr/bin/env bash
set -euo pipefail

OUTPUT_DIR="${1:-./sbom}"
FORMAT="${2:-cyclonedx-json}"
mkdir -p "$OUTPUT_DIR"

echo "Generating SBOM in $FORMAT format..."

if [ "$FORMAT" = "cyclonedx-json" ]; then
    python -m cyclonedx_py environment \
        --output-file "$OUTPUT_DIR/sbom-cyclonedx.json" \
        --output-format json \
        --purl-bom-ref
    echo "SBOM written to $OUTPUT_DIR/sbom-cyclonedx.json"
elif [ "$FORMAT" = "cyclonedx-xml" ]; then
    python -m cyclonedx_py environment \
        --output-file "$OUTPUT_DIR/sbom-cyclonedx.xml" \
        --output-format xml \
        --purl-bom-ref
    echo "SBOM written to $OUTPUT_DIR/sbom-cyclonedx.xml"
elif [ "$FORMAT" = "spdx-json" ]; then
    python -m cyclonedx_py environment \
        --output-file "$OUTPUT_DIR/sbom-spdx.json" \
        --output-format json \
        --schema spdx
    echo "SBOM written to $OUTPUT_DIR/sbom-spdx.json"
else
    echo "Unknown format: $FORMAT. Use cyclonedx-json, cyclonedx-xml, or spdx-json"
    exit 1
fi
