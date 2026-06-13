"""Frontend dependency analysis script.

Analyzes package sizes and identifies heavy dependencies.
"""

from __future__ import annotations

import json
from pathlib import Path

FRONTEND_DIR = Path(__file__).parent.parent / "frontend"

# Estimated sizes (gzipped) in KB based on typical bundle sizes
DEPENDENCY_SIZES = {
    # 3D Graphics (~1.0-1.4MB total)
    "three": 150,
    "@react-three/fiber": 45,
    "@react-three/drei": 120,
    "@react-three/postprocessing": 35,
    # Charting (~400-500KB total)
    "recharts": 200,
    "d3-array": 15,
    "d3-force": 20,
    "d3-scale": 15,
    "d3-shape": 15,
    # Animation (~200KB total)
    "framer-motion": 100,
    "gsap": 80,
    "lottie-react": 30,
    # UI Components (~150KB total)
    "@radix-ui/react-accordion": 5,
    "@radix-ui/react-alert-dialog": 5,
    "@radix-ui/react-checkbox": 3,
    "@radix-ui/react-dialog": 5,
    "@radix-ui/react-dropdown-menu": 5,
    "@radix-ui/react-popover": 5,
    "@radix-ui/react-select": 8,
    "@radix-ui/react-tabs": 5,
    "@radix-ui/react-tooltip": 3,
    "lucide-react": 30,
    "cmdk": 10,
    # Core React (~100KB total)
    "react": 40,
    "react-dom": 40,
    "react-router-dom": 15,
    # State & Data (~80KB total)
    "@tanstack/react-query": 40,
    "zustand": 10,
    "axios": 15,
    # Forms & Validation (~50KB total)
    "react-hook-form": 25,
    "zod": 20,
    # i18n (~30KB total)
    "i18next": 15,
    "react-i18next": 10,
    # Other (~50KB total)
    "dompurify": 5,
    "hls.js": 0,  # External
    "embla-carousel-react": 10,
    "react-virtuoso": 15,
    "react-window": 10,
}


def analyze_dependencies() -> None:
    """Analyze frontend dependencies and estimate bundle impact."""
    print("=" * 70)
    print("Frontend Dependency Analysis")
    print("=" * 70)

    # Read package.json
    with open(FRONTEND_DIR / "package.json") as f:
        pkg = json.load(f)

    deps = pkg.get("dependencies", {})

    # Categorize dependencies
    categories = {
        "3D Graphics": ["three", "@react-three"],
        "Charting": ["recharts", "d3-"],
        "Animation": ["framer-motion", "gsap", "lottie"],
        "UI Components": ["@radix-ui", "lucide-react", "cmdk", "vaul"],
        "Core React": ["react", "react-dom", "react-router"],
        "State & Data": ["@tanstack", "zustand", "axios"],
        "Forms": ["react-hook-form", "zod", "@hookform"],
        "i18n": ["i18next", "react-i18next"],
    }

    print("\n[Dependency Categories]\n")

    total_size = 0
    for category, prefixes in categories.items():
        cat_deps = []
        cat_size = 0
        for dep_name in deps:
            if any(dep_name.startswith(p) or dep_name == p for p in prefixes):
                size = DEPENDENCY_SIZES.get(dep_name, 5)
                cat_deps.append((dep_name, size))
                cat_size += size

        if cat_deps:
            print(f"  {category}:")
            for dep_name, size in sorted(cat_deps, key=lambda x: -x[1]):
                print(f"    {dep_name:40s} ~{size:4d} KB")
            print(f"    {'Subtotal':40s} ~{cat_size:4d} KB")
            print()
            total_size += cat_size

    print(f"  {'Estimated Total (gzipped)':40s} ~{total_size:4d} KB")
    print(f"  {'Estimated Total (uncompressed)':40s} ~{total_size * 3:4d} KB")

    print("\n[Size Limits from .size-limit.json]\n")
    with open(FRONTEND_DIR / ".size-limit.json") as f:
        limits = json.load(f)
    for limit in limits:
        print(f"  {limit['path']:30s} limit: {limit['limit']} (gzip)")

    print("\n" + "=" * 70)


if __name__ == "__main__":
    analyze_dependencies()
