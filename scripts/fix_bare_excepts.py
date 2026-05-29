import os
import re
from pathlib import Path


def fix_except_blocks(directory: str = "src") -> None:
    pattern = re.compile(r"except\s+([a-zA-Z0-9_.]+)\s*,\s*([a-zA-Z0-9_.]+)\s*:")
    count = 0
    for root, _, files in os.walk(directory):
        for file in files:
            if not file.endswith(".py"):
                continue
            filepath = Path(root) / file
            with open(filepath, encoding="utf-8") as f:
                content = f.read()

            new_content = pattern.sub(r"except (\1, \2):", content)

            if new_content != content:
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write(new_content)
                count += 1
                print(f"Fixed {filepath}")

    print(f"Fixed {count} files total.")


if __name__ == "__main__":
    fix_except_blocks()
