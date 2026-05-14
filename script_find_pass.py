import ast
import os
from pathlib import Path


def find_pass_in_except(directory: str = "src") -> None:
    for root, _, files in os.walk(directory):
        for file in files:
            if not file.endswith(".py"):
                continue
            filepath = Path(root) / file
            with open(filepath, encoding="utf-8") as f:
                content = f.read()

            try:
                tree = ast.parse(content)
            except SyntaxError:
                continue

            for node in ast.walk(tree):
                if isinstance(node, ast.ExceptHandler):
                    # Check if body is just 'pass'
                    if len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
                        print(f"{filepath}:{node.lineno}")

if __name__ == "__main__":
    find_pass_in_except()
