"""Fix remaining print calls in bin_downloader.py."""
path = r"D:\cyber security test pipeline - Copy\src\core\utils\bin_downloader.py"
with open(path, "r", encoding="utf-8") as f:
    content = f.read()

content = content.replace(
    'print("  \u2514\u2500 Unpacking archive and resolving binary...")',
    'logger.info("Unpacking archive and resolving binary...")',
)

with open(path, "w", encoding="utf-8") as f:
    f.write(content)
print("Fixed bin_downloader.py")
