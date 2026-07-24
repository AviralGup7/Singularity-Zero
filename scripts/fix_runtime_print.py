"""Fix print -> logger in runtime.py"""
path = r"D:\cyber security test pipeline - Copy\src\pipeline\runtime.py"
with open(path, encoding="utf-8") as f:
    content = f.read()
content = content.replace(
    '            print(format_validation_report(report))',
    '            logger.info(format_validation_report(report))',
)
with open(path, "w", encoding="utf-8") as f:
    f.write(content)
print("Fixed runtime.py")
