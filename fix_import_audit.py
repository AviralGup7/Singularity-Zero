with open("import_audit.py", encoding="utf-8") as f:
    lines = f.readlines()
new_lines = [line for line in lines if "package_map = {}" not in line and 'sep = ""' not in line]
with open("import_audit.py", "w", encoding="utf-8") as f:
    f.writelines(new_lines)
print("Fixed import_audit.py")
