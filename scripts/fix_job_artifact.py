"""Fix print -> logger in job_artifact_packager.py"""
path = r"D:\cyber security test pipeline - Copy\src\pipeline\services\job_artifact_packager.py"
with open(path, encoding="utf-8") as f:
    content = f.read()

# Only fix the success output prints in main(), not the CLI usage/error messages
content = content.replace(
    '        print(f"Archived to: {archive_path}")\n',
    '        logger.info("Archived to: %s", archive_path)\n',
)
content = content.replace(
    '        print(f"Size: {archive_path.stat().st_size:,} bytes")\n',
    '        logger.info("Size: %s bytes", f"{archive_path.stat().st_size:,}")\n',
)
content = content.replace(
    '        print(f"Verified unpack: job_id={snapshot.job_id} git={snapshot.git_commit_hash}")\n',
    '        logger.info("Verified unpack: job_id=%s git=%s", snapshot.job_id, snapshot.git_commit_hash)\n',
)

with open(path, "w", encoding="utf-8") as f:
    f.write(content)
print("Fixed job_artifact_packager.py")
