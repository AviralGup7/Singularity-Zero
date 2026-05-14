import json
import sqlite3

db_path = 'src/dashboard/output/jobs.db'
job_id = 'a6a109ca'

conn = sqlite3.connect(db_path)
cursor = conn.cursor()
cursor.execute("SELECT data FROM jobs WHERE job_id = ?", (job_id,))
row = cursor.fetchone()
if row:
    print(json.dumps(json.loads(row[0]), indent=2))
else:
    print(f"Job {job_id} not found")
conn.close()
