
import json
import sys
from pathlib import Path

file_path = Path("THIRD_PARTY_LICENSES.json")

if not file_path.is_file():
    print(f"::error file={file_path}::File {file_path} not found.")
    sys.exit(1)

data = json.loads(file_path.read_text(encoding="utf-8"))

# Expected format: List of objects with Name, Author, License, URL
entries = data if isinstance(data, list) else []

problem_entries = []

for e in entries:
    category = None
    if any(["UNKNOWN" in val.upper() for val in e.values()]):
        category = "UNKNOWN"
    license_val = e.get("License", "")
    if license_val:
        lic = str(license_val).strip()
        is_gpl_like = any(
            x in lic.upper()
            for x in ["GPL", "AGPL", "LGPL"]
        )
        category = "GPL/AGPL/LGPL" if is_gpl_like else category
    if category is not None:
        name = e.get("Name", "")
        author = e.get("Author", "")
        url = e.get("URL", "")

        problem_entries.append({
            "Name": name,
            "Author": author,
            "License": lic,
            "URL": url,
            "Category": category,
        })

# Warning annotations for each entry
for e in problem_entries:
    msg = f"{e['Category']}: {e['Name']} {e['Author']} ({e['License']})"
    print(f"::warning title=License-Scan::{msg}")

if problem_entries:
    sys.exit(1)
