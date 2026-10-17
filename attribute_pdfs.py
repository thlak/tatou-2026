"""
attribute_pdfs.py - fill Intended_for for returned PDFs using your own read_secret.
- A versions.tsv should be in the same directory
- RMAP_WM_KEY should be first exported 
python3 attribute_pdfs.py Group_29/ answers.csv versions.tsv
"""
import csv, os, sys
from pathlib import Path

## for access to utils
SRC    = Path("~/tatou-2026/server/src").expanduser() 
METHOD = "MyWatermarkingMethod"
KEY    = os.environ["RMAP_WM_KEY"]

sys.path.insert(0, str(SRC))
import watermarking_utils as wu
method = wu.get_method(METHOD)

pdf_dir = Path("Group_29/")
csv_path = Path("Group_29/answers.csv")
versions_path = Path("versions.tsv")

# secret -> intended_for, from a TSV export of the Versions table
# Create a disctionary with all the secrets and the intended for labels
with versions_path.open(encoding="utf-8-sig", newline="") as f:
    owner = {r["secret"]: r["intended_for"] for r in csv.DictReader(f, delimiter="\t")}

with csv_path.open(encoding="utf-8-sig", newline="") as f:
    reader = csv.DictReader(f)
    fields, rows = reader.fieldnames, list(reader)

## for each pdf document
for r in rows:
    pdf = pdf_dir / r["FileName"].strip()
    try:
        ## use MyWatermarkingMethod to read the secret, given a pdf file and the RMAP key
        secret = method.read_secret(str(pdf), KEY).strip()
        ## for that secret, search the dictionary
        ## if secret is not mapped to any, "Unknown"
        r["Intended_for"] = owner.get(secret, "Unknown")
    except Exception as e:
        secret, r["Intended_for"] = f"({type(e).__name__}: {e})", "Unknown"
    print(f"{pdf.name:45} -> {r['Intended_for']:20} {secret}")

out = csv_path.with_name(csv_path.stem + "_filled.csv")
with out.open("w", encoding="utf-8", newline="") as f:
    w = csv.DictWriter(f, fieldnames=fields); w.writeheader(); w.writerows(rows)
print("wrote", out)