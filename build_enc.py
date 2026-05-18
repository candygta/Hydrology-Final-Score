# -*- coding: utf-8 -*-
"""Build the encrypted student payload (enc.json) from the source xlsx.

Each student's full detail is encrypted with AES-256-GCM under a key derived
from THAT student's own ID (PBKDF2-HMAC-SHA256). The page ships no plaintext.
Re-run this whenever the spreadsheet changes, then re-embed enc.json.
"""
import pandas as pd, json, os, base64, secrets, hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

XLSX = "คะแนนเก็บ Hydrology 3-2568.xlsx"
HW_COLS = ['แบบฝึกหัดที่ 1', 'แบบฝึกหัดที่ 2', 'QUIZ 1', 'CW01', 'CW02', 'CW03',
           'แบบฝึกหัดที่ 3', 'BN01', 'CW04', 'CW05', 'แบบฝึกหัดที่ 4',
           'CW06', 'CW07']

hw = pd.read_excel(XLSX, sheet_name="HW_CW")
pj = pd.read_excel(XLSX, sheet_name="Project")

hw_max = hw.iloc[0]                 # row of maximum scores
hw_scaled_col = hw.columns[17]      # column R: ROUNDUP((sum/63)*20, 2)
hw_students = hw.iloc[1:]
pj_students = pj.iloc[1:]


def num(v):
    return None if pd.isna(v) else round(float(v), 2)


records = []
for _, row in hw_students.iterrows():
    sid = str(row["รหัสประจำตัว"]).strip().upper()
    name = str(row["ชื่อ-สกุล"]).strip()

    items = [{"l": c, "s": num(row[c]), "m": num(hw_max[c])} for c in HW_COLS]
    hw_raw = num(row["รวม"])
    hw_total_max = num(hw_max["รวม"])          # 63
    hw_scaled = num(row[hw_scaled_col])         # out of 20

    pm = pj_students[pj_students["รหัสประจำตัว"] == row["รหัสประจำตัว"]]
    if len(pm):
        pj_raw = num(pm.iloc[0]["คะแนน"])
        pj_late = num(pm.iloc[0]["ส่งช้า"])
        pj_final = num(pm.iloc[0]["คะแนนที่ได้"])
    else:
        pj_raw = pj_late = pj_final = None

    total = round((hw_scaled or 0) + (pj_final or 0), 2) \
        if (hw_scaled is not None and pj_final is not None) else None

    rec = {
        "no": int(row["ลำดับ"]),
        "name": name,
        "hw": hw_scaled,
        "project": pj_final,
        "total": total,
        "detail": {
            "items": items,
            "hwRaw": hw_raw,
            "hwMax": hw_total_max,
            "pjRaw": pj_raw,
            "pjLate": pj_late,
            "pjFinal": pj_final,
        },
    }
    records.append({"sid": sid, "rec": rec})

ITER = 200000
salt = secrets.token_bytes(16)
out = []
for r in records:
    key = hashlib.pbkdf2_hmac("sha256", r["sid"].encode(), salt, ITER, dklen=32)
    iv = secrets.token_bytes(12)
    ct = AESGCM(key).encrypt(
        iv, json.dumps(r["rec"], ensure_ascii=False).encode(), None)
    out.append({"iv": base64.b64encode(iv).decode(),
                "ct": base64.b64encode(ct).decode()})

secrets.SystemRandom().shuffle(out)
payload = {"salt": base64.b64encode(salt).decode(), "iter": ITER, "recs": out}
enc_literal = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))

# Embed directly into index.html (replace the existing const ENC = {...};)
import re
html = open("index.html", encoding="utf-8").read()
html, n = re.subn(r"const ENC = \{.*?\};",
                   "const ENC = " + enc_literal + ";",
                   html, count=1, flags=re.S)
assert n == 1, f"expected exactly one ENC literal in index.html, found {n}"
open("index.html", "w", encoding="utf-8").write(html)

# self-test: first student's ID must decrypt to its own record
t = records[0]
k = hashlib.pbkdf2_hmac("sha256", t["sid"].encode(), salt, ITER, dklen=32)
ok = False
for e in out:
    try:
        pt = AESGCM(k).decrypt(base64.b64decode(e["iv"]),
                               base64.b64decode(e["ct"]), None)
        d = json.loads(pt)
        assert d["name"] == t["rec"]["name"]
        print("self-test OK:", t["sid"], "->", d["name"],
              "| items:", len(d["detail"]["items"]),
              "| total:", d["total"])
        ok = True
        break
    except Exception:
        pass
assert ok, "self-test failed"
print("students:", len(out),
      "| embedded into index.html (", os.path.getsize("index.html"), "bytes )")
