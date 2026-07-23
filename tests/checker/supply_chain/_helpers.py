from __future__ import annotations

import csv
import hashlib
from base64 import urlsafe_b64encode


def write_record(dist_info, files):
    record = dist_info / "RECORD"
    rows = []
    for path in files:
        digest = urlsafe_b64encode(hashlib.sha256(path.read_bytes()).digest())
        rows.append(
            [
                str(path.relative_to(dist_info.parent)),
                f"sha256={digest.decode('ascii').rstrip('=')}",
                str(path.stat().st_size),
            ]
        )
    rows.append([str(record.relative_to(dist_info.parent)), "", ""])
    with record.open("w", encoding="utf-8", newline="") as handle:
        csv.writer(handle).writerows(rows)
