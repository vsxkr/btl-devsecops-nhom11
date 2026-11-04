"""Kiem ho so ngoai le chinh sach, thi hanh dieu khoan CS-08.

CS-08 yeu cau moi ngoai le phai co ly do, nguoi phe duyet dich danh va thoi han.
Het han la het hieu luc. Mot ban ghi ngoai le het han nhung van nam trong tep la
dang no ky thuat de bi bo quen nhat, nen chinh tep ngoai le cung phai co cong
kiem.

Script tra ve:
  0  moi ban ghi du truong va con han
  1  co ban ghi thieu truong, sai dinh dang ngay, hoac da het han
"""

from __future__ import annotations

import datetime as _dt
import json
from pathlib import Path
import sys

REQUIRED_FIELDS = ("id", "clause", "reason", "approved_by", "expires")
# Mot ngoai le sap het han can duoc nhac truoc, de viec gia han hoac thu hoi
# nam trong ke hoach chu khong xay ra vao dung ngay cong chan.
WARN_DAYS = 30


def main() -> int:
    path = Path(__file__).resolve().parent.parent / "policy" / "exceptions.json"
    if not path.is_file():
        print("[DAT] Khong co tep ngoai le, tuc khong co ngoai le nao.")
        return 0

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[LOI] Khong doc duoc {path}: {exc}", file=sys.stderr)
        return 1

    items = data.get("exceptions", [])
    if not isinstance(items, list):
        print("[LOI] Truong 'exceptions' phai la mot danh sach.", file=sys.stderr)
        return 1

    today = _dt.date.today()
    rc = 0
    print(f"[CS-08] Kiem {len(items)} ban ghi ngoai le, moc thoi gian {today.isoformat()}")

    for item in items:
        ex_id = item.get("id", "khong co id")

        missing = [f for f in REQUIRED_FIELDS if not item.get(f)]
        if missing:
            print(f"[LOI] {ex_id}: thieu truong bat buoc {missing}", file=sys.stderr)
            rc = 1
            continue

        try:
            expires = _dt.date.fromisoformat(str(item["expires"]))
        except ValueError:
            print(
                f"[LOI] {ex_id}: truong 'expires' khong dung dinh dang YYYY-MM-DD",
                file=sys.stderr,
            )
            rc = 1
            continue

        remaining = (expires - today).days
        scope = item.get("branch") or item.get("scope") or "khong ghi pham vi"

        if remaining < 0:
            print(
                f"[LOI] {ex_id} ({item['clause']}, {scope}): da het han "
                f"{-remaining} ngay. Phai gia han co phe duyet hoac go khoi tep.",
                file=sys.stderr,
            )
            rc = 1
        elif remaining <= WARN_DAYS:
            print(
                f"[CANH BAO] {ex_id} ({item['clause']}, {scope}): con {remaining} ngay."
            )
        else:
            print(f"[DAT] {ex_id} ({item['clause']}, {scope}): con {remaining} ngay.")

    if rc == 0:
        print("[DAT] Moi ngoai le du truong va con hieu luc.")
    return rc


if __name__ == "__main__":
    sys.exit(main())
