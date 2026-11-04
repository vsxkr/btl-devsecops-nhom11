"""Kiem cau truc phan hoi API truoc khi dua vao Conftest.

Ly do ton tai cua tep nay duoc ghi trong bao cao muc 4.2. Ban truoc cua
pipeline lap cung tren danh sach nhanh "main dev", trong khi kho ma nguon
khong co nhanh dev. GitHub tra ve mot doi tuong loi dang
{"message": "Branch not found", ...}; buoc lam gon JSON van chay, sinh ra
{"name": null, "protected": null, "protection": null}, va Conftest ket luan
vi pham tren mot doi tuong khong ton tai. Ket luan dung ve hinh thuc nhung
khong co doi tuong do, nen khong dung lam minh chung duoc.

Script nay chan truong hop do: neu phan hoi khong co dang mot nhanh thuc su
thi tra ve ma thoat 1 va khong ghi tep dau ra.

Cach dung:
    python3 ci/check_branch_payload.py <tep-raw.json> <tep-slim.json>
"""

from __future__ import annotations

import json
import sys

REQUIRED = ("name", "commit")


def main() -> int:
    if len(sys.argv) != 3:
        print("Cach dung: check_branch_payload.py <raw.json> <slim.json>", file=sys.stderr)
        return 2

    raw_path, slim_path = sys.argv[1], sys.argv[2]

    try:
        with open(raw_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"LOI CAU TRUC: khong doc duoc {raw_path}: {exc}", file=sys.stderr)
        return 1

    if not isinstance(data, dict):
        print(f"LOI CAU TRUC: {raw_path} khong phai mot doi tuong JSON", file=sys.stderr)
        return 1

    if "message" in data and "name" not in data:
        print(
            f"LOI CAU TRUC: API tra ve loi thay vi mot nhanh: {data.get('message')!r}. "
            "Khong danh gia chinh sach tren doi tuong nay.",
            file=sys.stderr,
        )
        return 1

    missing = [k for k in REQUIRED if not data.get(k)]
    if missing:
        print(
            f"LOI CAU TRUC: phan hoi thieu truong bat buoc {missing}. "
            "Khong danh gia chinh sach tren doi tuong nay.",
            file=sys.stderr,
        )
        return 1

    slim = {
        "name": data.get("name"),
        "protected": data.get("protected"),
        "protection": data.get("protection"),
    }

    with open(slim_path, "w", encoding="utf-8") as f:
        json.dump(slim, f, ensure_ascii=False, indent=2)

    has_protection_field = "protection" in data
    print(
        f"CAU TRUC DAT: nhanh {slim['name']!r}, protected={slim['protected']}, "
        f"co truong protection={has_protection_field}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
