#!/usr/bin/env python3
"""ci/validate_configs.py — kiem cu phap toan bo tep cau hinh YAML va JSON.

BA KHIEM KHUYET DA DO DUOC VA DA SUA, ghi lai de khong tai pham:

1. Duong dan goc sai. Ban truoc ghep `base_dir` voi "InlaneWeb", trong khi cay
   thu muc that la `app/InlaneWeb`. Khong tep nao khop, nen script in
   "0/0 tep cau hinh hop le" roi tra ve 0, tuc BAO DAT trong khi khong kiem gi.
   Day dung la cai bay "0 test" ma chinh du an canh bao o muc 3.4 cua bao cao,
   lan nay xay ra trong ma cua nhom.

2. Khong co cong chong 0 tep. Mot phep kiem chay tren tap rong luon dat. Ban nay
   tra ve 1 khi tong so tep bang 0.

3. Khong duoc goi o bat ky workflow nao, nen no la ma chet luon bao thanh cong.
   Ban nay duoc goi o stage 1.

Cach dung:
    python3 ci/validate_configs.py
"""

from __future__ import annotations

import glob
import json
import os
import sys

import yaml

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def rel(path: str) -> str:
    return os.path.relpath(path, BASE).replace(os.sep, "/")


def validate_yaml(path: str) -> bool:
    try:
        with open(path, "r", encoding="utf-8") as f:
            yaml.safe_load(f)
    except Exception as exc:
        print(f"[LOI] YAML {rel(path)}: {exc}", file=sys.stderr)
        return False
    print(f"[DAT] YAML {rel(path)}")
    return True


def validate_json(path: str) -> bool:
    try:
        with open(path, "r", encoding="utf-8") as f:
            json.load(f)
    except Exception as exc:
        print(f"[LOI] JSON {rel(path)}: {exc}", file=sys.stderr)
        return False
    print(f"[DAT] JSON {rel(path)}")
    return True


def collect() -> tuple[list[str], list[str]]:
    app = os.path.join(BASE, "app", "InlaneWeb")
    monitoring = os.path.join(app, "monitoring")

    yaml_files = sorted(
        glob.glob(os.path.join(app, "docker-compose*.yml"))
        + glob.glob(os.path.join(monitoring, "**", "*.yml"), recursive=True)
        + glob.glob(os.path.join(monitoring, "**", "*.yaml"), recursive=True)
        + glob.glob(os.path.join(BASE, ".github", "workflows", "*.yml"))
        + glob.glob(os.path.join(BASE, "ci", "semgrep-*.yml"))
        + glob.glob(os.path.join(BASE, "compliance", "inspec.yml"))
        + glob.glob(os.path.join(BASE, ".trivyignore.yaml"))
        + glob.glob(os.path.join(BASE, "patches", "monitoring", "**", "*.yml"), recursive=True)
    )
    json_files = sorted(
        glob.glob(os.path.join(monitoring, "**", "*.json"), recursive=True)
        + glob.glob(os.path.join(BASE, "policy", "*.json"))
        + glob.glob(os.path.join(BASE, "ci", "*.json"))
        + glob.glob(os.path.join(BASE, "fixtures", "*.json"))
    )
    return yaml_files, json_files


def main() -> int:
    print("[Validation Gate] Kiem cu phap tep cau hinh YAML va JSON")

    yaml_files, json_files = collect()
    total = len(yaml_files) + len(json_files)

    if total == 0:
        print(
            "[LOI] Khong tim thay tep cau hinh nao de kiem. Mot phep kiem chay tren "
            "tap rong luon dat, nen truong hop nay duoc coi la that bai chu khong "
            "phai dat.",
            file=sys.stderr,
        )
        return 1

    failures = 0
    for path in yaml_files:
        if not validate_yaml(path):
            failures += 1
    for path in json_files:
        if not validate_json(path):
            failures += 1

    print(f"\nKet qua: {total - failures}/{total} tep cau hinh hop le "
          f"({len(yaml_files)} YAML, {len(json_files)} JSON).")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
