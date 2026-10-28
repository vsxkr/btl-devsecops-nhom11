#!/usr/bin/env python3
"""
ci/validate_configs.py — Kiểm tra cú pháp toàn bộ tệp cấu hình YAML & JSON của hệ thống giám sát.
"""
import glob
import json
import os
import sys
import yaml

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")


def validate_yaml_file(filepath: str) -> bool:
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            yaml.safe_load(f)
        print(f"✅ YAML hợp lệ: {filepath}")
        return True
    except Exception as exc:
        print(f"❌ LỖI YAML ({filepath}): {exc}", file=sys.stderr)
        return False


def validate_json_file(filepath: str) -> bool:
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            json.load(f)
        print(f"✅ JSON hợp lệ: {filepath}")
        return True
    except Exception as exc:
        print(f"❌ LỖI JSON ({filepath}): {exc}", file=sys.stderr)
        return False


def main() -> int:
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    monitoring_dir = os.path.join(base_dir, "InlaneWeb", "monitoring")
    failures = 0
    total = 0

    print("🔍 [Validation Gate] Bắt đầu kiểm tra các tệp cấu hình Monitoring & Production Compose...")

    compose_files = [
        os.path.join(base_dir, "InlaneWeb", "docker-compose.monitoring.yml"),
        os.path.join(base_dir, "InlaneWeb", "docker-compose.prod.yml"),
    ]

    for comp in compose_files:
        if os.path.exists(comp):
            total += 1
            if not validate_yaml_file(comp):
                failures += 1

    for yml_path in glob.glob(os.path.join(monitoring_dir, "**", "*.yml"), recursive=True) + \
                     glob.glob(os.path.join(monitoring_dir, "**", "*.yaml"), recursive=True):
        total += 1
        if not validate_yaml_file(yml_path):
            failures += 1

    for json_path in glob.glob(os.path.join(monitoring_dir, "**", "*.json"), recursive=True):
        total += 1
        if not validate_json_file(json_path):
            failures += 1

    print(f"\n📊 Kết quả: {total - failures}/{total} tệp cấu hình hợp lệ.")
    return 1 if failures > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
