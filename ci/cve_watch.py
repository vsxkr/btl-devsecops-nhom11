"""Theo doi CVE moi tren hai anh nen va sinh mo ta ban va.

Dung trong workflow auto-remediate.yml, phan tu dong va cua chu trinh CD.

Cach lam:
  1. doc ket qua Trivy dang JSON cua mot anh,
  2. so sanh tap ID lo hong voi moc co so da ghi trong sbom/cve-baseline.json,
  3. neu co ID moi thi cap nhat moc co so va ghi mot mo ta ban va de mo pull
     request, dong thoi tra ma thoat 10 lam tin hieu cho workflow,
  4. neu khong co ID moi thi tra 0 va khong thay doi gi.

Ma thoat:
  0  khong co CVE moi
  10 co CVE moi, da ghi moc co so va mo ta
  1  loi dau vao
"""

from __future__ import annotations

import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
BASELINE = ROOT / "sbom" / "cve-baseline.json"
SEVERITIES = ("CRITICAL", "HIGH")


def collect(report_path: Path) -> dict[str, dict]:
    with open(report_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    found: dict[str, dict] = {}
    for result in data.get("Results") or []:
        for v in result.get("Vulnerabilities") or []:
            if v.get("Severity") not in SEVERITIES:
                continue
            found[v["VulnerabilityID"]] = {
                "severity": v.get("Severity"),
                "pkg": v.get("PkgName"),
                "installed": v.get("InstalledVersion"),
                "fixed": v.get("FixedVersion") or "chua co ban va",
            }
    return found


def load_baseline() -> dict:
    if BASELINE.is_file():
        with open(BASELINE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"images": {}}


def main() -> int:
    if len(sys.argv) < 3:
        print("Cach dung: cve_watch.py <ten-anh> <trivy-report.json> [<ten-anh> <report> ...]", file=sys.stderr)
        return 1

    args = sys.argv[1:]
    if len(args) % 2 != 0:
        print("So doi so phai la so chan: tung cap <ten-anh> <report>", file=sys.stderr)
        return 1

    baseline = load_baseline()
    baseline.setdefault("images", {})
    new_lines: list[str] = []

    for i in range(0, len(args), 2):
        image, report = args[i], Path(args[i + 1])
        if not report.is_file():
            print(f"[LOI] Khong tim thay {report}", file=sys.stderr)
            return 1

        found = collect(report)
        known = set(baseline["images"].get(image, {}).get("ids", []))
        fresh = sorted(set(found) - known)

        print(f"{image}: {len(found)} lo hong muc {'/'.join(SEVERITIES)}, trong do {len(fresh)} la moi")

        if fresh:
            new_lines.append(f"### {image}")
            new_lines.append("")
            new_lines.append("| CVE | Muc | Goi | Ban dang dung | Ban da va |")
            new_lines.append("| :--- | :--- | :--- | :--- | :--- |")
            for cid in fresh:
                d = found[cid]
                new_lines.append(
                    f"| {cid} | {d['severity']} | {d['pkg']} | {d['installed']} | {d['fixed']} |"
                )
            new_lines.append("")

        baseline["images"][image] = {"ids": sorted(found)}

    if not new_lines:
        print("Khong co CVE moi so voi moc co so. Khong mo pull request.")
        return 0

    with open(BASELINE, "w", encoding="utf-8") as f:
        json.dump(baseline, f, ensure_ascii=False, indent=2, sort_keys=True)
        f.write("\n")

    body = [
        "## Tu dong phat hien CVE moi tren anh nen",
        "",
        "Pull request nay do stage vong doi quy tac sinh ra, khong do nguoi tao.",
        "Noi dung: cap nhat moc co so CVE va yeu cau danh gia nang phien ban anh nen.",
        "",
        "Can cu dieu khoan CS-02 va CS-07 trong `policy/00-chinh-sach-attt.md`.",
        "",
    ] + new_lines + [
        "### Viec can lam truoc khi hop nhat",
        "",
        "1. Danh gia tung CVE moi: co anh huong den InlaneWeb hay khong.",
        "2. Neu co ban va, nang phien ban anh nen va ghim lai theo ma bam.",
        "3. Neu chua co ban va, ghi mot ngoai le co thoi han theo CS-08.",
    ]

    out = ROOT / "evidence" / "auto-remediate-pr-body.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        f.write("\n".join(body) + "\n")

    print(f"Da ghi mo ta pull request vao {out}")
    return 10


if __name__ == "__main__":
    sys.exit(main())
