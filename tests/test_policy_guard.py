"""Bo test cho ci/policy_guard.py.

Giu hai chieu cho tung quy tac: mot dau vao hop le phai duoc chap nhan, va mot
dau vao vi pham phai bi tu choi. Mot cong chi tu choi dung thu can tu choi van
chua du; no con phai chap nhan dung thu hop le, neu khong thi chinh cong tro
thanh vat can va se bi nguoi dung tim cach di vong.

Chay: python -m pytest tests/test_policy_guard.py -q
Hoac: python tests/test_policy_guard.py
"""

from __future__ import annotations

import datetime as _dt
import importlib.util
import json
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent


def _load():
    spec = importlib.util.spec_from_file_location("policy_guard", ROOT / "ci" / "policy_guard.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


pg = _load()


# --- 1. Quy uoc dat ten commit ----------------------------------------------

VALID_COMMITS = [
    "feat: them tinh nang",
    "feat(auth): them xac thuc token",
    "sec(gate): giu ma thoat cho buoc co pipe",
    # Danh sach scope cach nhau boi dau phay. Lich su kho ma nguon da dung dang
    # nay, nen quy tac phai chap nhan.
    "feat(report,telemetry): bang chung bac 3",
    "sec(deploy, sonar): va cau hinh trien khai",
    "release: v1.0.0 - phat hanh dau tien",
    "Merge pull request #7 from vsxkr/patched",
    "Revert \"feat(auth): them xac thuc token\"",
]

INVALID_COMMITS = [
    "sua loi",
    "",
    "update",
    "feat(): scope rong",
    "feature(auth): loai khong hop le",
    "feat(auth) thieu dau hai cham",
]


def test_commit_messages() -> list[str]:
    errs = []
    for msg in VALID_COMMITS:
        ok, _ = pg.validate_commit_message(msg)
        if not ok:
            errs.append(f"dang hop le bi tu choi: {msg!r}")
    for msg in INVALID_COMMITS:
        ok, _ = pg.validate_commit_message(msg)
        if ok:
            errs.append(f"dang vi pham duoc chap nhan: {msg!r}")
    return errs


# --- 2. Cong CS-01, day truc tiep vao nhanh phat hanh -----------------------

def _push_event(ref: str, message: str, forced: bool = False) -> dict:
    return {
        "ref": ref,
        "forced": forced,
        "head_commit": {"id": "a" * 7, "message": message},
        "commits": [{"id": "a" * 11, "message": message}],
    }


def _write_exceptions(entries: list[dict]) -> str:
    fd, path = tempfile.mkstemp(suffix=".json")
    with open(fd, "w", encoding="utf-8") as f:
        json.dump({"exceptions": entries}, f, ensure_ascii=False)
    return path


def test_release_branch_gate() -> list[str]:
    import os

    errs = []
    future = (_dt.date.today() + _dt.timedelta(days=30)).isoformat()
    past = (_dt.date.today() - _dt.timedelta(days=1)).isoformat()

    valid_ex = {
        "id": "EX-TEST-OK",
        "clause": "CS-01",
        "branch": "main",
        "reason": "ngoai le dung cho bo test",
        "approved_by": "bo test",
        "expires": future,
    }
    expired_ex = dict(valid_ex, id="EX-TEST-HET-HAN", expires=past)

    cases = [
        # (mo ta, ref, thong diep, ngoai le, ma thoat mong doi)
        ("day truc tiep vao main, co ngoai le con han",
         "refs/heads/main", "feat(x): y", [valid_ex], 0),
        ("day truc tiep vao main, ngoai le het han",
         "refs/heads/main", "feat(x): y", [expired_ex], 1),
        ("day truc tiep vao main, khong co ngoai le",
         "refs/heads/main", "feat(x): y", [], 1),
        ("thay doi den tu pull request da hop nhat",
         "refs/heads/main", "Merge pull request #7 from vsxkr/patched", [], 0),
        ("nhanh khong thuoc dien chinh sach",
         "refs/heads/patched", "feat(x): y", [], 0),
    ]

    old = os.environ.get("POLICY_EXCEPTIONS_FILE")
    for mo_ta, ref, msg, entries, want in cases:
        path = _write_exceptions(entries)
        os.environ["POLICY_EXCEPTIONS_FILE"] = path
        try:
            got = pg.validate_release_branch_push(_push_event(ref, msg), ref)
        finally:
            Path(path).unlink(missing_ok=True)
        if got != want:
            errs.append(f"{mo_ta}: mong ma thoat {want}, nhan {got}")

    if old is None:
        os.environ.pop("POLICY_EXCEPTIONS_FILE", None)
    else:
        os.environ["POLICY_EXCEPTIONS_FILE"] = old
    return errs


# --- 3. Day cuong buc vao nhanh phat hanh -----------------------------------

def test_force_push_blocked() -> list[str]:
    import os

    errs = []
    path = _write_exceptions([])
    os.environ["POLICY_EXCEPTIONS_FILE"] = path
    try:
        ev = _push_event("refs/heads/main", "Merge pull request #9 from vsxkr/patched", forced=True)
        if pg.validate_release_branch_push(ev, "refs/heads/main") != 1:
            errs.append("day cuong buc vao nhanh phat hanh phai bi chan du la merge commit")
    finally:
        Path(path).unlink(missing_ok=True)
        os.environ.pop("POLICY_EXCEPTIONS_FILE", None)
    return errs


def main() -> int:
    all_errs = []
    for fn in (test_commit_messages, test_release_branch_gate, test_force_push_blocked):
        errs = fn()
        status = "DAT" if not errs else "KHONG DAT"
        print(f"[{status}] {fn.__name__}")
        all_errs.extend(errs)

    if all_errs:
        print()
        for e in all_errs:
            print("  -", e, file=sys.stderr)
        print(f"\nCO {len(all_errs)} LOI", file=sys.stderr)
        return 1

    print("\nTOAN BO PHEP KIEM DAT")
    return 0


if __name__ == "__main__":
    sys.exit(main())
