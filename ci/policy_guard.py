"""Policy Guard: kiem quy uoc dat ten commit, tieu de pull request va quy uoc
dua ma vao nhanh phat hanh.

Chi dung thu vien chuan cua Python, chay duoc ca tren GitHub Actions lan git
hook cuc bo.

Thay doi so voi ban dau, can cu bao cao muc 4.2:

  - Ban dau ham validate_push_event() chi doi chieu dinh dang thong diep
    commit. Khong co doan ma nao tu choi mot lan day ma vi ly do day truc tiep
    vao nhanh phat hanh, trong khi dieu khoan CS-01 cam dung viec do. Lop kiem
    soat duoc khai bao nhung khong co hieu luc thi hanh.

  - Ban nay tu choi day truc tiep vao nhanh phat hanh, tru khi co mot ngoai le
    duoc ghi ho so trong policy/exceptions.json, con han, va co nguoi phe
    duyet dich danh. Dieu khoan CS-08 yeu cau moi ngoai le phai co thoi han.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
from pathlib import Path
import re
import sys

# Dam bao ma hoa UTF-8 tren moi nen tang (Windows console va Linux runner)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

# LUU Y VE PHAM VI SCOPE, da do duoc:
# Ban dau scope chi nhan mot dinh danh, dang `\([a-zA-Z0-9_\-\.\/]+\)`. Lich su
# kho ma nguon da co commit dang `feat(report,telemetry): ...`, tuc quy tac tu
# choi mot dang ma nhom dang dung that. Mot cong tu choi dau vao hop le cung la
# mot cong sai, nen bieu thuc duoc mo rong de nhan danh sach scope cach nhau boi
# dau phay. Bo test o tests/test_policy_guard.py giu ca hai chieu.
#
# Quy uoc commit: Conventional Commits
# Cu phap: <type>(<scope>): <mo ta> hoac <type>: <mo ta>
# Cho phep merge commit mac dinh cua Git: Merge branch... hoac Merge pull request...
COMMIT_REGEX = re.compile(
    r"^(Merge\s.+|Revert\s.+|(release|RELEASE):\s+v[0-9]+\.[0-9]+\.[0-9]+.*|(feat|fix|sec|ci|docs|refactor|test|chore|style|perf|revert|release)(\([a-zA-Z0-9_\-\.\/]+(\s*,\s*[a-zA-Z0-9_\-\.\/]+)*\))?:\s.+)",
    re.IGNORECASE,
)

# Quy uoc PR vao dev: [<ma_nhanh>] <type>(<scope>): <mo ta>
PR_DEV_REGEX = re.compile(
    r"^\[(namng|haind|manhdx|anhld|mainp)\]\s+(feat|fix|sec|ci|docs|refactor|test|chore|style|perf|revert)(\([a-zA-Z0-9_\-\.\/]+(\s*,\s*[a-zA-Z0-9_\-\.\/]+)*\))?:\s.+",
    re.IGNORECASE,
)

# Quy uoc PR vao main: release: vX.Y.Z - <mo ta>
PR_MAIN_REGEX = re.compile(
    r"^(release|RELEASE):\s+v[0-9]+\.[0-9]+\.[0-9]+(\s+-\s+.+|\s*:\s*.+)",
    re.IGNORECASE,
)

# Nhanh phat hanh: moi thay doi phai di qua pull request, theo CS-01.
PROTECTED_BRANCHES = ("main",)

def exceptions_file() -> Path:
    """Duong dan tep ngoai le. Cho phep ghi de de kiem duoc ca hai chieu."""
    override = os.environ.get("POLICY_EXCEPTIONS_FILE")
    if override:
        return Path(override)
    return Path(__file__).resolve().parent.parent / "policy" / "exceptions.json"

LINE = "=" * 70


def log_error(title: str, message: str) -> None:
    """In loi kem cu phap chu thich cua GitHub Actions."""
    escaped_msg = message.replace("\n", "%0A")
    print(f"::error title={title}::{escaped_msg}", file=sys.stderr)


def validate_commit_message(msg: str) -> tuple[bool, str]:
    """Kiem mot chuoi thong diep commit."""
    first_line = msg.strip().splitlines()[0] if msg.strip() else ""
    if not first_line:
        return False, "Tieu de commit khong duoc de trong."
    if COMMIT_REGEX.match(first_line):
        return True, ""
    return False, (
        f"Tieu de commit '{first_line}' vi pham chuan Conventional Commits.\n"
        "Cu phap bat buoc: <loai>(<pham_vi>): <mo ta>\n"
        "Cac loai hop le: feat, fix, sec, ci, docs, refactor, test, chore, style, perf.\n"
        "Vi du: feat(auth): them chuc nang xac thuc token JWT"
    )


def load_exceptions() -> list[dict]:
    """Doc danh sach ngoai le co ho so. Thieu tep thi coi nhu khong co ngoai le."""
    path = exceptions_file()
    if not path.is_file():
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[LOI] Khong doc duoc {path}: {exc}", file=sys.stderr)
        return []
    items = data.get("exceptions", [])
    return items if isinstance(items, list) else []


def find_valid_exception(clause: str, branch: str) -> tuple[dict | None, list[str]]:
    """Tim mot ngoai le con hieu luc cho dieu khoan va nhanh da cho.

    Tra ve ngoai le dau tien hop le, kem danh sach ly do loai bo cac muc khac,
    de nhat ky noi ro vi sao mot ngoai le khong duoc chap nhan.
    """
    today = _dt.date.today()
    rejected: list[str] = []

    for item in load_exceptions():
        ex_id = item.get("id", "khong co id")
        if item.get("clause") != clause or item.get("branch") != branch:
            continue
        for field in ("reason", "approved_by", "expires"):
            if not item.get(field):
                rejected.append(f"{ex_id}: thieu truong bat buoc '{field}'")
                break
        else:
            try:
                expires = _dt.date.fromisoformat(str(item["expires"]))
            except ValueError:
                rejected.append(f"{ex_id}: truong 'expires' khong dung dinh dang YYYY-MM-DD")
                continue
            if expires < today:
                rejected.append(f"{ex_id}: da het han ngay {expires.isoformat()}")
                continue
            return item, rejected

    return None, rejected


def validate_release_branch_push(event_data: dict, ref: str) -> int:
    """CS-01: nhanh phat hanh chi nhan thay doi qua pull request."""
    branch = ref.split("/")[-1]
    if branch not in PROTECTED_BRANCHES:
        return 0

    head = event_data.get("head_commit") or {}
    head_msg = (head.get("message") or "").strip()
    is_merge_of_pr = head_msg.startswith("Merge pull request")
    forced = bool(event_data.get("forced"))

    if is_merge_of_pr and not forced:
        print(f"[DAT] Thay doi vao nhanh '{branch}' den tu mot pull request da hop nhat.")
        return 0

    exception, rejected = find_valid_exception("CS-01", branch)
    for line in rejected:
        print(f"[CANH BAO] Ngoai le bi loai bo, {line}", file=sys.stderr)

    if exception is not None:
        print(
            f"[DAT, CO NGOAI LE] Day truc tiep vao nhanh '{branch}' duoc mien theo "
            f"ngoai le {exception['id']}, het han {exception['expires']}, "
            f"nguoi phe duyet {exception['approved_by']}."
        )
        print(f"         Ly do: {exception['reason']}")
        return 0

    err_msg = (
        f"Day truc tiep vao nhanh phat hanh '{branch}' vi pham dieu khoan CS-01.\n"
        "Moi thay doi vao nhanh phat hanh phai di qua pull request co nguoi phe duyet.\n"
        "Neu day la truong hop bat buoc, phai ghi mot ngoai le co thoi han trong "
        "policy/exceptions.json voi du nam truong: clause, branch, reason, approved_by, expires."
    )
    print("\n" + LINE, file=sys.stderr)
    print("[LOI] VI PHAM CHINH SACH DUA MA VAO NHANH PHAT HANH", file=sys.stderr)
    print(LINE, file=sys.stderr)
    print(err_msg, file=sys.stderr)
    if forced:
        print("Lan day nay con la day cuong buc, lam mat lich su cu.", file=sys.stderr)
    print(LINE + "\n", file=sys.stderr)
    log_error("Vi pham CS-01, day truc tiep vao nhanh phat hanh", err_msg)
    return 1


def validate_push_event(event_data: dict) -> int:
    """Kiem toan bo commit trong su kien push, va quy uoc nhanh phat hanh."""
    commits = event_data.get("commits", [])
    ref = event_data.get("ref", "")
    print(f"[Policy Guard] Kiem cac commit duoc day len ref: {ref}")

    rc = validate_release_branch_push(event_data, ref)

    if not commits:
        print("[THONG TIN] Khong co commit moi trong payload. Bo qua phan kiem ten commit.")
        return rc

    failed_commits = []
    for c in commits:
        c_id = c.get("id", "")[:7]
        c_msg = c.get("message", "")
        valid, reason = validate_commit_message(c_msg)
        if not valid:
            failed_commits.append((c_id, c_msg.splitlines()[0], reason))

    if failed_commits:
        print("\n" + LINE, file=sys.stderr)
        print("[LOI] VI PHAM QUY UOC DAT TEN COMMIT", file=sys.stderr)
        print(LINE, file=sys.stderr)
        for c_id, first_line, reason in failed_commits:
            print(f"\n- Commit [{c_id}]: \"{first_line}\"", file=sys.stderr)
            print(f"  Ly do: {reason}", file=sys.stderr)
            log_error(
                "Sai dinh dang tieu de commit",
                f"Commit [{c_id}] '{first_line}' khong dung dinh dang. "
                "Cu phap: <loai>(<pham_vi>): <mo ta>",
            )
        print("\n" + "-" * 70, file=sys.stderr)
        print("CACH KHAC PHUC:", file=sys.stderr)
        print("1. Neu commit vi pham la commit gan nhat:", file=sys.stderr)
        print("   git commit --amend -m \"feat(<pham_vi>): <mo ta lai cho dung>\"", file=sys.stderr)
        print("2. Neu co nhieu commit vi pham:", file=sys.stderr)
        print("   git rebase -i HEAD~<so_luong_commit>, doi 'pick' thanh 'reword'.", file=sys.stderr)
        print(LINE + "\n", file=sys.stderr)
        return 1

    print(f"[DAT] Toan bo {len(commits)} commit tuan thu quy uoc Conventional Commits.")
    return rc


def validate_pull_request_event(event_data: dict) -> int:
    """Kiem chinh sach luong nhanh va tieu de pull request."""
    pr = event_data.get("pull_request", {})
    if not pr:
        print("[THONG TIN] Khong tim thay du lieu pull request.")
        return 0

    base_branch = pr.get("base", {}).get("ref", "")
    head_branch = pr.get("head", {}).get("ref", "")
    pr_title = pr.get("title", "").strip()

    print(f"[Policy Guard] Kiem pull request: [{head_branch}] -> [{base_branch}]")
    print(f"               Tieu de: \"{pr_title}\"")

    # 1. Luong nhanh vao main
    if base_branch == "main" and head_branch != "dev":
        err_msg = (
            "Chi cho phep mo pull request vao nhanh 'main' xuat phat tu nhanh 'dev'.\n"
            f"Khong mo pull request truc tiep tu nhanh '{head_branch}' len 'main'."
        )
        print("\n" + LINE, file=sys.stderr)
        print("[LOI] VI PHAM CHINH SACH LUONG NHANH", file=sys.stderr)
        print(LINE, file=sys.stderr)
        print(err_msg, file=sys.stderr)
        print(LINE + "\n", file=sys.stderr)
        log_error("Vi pham luong phan nhanh", err_msg)
        return 1

    # 2. Dinh dang tieu de PR vao dev
    if base_branch == "dev":
        if not PR_DEV_REGEX.match(pr_title):
            err_msg = (
                f"Tieu de PR \"{pr_title}\" khong dung quy uoc dong gop vao nhanh 'dev'.\n"
                "Cu phap bat buoc: [<ma_nhanh>] <loai>(<pham_vi>): <mo ta>\n"
                "Ma nhanh hop le: [namng], [haind], [manhdx], [anhld], [mainp]"
            )
            print("\n" + LINE, file=sys.stderr)
            print("[LOI] SAI QUY UOC DAT TEN PULL REQUEST VAO NHANH DEV", file=sys.stderr)
            print(LINE, file=sys.stderr)
            print(err_msg, file=sys.stderr)
            print(LINE + "\n", file=sys.stderr)
            log_error("Sai quy uoc dat ten PR vao dev", err_msg)
            return 1
        print("[DAT] Tieu de pull request vao nhanh 'dev' dung quy uoc.")

    # 3. Dinh dang tieu de PR vao main
    if base_branch == "main":
        if not PR_MAIN_REGEX.match(pr_title):
            err_msg = (
                f"Tieu de PR \"{pr_title}\" khong dung chuan phat hanh SemVer vao nhanh 'main'.\n"
                "Cu phap bat buoc: release: v<Major>.<Minor>.<Patch> - <mo ta phien ban>"
            )
            print("\n" + LINE, file=sys.stderr)
            print("[LOI] SAI QUY UOC DAT TEN PULL REQUEST PHAT HANH VAO NHANH MAIN", file=sys.stderr)
            print(LINE, file=sys.stderr)
            print(err_msg, file=sys.stderr)
            print(LINE + "\n", file=sys.stderr)
            log_error("Sai quy uoc dat ten PR vao main", err_msg)
            return 1
        print("[DAT] Tieu de pull request vao nhanh 'main' dung chuan phat hanh SemVer.")

    return 0


def main() -> int:
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    event_name = os.environ.get("GITHUB_EVENT_NAME", "")

    if not event_path or not Path(event_path).is_file():
        # Che do chay thu cuc bo qua dong lenh
        if len(sys.argv) > 1:
            test_msg = " ".join(sys.argv[1:])
            valid, reason = validate_commit_message(test_msg)
            if valid:
                print(f"[DAT] Hop le: \"{test_msg}\"")
                return 0
            print(f"[LOI] Khong hop le: {reason}", file=sys.stderr)
            return 1
        print("[THONG TIN] Khong co GITHUB_EVENT_PATH. Bo qua kiem tra o che do nay.")
        return 0

    try:
        with open(event_path, "r", encoding="utf-8") as f:
            event_data = json.load(f)
    except Exception as exc:
        print(f"[LOI] Khong doc duoc GITHUB_EVENT_PATH: {exc}", file=sys.stderr)
        return 1

    if event_name == "push":
        return validate_push_event(event_data)
    if event_name == "pull_request":
        return validate_pull_request_event(event_data)

    print(f"[THONG TIN] Su kien '{event_name}' khong thuoc dien kiem policy.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
