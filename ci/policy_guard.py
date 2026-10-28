"""Policy Guard: Kiểm tra quy chuẩn phân nhánh, tiêu đề Commit và tiêu đề Pull Request.

Sử dụng thư viện chuẩn của Python, chạy cả trên GitHub Actions lẫn Local Hook.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import sys

# Đảm bảo mã hóa UTF-8 trên mọi nền tảng (Windows console / Linux runner)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

# Quy ước Commit: Conventional Commits
# Cú pháp: <type>(<scope>): <mô tả> hoặc <type>: <mô tả>
# Cho phép merge commit mặc định của Git: Merge branch... hoặc Merge pull request...
COMMIT_REGEX = re.compile(
    r"^(Merge\s.+|Revert\s.+|(release|RELEASE):\s+v[0-9]+\.[0-9]+\.[0-9]+.*|(feat|fix|sec|ci|docs|refactor|test|chore|style|perf|revert|release)(\([a-zA-Z0-9_\-\.\/]+\))?:\s.+)",
    re.IGNORECASE,
)

# Quy ước PR vào dev: [<mã_nhánh>] <type>(<scope>): <mô tả>
PR_DEV_REGEX = re.compile(
    r"^\[(namng|haind|manhdx|anhld|mainp)\]\s+(feat|fix|sec|ci|docs|refactor|test|chore|style|perf|revert)(\([a-zA-Z0-9_\-\.\/]+\))?:\s.+",
    re.IGNORECASE,
)

# Quy ước PR vào main: release: vX.Y.Z - <mô tả>
PR_MAIN_REGEX = re.compile(
    r"^(release|RELEASE):\s+v[0-9]+\.[0-9]+\.[0-9]+(\s+-\s+.+|\s*:\s*.+)",
    re.IGNORECASE,
)


def log_error(title: str, message: str) -> None:
    """In lỗi ra stdout/stderr kèm cú pháp chú thích GitHub Actions."""
    escaped_msg = message.replace("\n", "%0A")
    print(f"::error title={title}::{escaped_msg}", file=sys.stderr)


def validate_commit_message(msg: str) -> tuple[bool, str]:
    """Kiểm tra 1 chuỗi commit message."""
    first_line = msg.strip().splitlines()[0] if msg.strip() else ""
    if not first_line:
        return False, "Tiêu đề commit không được để trống."
    if COMMIT_REGEX.match(first_line):
        return True, ""
    return False, (
        f"Tiêu đề commit '{first_line}' vi phạm chuẩn Conventional Commits.\n"
        "Cú pháp bắt buộc: <loại>(<phạm_vi>): <mô tả>\n"
        "Các loại (types) hợp lệ: feat, fix, sec, ci, docs, refactor, test, chore, style, perf.\n"
        "Ví dụ chuẩn: feat(auth): thêm chức năng xác thực token JWT\n"
        "             fix(db): khắc phục timeout khi truy vấn mariadb\n"
        "             ci(docker): bổ sung cổng smoke test kiểm tra healthcheck"
    )


def validate_push_event(event_data: dict) -> int:
    """Kiểm tra tất cả commit trong sự kiện push."""
    commits = event_data.get("commits", [])
    ref = event_data.get("ref", "")
    print(f"🔍 [Policy Guard] Kiểm tra các commit được push lên ref: {ref}")

    if not commits:
        print("ℹ️ Không tìm thấy commit mới trong payload webhook. Bỏ qua kiểm tra.")
        return 0

    failed_commits = []
    for c in commits:
        c_id = c.get("id", "")[:7]
        c_msg = c.get("message", "")
        valid, reason = validate_commit_message(c_msg)
        if not valid:
            failed_commits.append((c_id, c_msg.splitlines()[0], reason))

    if failed_commits:
        print("\n" + "=" * 70, file=sys.stderr)
        print("❌ LỖI VI PHẠM CHÍNH SÁCH ĐẶT TÊN COMMIT (CONVENTIONAL COMMITS)", file=sys.stderr)
        print("=" * 70, file=sys.stderr)
        for c_id, first_line, reason in failed_commits:
            print(f"\n🚫 Commit [{c_id}]: \"{first_line}\"", file=sys.stderr)
            print(f"👉 Lý do: {reason}", file=sys.stderr)
            log_error(
                "Sai định dạng tiêu đề Commit",
                f"Commit [{c_id}] '{first_line}' không đúng định dạng. Cú pháp: <loại>(<phạm_vi>): <mô tả>",
            )

        print("\n" + "-" * 70, file=sys.stderr)
        print("🛠️ HƯỚNG DẪN KHẮC PHỤC NHANH TRÊN MÁY CỦA BẠN:", file=sys.stderr)
        print("1. Nếu commit vi phạm là commit gần nhất:", file=sys.stderr)
        print("   git commit --amend -m \"feat(<phạm_vi>): <mô tả lại cho đúng>\"", file=sys.stderr)
        print("   git push --force origin <tên_nhánh_của_bạn>", file=sys.stderr)
        print("2. Nếu có nhiều commit vi phạm:", file=sys.stderr)
        print("   git rebase -i HEAD~<số_lượng_commit>", file=sys.stderr)
        print("   Đổi chữ 'pick' thành 'reword' ở các commit sai, sửa lại tên rồi push --force.", file=sys.stderr)
        print("=" * 70 + "\n", file=sys.stderr)
        return 1

    print(f"✅ Toàn bộ {len(commits)} commit đều tuân thủ chính xác quy chuẩn Conventional Commits!")
    return 0


def validate_pull_request_event(event_data: dict) -> int:
    """Kiểm tra chính sách phân nhánh và tiêu đề Pull Request."""
    pr = event_data.get("pull_request", {})
    if not pr:
        print("ℹ️ Không tìm thấy dữ liệu Pull Request.")
        return 0

    base_branch = pr.get("base", {}).get("ref", "")
    head_branch = pr.get("head", {}).get("ref", "")
    pr_title = pr.get("title", "").strip()

    print(f"🔍 [Policy Guard] Kiểm tra Pull Request: [{head_branch}] ➔ [{base_branch}]")
    print(f"🏷️ Tiêu đề PR: \"{pr_title}\"")

    # 1. Kiểm tra luồng nhánh đối với nhánh main
    if base_branch == "main" and head_branch != "dev":
        err_msg = (
            f"Chỉ cho phép tạo Pull Request vào nhánh 'main' xuất phát từ nhánh 'dev'.\n"
            f"Nghiêm cấm tạo PR trực tiếp từ nhánh phát triển '{head_branch}' lên 'main'!"
        )
        print("\n" + "=" * 70, file=sys.stderr)
        print("⛔ VI PHẠM CHÍNH SÁCH BẢO VỆ NHÁNH MAIN", file=sys.stderr)
        print("=" * 70, file=sys.stderr)
        print(err_msg, file=sys.stderr)
        print("-" * 70, file=sys.stderr)
        print("🛠️ HƯỚNG DẪN: Hãy đóng PR này và mở PR mới hướng vào nhánh 'dev' trước.", file=sys.stderr)
        print("=" * 70 + "\n", file=sys.stderr)
        log_error("Vi phạm luồng phân nhánh", err_msg)
        return 1

    # 2. Kiểm tra định dạng tiêu đề PR vào dev
    if base_branch == "dev":
        if not PR_DEV_REGEX.match(pr_title):
            err_msg = (
                f"Tiêu đề PR \"{pr_title}\" không đúng quy ước đóng góp vào nhánh 'dev'.\n"
                "Cú pháp bắt buộc: [<mã_nhánh>] <loại>(<phạm_vi>): <mô tả>\n"
                "Các mã nhánh hợp lệ: [namng], [haind], [manhdx], [anhld], [mainp]\n"
                "Các loại hợp lệ: feat, fix, sec, ci, docs, refactor, test, chore\n"
                "Ví dụ chuẩn: [namng] feat(db): bổ sung endpoint healthcheck phục vụ preview"
            )
            print("\n" + "=" * 70, file=sys.stderr)
            print("❌ SAI QUY ƯỚC ĐẶT TÊN PULL REQUEST VÀO NHÁNH DEV", file=sys.stderr)
            print("=" * 70, file=sys.stderr)
            print(err_msg, file=sys.stderr)
            print("-" * 70, file=sys.stderr)
            print("🛠️ CÁCH SỬA NHANH TRÊN GIAO DIỆN GITHUB:", file=sys.stderr)
            print("1. Tại trang Pull Request này trên GitHub, bấm nút 'Edit' ở cạnh tiêu đề.", file=sys.stderr)
            print("2. Đổi lại tiêu đề theo đúng mẫu: [tên_nhánh] loại(phạm_vi): mô tả", file=sys.stderr)
            print("3. Nhấn 'Save'. Pipeline sẽ tự động kiểm tra lại và bật xanh!", file=sys.stderr)
            print("=" * 70 + "\n", file=sys.stderr)
            log_error("Sai quy ước đặt tên PR vào dev", err_msg)
            return 1
        print("✅ Tiêu đề PR vào nhánh 'dev' hoàn toàn chuẩn xác!")

    # 3. Kiểm tra định dạng tiêu đề PR vào main
    if base_branch == "main":
        if not PR_MAIN_REGEX.match(pr_title):
            err_msg = (
                f"Tiêu đề PR \"{pr_title}\" không đúng chuẩn Release SemVer vào nhánh 'main'.\n"
                "Cú pháp bắt buộc: release: v<Major>.<Minor>.<Patch> - <Mô tả phiên bản>\n"
                "Ví dụ chuẩn: release: v1.0.0 - Triển khai cổng thông tin InlaneWeb lên Production"
            )
            print("\n" + "=" * 70, file=sys.stderr)
            print("❌ SAI QUY ƯỚC ĐẶT TÊN PULL REQUEST RELEASE VÀO NHÁNH MAIN", file=sys.stderr)
            print("=" * 70, file=sys.stderr)
            print(err_msg, file=sys.stderr)
            print("-" * 70, file=sys.stderr)
            print("🛠️ CÁCH SỬA NHANH TRÊN GIAO DIỆN GITHUB:", file=sys.stderr)
            print("1. Bấm nút 'Edit' cạnh tiêu đề PR trên GitHub.", file=sys.stderr)
            print("2. Đổi tiêu đề thành: release: vX.Y.Z - <Mô tả phiên bản phát hành>", file=sys.stderr)
            print("3. Bấm 'Save' để kích hoạt lại kiểm tra.", file=sys.stderr)
            print("=" * 70 + "\n", file=sys.stderr)
            log_error("Sai quy ước đặt tên PR vào main", err_msg)
            return 1
        print("✅ Tiêu đề PR vào nhánh 'main' đúng chuẩn phát hành SemVer!")

    return 0


def main() -> int:
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    event_name = os.environ.get("GITHUB_EVENT_NAME", "")

    if not event_path or not Path(event_path).is_file():
        # Chế độ chạy thử nghiệm CLI cục bộ
        if len(sys.argv) > 1:
            test_msg = " ".join(sys.argv[1:])
            valid, reason = validate_commit_message(test_msg)
            if valid:
                print(f"✅ Hợp lệ: \"{test_msg}\"")
                return 0
            print(f"❌ Không hợp lệ: {reason}", file=sys.stderr)
            return 1
        print("ℹ️ Chạy ở môi trường local hoặc không có GITHUB_EVENT_PATH. Bỏ qua kiểm tra.")
        return 0

    try:
        with open(event_path, "r", encoding="utf-8") as f:
            event_data = json.load(f)
    except Exception as e:
        print(f"❌ Không thể đọc GITHUB_EVENT_PATH: {e}", file=sys.stderr)
        return 1

    if event_name == "push":
        return validate_push_event(event_data)
    elif event_name == "pull_request":
        return validate_pull_request_event(event_data)
    else:
        print(f"ℹ️ Sự kiện '{event_name}' không thuộc diện cần kiểm tra policy.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
