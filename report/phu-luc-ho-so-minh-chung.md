# Phụ lục: hồ sơ minh chứng

Tệp này tách khỏi bản nộp để báo cáo giữ trong giới hạn 30 trang. Mọi số liệu
trong báo cáo đều dẫn thẳng tới đường dẫn hoặc mã run tương ứng tại chỗ, nên
danh mục dưới đây là bản tra cứu gộp, không phải nguồn duy nhất.

Số liệu báo cáo trích từ các nguồn dưới đây. Quy chuẩn minh chứng hình ảnh lưu tại `docs/` trong kho mã, ngoài phạm vi báo cáo.

*Bảng: Danh mục minh chứng*

| TT | Minh chứng | Vị trí |
| :---: | :--- | :--- |
| 1 | Chính sách CS-01 đến CS-08, hồ sơ ngoại lệ và cổng kiểm thời hạn | `policy/00-chinh-sach-attt.md`, `policy/exceptions.json`, `ci/check_exceptions.py` |
| 2 | Pipeline năm stage có chặn, và vòng lặp vận hành theo dõi CVE | `.github/workflows/devsecops-gate.yml`, `auto-remediate.yml`, `ci/cve_watch.py` |
| 3 | Policy as Code: quy ước commit, cổng CS-01, chính sách khai báo và bộ test của nó | `ci/policy_guard.py`, `tests/test_policy_guard.py`, `policy/*.rego`, `policy/*_test.rego` |
| 4 | Security as Code: tiêu chí quality gate và quy tắc tự viết | `ci/sonarqube-quality-gate.json`, `ci/semgrep-policy-php.yml`, `ci/semgrep-local-rules.yml` |
| 5 | TDS, Compliance as Code và cặp fixture đạt chuẩn với vi phạm | `tests/security/run.sh`, `compliance/`, `fixtures/` |
| 6 | Trạng thái bảo vệ nhánh qua API, ba kịch bản cổng CS-01, và miễn trừ CVE có thời hạn | `evidence/api/`, `evidence/20-policy-guard-cs01.txt`, `.trivyignore.yaml` |
| 7 | Kết quả quét của hai nhánh | artifact `evidence-security-as-code` của run `40748974196` và `40748974200` |
| 8 | Cổng không chặn, rồi chặn đúng chức năng | artifact `evidence-policy-as-code` của run `40748974196` và `41810794218` |
| 9 | Stage CD: phát hành, xác minh, quay lui | `evidence/36-cd-phat-hanh-xac-minh-quay-lui.txt`, artifact `evidence-cd-release` của run `41817338284` |
| 10 | Danh sách khiếm khuyết đã vá, cổng phát hiện và chủ sở hữu | `patches/README.md` |

Kết quả quét tái lập từ artifact `evidence-security-as-code` của run qua `sonarqube/report.html`, kèm dạng máy đọc `sonarqube/metrics.json`, `sonarqube/quality-gate.json`, `sonarqube/issues.json`, `ci-05-semgrep.json`. Phép kiểm hai chiều cổng chính sách tái lập từ `evidence-policy-as-code`, đối chiếu `ci-01-dockerfile.txt`, `ci-02-compose.txt`, `ci-03-branch-protection.txt` với trạng thái bước trên trang run.
