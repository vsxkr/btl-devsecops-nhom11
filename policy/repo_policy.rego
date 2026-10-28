package repo

import rego.v1

# =============================================================================
# Chinh sach quan tri kho ma (lop danh tinh va quy trinh).
#
# Can cu: Policy_as_code_Lab ConfTest.docx, bang muc 1. MFA la kiem soat danh
# tinh nen phai kiem tai he thong so huu danh tinh, khong kiem bang LABEL tu khai
# trong Dockerfile. A.5 lam dieu do bang `gh api orgs/<ORG>` roi cho Conftest
# danh gia JSON.
#
# InlaneWeb nam duoi mot tai khoan ca nhan nen khong co thiet lap MFA cap to
# chuc. Kiem soat tuong duong, va la kiem soat ma `ci/policy_guard.py` KHONG
# the thuc thi, la bao ve nhanh phia GitHub.
#
#   curl -H "Authorization: Bearer $GH_TOKEN" \
#     https://api.github.com/repos/<owner>/<repo>/branches/main > branch-main.json
#   conftest test branch-main.json -p policy/ --namespace repo
# =============================================================================

required_check_patterns := {"Policy Guard", "SonarQube", "Semgrep"}

deny contains msg if {
	not input.protected == true
	msg := sprintf("GOVERNANCE: branch '%s' has no protection rule; direct pushes and force pushes are possible regardless of what the in-repo policy script checks.", [input.name])
}

deny contains msg if {
	input.protected == true
	input.protection.required_status_checks.enforcement_level == "off"
	msg := sprintf("GOVERNANCE: branch '%s' is protected but required status checks are off, so a failing pipeline does not block a merge.", [input.name])
}

deny contains msg if {
	input.protected == true
	some pattern in required_check_patterns
	not check_present(pattern)
	msg := sprintf("GOVERNANCE: branch '%s' does not require a status check matching '%s'.", [input.name, pattern])
}

check_present(pattern) if {
	some c in input.protection.required_status_checks.contexts
	contains(c, pattern)
}

check_present(pattern) if {
	some c in input.protection.required_status_checks.checks
	contains(c.context, pattern)
}
