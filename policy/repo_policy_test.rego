package repo

import rego.v1

unprotected := {
	"name": "main",
	"protected": false,
	"protection": {"enabled": false, "required_status_checks": {"enforcement_level": "off", "contexts": [], "checks": []}},
}

protected_no_checks := {
	"name": "main",
	"protected": true,
	"protection": {"enabled": true, "required_status_checks": {"enforcement_level": "off", "contexts": [], "checks": []}},
}

compliant := {
	"name": "main",
	"protected": true,
	"protection": {"enabled": true, "required_status_checks": {
		"enforcement_level": "everyone",
		"contexts": [
			"[STAGE 1] Policy Guard",
			"[STAGE 2: Dev Gate] SonarQube SAST & Quality Gate",
			"[STAGE 2: Dev Gate] Semgrep Security SAST",
		],
		"checks": [],
	}},
}

test_unprotected_branch_denied if {
	some msg in deny with input as unprotected
	contains(msg, "has no protection rule")
}

test_protected_without_required_checks_denied if {
	some msg in deny with input as protected_no_checks
	contains(msg, "required status checks are off")
}

test_compliant_branch_has_no_denies if {
	count(deny) == 0 with input as compliant
}

test_missing_semgrep_check_denied if {
	partial := object.union(compliant, {"protection": {"enabled": true, "required_status_checks": {
		"enforcement_level": "everyone",
		"contexts": ["[STAGE 1] Policy Guard", "[STAGE 2: Dev Gate] SonarQube SAST & Quality Gate"],
		"checks": [],
	}}})
	some msg in deny with input as partial
	contains(msg, "matching 'Semgrep'")
}
