package dockerfile

import rego.v1

# =============================================================================
# Unit test cho chinh bo luat. Chay: conftest verify -p policy/
# Nguon: Policy_as_code_Lab ConfTest.docx, Appendix A.2 (9 test).
# Ly do ton tai: tai lieu ly thuyet cua mon hoc ghi "Configuration is as
# dangerous as source code ... requires the same level of syntax checking and
# automated testing as the application code itself".
# =============================================================================

good := [
	{"Cmd": "from", "Stage": 0, "Value": ["node:22-alpine@sha256:abc"]},
	{"Cmd": "label", "Stage": 0, "Value": ["org.opencontainers.image.source", "\"https://x\"", "=", "org.opencontainers.image.revision", "\"abc\"", "="]},
	{"Cmd": "user", "Stage": 0, "Value": ["10001:10001"]},
	{"Cmd": "expose", "Stage": 0, "Value": ["3000/tcp"]},
	{"Cmd": "healthcheck", "Stage": 0, "Value": ["CMD", "true"]},
]

test_good_has_no_denies if {
	count(deny) == 0 with input as good
}

test_user_root_colon_root_denied if {
	bad := array.concat(array.slice(good, 0, 2), array.concat([{"Cmd": "user", "Stage": 0, "Value": ["root:root"]}], array.slice(good, 3, 5)))
	some msg in deny with input as bad
	contains(msg, "runs as 'root'")
}

test_user_0_0_denied if {
	bad := array.concat(array.slice(good, 0, 2), array.concat([{"Cmd": "user", "Stage": 0, "Value": ["0:0"]}], array.slice(good, 3, 5)))
	some msg in deny with input as bad
	contains(msg, "runs as '0'")
}

test_expose_range_denied if {
	bad := array.concat(array.slice(good, 0, 3), array.concat([{"Cmd": "expose", "Stage": 0, "Value": ["20-25"]}], [good[4]]))
	some msg in deny with input as bad
	contains(msg, "port 22")
}

test_expose_proto_denied if {
	bad := array.concat(array.slice(good, 0, 3), array.concat([{"Cmd": "expose", "Stage": 0, "Value": ["22/tcp"]}], [good[4]]))
	some msg in deny with input as bad
	contains(msg, "port 22")
}

test_multistage_root_final_denied if {
	bad := array.concat(
		[{"Cmd": "user", "Stage": 0, "Value": ["builder"]}],
		[{"Cmd": "from", "Stage": 1, "Value": ["alpine:3.20@sha256:abc"]}],
	)
	some msg in deny with input as bad
	contains(msg, "no USER")
}

test_healthcheck_none_denied if {
	bad := array.concat(array.slice(good, 0, 4), [{"Cmd": "healthcheck", "Stage": 0, "Value": ["NONE"]}])
	some msg in deny with input as bad
	contains(msg, "HEALTHCHECK NONE")
}

test_missing_provenance_label_denied if {
	bad := array.concat([good[0]], array.slice(good, 2, 5))
	some msg in deny with input as bad
	contains(msg, "org.opencontainers.image.source")
}

test_latest_denied if {
	bad := array.concat([{"Cmd": "from", "Stage": 0, "Value": ["node:latest"]}], array.slice(good, 1, 5))
	some msg in deny with input as bad
	contains(msg, ":latest")
}
