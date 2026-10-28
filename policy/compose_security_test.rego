package compose

import rego.v1

# =============================================================================
# Unit test cho chinh sach compose. Chay: conftest verify -p policy/
# Trong tam la ba luat mo rong cua nhom:
#   1. `environment` dang tu dien VA dang danh sach
#   2. `:latest` o dang noi suy ${VAR:-anh:latest}
#   3. moi cong da cong bo phai buoc vao loopback
# =============================================================================

base := {
	"image": "php:8.2-apache",
	"user": "www-data",
	"ports": ["127.0.0.1:8088:80"],
	"environment": {"DB_PASS": "${DB_PASS}"},
	"volumes": ["./src:/var/www/html:ro"],
	"cap_drop": ["ALL"],
	"security_opt": ["no-new-privileges:true"],
	"read_only": true,
	"healthcheck": {"test": ["CMD", "true"]},
}

good := {"services": {"app": base}}

patched(p) := {"services": {"app": object.union(base, p)}}

stripped(keys) := {"services": {"app": object.remove(base, keys)}}

# ---- moc: cau hinh dat thi im lang hoan toan -------------------------------
test_good_no_denies if {
	count(deny) == 0 with input as good
}

test_good_no_warns if {
	count(warn) == 0 with input as good
}

# ---- luat mo rong 1: environment hai dang ----------------------------------
test_secret_dict_form_denied if {
	some msg in deny with input as patched({"environment": {"MYSQL_ROOT_PASSWORD": "password"}})
	contains(msg, "CREDENTIALS")
	contains(msg, "MYSQL_ROOT_PASSWORD")
}

test_secret_list_form_denied if {
	some msg in deny with input as patched({"environment": ["GF_SECURITY_ADMIN_PASSWORD=abc123"]})
	contains(msg, "CREDENTIALS")
	contains(msg, "GF_SECURITY_ADMIN_PASSWORD")
}

test_secret_value_with_equals_sign_denied if {
	some msg in deny with input as patched({"environment": ["API_KEY=aa=bb=cc"]})
	contains(msg, "API_KEY")
}

test_secret_injected_is_allowed if {
	count([m | some m in deny with input as patched({"environment": {"DB_PASSWORD": "${DB_PASSWORD}"}}); contains(m, "CREDENTIALS")]) == 0
}

test_secret_db_pass_denied if {
	some msg in deny with input as patched({"environment": {"DB_PASS": "password"}})
	contains(msg, "CREDENTIALS")
	contains(msg, "DB_PASS")
}

test_secret_key_word_boundary_no_false_positive if {
	count([m |
		some m in deny with input as patched({"environment": {"BYPASS_CACHE": "1", "PASSTHROUGH_MODE": "on"}})
		contains(m, "CREDENTIALS")
	]) == 0
}

test_privileged_db_user_denied if {
	some msg in deny with input as patched({"environment": {"DB_USER": "root"}})
	contains(msg, "privileged account 'root'")
}

test_least_privilege_db_user_allowed if {
	count([m |
		some m in deny with input as patched({"environment": {"DB_USER": "ilf_app"}})
		contains(m, "privileged account")
	]) == 0
}

# ---- luat mo rong 2: :latest o dang noi suy ---------------------------------
test_latest_interpolated_denied if {
	some msg in deny with input as patched({"image": "${INLANEWEB_DB_IMAGE:-ghcr.io/x/inlaneweb-db:latest}"})
	contains(msg, "SUPPLY-CHAIN")
}

test_latest_plain_denied if {
	some msg in deny with input as patched({"image": "willfarrell/autoheal:latest"})
	contains(msg, "SUPPLY-CHAIN")
}

test_pinned_image_allowed if {
	count([m | some m in deny with input as patched({"image": "grafana/loki:3.0.0"}); contains(m, "SUPPLY-CHAIN")]) == 0
}

# ---- luat mo rong 3: cong phai buoc vao loopback ----------------------------
test_port_all_interfaces_denied if {
	some msg in deny with input as patched({"ports": ["0.0.0.0:3000:3000"]})
	contains(msg, "instead of 127.0.0.1")
}

test_port_short_form_denied if {
	some msg in deny with input as patched({"ports": ["3100:3100"]})
	contains(msg, "ATTACK-SURFACE")
}

test_port_admin_port_denied if {
	some msg in deny with input as patched({"ports": ["127.0.0.1:3306:3306"]})
	contains(msg, "administrative/database port 3306")
}

# ---- luat chuyen tu k8s_security.rego --------------------------------------
test_user_root_denied if {
	some msg in deny with input as patched({"user": "root"})
	contains(msg, "runs as root")
}

test_privileged_denied if {
	some msg in deny with input as patched({"privileged": true})
	contains(msg, "runs privileged")
}

test_missing_cap_drop_denied if {
	some msg in deny with input as stripped({"cap_drop"})
	contains(msg, "drop ALL capabilities")
}

test_missing_no_new_privileges_denied if {
	some msg in deny with input as stripped({"security_opt"})
	contains(msg, "no-new-privileges")
}

test_docker_sock_writable_denied if {
	some msg in deny with input as patched({"volumes": ["/var/run/docker.sock:/var/run/docker.sock"]})
	contains(msg, "ISOLATION")
	contains(msg, "writable")
}

test_docker_sock_readonly_is_warn_not_deny if {
	count([m | some m in deny with input as patched({"volumes": ["/var/run/docker.sock:/var/run/docker.sock:ro"]}); contains(m, "ISOLATION")]) == 0
	some w in warn with input as patched({"volumes": ["/var/run/docker.sock:/var/run/docker.sock:ro"]})
	contains(w, "read-only")
}

test_missing_healthcheck_warns if {
	some w in warn with input as stripped({"healthcheck"})
	contains(w, "no healthcheck")
}
