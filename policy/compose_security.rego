package compose

import rego.v1

# =============================================================================
# Chinh sach Docker Compose (thoi diem trien khai).
#
# Can cu: Policy_as_code_Lab ConfTest.docx muc 1 ghi ro diem thi hanh dung cho
# least privilege va firewall la "Kubernetes securityContext ... compose ports:".
# InlaneWeb trien khai bang Compose chu khong bang Kubernetes, nen cac luat cua
# k8s_security.rego (A.3) duoc chuyen sang truong tuong duong cua Compose.
#
# Chay: conftest test <file> -p policy/ --namespace compose
# Thieu --namespace thi Conftest bao "0 tests" va tra ma thoat 0 (xem evidence/05).
# =============================================================================

# ---- ham phu ----------------------------------------------------------------
svcs[name] := svc if {
	some name, svc in input.services
	is_object(svc)
}

# `environment` cua Compose co HAI dang hop le. Luat chi xu ly mot dang se bo
# sot dang con lai ma van bao "pass". Day la luat mo rong cua nhom.
split_kv(e) := [k, v] if {
	idx := indexof(e, "=")
	idx > 0
	k := substring(e, 0, idx)
	v := substring(e, idx + 1, -1)
}

env_pairs(svc) := {split_kv(e) | some e in svc.environment} if is_array(svc.environment)

env_pairs(svc) := {[k, sprintf("%v", [v])] | some k, v in svc.environment} if is_object(svc.environment)

# Khop theo BIEN TU, khong khop chuoi con. Ban dau luat viet
# `(?i)(password|passwd|secret|token|...)` va da BO SOT khoa `DB_PASS` trong
# docker-compose.yml:56 va prod.yml:50. Bien tu cung tranh bao sai tren cac khoa
# nhu BYPASS_CACHE hay PASSTHROUGH_MODE.
secret_key := `(?i)(^|[_-])(pass|pwd|password|passwd|secret|token|key|credential|credentials)([_-]|$)`

# Tai khoan CSDL dac quyen cung la mot su kien o lop cau hinh, kiem duoc.
db_user_key := `(?i)(^|[_-])(db_?user|mysql_?user|postgres_?user|database_?user)([_-]|$)`

privileged_db_users := {"root", "admin", "sa", "postgres", "mysql"}

# Gia tri lay tu bien moi truong thi khong phai bi mat gan cung.
injected(v) if startswith(v, "${")

injected(v) if startswith(v, "$")

# ---- cong da cong bo --------------------------------------------------------
port_parts(p) := split(sprintf("%v", [p]), ":")

host_ip(p) := parts[0] if {
	parts := port_parts(p)
	count(parts) == 3
}

host_ip(p) := "0.0.0.0" if {
	parts := port_parts(p)
	count(parts) == 2
}

host_port(p) := parts[count(parts) - 2] if {
	parts := port_parts(p)
	count(parts) >= 2
}

loopback := {"127.0.0.1", "localhost", "::1"}

forbidden_ports := {"22", "23", "2375", "2376", "3306", "5432", "6379", "27017"}

# ---- 1. LEAST PRIVILEGE ----------------------------------------------------
deny contains msg if {
	some name, svc in svcs
	svc.privileged == true
	msg := sprintf("LEAST-PRIVILEGE: service '%s' runs privileged.", [name])
}

deny contains msg if {
	some name, svc in svcs
	split(sprintf("%v", [svc.user]), ":")[0] in {"root", "0"}
	msg := sprintf("LEAST-PRIVILEGE: service '%s' runs as root (user: %v).", [name, svc.user])
}

has_cap_drop_all(svc) if {
	some c in svc.cap_drop
	upper(sprintf("%v", [c])) == "ALL"
}

deny contains msg if {
	some name, svc in svcs
	not has_cap_drop_all(svc)
	msg := sprintf("LEAST-PRIVILEGE: service '%s' must drop ALL capabilities (cap_drop: [ALL]).", [name])
}

has_no_new_privileges(svc) if {
	some o in svc.security_opt
	lower(sprintf("%v", [o])) == "no-new-privileges:true"
}

deny contains msg if {
	some name, svc in svcs
	not has_no_new_privileges(svc)
	msg := sprintf("LEAST-PRIVILEGE: service '%s' must set security_opt: [\"no-new-privileges:true\"].", [name])
}

warn contains msg if {
	some name, svc in svcs
	not svc.read_only == true
	msg := sprintf("LEAST-PRIVILEGE: service '%s' should set read_only: true and mount tmpfs for writable paths.", [name])
}

# ---- 2. ATTACK SURFACE -----------------------------------------------------
# Luat mo rong cua nhom: lab chi nham cong 5432. Dieu kien dung la MOI cong da
# cong bo phai buoc vao loopback, vi dich phia sau la reverse proxy.
deny contains msg if {
	some name, svc in svcs
	some p in svc.ports
	ip := host_ip(p)
	not ip in loopback
	msg := sprintf("ATTACK-SURFACE: service '%s' publishes '%v' on %s instead of 127.0.0.1.", [name, p, ip])
}

deny contains msg if {
	some name, svc in svcs
	some p in svc.ports
	host_port(p) in forbidden_ports
	msg := sprintf("ATTACK-SURFACE: service '%s' publishes administrative/database port %s.", [name, host_port(p)])
}

# ---- 3. CREDENTIALS (PCI DSS 8.6.2, GDPR Art. 32) --------------------------
# Luat mo rong cua nhom: xu ly ca `environment` dang tu dien va dang danh sach.
deny contains msg if {
	some name, svc in svcs
	some pair in env_pairs(svc)
	regex.match(secret_key, pair[0])
	not injected(pair[1])
	msg := sprintf("CREDENTIALS: service '%s' hard-codes secret '%s' in environment; inject it at deploy time.", [name, pair[0]])
}

deny contains msg if {
	some name, svc in svcs
	some pair in env_pairs(svc)
	regex.match(db_user_key, pair[0])
	lower(pair[1]) in privileged_db_users
	msg := sprintf("LEAST-PRIVILEGE: service '%s' connects to the database as privileged account '%s'; use a least-privilege account.", [name, pair[1]])
}

# ---- 4. SUPPLY CHAIN -------------------------------------------------------
# Luat mo rong cua nhom: bat ca dang noi suy `${VAR:-anh:latest}`, dang ma mot
# phep kiem `endswith(image, ":latest")` se bo sot vi chuoi ket thuc bang '}'.
deny contains msg if {
	some name, svc in svcs
	regex.match(`:latest($|\})`, sprintf("%v", [svc.image]))
	msg := sprintf("SUPPLY-CHAIN: service '%s' uses image '%v' pinned to :latest.", [name, svc.image])
}

# ---- 5. ISOLATION ----------------------------------------------------------
deny contains msg if {
	some name, svc in svcs
	some v in svc.volumes
	contains(sprintf("%v", [v]), "/var/run/docker.sock")
	not endswith(sprintf("%v", [v]), ":ro")
	msg := sprintf("ISOLATION: service '%s' mounts the Docker socket writable; that is equivalent to host root.", [name])
}

warn contains msg if {
	some name, svc in svcs
	some v in svc.volumes
	contains(sprintf("%v", [v]), "/var/run/docker.sock")
	endswith(sprintf("%v", [v]), ":ro")
	msg := sprintf("ISOLATION: service '%s' mounts the Docker socket read-only; confirm this is required.", [name])
}

# ---- 6. OBSERVABILITY ------------------------------------------------------
warn contains msg if {
	some name, svc in svcs
	not svc.healthcheck
	msg := sprintf("OBSERVABILITY: service '%s' has no healthcheck.", [name])
}
