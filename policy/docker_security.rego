package dockerfile

import rego.v1

# =============================================================================
# Chinh sach Dockerfile (thoi diem build).
# Nguon: DevSecOps-DuyPhamHoang/ConfTest Policy As Code/Policy_as_code_Lab
# ConfTest.docx, Appendix A.1. Giu nguyen nhom thong diep LEAST-PRIVILEGE,
# ATTACK-SURFACE, PROVENANCE, OBSERVABILITY, SUPPLY-CHAIN de doi chieu voi lab.
#
# Pham vi: Dockerfile chi chung minh duoc nhung gi di VAO anh. Tuong lua, nhat ky
# runtime va MFA duoc thi hanh o lop khac (compose_security.rego, repo_policy.rego).
# =============================================================================

# ---- ham phu ----------------------------------------------------------------
# Chi stage CUOI di vao anh duoc phat hanh.
final_stage := max([cmd.Stage | some cmd in input])

final_cmds := [cmd | some cmd in input; cmd.Stage == final_stage]

user_cmds := [cmd | some cmd in final_cmds; cmd.Cmd == "user"]

# Nguoi dung hieu luc la lenh USER cuoi cung; bo ":group", ha chu thuong.
effective_user := u if {
	count(user_cmds) > 0
	raw := user_cmds[count(user_cmds) - 1].Value[0]
	u := split(lower(trim_space(raw)), ":")[0]
}

# Gia tri LABEL den theo dang [key, value, "=", key, value, "=", ...]
labels[key] := value if {
	some cmd in final_cmds
	cmd.Cmd == "label"
	some i, key in cmd.Value
	i % 3 == 0
	value := trim(cmd.Value[i + 1], "\"'")
}

# ---- 1. LEAST PRIVILEGE ------------------------------------------------------
deny contains msg if {
	count(user_cmds) == 0
	msg := "LEAST-PRIVILEGE: final stage has no USER instruction (image runs as root unless the base image sets a user)."
}

deny contains msg if {
	effective_user in {"root", "0", "0:0"}
	msg := sprintf("LEAST-PRIVILEGE: final stage runs as '%s'.", [effective_user])
}

# Bien khong danh gia tinh duoc -> danh dau cho nguoi ra soat.
warn contains msg if {
	startswith(effective_user, "$")
	msg := "LEAST-PRIVILEGE: USER is a build-arg/variable and cannot be verified statically."
}

# ---- 2. ATTACK SURFACE -------------------------------------------------------
# EXPOSE chi la tai lieu; chan cong that nam o compose_security.rego.
forbidden_ports := {22, 23, 2375, 2376, 3306, 5432, 6379, 27017}

port_range(token) := [to_number(parts[0]), to_number(parts[count(parts) - 1])] if {
	spec := split(token, "/")[0]
	regex.match(`^[0-9]+(-[0-9]+)?$`, spec)
	parts := split(spec, "-")
}

deny contains msg if {
	some cmd in final_cmds
	cmd.Cmd == "expose"
	some token in cmd.Value
	range := port_range(token)
	some port in forbidden_ports
	port >= range[0]
	port <= range[1]
	msg := sprintf("ATTACK-SURFACE: EXPOSE '%s' covers administrative/database port %d.", [token, port])
}

warn contains msg if {
	some cmd in final_cmds
	cmd.Cmd == "expose"
	some token in cmd.Value
	not port_range(token)
	msg := sprintf("ATTACK-SURFACE: EXPOSE '%s' is not a literal port; cannot verify.", [token])
}

# ---- 3. PROVENANCE -----------------------------------------------------------
required_labels := {
	"org.opencontainers.image.source",
	"org.opencontainers.image.revision",
}

deny contains msg if {
	some name in required_labels
	not labels[name]
	msg := sprintf("PROVENANCE: required OCI label '%s' is missing.", [name])
}

# ---- 4. OBSERVABILITY --------------------------------------------------------
deny contains msg if {
	count([c | some c in final_cmds; c.Cmd == "healthcheck"]) == 0
	msg := "OBSERVABILITY: no HEALTHCHECK in final stage."
}

deny contains msg if {
	some cmd in final_cmds
	cmd.Cmd == "healthcheck"
	upper(cmd.Value[0]) == "NONE"
	msg := "OBSERVABILITY: HEALTHCHECK NONE disables health reporting."
}

# ---- 5. SUPPLY CHAIN --------------------------------------------------------
deny contains msg if {
	some cmd in input
	cmd.Cmd == "from"
	image := cmd.Value[0]
	image != "scratch"
	not contains(image, "@sha256:")
	endswith(image, ":latest")
	msg := sprintf("SUPPLY-CHAIN: base image '%s' uses :latest.", [image])
}

warn contains msg if {
	some cmd in input
	cmd.Cmd == "from"
	image := cmd.Value[0]
	image != "scratch"
	not contains(image, "@sha256:")
	not endswith(image, ":latest")
	msg := sprintf("SUPPLY-CHAIN: base image '%s' is not pinned by digest.", [image])
}

deny contains msg if {
	some cmd in input
	cmd.Cmd == "add"
	msg := "SUPPLY-CHAIN: use COPY instead of ADD (ADD can fetch remote URLs and auto-extract archives)."
}
