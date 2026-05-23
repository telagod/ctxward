package llm.privacy

default decision := null

decision := {
  "action": "block",
  "reason": "OPA policy blocks bearer_token for non-admin callers"
} if {
  input.direction == "request"
  some finding in input.findings
  finding.label == "bearer_token"
  input.principal.role != "admin"
}

decision := {
  "action": "review",
  "reason": "OPA escalates multi-turn sessions touching national_id"
} if {
  input.direction == "request"
  input.session_escalated == true
  some finding in input.findings
  finding.label == "national_id"
}

decision := {
  "action": "redact",
  "reason": "OPA forces response redaction when secret_like appears"
} if {
  input.direction == "response"
  some finding in input.findings
  finding.label == "secret_like"
}
