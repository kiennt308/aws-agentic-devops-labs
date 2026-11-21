package main

import rego.v1

cfg := object.get(input, "spec", input)

resources := object.get(input, "Resources", {})

retired_telemetry := {"xray_sdk", "xray_daemon"}

mandatory_forbids := {
	"aurora___delete_db_cluster",
	"kms___schedule_key_deletion",
	"iam___attach_role_policy",
}

known_s3_props := {
	"BucketName",
	"BucketEncryption",
	"PublicAccessBlockConfiguration",
	"OwnershipControls",
	"VersioningConfiguration",
	"Tags",
}

has_hallucinated_s3_prop(props) if {
	some key, _ in props
	not (key in known_s3_props)
}

# 1. Deprecation check: retired standalone strands-agents-tools
deny contains msg if {
	"strands-agents-tools" in object.get(cfg, "packages", [])
	msg := "DEPRECATED_STRANDS_TOOLS: use strands-agents SDK v1.64+"
}

deny contains msg if {
	object.get(cfg, "uses_deprecated_strands_tools", false) == true
	msg := "DEPRECATED_STRANDS_TOOLS: migrate off strands-agents-tools"
}

# 2. Retired AWS underlay practices (Vol. 04 alignment)
deny contains msg if {
	object.get(cfg, "telemetry_backend", "") in retired_telemetry
	msg := "RETIRED_AWS_UNDERLAY: migrate X-Ray to CloudWatch OTLP"
}

deny contains msg if {
	object.get(cfg, "audit_store", "") == "cloudtrail_lake_eventdatastore"
	msg := "RETIRED_AWS_UNDERLAY: CloudTrail Lake closed May 2026"
}

deny contains msg if {
	object.get(cfg, "billing_export", "") == "CUR_1_0"
	msg := "RETIRED_AWS_UNDERLAY: upgrade CUR 1.0 to FOCUS 1.2"
}

deny contains msg if {
	object.get(cfg, "imdsv1_allowed", false) == true
	msg := "RETIRED_AWS_UNDERLAY: require EC2 IMDSv2 HttpTokens"
}

deny contains msg if {
	object.get(cfg, "static_akia_keys", false) == true
	msg := "RETIRED_AWS_UNDERLAY: ban static AKIA IAM access keys"
}

deny contains msg if {
	some _, res in resources
	res.Type == "AWS::CloudTrail::EventDataStore"
	msg := "RETIRED_AWS_UNDERLAY: CloudTrail EventDataStore deprecated"
}

deny contains msg if {
	some _, res in resources
	res.Type == "AWS::CloudFront::CloudFrontOriginAccessIdentity"
	msg := "RETIRED_AWS_UNDERLAY: replace legacy OAI with OAC"
}

deny contains msg if {
	some _, res in resources
	res.Type == "AWS::S3::Bucket"
	props := object.get(res, "Properties", {})
	object.get(props, "AccessControl", "") == "PublicRead"
	msg := "RETIRED_AWS_UNDERLAY: forbid legacy public S3 Bucket ACL"
}

deny contains msg if {
	some _, res in resources
	res.Type == "AWS::S3::Bucket"
	props := object.get(res, "Properties", {})
	has_hallucinated_s3_prop(props)
	msg := "HALLUCINATED_CFN_PROPERTY: invalid S3 property detected"
}

# 3. Strands Agents SDK v1.64 loop and cancellation safety
deny contains msg if {
	object.get(cfg, "framework", "") == "strands-agents-sdk"
	turns := object.get(cfg, "max_turns", 0)
	turns > 12
	msg := sprintf("STRANDS_LOOP_UNBOUNDED: max_turns %d exceeds 12", [
		turns,
	])
}

deny contains msg if {
	object.get(cfg, "framework", "") == "strands-agents-sdk"
	object.get(cfg, "max_turns", 0) <= 0
	msg := "STRANDS_LOOP_UNBOUNDED: max_turns must be positive"
}

deny contains msg if {
	object.get(cfg, "framework", "") == "strands-agents-sdk"
	object.get(cfg, "agent_cancel_supported", false) != true
	msg := "STRANDS_CANCEL_MISSING: enable agent.cancel() lifecycle hook"
}

deny contains msg if {
	object.get(cfg, "framework", "") == "strands-agents-sdk"
	object.get(cfg, "max_input_tokens_budget", 0) <= 0
	msg := "STRANDS_LOOP_UNBOUNDED: set max_input_tokens_budget"
}

# 4. Amazon Bedrock AgentCore isolation and identity guards
deny contains msg if {
	object.get(cfg, "hosting_plane", "") in {
		"bedrock-agentcore",
		"custom-ecs-wrapper",
	}
	object.get(cfg, "session_isolation", "") != "microvm"
	msg := "AGENTCORE_NO_MICROVM_ISOLATION: require Runtime microVM"
}

deny contains msg if {
	object.get(cfg, "hosting_plane", "") in {
		"bedrock-agentcore",
		"custom-ecs-wrapper",
	}
	object.get(cfg, "memory_namespace_scoped_by_account", false) != true
	msg := "AGENTCORE_SHARED_TENANT_MEMORY: scope memory by account"
}

deny contains msg if {
	object.get(cfg, "hosting_plane", "") in {
		"bedrock-agentcore",
		"custom-ecs-wrapper",
	}
	object.get(cfg, "identity_mode", "") == "static_secret"
	msg := "AGENTCORE_STATIC_SECRET: require AgentCore Identity OAuth/IAM"
}

# 5. awslabs/mcp Streamable HTTP and IAM AI caller attribution
deny contains msg if {
	object.get(cfg, "protocol", "") == "MCP"
	object.get(cfg, "transport", "") != "streamable-http"
	msg := "MCP_LEGACY_SSE_DENIED: require MCP streamable-http"
}

deny contains msg if {
	object.get(cfg, "protocol", "") == "MCP"
	object.get(cfg, "iam_agent_caller_condition_key", false) != true
	msg := "MCP_MISSING_AGENT_CALLER_KEY: enforce agent caller IAM key"
}

# 6. AWS DevOps Agent Spaces, agent-seconds cap, and JournalRecord
deny contains msg if {
	object.get(cfg, "service", "") == "aws-devops-agent"
	trim_space(object.get(cfg, "agent_space_id", "")) == ""
	msg := "DEVOPS_AGENT_SPACE_MISSING: configure isolated Agent Space"
}

deny contains msg if {
	object.get(cfg, "service", "") == "aws-devops-agent"
	sec := object.get(cfg, "max_agent_seconds_per_execution", 0)
	sec <= 0
	msg := "DEVOPS_AGENT_SECONDS_UNBOUNDED: set agent-seconds cap"
}

deny contains msg if {
	object.get(cfg, "service", "") == "aws-devops-agent"
	sec := object.get(cfg, "max_agent_seconds_per_execution", 0)
	sec > 600
	msg := sprintf("DEVOPS_AGENT_SECONDS_UNBOUNDED: %ds > 600s cap", [
		sec,
	])
}

deny contains msg if {
	object.get(cfg, "service", "") == "aws-devops-agent"
	object.get(cfg, "journal_record_immutable", false) != true
	msg := "JOURNAL_RECORD_INCOMPLETE: require immutable JournalRecord"
}

# 7. Cedar Policy in AgentCore Gateway enforcement
deny contains msg if {
	object.get(cfg, "policy_engine", "") == "agentcore-cedar"
	some act in object.get(cfg, "permitted_actions", [])
	contains(act, "*")
	msg := sprintf("CEDAR_WILDCARD_ACTION_DENIED: wildcard in %s", [act])
}

deny contains msg if {
	object.get(cfg, "policy_engine", "") == "agentcore-cedar"
	forbids := {a | some a in object.get(cfg, "forbidden_actions", [])}
	some req in mandatory_forbids
	not (req in forbids)
	msg := sprintf("CEDAR_DESTRUCTIVE_FORBID_MISSING: forbid %s", [req])
}

deny contains msg if {
	object.get(cfg, "policy_engine", "") == "agentcore-cedar"
	not (object.get(cfg, "enforcement_mode", "") in {"LOG_ONLY", "ENFORCE"})
	msg := "CEDAR_INVALID_MODE: mode must be LOG_ONLY or ENFORCE"
}

# 8. Bedrock Guardrails Automated Reasoning & OCSF 2004
deny contains msg if {
	object.get(cfg, "guardrail_layer", "") == "bedrock-guardrails"
	object.get(cfg, "compliance_verifier", "") != "automated-reasoning"
	msg := "LLM_JUDGE_ONLY_DENIED: require Automated Reasoning Checks"
}

deny contains msg if {
	object.get(cfg, "guardrail_layer", "") == "bedrock-guardrails"
	object.get(cfg, "ocsf_class_uid", 0) != 2004
	msg := "GUARDRAIL_OCSF_2004_REQUIRED: emit OCSF Detection Finding"
}

# 9. Security Hub AI Inventory SBOM & GuardDuty DNS checks
deny contains msg if {
	object.get(cfg, "security_plane", "") == "security-hub-ai-inventory"
	object.get(cfg, "inspector_sbom_enabled", false) != true
	msg := "SHADOW_AI_SBOM_DISABLED: enable Inspector SBOM discovery"
}

deny contains msg if {
	object.get(cfg, "security_plane", "") == "security-hub-ai-inventory"
	object.get(cfg, "guardduty_dns_ai_discovery", false) != true
	msg := "GUARDDUTY_DNS_DISABLED: enable GuardDuty DNS discovery"
}

# 10. AWS Agentic FinOps (Prompt Caching + FOCUS 1.2 + 20-pt PRR)
deny contains msg if {
	object.get(cfg, "finops_prr", false) == true
	object.get(cfg, "prompt_caching_enabled", false) != true
	msg := "PROMPT_CACHING_DISABLED: enable Bedrock Prompt Caching"
}

deny contains msg if {
	object.get(cfg, "finops_prr", false) == true
	object.get(cfg, "focus_version", "") != "1.2"
	msg := "FOCUS12_ATTRIBUTION_MISSING: require FOCUS 1.2 cost tagging"
}

deny contains msg if {
	object.get(cfg, "finops_prr", false) == true
	score := object.get(cfg, "prr_score", 0)
	score < 20
	msg := sprintf("AWS_PRR_INCOMPLETE: score %d < 20 required", [score])
}
