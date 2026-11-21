# OrderFlow Global AWS Agentic Operations — Companion Code Labs

Zero-AWS-Bill (`$0.00`) and Zero-API-Bill (`$0.00`) managed AWS
operations labs covering `Strands Agents SDK v1.64.0`, `Amazon Bedrock
AgentCore` (`Runtime`, `Gateway`, `Policy`, `Memory`, `Code
Interpreter`, `Identity`), `awslabs/mcp` & Agent Toolkit for AWS,
`AWS DevOps Agent` (`Agent Spaces`, `JournalRecord`), `Cedar v4.15.0`,
`Bedrock Automated Reasoning Checks`, `AWS Security Hub AI Inventory`,
`GuardDuty AI Protection`, `OCSF` (`v1.6` / `v1.9.0` `class_uid = 2004`),
`Bedrock Prompt Caching`, and `AWS Data Exports FOCUS 1.2`:

> **Agentic AI on AWS for DevOps and Cloud Operations**
> *A Practical Guide to Amazon Bedrock AgentCore, Strands Agents SDK,*
> *AWS MCP Servers, Cedar Policy Authorization, Automated Reasoning,*
> *and Serverless Cloud Operations*
> *Practical Engineering Series — Volume 08 (Arc II AWS Plane)*
> **Author & Publisher:** Kien Nguyen
> **Repository:** `https://github.com/kiennt308/aws-agentic-devops-labs`

Copyright (c) 2026 Kien Nguyen. Companion Python harnesses, MCP tools,
Cedar schemas and policies, CloudFormation/Conftest/cfn-guard gates,
Automated Reasoning rule sets, and SQLite OCSF/FOCUS queries in this
repository are licensed under **Apache-2.0**.

---

## Zero-AWS-Bill & Zero-API-Bill Toolchain

Every chapter lab runs 100% offline with Docker and Python `3.11+`
using `ch01/01-aws-agent-replay-gateway.py` (`LLM_BASE_URL` can point
to local `Ollama` or any OpenAI-compatible gateway) with `$0.00` spend:

- `Python 3.11+`, `mcp v2.2+`, `PyJWT`, `cryptography`, `pytest`,
  `PyYAML`, `SQLite`
- `openpolicyagent/conftest:latest` (`v0.71.1` / `OPA v1.21.1` `rego.v1`)
- `localstack/localstack:4` (ephemeral live AWS EventBridge / S3 / STS)
- `public.ecr.aws/aws-cli/aws-cli:latest` (`v2.41.1`)
- `aquasec/trivy:latest` (CloudFormation IaC misconfiguration scan)
- Authored-to-spec `Cedar v4.15.0` (verified via Python engine +
  optional native `cedar-policy-cli`) & `cfn-guard v3.2.1` rules

---

## Canonical OrderFlow Global Agentic Identities

- **Agent Spaces (`AWS DevOps Agent`):** `orderflow-prod-ops-space`,
  `orderflow-staging-ops-space`
- **Strands Agents (`SDK v1.64.0`):** `orderflow-aws-triage-agent`,
  `orderflow-iac-grounding-agent`, `orderflow-finops-advisor-agent`
- **AgentCore Gateway ARN:**
  `arn:aws:bedrock-agentcore:us-east-1:111122223333:gateway/`
  `orderflow-ops-gw` (split only for display)
- **Authorized Read Actions:** `cloudwatch___get_metric_data`,
  `aurora___describe_db_clusters`, `eks___list_insights`,
  `devopsagent___list_journal_records`
- **Hard `forbid` Guarded Actions:** `aurora___delete_db_cluster`,
  `kms___schedule_key_deletion`, `iam___attach_role_policy`

---

## Directory Index (48 Clean Files)

```text
code-labs/
├── README.md      Zero-AWS-Bill & Zero-API-Bill lab guide
├── policies/      OPA rego.v1 AWS Agentic & Cedar readiness gates
├── ch01/          Mock Bedrock replay gateway & EventBridge router
├── ch02/          Strands v1.64 loop, middleware, S3 Vectors & cancel()
├── ch03/          AgentCore Runtime microVM, Gateway JWT & Memory scope
├── ch04/          awslabs/mcp server, CFN/Trivy/cfn-guard grounding
├── ch05/          AWS DevOps Agent Spaces & JournalRecord hash audit
├── ch06/          Cedar v4.15 AgentCore schema, policies & evaluator
├── ch07/          Bedrock Guardrails, Automated Reasoning & OCSF 2004
├── ch08/          Security Hub AI Inventory SBOM & OCSF SQL correlator
└── ch09/          Prompt Caching benchmark, FOCUS 1.2 SQL & 20-pt PRR
```

---

## Quick Verification Commands

```bash
docker run --rm -v "${PWD}:/work" -w /work \
  openpolicyagent/conftest:latest test \
  -p policies/aws_agentic_gates.rego \
  ch01/03-orderflow-aws-agentic-baseline-valid.yaml \
  ch02/02-strands-agent-spec-valid.yaml \
  ch03/01-agentcore-runtime-gateway-spec.yaml \
  ch04/02-orderflow-iac-valid.yaml \
  ch04/05-awslabs-mcp-config.yaml \
  ch05/01-devops-agent-spaces.yaml \
  ch06/05-cedar-gateway-config-valid.yaml \
  ch07/01-bedrock-guardrail-ar-config.yaml \
  ch08/04-security-hub-ocsf-config-valid.yaml \
  ch09/04-aws-agentic-prr-ready.json

pytest -v ch02/04-test-strands-loop.py \
  ch03/04-test-agentcore-isolation.py \
  ch04/06-test-awslabs-mcp-grounding.py \
  ch06/04-test-cedar-agentcore.py \
  ch07/04-test-guardrails-ar.py \
  ch09/06-test-finops-prr.py
```
