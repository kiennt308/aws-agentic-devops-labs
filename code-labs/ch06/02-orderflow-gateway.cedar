// Copyright (c) 2026 Kien Nguyen (Apache-2.0)
// Cedar v4.15.0 policies for AgentCore Gateway:
// AgentCore::Gateway::
//   "arn:aws:bedrock-agentcore:us-east-1:111122223333:
//    gateway/orderflow-ops-gw"

// 1. Permit read diagnostics for OAuthUser with ops:read scope
permit (
  principal is AgentCore::OAuthUser,
  action in [
    AgentCore::Action::"cloudwatch___get_metric_data",
    AgentCore::Action::"aurora___describe_db_clusters",
    AgentCore::Action::"eks___list_insights",
    AgentCore::Action::"devopsagent___list_journal_records"
  ],
  resource is AgentCore::Gateway
) when {
  principal.scope == "ops:read" &&
  resource.gateway_id == "orderflow-ops-gw" &&
  resource.account_id == "111122223333" &&
  resource.region == "us-east-1" &&
  resource.gateway_arn like
    "arn:aws:bedrock-agentcore:us-east-1:111122223333:gateway/*" &&
  resource.gateway_arn like
    "*:111122223333:gateway/orderflow-ops-gw" &&
  !(resource.gateway_arn like "*gateway/*:*") &&
  !(resource.gateway_arn like "*gateway/*/*")
};

// 2. Permit read diagnostics for IamEntity with ops:read scope
permit (
  principal is AgentCore::IamEntity,
  action in [
    AgentCore::Action::"cloudwatch___get_metric_data",
    AgentCore::Action::"aurora___describe_db_clusters",
    AgentCore::Action::"eks___list_insights",
    AgentCore::Action::"devopsagent___list_journal_records"
  ],
  resource is AgentCore::Gateway
) when {
  principal.scope == "ops:read" &&
  resource.gateway_id == "orderflow-ops-gw" &&
  resource.account_id == "111122223333" &&
  resource.region == "us-east-1" &&
  resource.gateway_arn like
    "arn:aws:bedrock-agentcore:us-east-1:111122223333:gateway/*" &&
  resource.gateway_arn like
    "*:111122223333:gateway/orderflow-ops-gw" &&
  !(resource.gateway_arn like "*gateway/*:*") &&
  !(resource.gateway_arn like "*gateway/*/*")
};

// 3. Hard forbid destructive actions regardless of caller role
forbid (
  principal,
  action in [
    AgentCore::Action::"aurora___delete_db_cluster",
    AgentCore::Action::"kms___schedule_key_deletion",
    AgentCore::Action::"iam___attach_role_policy"
  ],
  resource
);

// 4. Hard forbid skipping final Aurora snapshots in any tool call
forbid (
  principal,
  action,
  resource
) when {
  context has skip_final_snapshot &&
  context.skip_final_snapshot == true
};

// 5. Hard forbid destructive flags against production gateway
forbid (
  principal,
  action,
  resource is AgentCore::Gateway
) when {
  resource.environment == "production" &&
  context has allow_destructive &&
  context.allow_destructive == true
};

// 6. Hard forbid short KMS deletion windows (< 7 days)
forbid (
  principal,
  action,
  resource
) when {
  context has pending_window_in_days &&
  context.pending_window_in_days < 7
};

// 7. Hard forbid attaching broad AdministratorAccess policies
forbid (
  principal,
  action,
  resource
) when {
  context has policy_arn &&
  context.policy_arn like "*AdministratorAccess*"
};
