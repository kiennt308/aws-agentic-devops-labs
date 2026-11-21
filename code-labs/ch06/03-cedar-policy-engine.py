# Copyright (c) 2026 Kien Nguyen (Apache-2.0)
"""Deterministic Cedar v4.15 policy engine for AgentCore Gateway."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

VALID_MODES = frozenset({"ENFORCE", "LOG_ONLY"})
GATEWAY_ARN = (
    "arn:aws:bedrock-agentcore:us-east-1:"
    "111122223333:gateway/orderflow-ops-gw"
)


@dataclass(frozen=True)
class Entity:
    """Cedar entity with namespace-qualified type, UID, and attrs."""

    entity_type: str
    uid: str
    attrs: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ScopeMatcher:
    """Constraint on principal, action, or resource in policy head."""

    entity_type: str | None = None
    allowed_uids: frozenset[str] | None = None

    def matches(self, entity: Entity) -> bool:
        """Return True if entity satisfies type and UID rules."""
        if self.entity_type and entity.entity_type != self.entity_type:
            return False
        if self.allowed_uids is not None:
            return entity.uid in self.allowed_uids
        return True


@dataclass(frozen=True)
class CedarPolicy:
    """Parsed Cedar permit or forbid statement."""

    policy_id: int
    effect: str
    principal: ScopeMatcher
    action: ScopeMatcher
    resource: ScopeMatcher
    when_tokens: list[tuple[str, str]]
    unless_tokens: list[tuple[str, str]]


@dataclass(frozen=True)
class AuthDecision:
    """Result of evaluating a Gateway tool request against Cedar."""

    decision: str
    cedar_verdict: str
    mode: str
    matched_permits: tuple[int, ...]
    matched_forbids: tuple[int, ...]
    reason: str


def strip_comments(source: str) -> str:
    """Remove // line comments while preserving string literals."""
    out: list[str] = []
    i = 0
    in_str = False
    while i < len(source):
        ch = source[i]
        if ch == "\\" and in_str and i + 1 < len(source):
            out.append(source[i : i + 2])
            i += 2
            continue
        if ch == '"':
            in_str = not in_str
            out.append(ch)
            i += 1
            continue
        if not in_str and source[i : i + 2] == "//":
            while i < len(source) and source[i] != "\n":
                i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def split_statements(cleaned: str) -> list[str]:
    """Split Cedar source into semicolon-terminated statements."""
    stmts: list[str] = []
    buf: list[str] = []
    in_str = False
    i = 0
    while i < len(cleaned):
        ch = cleaned[i]
        if ch == "\\" and in_str and i + 1 < len(cleaned):
            buf.append(cleaned[i : i + 2])
            i += 2
            continue
        if ch == '"':
            in_str = not in_str
        if ch == ";" and not in_str:
            stmt = "".join(buf).strip()
            if stmt:
                stmts.append(stmt)
            buf = []
        else:
            buf.append(ch)
        i += 1
    return stmts


def _find_matching(
    text: str, start: int, open_c: str, close_c: str
) -> int:
    depth = 0
    in_str = False
    i = start
    while i < len(text):
        ch = text[i]
        if ch == "\\" and in_str and i + 1 < len(text):
            i += 2
            continue
        if ch == '"':
            in_str = not in_str
        elif not in_str:
            if ch == open_c:
                depth += 1
            elif ch == close_c:
                depth -= 1
                if depth == 0:
                    return i
        i += 1
    raise ValueError(f"Unclosed delimiter {open_c} at {start}")


def _split_top_commas(text: str) -> list[str]:
    parts: list[str] = []
    buf: list[str] = []
    depth = 0
    in_str = False
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == "\\" and in_str and i + 1 < len(text):
            buf.append(text[i : i + 2])
            i += 2
            continue
        if ch == '"':
            in_str = not in_str
        elif not in_str:
            if ch in "([":
                depth += 1
            elif ch in ")]":
                depth -= 1
            elif ch == "," and depth == 0:
                parts.append("".join(buf).strip())
                buf = []
                i += 1
                continue
        buf.append(ch)
        i += 1
    tail = "".join(buf).strip()
    if tail:
        parts.append(tail)
    return parts


def _parse_entity_uid(expr: str) -> tuple[str, str]:
    match = re.fullmatch(
        r'([A-Za-z_][A-Za-z0-9_:]*)::"([^"]*)"', expr.strip()
    )
    if not match:
        raise ValueError(f"Invalid Cedar entity UID: {expr}")
    return match.group(1), match.group(2)


def _parse_scope_clause(clause: str, role: str) -> ScopeMatcher:
    text = clause.strip()
    if text == role:
        return ScopeMatcher()
    if text.startswith(f"{role} is "):
        rest = text[len(f"{role} is ") :].strip()
        if " in " in rest:
            etype, target = rest.split(" in ", 1)
            _, uid = _parse_entity_uid(target)
            return ScopeMatcher(etype.strip(), frozenset({uid}))
        return ScopeMatcher(entity_type=rest)
    if text.startswith(f"{role} == "):
        etype, uid = _parse_entity_uid(text[len(f"{role} == ") :])
        return ScopeMatcher(etype, frozenset({uid}))
    if text.startswith(f"{role} in "):
        rhs = text[len(f"{role} in ") :].strip()
        if rhs.startswith("[") and rhs.endswith("]"):
            items = _split_top_commas(rhs[1:-1])
            parsed = [_parse_entity_uid(item) for item in items]
            types = {t for t, _ in parsed}
            etype = next(iter(types)) if len(types) == 1 else None
            return ScopeMatcher(etype, frozenset(u for _, u in parsed))
        etype, uid = _parse_entity_uid(rhs)
        return ScopeMatcher(etype, frozenset({uid}))
    raise ValueError(f"Unsupported scope clause: {clause}")


def tokenize_expr(expr: str) -> list[tuple[str, str]]:
    """Tokenize a Cedar when/unless condition expression."""
    tokens: list[tuple[str, str]] = []
    i = 0
    while i < len(expr):
        if expr[i].isspace():
            i += 1
            continue
        two = expr[i : i + 2]
        if two in {"&&", "||", "==", "!=", "<=", ">=", "::"}:
            tokens.append(("OP", two))
            i += 2
            continue
        if expr[i] in {"(", ")", "[", "]", ",", ".", "!", "<", ">"}:
            tokens.append(("OP", expr[i]))
            i += 1
            continue
        if expr[i] == '"':
            j = i + 1
            chars: list[str] = []
            while j < len(expr) and expr[j] != '"':
                if expr[j] == "\\" and j + 1 < len(expr):
                    chars.append(expr[j + 1])
                    j += 2
                else:
                    chars.append(expr[j])
                    j += 1
            tokens.append(("STR", "".join(chars)))
            i = j + 1
            continue
        if expr[i].isdigit() or (
            expr[i] == "-" and i + 1 < len(expr) and expr[i + 1].isdigit()
        ):
            j = i + 1
            while j < len(expr) and expr[j].isdigit():
                j += 1
            tokens.append(("INT", expr[i:j]))
            i = j
            continue
        if expr[i].isalpha() or expr[i] == "_":
            j = i + 1
            while j < len(expr) and (expr[j].isalnum() or expr[j] == "_"):
                j += 1
            word = expr[i:j]
            if word in {"true", "false"}:
                tokens.append(("BOOL", word))
            elif word in {"has", "is", "in", "like"}:
                tokens.append(("KW", word))
            else:
                tokens.append(("ID", word))
            i = j
            continue
        raise ValueError(f"Unexpected char in Cedar expr: {expr[i]!r}")
    return tokens


def _cedar_like_match(value: str, pattern: str) -> bool:
    regex_parts = [r"\A"]
    i = 0
    while i < len(pattern):
        if pattern[i] == "\\" and i + 1 < len(pattern):
            regex_parts.append(re.escape(pattern[i + 1]))
            i += 2
        elif pattern[i] == "*":
            regex_parts.append(".*")
            i += 1
        else:
            regex_parts.append(re.escape(pattern[i]))
            i += 1
    regex_parts.append(r"\Z")
    return re.match("".join(regex_parts), value, re.DOTALL) is not None


class _ExprParser:
    """Recursive-descent parser producing a short-circuit AST."""

    def __init__(self, tokens: list[tuple[str, str]]) -> None:
        self.tokens = tokens
        self.pos = 0

    def _peek(self) -> tuple[str, str] | None:
        if self.pos < len(self.tokens):
            return self.tokens[self.pos]
        return None

    def _consume(self, expected: str | None = None) -> tuple[str, str]:
        tok = self._peek()
        if tok is None:
            raise ValueError("Unexpected end of Cedar expression")
        if expected is not None and tok[1] != expected:
            raise ValueError(f"Expected {expected}, got {tok}")
        self.pos += 1
        return tok

    def parse(self) -> tuple[Any, ...]:
        """Parse full condition expression into an AST tuple."""
        return self._parse_or()

    def _parse_or(self) -> tuple[Any, ...]:
        node = self._parse_and()
        while self._peek() == ("OP", "||"):
            self._consume("||")
            node = ("or", node, self._parse_and())
        return node

    def _parse_and(self) -> tuple[Any, ...]:
        node = self._parse_cmp()
        while self._peek() == ("OP", "&&"):
            self._consume("&&")
            node = ("and", node, self._parse_cmp())
        return node

    def _parse_cmp(self) -> tuple[Any, ...]:
        lhs = self._parse_unary()
        tok = self._peek()
        if tok is None:
            return lhs
        if tok == ("KW", "has"):
            self._consume("has")
            attr = self._consume()[1]
            return ("has", lhs, attr)
        if tok == ("KW", "is"):
            self._consume("is")
            etype = self._parse_type_name()
            return ("is", lhs, etype)
        if tok[1] in {"==", "!=", "<", "<=", ">", ">=", "like", "in"}:
            op = self._consume()[1]
            rhs = self._parse_unary()
            return ("cmp", op, lhs, rhs)
        return lhs

    def _parse_type_name(self) -> str:
        parts = [self._consume()[1]]
        while self._peek() == ("OP", "::"):
            self._consume("::")
            parts.append(self._consume()[1])
        return "::".join(parts)

    def _parse_unary(self) -> tuple[Any, ...]:
        if self._peek() == ("OP", "!"):
            self._consume("!")
            return ("not", self._parse_unary())
        return self._parse_primary()

    def _parse_primary(self) -> tuple[Any, ...]:
        tok = self._peek()
        if tok is None:
            raise ValueError("Empty primary expression")
        if tok == ("OP", "("):
            self._consume("(")
            node = self._parse_or()
            self._consume(")")
            return node
        if tok == ("OP", "["):
            self._consume("[")
            items: list[tuple[Any, ...]] = []
            while self._peek() != ("OP", "]"):
                items.append(self._parse_or())
                if self._peek() == ("OP", ","):
                    self._consume(",")
            self._consume("]")
            return ("list", items)
        if tok[0] == "STR":
            return ("lit", self._consume()[1])
        if tok[0] == "INT":
            return ("lit", int(self._consume()[1]))
        if tok[0] == "BOOL":
            return ("lit", self._consume()[1] == "true")
        if tok[0] == "ID":
            root = self._consume()[1]
            if self._peek() == ("OP", "::"):
                parts = [root]
                while self._peek() == ("OP", "::"):
                    self._consume("::")
                    nxt = self._peek()
                    if nxt and nxt[0] == "STR":
                        return ("lit", self._consume()[1])
                    parts.append(self._consume()[1])
                return ("lit", "::".join(parts))
            path: list[str] = []
            while self._peek() == ("OP", "."):
                self._consume(".")
                path.append(self._consume()[1])
            return ("var", root, path)
        raise ValueError(f"Unsupported Cedar token: {tok}")


def _eval_ast(node: tuple[Any, ...], env: dict[str, Any]) -> Any:
    """Evaluate parsed Cedar AST with short-circuit semantics."""
    kind = node[0]
    if kind == "lit":
        return node[1]
    if kind == "list":
        return [_eval_ast(item, env) for item in node[1]]
    if kind == "var":
        val = env.get(node[1])
        for attr in node[2]:
            if isinstance(val, Entity):
                val = val.attrs.get(attr)
            elif isinstance(val, dict):
                val = val.get(attr)
            else:
                val = None
        return val
    if kind == "not":
        return not bool(_eval_ast(node[1], env))
    if kind == "and":
        return bool(_eval_ast(node[1], env)) and bool(
            _eval_ast(node[2], env)
        )
    if kind == "or":
        return bool(_eval_ast(node[1], env)) or bool(
            _eval_ast(node[2], env)
        )
    if kind == "has":
        target = _eval_ast(node[1], env)
        attr = node[2]
        if isinstance(target, Entity):
            return attr in target.attrs
        return isinstance(target, dict) and attr in target
    if kind == "is":
        target = _eval_ast(node[1], env)
        return (
            isinstance(target, Entity)
            and target.entity_type == node[2]
        )
    if kind == "cmp":
        _, op, lhs_node, rhs_node = node
        lhs = _eval_ast(lhs_node, env)
        rhs = _eval_ast(rhs_node, env)
        if op == "==":
            return lhs == rhs
        if op == "!=":
            return lhs != rhs
        if op == "<":
            return lhs < rhs
        if op == "<=":
            return lhs <= rhs
        if op == ">":
            return lhs > rhs
        if op == ">=":
            return lhs >= rhs
        if op == "like":
            return isinstance(lhs, str) and _cedar_like_match(
                lhs, str(rhs)
            )
        if op == "in":
            return lhs in rhs
    raise ValueError(f"Unknown Cedar AST node: {node}")


class _ExprEvaluator:
    """Short-circuit evaluator for tokenized Cedar condition lists."""

    def __init__(
        self,
        tokens: list[tuple[str, str]],
        env: dict[str, Any],
    ) -> None:
        self.ast = _ExprParser(tokens).parse()
        self.env = env

    def evaluate(self) -> bool:
        """Evaluate parsed AST and coerce result to boolean."""
        return bool(_eval_ast(self.ast, self.env))


def parse_policies(source: str) -> list[CedarPolicy]:
    """Parse Cedar policy statements from file text."""
    cleaned = strip_comments(source)
    stmts = split_statements(cleaned)
    policies: list[CedarPolicy] = []
    for idx, stmt in enumerate(stmts, start=1):
        match = re.match(r"^(permit|forbid)\s*\(", stmt)
        if not match:
            raise ValueError(f"Invalid policy #{idx}: {stmt[:30]}")
        effect = match.group(1)
        open_idx = stmt.find("(")
        close_idx = _find_matching(stmt, open_idx, "(", ")")
        head = stmt[open_idx + 1 : close_idx]
        clauses = _split_top_commas(head)
        if len(clauses) != 3:
            raise ValueError(f"Policy #{idx} needs 3 scope clauses")
        tail = stmt[close_idx + 1 :].strip()
        when_tokens: list[tuple[str, str]] = []
        unless_tokens: list[tuple[str, str]] = []
        while tail:
            if tail.startswith("when"):
                b_start = tail.find("{")
                b_end = _find_matching(tail, b_start, "{", "}")
                when_tokens = tokenize_expr(tail[b_start + 1 : b_end])
                tail = tail[b_end + 1 :].strip()
            elif tail.startswith("unless"):
                b_start = tail.find("{")
                b_end = _find_matching(tail, b_start, "{", "}")
                unless_tokens = tokenize_expr(tail[b_start + 1 : b_end])
                tail = tail[b_end + 1 :].strip()
            else:
                raise ValueError(f"Unexpected policy tail: {tail}")
        policies.append(
            CedarPolicy(
                policy_id=idx,
                effect=effect,
                principal=_parse_scope_clause(clauses[0], "principal"),
                action=_parse_scope_clause(clauses[1], "action"),
                resource=_parse_scope_clause(clauses[2], "resource"),
                when_tokens=when_tokens,
                unless_tokens=unless_tokens,
            )
        )
    return policies


class CedarPolicyEngine:
    """Evaluates AgentCore Gateway requests using Cedar v4.15 rules."""

    def __init__(
        self,
        policies: list[CedarPolicy],
        mode: str = "ENFORCE",
    ) -> None:
        if mode not in VALID_MODES:
            raise ValueError(f"Invalid enforcement mode: {mode}")
        self.policies = policies
        self.mode = mode
        self.audit_log: list[dict[str, Any]] = []

    @classmethod
    def from_file(
        cls,
        path: Path | str,
        mode: str = "ENFORCE",
    ) -> CedarPolicyEngine:
        """Load Cedar policies directly from a .cedar policy file."""
        text = Path(path).read_text(encoding="utf-8")
        return cls(parse_policies(text), mode=mode)

    def _policy_matches(
        self,
        policy: CedarPolicy,
        principal: Entity,
        action_ent: Entity,
        resource: Entity,
        context: dict[str, Any],
    ) -> bool:
        if not policy.principal.matches(principal):
            return False
        if not policy.action.matches(action_ent):
            return False
        if not policy.resource.matches(resource):
            return False
        env = {
            "principal": principal,
            "action": action_ent,
            "resource": resource,
            "context": context,
        }
        if policy.when_tokens:
            if not _ExprEvaluator(policy.when_tokens, env).evaluate():
                return False
        if policy.unless_tokens:
            if _ExprEvaluator(policy.unless_tokens, env).evaluate():
                return False
        return True

    def evaluate(
        self,
        principal: Entity,
        action: str,
        resource: Entity,
        context: dict[str, Any] | None = None,
        mode: str | None = None,
    ) -> AuthDecision:
        """Apply default-deny and forbid-overrides-permit semantics."""
        active_mode = mode or self.mode
        if active_mode not in VALID_MODES:
            raise ValueError(f"Invalid enforcement mode: {active_mode}")
        ctx = context or {}
        action_ent = Entity("AgentCore::Action", action, {})
        permits: list[int] = []
        forbids: list[int] = []
        for pol in self.policies:
            if self._policy_matches(
                pol, principal, action_ent, resource, ctx
            ):
                if pol.effect == "permit":
                    permits.append(pol.policy_id)
                else:
                    forbids.append(pol.policy_id)
        if forbids:
            verdict = "DENY"
            reason = f"Explicit forbid rule(s) matched: {forbids}"
        elif permits:
            verdict = "ALLOW"
            reason = f"Permit rule(s) matched: {permits}"
        else:
            verdict = "DENY"
            reason = "Default deny: no permit policy matched"

        if verdict == "DENY" and active_mode == "LOG_ONLY":
            decision = "ALLOW_WITH_AUDIT_DENY"
            self.audit_log.append(
                {
                    "mode": active_mode,
                    "principal": principal.uid,
                    "action": action,
                    "resource": resource.uid,
                    "would_deny_reason": reason,
                    "matched_forbids": forbids,
                }
            )
        else:
            decision = verdict
        return AuthDecision(
            decision=decision,
            cedar_verdict=verdict,
            mode=active_mode,
            matched_permits=tuple(permits),
            matched_forbids=tuple(forbids),
            reason=reason,
        )


def build_default_gateway() -> Entity:
    """Return canonical OrderFlow AgentCore Gateway entity."""
    return Entity(
        entity_type="AgentCore::Gateway",
        uid=GATEWAY_ARN,
        attrs={
            "gateway_id": "orderflow-ops-gw",
            "gateway_arn": GATEWAY_ARN,
            "account_id": "111122223333",
            "region": "us-east-1",
            "environment": "production",
        },
    )


def main() -> None:
    """Run local Cedar Gateway verification against sample payloads."""
    cedar_path = Path(__file__).resolve().parent / (
        "02-orderflow-gateway.cedar"
    )
    engine = CedarPolicyEngine.from_file(cedar_path, mode="ENFORCE")
    gw = build_default_gateway()
    caller = Entity(
        entity_type="AgentCore::OAuthUser",
        uid="orderflow-triage-agent",
        attrs={"sub": "agent-01", "scope": "ops:read"},
    )
    ok = engine.evaluate(caller, "aurora___describe_db_clusters", gw)
    blocked = engine.evaluate(
        caller,
        "aurora___delete_db_cluster",
        gw,
        {"skip_final_snapshot": True},
    )
    shadow = engine.evaluate(
        caller,
        "kms___schedule_key_deletion",
        gw,
        {"pending_window_in_days": 3},
        mode="LOG_ONLY",
    )
    print(
        json.dumps(
            {
                "benign_read": ok.decision,
                "injected_delete_enforce": blocked.decision,
                "injected_kms_log_only": shadow.decision,
                "audit_entries": len(engine.audit_log),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
