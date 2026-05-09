from engine.process_context import ProcessContext
from engine.rules import credential_access, execution, discovery

ALL_RULES = [
    credential_access.rule_lsass_access,
    execution.rule_encoded_powershell,
    execution.rule_suspicious_parent,
    discovery.rule_ldap_enumeration,
    discovery.rule_dns_recon,
]


def evaluate(ctx: ProcessContext):
    for rule_fn in ALL_RULES:
        result = rule_fn(ctx)
        if result:
            ctx.add_rule_hit(
                rule_name=result["rule"],
                weight=result["weight"],
                reason=result["reason"],
                behavior=result.get("behavior", ""),
                offensive_context=result.get("offensive_context", ""),
                mitre=result.get("mitre", "")
            )