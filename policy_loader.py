"""
Selected policy loader.

Fetches a Firewall Policy and its Rule Collection Groups for a given policy ID.
Returns both the raw JSON-ish dict and a placeholder for parsed rules (hook up
to your existing parser if available).
"""

from typing import Tuple, Dict, Any


def load_policy_rules(policy_id: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Load a single policy by its Azure resource ID.

    Returns (policy_json, rules_dict).
    """
    try:
        from azure.identity import DefaultAzureCredential  # type: ignore
        from azure.mgmt.network import NetworkManagementClient  # type: ignore
    except Exception:
        # SDK not available; return empty structures
        return {"policy": {}, "ruleCollectionGroups": []}, {
            "network_rules": [],
            "application_rules": [],
            "dnat_rules": [],
        }

    parts = policy_id.split("/")
    # Expect: /subscriptions/<subId>/resourceGroups/<rg>/providers/Microsoft.Network/firewallPolicies/<name>
    sub_id = parts[2] if len(parts) > 2 else ""
    rg = parts[4] if len(parts) > 4 else ""
    policy_name = parts[-1] if parts else ""

    try:
        cred = DefaultAzureCredential()
        net = NetworkManagementClient(cred, sub_id)
        policy = net.firewall_policies.get(rg, policy_name)
        rcgs = list(net.firewall_policy_rule_collection_groups.list(rg, policy_name))

        policy_json = {
            "policy": policy.as_dict(),
            "ruleCollectionGroups": [r.as_dict() for r in rcgs],
        }

        # Hook this to your real parser if available.
        rules = {
            "network_rules": [],
            "application_rules": [],
            "dnat_rules": [],
        }
        return policy_json, rules
    except Exception:
        # On failure, return empty structures rather than raising in UI
        return {"policy": {}, "ruleCollectionGroups": []}, {
            "network_rules": [],
            "application_rules": [],
            "dnat_rules": [],
        }


