"""
Selected policy loader.

Fetches a Firewall Policy and its Rule Collection Groups for a given policy ID.
Returns both the raw JSON-ish dict and parsed rules using the firewall_parser.
"""

from typing import Tuple, Dict, Any
import logging

logger = logging.getLogger(__name__)

def load_policy_rules(policy_id: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Load a single policy by its Azure resource ID.

    Returns (policy_json, rules_dict) where rules_dict has 'network' and 'application' keys.
    """
    try:
        from azure.identity import DefaultAzureCredential  # type: ignore
        from azure.mgmt.network import NetworkManagementClient  # type: ignore
    except Exception:
        # SDK not available; return empty structures
        logger.warning("Azure SDK not available")
        return {"policy": {}, "ruleCollectionGroups": []}, {
            "network": [],
            "application": [],
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

        policy_dict = policy.as_dict()
        rcg_dicts = [r.as_dict() for r in rcgs]

        policy_json = {
            "policy": policy_dict,
            "ruleCollectionGroups": rcg_dicts,
        }

        # Parse the policy using the firewall_parser
        from firewall_parser import parse_firewall_policy
        
        # The parser expects either:
        # 1. A dict with 'properties' containing 'ruleCollectionGroups', OR
        # 2. A list of rule collection groups
        # Since we have a list of RCGs, pass them directly
        rules = parse_firewall_policy(rcg_dicts)
        
        logger.info(f"Parsed policy: {len(rules.get('network', []))} network rules, {len(rules.get('application', []))} application rules")
        
        return policy_json, rules
    except Exception as e:
        # On failure, return empty structures rather than raising in UI
        logger.error(f"Error loading policy {policy_id}: {e}", exc_info=True)
        return {"policy": {}, "ruleCollectionGroups": []}, {
            "network": [],
            "application": [],
        }


