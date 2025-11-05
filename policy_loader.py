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

        logger.info(f"Fetched policy '{policy_name}' with {len(rcgs)} rule collection groups")
        
        policy_dict = policy.as_dict()
        rcg_dicts = [r.as_dict() for r in rcgs]

        # Log structure of first RCG for debugging
        if rcg_dicts:
            logger.info(f"First RCG keys: {list(rcg_dicts[0].keys())}")
            if 'properties' in rcg_dicts[0]:
                props = rcg_dicts[0]['properties']
                if isinstance(props, dict):
                    logger.info(f"RCG properties keys: {list(props.keys())}")
                    if 'ruleCollections' in props:
                        logger.info(f"Found {len(props['ruleCollections'])} rule collections in first RCG")
                        if props['ruleCollections']:
                            first_collection = props['ruleCollections'][0]
                            logger.info(f"First rule collection keys: {list(first_collection.keys())}")
                            logger.info(f"First rule collection type: {first_collection.get('ruleCollectionType', 'N/A')}")
                            logger.info(f"First rule collection has {len(first_collection.get('rules', []))} rules")

        # Structure policy_json similar to what azure_service.get_firewall_policy returns
        # This format matches what the parser expects
        policy_json = {
            "policy": policy_dict,
            "ruleCollectionGroups": rcg_dicts,
        }

        # Parse the policy using the firewall_parser
        from firewall_parser import parse_firewall_policy
        
        # The parser expects either:
        # 1. A dict with 'properties' containing 'ruleCollectionGroups', OR
        # 2. A list of rule collection groups
        # Match the format that azure_service uses (which works)
        logger.info(f"Calling parse_firewall_policy with structured format")
        try:
            # Format similar to azure_service.get_firewall_policy output
            # Wrap in the format expected by the parser's first branch
            structured_for_parser = {
                "properties": {
                    "ruleCollectionGroups": rcg_dicts
                }
            }
            rules = parse_firewall_policy(structured_for_parser)
            logger.info(f"Parsed successfully: {len(rules.get('network', []))} network rules, {len(rules.get('application', []))} application rules")
        except Exception as parse_error:
            logger.error(f"Parser error with structured format: {parse_error}", exc_info=True)
            # Try alternative: pass list directly
            logger.info("Trying alternative format: passing RCG list directly")
            try:
                rules = parse_firewall_policy(rcg_dicts)
                logger.info(f"Parsed with list format: {len(rules.get('network', []))} network rules, {len(rules.get('application', []))} application rules")
            except Exception as parse_error2:
                logger.error(f"Parser error with list format: {parse_error2}", exc_info=True)
                raise parse_error2
        
        return policy_json, rules
    except Exception as e:
        # On failure, return empty structures rather than raising in UI
        logger.error(f"Error loading policy {policy_id}: {e}", exc_info=True)
        return {"policy": {}, "ruleCollectionGroups": []}, {
            "network": [],
            "application": [],
        }


