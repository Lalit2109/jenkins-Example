"""
Selected policy loader.

Fetches a Firewall Policy and its Rule Collection Groups for a given policy ID.
Reuses azure_service transformation logic and firewall_parser.
"""

from typing import Tuple, Dict, Any
import logging

logger = logging.getLogger(__name__)

def load_policy_rules(policy_id: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Load a single policy by its Azure resource ID.

    Returns (policy_json, rules_dict) where rules_dict has 'network' and 'application' keys.
    Reuses azure_service.get_firewall_policy to transform SDK format to parser format.
    """
    try:
        from azure_service import AzureService
        from app_config import get_azure_config
    except ImportError:
        logger.warning("Azure service not available")
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
        # Use AzureService which already has the transformation logic
        config = get_azure_config()
        config['subscription_id'] = sub_id  # Override with policy's subscription
        azure_service = AzureService(config)
        
        if not azure_service.authenticated:
            logger.error("Azure authentication failed")
            return {"policy": {}, "ruleCollectionGroups": []}, {
                "network": [],
                "application": [],
            }
        
        # Use existing method that already transforms SDK format to parser format
        policy_json = azure_service.get_firewall_policy(policy_name, rg, sub_id)
        
        if not policy_json:
            logger.error(f"Failed to fetch policy {policy_name}")
            return {"policy": {}, "ruleCollectionGroups": []}, {
                "network": [],
                "application": [],
            }
        
        logger.info(f"Fetched policy '{policy_name}' via AzureService")
        
        # Parse using firewall_parser (same as data_manager does)
        from firewall_parser import parse_firewall_policy
        rules = parse_firewall_policy(policy_json)
        
        logger.info(f"Parsed successfully: {len(rules.get('network', []))} network rules, {len(rules.get('application', []))} application rules")
        
        return policy_json, rules
    except Exception as e:
        # On failure, return empty structures rather than raising in UI
        logger.error(f"Error loading policy {policy_id}: {e}", exc_info=True)
        return {"policy": {}, "ruleCollectionGroups": []}, {
            "network": [],
            "application": [],
        }


