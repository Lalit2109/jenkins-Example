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
        
        # Transform RCGs from Azure SDK format (snake_case) to parser format (camelCase)
        # This matches how azure_service.get_firewall_policy structures the data
        rcg_dicts = []
        for rcg in rcgs:
            rcg_dict = {
                'id': rcg.id,
                'name': rcg.name,
                'priority': getattr(rcg, 'priority', None),
                'properties': {
                    'ruleCollections': []
                }
            }
            
            # Transform rule collections from snake_case to camelCase
            if hasattr(rcg, 'rule_collections') and rcg.rule_collections:
                for rule_collection in rcg.rule_collections:
                    # Map rule collection type
                    rc_type = getattr(rule_collection, 'rule_collection_type', None)
                    if rc_type == 'FirewallPolicyFilterRuleCollection':
                        mapped_type = 'FirewallPolicyFilterRuleCollection'
                    elif rc_type == 'FirewallPolicyNatRuleCollection':
                        mapped_type = 'NetworkRuleCollection'
                    else:
                        mapped_type = rc_type
                    
                    rule_collection_dict = {
                        'ruleCollectionType': mapped_type,
                        'name': getattr(rule_collection, 'name', 'Unknown'),
                        'priority': getattr(rule_collection, 'priority', None),
                        'rules': []
                    }
                    
                    # Transform rules from snake_case to camelCase
                    if hasattr(rule_collection, 'rules') and rule_collection.rules:
                        for rule in rule_collection.rules:
                            rule_dict = {
                                'ruleType': getattr(rule, 'rule_type', None),
                                'name': getattr(rule, 'name', 'Unknown'),
                                'priority': getattr(rule, 'priority', None),
                                'action': {
                                    'type': getattr(rule.action, 'type', None) if hasattr(rule, 'action') and rule.action else None
                                },
                                'sourceAddresses': getattr(rule, 'source_addresses', []) or [],
                                'sourceIpGroups': getattr(rule, 'source_ip_groups', []) or [],
                                'sourceServiceTags': getattr(rule, 'source_service_tags', []) or [],
                                'destinationAddresses': getattr(rule, 'destination_addresses', []) or [],
                                'destinationFqdns': getattr(rule, 'destination_fqdns', []) or [],
                                'destinationIpGroups': getattr(rule, 'destination_ip_groups', []) or [],
                                'destinationServiceTags': getattr(rule, 'destination_service_tags', []) or [],
                                'destinationPorts': getattr(rule, 'destination_ports', []) or [],
                                'ipProtocols': getattr(rule, 'ip_protocols', []) or [],
                                'fqdnTags': getattr(rule, 'fqdn_tags', []) or [],
                                'targetFqdns': getattr(rule, 'target_fqdns', []) or [],
                                'targetUrls': getattr(rule, 'target_urls', []) or [],
                                'protocols': []
                            }
                            
                            # Handle protocols (for application rules)
                            if hasattr(rule, 'protocols') and rule.protocols:
                                for protocol in rule.protocols:
                                    if hasattr(protocol, 'protocol_type') and hasattr(protocol, 'port'):
                                        rule_dict['protocols'].append({
                                            'protocolType': getattr(protocol, 'protocol_type', None),
                                            'port': getattr(protocol, 'port', None)
                                        })
                            
                            rule_collection_dict['rules'].append(rule_dict)
                    
                    rcg_dict['properties']['ruleCollections'].append(rule_collection_dict)
            
            rcg_dicts.append(rcg_dict)
        
        logger.info(f"Transformed {len(rcg_dicts)} RCGs with {sum(len(rcg['properties']['ruleCollections']) for rcg in rcg_dicts)} rule collections")
        
        # Structure policy_json similar to what azure_service.get_firewall_policy returns
        policy_json = {
            "policy": policy_dict,
            "ruleCollectionGroups": rcg_dicts,
        }

        # Parse the policy using the firewall_parser
        from firewall_parser import parse_firewall_policy
        
        # Format matches what azure_service uses (which works)
        logger.info(f"Calling parse_firewall_policy with structured format")
        structured_for_parser = {
            "properties": {
                "ruleCollectionGroups": rcg_dicts
            }
        }
        rules = parse_firewall_policy(structured_for_parser)
        logger.info(f"Parsed successfully: {len(rules.get('network', []))} network rules, {len(rules.get('application', []))} application rules")
        
        return policy_json, rules
    except Exception as e:
        # On failure, return empty structures rather than raising in UI
        logger.error(f"Error loading policy {policy_id}: {e}", exc_info=True)
        return {"policy": {}, "ruleCollectionGroups": []}, {
            "network": [],
            "application": [],
        }


