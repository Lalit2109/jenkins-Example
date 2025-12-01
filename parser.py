import json
from typing import Dict, List, Any, Optional
import logging

# Ensure logging is configured
logger = logging.getLogger(__name__)

def parse_firewall_policy(policy_json: Any) -> Dict[str, List[dict]]:
    """
    Extract network and application rule collections from Azure Firewall Policy JSON.
    Supports both ARM (dict with 'properties' and 'ruleCollectionGroups') and CLI/list format.
    Returns a dict with 'network' and 'application' keys.
    """
    network_rules = []
    application_rules = []

    # --- ARM/Portal/SDK format: dict with 'properties' and 'ruleCollectionGroups' ---
    if isinstance(policy_json, dict) and 'properties' in policy_json:
        groups = policy_json.get('properties', {}).get('ruleCollectionGroups', [])
        for i, group in enumerate(groups):
            if isinstance(group, dict):
                collections = group.get('properties', {}).get('ruleCollections', [])
            else:
                continue
            
            
            for collection in collections:
                # Accept both ARM and CLI casing/types
                rc_type = collection.get('ruleCollectionType', '').lower()
                rules = collection.get('rules', [])

                # Handle different rule types
                collection_name = collection.get('name', 'Unknown')
                if rc_type in ['networkrulecollection', 'firewallpolicyfilterrulecollection']:
                    for rule in rules:
                        rule_type = rule.get('ruleType', '').lower()
                        # Add rule collection name to the rule
                        rule['ruleCollectionName'] = collection_name
                        if rule_type == 'networkrule':
                            network_rules.append(rule)
                        elif rule_type == 'applicationrule':
                            application_rules.append(rule)
                elif rc_type == 'applicationrulecollection':
                    for rule in rules:
                        rule_type = rule.get('ruleType', '').lower()
                        # Add rule collection name to the rule
                        rule['ruleCollectionName'] = collection_name
                        if rule_type == 'applicationrule':
                            application_rules.append(rule)
    # --- CLI/Flat format: list of rule collection groups ---
    elif isinstance(policy_json, list):
        for group in policy_json:
            # Handle both direct ruleCollections and nested properties.ruleCollections
            collections = group.get('ruleCollections', [])
            if not collections and 'properties' in group:
                collections = group.get('properties', {}).get('ruleCollections', [])
            
            for collection in collections:
                # Accept both ARM and CLI casing/types
                rc_type = collection.get('ruleCollectionType', '').lower()
                rules = collection.get('rules', [])
                collection_name = collection.get('name', 'Unknown')
                
                # Debug logging
                
                # Handle different rule types (case insensitive)
                if rc_type.lower() in ['networkrulecollection', 'firewallpolicyfilterrulecollection']:
                    for rule in rules:
                        rule_type = rule.get('ruleType', '').lower()
                        # Add rule collection name to the rule
                        rule['ruleCollectionName'] = collection_name
                        if rule_type == 'networkrule':
                            network_rules.append(rule)
                        elif rule_type == 'applicationrule':
                            application_rules.append(rule)
                        else:
                            pass  # Unknown rule type, skip
                elif rc_type == 'applicationrulecollection':
                    for rule in rules:
                        rule_type = rule.get('ruleType', '').lower()
                        # Add rule collection name to the rule
                        rule['ruleCollectionName'] = collection_name
                        if rule_type == 'applicationrule':
                            application_rules.append(rule)
    else:
        # Unknown format
        raise ValueError("Unsupported Azure Firewall Policy format.")

    return {'network': network_rules, 'application': application_rules}
