import json
from typing import Dict, List, Any, Optional
import ipaddress
import fnmatch
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

def search_rules(rules: dict, source: str = '', destination: str = '') -> list:
    """
    Search for rules that match the given source and/or destination.
    Handles both network and application rules, including FQDNs and partial string matches.
    Returns a list of matching rules with allow/deny info.
    """
    matches = []
    # --- Network rules (including FirewallPolicyFilterRuleCollection) ---
    for rule in rules.get('network', []):
        all_sources = rule.get('sourceAddresses', []) + rule.get('sourceIpGroups', [])
        for src in all_sources:
            src_match = True if not source else False
            try:
                # Try IP/CIDR overlap for source
                if not source or ipaddress.ip_network(source, strict=False).overlaps(ipaddress.ip_network(src, strict=False)):
                    src_match = True
            except Exception:
                # If not a valid IP/CIDR, fallback to string/partial match (for IP Groups or partial IPs)
                if not source or source in src:
                    src_match = True
            if src_match:
                all_dests = rule.get('destinationAddresses', []) + rule.get('destinationFqdns', []) + rule.get('destinationIpGroups', [])
                for dst in all_dests:
                    dst_match = True if not destination else False
                    # Try IP/CIDR match, then FQDN/wildcard/partial match
                    if not destination:
                        dst_match = True
                    else:
                        # Try IP/CIDR match
                        try:
                            if _ip_or_cidr_match(destination, dst):
                                dst_match = True
                        except Exception:
                            pass
                        # Try FQDN/wildcard/partial match
                        if _fqdn_match(destination, dst) or destination in dst:
                            dst_match = True
                    if dst_match:
                        matches.append({
                            'type': 'network',
                            'name': rule.get('name'),
                            'action': rule.get('action', rule.get('action', 'Allow')),
                            'source': src,
                            'destination': dst,
                            'details': rule
                        })
    # --- Application rules ---
    for rule in rules.get('application', []):
        all_sources = rule.get('sourceAddresses', []) + rule.get('sourceIpGroups', [])
        for src in all_sources:
            src_match = True if not source else False
            try:
                if not source or ipaddress.ip_network(source, strict=False).overlaps(ipaddress.ip_network(src, strict=False)):
                    src_match = True
            except Exception:
                if not source or source in src:
                    src_match = True
            if src_match:
                all_dests = rule.get('targetFqdns', []) + rule.get('targetUrls', [])
                for dst in all_dests:
                    dst_match = True if not destination else False
                    if not destination:
                        dst_match = True
                    else:
                        if _fqdn_match(destination, dst) or destination in dst:
                            dst_match = True
                    if dst_match:
                        matches.append({
                            'type': 'application',
                            'name': rule.get('name'),
                            'action': rule.get('action', rule.get('action', 'Allow')),
                            'source': src,
                            'destination': dst,
                            'details': rule
                        })
    return matches

def _ip_or_cidr_match(val1: str, val2: str) -> bool:
    """Return True if val1 and val2 are overlapping IPs or CIDRs."""
    try:
        net1 = ipaddress.ip_network(val1, strict=False)
        net2 = ipaddress.ip_network(val2, strict=False)
        return net1.overlaps(net2)
    except Exception:
        return False

def _fqdn_match(val1: str, val2: str) -> bool:
    """Return True if val1 matches val2 as FQDN or wildcard."""
    return fnmatch.fnmatch(val1, val2)

def compare_sources(rules: dict, source_a: str, source_b: str) -> dict:
    """
    Compare two source IPs/CIDRs and return destinations accessible by A only, B only, and both.
    Returns a dict: {'a_only': [...], 'b_only': [...], 'both': [...]} with rule details.
    """
    # Get all destinations for each source
    def get_destinations(source):
        dests = set()
        details = {}
        # Network rules
        for rule in rules.get('network', []):
            for src in rule.get('sourceAddresses', []):
                try:
                    if ipaddress.ip_network(source, strict=False).overlaps(ipaddress.ip_network(src, strict=False)):
                        for dst in rule.get('destinationAddresses', []):
                            dests.add((dst, 'network', rule.get('name'), rule.get('action', 'Allow')))
                            details[(dst, 'network', rule.get('name'))] = rule
                except Exception:
                    continue
        # Application rules
        for rule in rules.get('application', []):
            for src in rule.get('sourceAddresses', []):
                try:
                    if ipaddress.ip_network(source, strict=False).overlaps(ipaddress.ip_network(src, strict=False)):
                        for dst in rule.get('targetFqdns', []) + rule.get('targetUrls', []):
                            dests.add((dst, 'application', rule.get('name'), rule.get('action', 'Allow')))
                            details[(dst, 'application', rule.get('name'))] = rule
                except Exception:
                    continue
        return dests, details
    a_dests, a_details = get_destinations(source_a)
    b_dests, b_details = get_destinations(source_b)
    a_only = a_dests - b_dests
    b_only = b_dests - a_dests
    both = a_dests & b_dests
    return {
        'a_only': [{'destination': d[0], 'type': d[1], 'rule_name': d[2], 'action': d[3], 'details': a_details.get((d[0], d[1], d[2]), {})} for d in a_only],
        'b_only': [{'destination': d[0], 'type': d[1], 'rule_name': d[2], 'action': d[3], 'details': b_details.get((d[0], d[1], d[2]), {})} for d in b_only],
        'both': [{'destination': d[0], 'type': d[1], 'rule_name': d[2], 'action': d[3], 'details': a_details.get((d[0], d[1], d[2]), {})} for d in both]
    }
