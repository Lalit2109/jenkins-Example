"""
Azure Service Module
Handles Azure API calls using Azure SDK with Managed Identity (web app) or service principal (local dev)
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Optional, Any
import logging

logger = logging.getLogger(__name__)

# Check if we're in local mode first
IS_LOCAL_MODE = os.environ.get('STREAMLIT_ENVIRONMENT', '').lower() == 'local'

# Only import Azure SDK if not in local mode
if not IS_LOCAL_MODE:
    try:
        from azure.identity import DefaultAzureCredential, ClientSecretCredential
        from azure.mgmt.network import NetworkManagementClient
        from azure.mgmt.resource import ResourceManagementClient
        from azure.mgmt.web import WebSiteManagementClient
        from azure.core.exceptions import AzureError
        AZURE_SDK_AVAILABLE = True
    except ImportError as e:
        logger.warning(f"Azure SDK not available: {e}")
        AZURE_SDK_AVAILABLE = False
else:
    AZURE_SDK_AVAILABLE = False

# Configure logging for Azure Web App
import sys
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)  # Force output to stdout
    ]
)

# Always create logger
logger = logging.getLogger(__name__)

# Suppress verbose Azure SDK logging
logging.getLogger('azure').setLevel(logging.WARNING)
logging.getLogger('azure.core').setLevel(logging.WARNING)
logging.getLogger('azure.mgmt').setLevel(logging.WARNING)
logging.getLogger('urllib3').setLevel(logging.WARNING)


class AzureService:
    def __init__(self, config: Dict[str, str] = None):
        """
        Simple Azure service - only works in production mode
        In local mode: does nothing, uses sample data only
        """
        logger.info("=== AzureService.__init__ START ===")
        logger.info(f"IS_LOCAL_MODE: {IS_LOCAL_MODE}")
        logger.info(f"AZURE_SDK_AVAILABLE: {AZURE_SDK_AVAILABLE}")
        
        self.config = config or {}
        self.authenticated = False
        self.credential = None
        self.subscription_id = None
        self.network_client = None
        self.resource_client = None
        self.web_client = None
        
        # Log environment variables
        logger.info("=== Environment Variables ===")
        logger.info(f"STREAMLIT_ENVIRONMENT: {os.environ.get('STREAMLIT_ENVIRONMENT', 'not set')}")
        logger.info(f"WEBSITE_SITE_NAME: {os.environ.get('WEBSITE_SITE_NAME', 'not set')}")
        logger.info(f"AZURE_WEBAPP_NAME: {os.environ.get('AZURE_WEBAPP_NAME', 'not set')}")
        logger.info(f"AZURE_SUBSCRIPTION_ID: {os.environ.get('AZURE_SUBSCRIPTION_ID', 'not set')}")
        logger.info(f"AZURE_RESOURCE_GROUP: {os.environ.get('AZURE_RESOURCE_GROUP', 'not set')}")
        logger.info(f"AZURE_TENANT_ID: {os.environ.get('AZURE_TENANT_ID', 'not set')}")
        logger.info(f"AZURE_CLIENT_ID: {os.environ.get('AZURE_CLIENT_ID', 'not set')}")
        logger.info(f"AZURE_CLIENT_SECRET: {'***' if os.environ.get('AZURE_CLIENT_SECRET') else 'not set'}")
        
        # Only try Azure setup if not in local mode
        if not IS_LOCAL_MODE:
            logger.info("Not in local mode - attempting Azure setup")
            self._setup_authentication()
        else:
            logger.info("Local mode - skipping Azure setup")
        
        logger.info("=== AzureService.__init__ END ===")
        
    def _setup_authentication(self):
        """Setup Azure authentication - only called in production mode"""
        logger.info("=== _setup_authentication START ===")
        
        if not AZURE_SDK_AVAILABLE:
            logger.warning("Azure SDK not available - skipping authentication setup")
            self.authenticated = False
            return
            
        try:
            # Always prioritize subscription ID from config/environment variables
            # This allows the app to access resources in a different subscription than where it's deployed
            self.subscription_id = self.config.get('subscription_id') or os.environ.get('AZURE_SUBSCRIPTION_ID')
            logger.info(f"Target subscription ID: {self.subscription_id}")
            
            # Check if running in Azure Web App environment
            if os.environ.get('WEBSITE_SITE_NAME') or os.environ.get('AZURE_WEBAPP_NAME'):
                logger.info("Detected Azure Web App environment - using Managed Identity")
                self.credential = DefaultAzureCredential()
                logger.info("Using Managed Identity for cross-subscription access")
            else:
                logger.info("Not in Azure Web App environment - checking for service principal")
                # Use service principal for local development
                tenant_id = self.config.get('tenant_id') or os.environ.get('AZURE_TENANT_ID')
                client_id = self.config.get('client_id') or os.environ.get('AZURE_CLIENT_ID')
                client_secret = self.config.get('client_secret') or os.environ.get('AZURE_CLIENT_SECRET')
                
                logger.info(f"Service principal config - tenant_id: {'***' if tenant_id else 'not set'}")
                logger.info(f"Service principal config - client_id: {'***' if client_id else 'not set'}")
                logger.info(f"Service principal config - client_secret: {'***' if client_secret else 'not set'}")
                logger.info(f"Service principal config - subscription_id: {self.subscription_id or 'not set'}")
                
                if all([tenant_id, client_id, client_secret, self.subscription_id]):
                    logger.info("Using service principal authentication (local development)")
                    self.credential = ClientSecretCredential(
                        tenant_id=tenant_id,
                        client_id=client_id,
                        client_secret=client_secret
                    )
                else:
                    logger.info("No service principal config found - using Managed Identity")
                    self.credential = DefaultAzureCredential()
                    self.subscription_id = os.environ.get('AZURE_SUBSCRIPTION_ID')
            
            if not self.subscription_id:
                logger.warning("No subscription ID found - Azure API calls will fail")
                self.authenticated = False
                return
                
            # Initialize Azure clients only if we have credentials and subscription ID
            if self.credential and self.subscription_id:
                logger.info(f"Initializing Azure clients for subscription: {self.subscription_id}")
                self.network_client = NetworkManagementClient(self.credential, self.subscription_id)
                self.resource_client = ResourceManagementClient(self.credential, self.subscription_id)
                self.web_client = WebSiteManagementClient(self.credential, self.subscription_id)
                
                self.authenticated = True
                logger.info("Azure authentication setup successful for cross-subscription access")
            else:
                if not self.credential:
                    logger.warning("No credentials available - Azure API calls will fail")
                if not self.subscription_id:
                    logger.warning("No subscription ID provided - Azure API calls will fail")
                self.authenticated = False
                
        except Exception as e:
            logger.error(f"Failed to setup Azure authentication: {str(e)}")
            self.authenticated = False
        
        logger.info("=== _setup_authentication END ===")

    def get_firewall_policy(self, policy_name: str, resource_group_name: str, subscription_id: str = None) -> Optional[Dict[str, Any]]:
        """
        Get a specific firewall policy by name
        
        Args:
            policy_name: Name of the firewall policy
            resource_group_name: Name of the resource group
            subscription_id: Subscription ID (optional, uses instance subscription if not provided)
            
        Returns:
            Firewall policy dictionary or None if not found
        """
        if not self.authenticated:
            logger.error("Not authenticated with Azure")
            return None
        
        try:
            # Use provided subscription or instance subscription
            sub_id = subscription_id or self.subscription_id
            if not sub_id:
                logger.error("No subscription ID provided")
                return None
            
            logger.info(f"Getting firewall policy '{policy_name}' from resource group '{resource_group_name}' in subscription '{sub_id}'")
            logger.info(f"Using network client: {self.network_client}")
            logger.info(f"Network client subscription: {sub_id}")
            
            # Get the policy
            logger.info("🔍 About to call network_client.firewall_policies.get()...")
            policy = self.network_client.firewall_policies.get(resource_group_name, policy_name)
            logger.info("🔍 network_client.firewall_policies.get() call completed")
            logger.info(f"Policy retrieved: {policy.name if policy else 'None'}")
            
            policy_dict = {
                'id': policy.id,
                'name': policy.name,
                'location': policy.location,
                'provisioning_state': policy.provisioning_state,
                'properties': {
                    'ruleCollectionGroups': []
                }
            }
            
            # Get rule collection groups
            try:
                for rcg in self.network_client.firewall_policy_rule_collection_groups.list(resource_group_name, policy_name):
                    rcg_dict = {
                        'id': rcg.id,
                        'name': rcg.name,
                        'priority': getattr(rcg, 'priority', None),  # Safe access to priority
                        'properties': {
                            'ruleCollections': []
                        }
                    }
                    
                    # Get rule collections
                    if rcg.rule_collections:
                        for rule_collection in rcg.rule_collections:
                            # Map Azure SDK rule collection types to parser-expected types
                            rc_type = rule_collection.rule_collection_type
                            if rc_type == 'FirewallPolicyFilterRuleCollection':
                                # This contains both network and application rules, we'll determine by rule type
                                mapped_type = 'FirewallPolicyFilterRuleCollection'
                            elif rc_type == 'FirewallPolicyNatRuleCollection':
                                mapped_type = 'NetworkRuleCollection'  # NAT rules are treated as network rules
                            else:
                                mapped_type = rc_type
                            
                            rule_collection_dict = {
                                'ruleCollectionType': mapped_type,
                                'name': rule_collection.name,
                                'priority': getattr(rule_collection, 'priority', None),  # Safe access to priority
                                'rules': []
                            }
                            
                            # Get rules based on type
                            if hasattr(rule_collection, 'rules'):
                                for rule in rule_collection.rules:
                                    rule_dict = {
                                        'ruleType': rule.rule_type,
                                        'name': rule.name,
                                        'priority': getattr(rule, 'priority', None),  # Safe access to priority
                                        'action': {
                                            'type': rule.action.type if hasattr(rule, 'action') and rule.action else None
                                        },
                                        'sourceAddresses': rule.source_addresses if hasattr(rule, 'source_addresses') else [],
                                        'sourceIpGroups': rule.source_ip_groups if hasattr(rule, 'source_ip_groups') else [],
                                        'sourceServiceTags': rule.source_service_tags if hasattr(rule, 'source_service_tags') else [],
                                        'destinationAddresses': rule.destination_addresses if hasattr(rule, 'destination_addresses') else [],
                                        'destinationFqdns': rule.destination_fqdns if hasattr(rule, 'destination_fqdns') else [],
                                        'destinationIpGroups': rule.destination_ip_groups if hasattr(rule, 'destination_ip_groups') else [],
                                        'destinationServiceTags': rule.destination_service_tags if hasattr(rule, 'destination_service_tags') else [],
                                        'destinationPorts': rule.destination_ports if hasattr(rule, 'destination_ports') else [],
                                        'ipProtocols': rule.ip_protocols if hasattr(rule, 'ip_protocols') else [],
                                        'fqdnTags': rule.fqdn_tags if hasattr(rule, 'fqdn_tags') else [],
                                        'targetFqdns': rule.target_fqdns if hasattr(rule, 'target_fqdns') else [],
                                        'targetUrls': rule.target_urls if hasattr(rule, 'target_urls') else [],
                                        'protocols': [
                                            {
                                                'protocolType': p.protocol_type if hasattr(p, 'protocol_type') else None,
                                                'port': p.port if hasattr(p, 'port') else None
                                            } for p in (rule.protocols if hasattr(rule, 'protocols') and rule.protocols else [])
                                        ]
                                    }
                                    rule_collection_dict['rules'].append(rule_dict)
                            
                            rcg_dict['properties']['ruleCollections'].append(rule_collection_dict)
                    
                    policy_dict['properties']['ruleCollectionGroups'].append(rcg_dict)
            except Exception as e:
                logger.warning(f"Failed to get rule collection groups for policy {policy_name}: {str(e)}")
                # Continue with empty rule collection groups
                
                # Add metadata
            policy_dict['metadata'] = {
                        'fetched_at': datetime.now().isoformat(),
                        'policy_name': policy_name,
                'resource_group': resource_group_name,
                'subscription_id': sub_id,
                'source': 'azure_sdk',
                'auth_method': 'managed_identity' if os.environ.get('WEBSITE_SITE_NAME') or os.environ.get('AZURE_WEBAPP_NAME') else 'service_principal'
            }
            
            logger.info(f"Successfully retrieved firewall policy '{policy_name}'")
            
            # Debug: Log the structure of what we're returning
            logger.info(f"Policy structure - ruleCollectionGroups count: {len(policy_dict.get('properties', {}).get('ruleCollectionGroups', []))}")
            for i, rcg in enumerate(policy_dict.get('properties', {}).get('ruleCollectionGroups', [])):
                rule_collections = rcg.get('properties', {}).get('ruleCollections', [])
                logger.info(f"  RCG {i}: {len(rule_collections)} rule collections")
                for j, rc in enumerate(rule_collections):
                    rules = rc.get('rules', [])
                    logger.info(f"    RC {j} ({rc.get('ruleCollectionType', 'unknown')}): {len(rules)} rules")
                    for k, rule in enumerate(rules[:3]):  # Log first 3 rules
                        logger.info(f"      Rule {k}: {rule.get('ruleType', 'unknown')} - {rule.get('name', 'unnamed')}")
            
            return policy_dict
            
        except AzureError as e:
            logger.error(f"Azure API error getting firewall policy: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error getting firewall policy: {str(e)}")
            return None
    
    def get_firewall_policies(self, resource_group_name: str) -> List[Dict[str, Any]]:
        """
        Get all firewall policies from a resource group
        
        Args:
            resource_group_name: Name of the resource group
            
        Returns:
            List of firewall policy dictionaries
        """
        if not self.authenticated:
            logger.error("Not authenticated with Azure")
            return []
            
        try:
            policies = []
            for policy in self.network_client.firewall_policies.list(resource_group_name):
                policy_dict = {
                    'id': policy.id,
                    'name': policy.name,
                    'location': policy.location,
                    'provisioning_state': policy.provisioning_state,
                    'rule_collection_groups': []
                }
                
                # Get rule collection groups
                try:
                    for rcg in self.network_client.firewall_policy_rule_collection_groups.list(resource_group_name, policy.name):
                        rcg_dict = {
                            'id': rcg.id,
                            'name': rcg.name,
                            'priority': rcg.priority,
                            'rule_collections': []
                        }
                        
                        # Get rule collections
                        if rcg.rule_collections:
                            for rule_collection in rcg.rule_collections:
                                rule_collection_dict = {
                                    'rule_collection_type': rule_collection.rule_collection_type,
                                    'name': rule_collection.name,
                                    'priority': rule_collection.priority,
                                    'rules': []
                                }
                                
                                # Get rules based on type
                                if hasattr(rule_collection, 'rules'):
                                    for rule in rule_collection.rules:
                                        rule_dict = {
                                            'rule_type': rule.rule_type,
                                            'name': rule.name,
                                            'priority': rule.priority,
                                            'action': rule.action.type if rule.action else None,
                                            'source_addresses': rule.source_addresses if hasattr(rule, 'source_addresses') else [],
                                            'destination_addresses': rule.destination_addresses if hasattr(rule, 'destination_addresses') else [],
                                            'destination_ports': rule.destination_ports if hasattr(rule, 'destination_ports') else [],
                                            'protocols': rule.ip_protocols if hasattr(rule, 'ip_protocols') else [],
                                            'fqdn_tags': rule.fqdn_tags if hasattr(rule, 'fqdn_tags') else [],
                                            'target_fqdns': rule.target_fqdns if hasattr(rule, 'target_fqdns') else []
                                        }
                                        rule_collection_dict['rules'].append(rule_dict)
                                
                                rcg_dict['rule_collections'].append(rule_collection_dict)
                        
                        policy_dict['rule_collection_groups'].append(rcg_dict)
                except Exception as e:
                    logger.warning(f"Failed to get rule collection groups for policy {policy.name}: {str(e)}")
                    # Continue with empty rule collection groups
                
                policies.append(policy_dict)
            
            logger.info(f"Retrieved {len(policies)} firewall policies from {resource_group_name}")
            return policies
            
        except AzureError as e:
            logger.error(f"Azure API error: {str(e)}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return []

    def get_virtual_networks(self, resource_group_name: str) -> List[Dict[str, Any]]:
        """
        Get all virtual networks from a resource group
        
        Args:
            resource_group_name: Name of the resource group
            
        Returns:
            List of virtual network dictionaries
        """
        if not self.authenticated:
            logger.error("Not authenticated with Azure")
            return []
            
        try:
            vnets = []
            for vnet in self.network_client.virtual_networks.list(resource_group_name):
                vnet_dict = {
                    'id': vnet.id,
                    'name': vnet.name,
                    'location': vnet.location,
                    'addressSpace': {
                        'addressPrefixes': [str(addr) for addr in vnet.address_space.address_prefixes]
                    },
                    'subnets': []
                }
                
                # Get subnets
                if vnet.subnets:
                    for subnet in vnet.subnets:
                        subnet_dict = {
                            'id': subnet.id,
                            'name': subnet.name,
                            'addressPrefix': subnet.address_prefix,
                            'addressPrefixes': [str(addr) for addr in subnet.address_prefixes] if subnet.address_prefixes else [subnet.address_prefix]
                        }
                        vnet_dict['subnets'].append(subnet_dict)
                
                vnets.append(vnet_dict)
            
            logger.info(f"Retrieved {len(vnets)} virtual networks from {resource_group_name}")
            return vnets
            
        except AzureError as e:
            logger.error(f"Azure API error: {str(e)}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return []

    def get_all_virtual_networks(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Get all virtual networks across all subscriptions the managed identity has access to
        
        Returns:
            Dictionary with subscription_id as key and list of VNets as value
        """
        if not self.authenticated:
            logger.error("Not authenticated with Azure")
            return {}
            
        try:
            all_vnets = {}
            
            # Get all subscriptions the managed identity has access to
            subscriptions = self._get_accessible_subscriptions()
            if not subscriptions:
                logger.warning("No accessible subscriptions found")
                return {}
            
            logger.info(f"Found {len(subscriptions)} accessible subscriptions")
            
            for subscription in subscriptions:
                sub_id = subscription['subscription_id']
                sub_name = subscription.get('display_name', sub_id)
                logger.info(f"Processing subscription: {sub_name} ({sub_id})")
                
                try:
                    # Create a new network client for this subscription
                    sub_network_client = NetworkManagementClient(self.credential, sub_id)
                    sub_resource_client = ResourceManagementClient(self.credential, sub_id)
                    
                    # Get all resource groups in this subscription
                    resource_groups = []
                    for rg in sub_resource_client.resource_groups.list():
                        resource_groups.append(rg.name)
                    
                    logger.info(f"Found {len(resource_groups)} resource groups in {sub_name}")
                    
                    # Get VNets from all resource groups
                    subscription_vnets = []
                    for rg_name in resource_groups:
                        try:
                            rg_vnets = []
                            for vnet in sub_network_client.virtual_networks.list(rg_name):
                                vnet_dict = {
                                    'id': vnet.id,
                                    'name': vnet.name,
                                    'location': vnet.location,
                                    'resource_group': rg_name,
                                    'subscription_id': sub_id,
                                    'subscription_name': sub_name,
                                    'addressSpace': {
                                        'addressPrefixes': [str(addr) for addr in vnet.address_space.address_prefixes]
                                    },
                                    'subnets': []
                                }
                                
                                # Get subnets (we need these for IP range calculation)
                                if vnet.subnets:
                                    for subnet in vnet.subnets:
                                        subnet_dict = {
                                            'id': subnet.id,
                                            'name': subnet.name,
                                            'addressPrefix': subnet.address_prefix,
                                            'addressPrefixes': [str(addr) for addr in subnet.address_prefixes] if subnet.address_prefixes else [subnet.address_prefix]
                                        }
                                        vnet_dict['subnets'].append(subnet_dict)
                                
                                rg_vnets.append(vnet_dict)
                            
                            subscription_vnets.extend(rg_vnets)
                            if rg_vnets:
                                logger.info(f"Found {len(rg_vnets)} VNets in {rg_name}")
                                
                        except Exception as e:
                            logger.warning(f"Failed to fetch VNets from {rg_name} in {sub_name}: {e}")
                            continue
                    
                    if subscription_vnets:
                        all_vnets[sub_id] = subscription_vnets
                        logger.info(f"Total VNets in {sub_name}: {len(subscription_vnets)}")
                    else:
                        logger.info(f"No VNets found in {sub_name}")
                        
                except Exception as e:
                    logger.warning(f"Failed to process subscription {sub_name}: {e}")
                    continue
            
            total_vnets = sum(len(vnets) for vnets in all_vnets.values())
            logger.info(f"Retrieved {total_vnets} VNets across {len(all_vnets)} subscriptions")
            return all_vnets
            
        except Exception as e:
            logger.error(f"Error getting all virtual networks: {str(e)}")
            return {}

    def _get_accessible_subscriptions(self) -> List[Dict[str, str]]:
        """
        Get all subscriptions the managed identity has access to
        
        Returns:
            List of subscription dictionaries
        """
        try:
            from azure.mgmt.resource import SubscriptionClient
            
            subscription_client = SubscriptionClient(self.credential)
            subscriptions = []
            
            for subscription in subscription_client.subscriptions.list():
                subscriptions.append({
                    'subscription_id': subscription.subscription_id,
                    'display_name': subscription.display_name,
                    'state': subscription.state
                })
            
            logger.info(f"Found {len(subscriptions)} accessible subscriptions")
            return subscriptions
            
        except Exception as e:
            logger.error(f"Error getting accessible subscriptions: {str(e)}")
            return []

    def get_resource_groups(self) -> List[Dict[str, Any]]:
        """
        Get all resource groups in the subscription
        
        Returns:
            List of resource group dictionaries
        """
        if not self.authenticated:
            logger.error("Not authenticated with Azure")
            return []
            
        try:
            resource_groups = []
            for rg in self.resource_client.resource_groups.list():
                rg_dict = {
                    'id': rg.id,
                    'name': rg.name,
                    'location': rg.location,
                    'provisioning_state': rg.provisioning_state,
                    'tags': rg.tags or {}
                }
                resource_groups.append(rg_dict)
            
            logger.info(f"Retrieved {len(resource_groups)} resource groups")
            return resource_groups
            
        except AzureError as e:
            logger.error(f"Azure API error: {str(e)}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return []

    def test_connection(self) -> bool:
        """
        Test Azure connection
        
        Returns:
            bool: True if connection is successful
        """
        if not self.authenticated:
            return False
            
        try:
            # Try to list resource groups as a test
            list(self.resource_client.resource_groups.list())
            logger.info("Azure connection test successful")
            return True
        except Exception as e:
            logger.error(f"Azure connection test failed: {str(e)}")
            return False
    
    def save_policy_to_file(self, policy_data: Dict[str, Any], filename: str = "firewall_policy.json"):
        """
        Save policy data to JSON file
        
        Args:
            policy_data: Policy data to save
            filename: Target filename
        """
        try:
            with open(filename, 'w') as f:
                json.dump(policy_data, f, indent=2)
            logger.info(f"Policy saved to {filename}")
        except Exception as e:
            logger.error(f"Error saving policy: {e}")
    
    
    def get_policy_name(self) -> str:
        """
        Get the firewall policy name from configuration
        
        Returns:
            Policy name or 'Unknown Policy'
        """
        return self.config.get('firewall_policy_name', 'Unknown Policy')
    

# Legacy functions for backward compatibility
def load_policy_from_file(file_path: str) -> Dict[str, Any]:
    """Load firewall policy from JSON file"""
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Failed to load policy from file {file_path}: {str(e)}")
        return {}


def get_file_creation_time(file_path: str) -> Optional[datetime]:
    """Get file creation time"""
    try:
        return datetime.fromtimestamp(os.path.getctime(file_path))
    except Exception as e:
        logger.error(f"Failed to get file creation time for {file_path}: {str(e)}")
        return None
