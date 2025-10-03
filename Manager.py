"""
Data Management for Azure Firewall Analyzer
Handles policy loading, Azure refresh, and data processing
"""

import streamlit as st
import logging
import json
import os
from datetime import datetime
from azure_service import AzureService
from firewall_parser import parse_firewall_policy
from app_config import get_azure_config

logger = logging.getLogger(__name__)

def get_file_creation_time(file_path):
    """Get the creation time of a file"""
    try:
        if os.path.exists(file_path):
            stat = os.stat(file_path)
            return datetime.fromtimestamp(stat.st_ctime)
        return None
    except Exception as e:
        logger.error(f"Error getting file creation time: {e}")
        return None

def save_policy_to_file(policy_data, file_path="firewall_policy.json"):
    """Save policy data to file with metadata"""
    try:
        # Create data structure with metadata
        data_with_metadata = {
            "data": policy_data,
            "metadata": {
                "created_at": datetime.now().isoformat(),
                "source": "azure",
                "version": "1.0"
            }
        }
        
        with open(file_path, 'w') as f:
            json.dump(data_with_metadata, f, indent=2)
        
        logger.info(f"Policy data saved to {file_path}")
        return True
    except Exception as e:
        logger.error(f"Error saving policy to file: {e}")
        return False

def save_vnet_data_to_file(vnet_data, file_path="vnet_data.json"):
    """Save VNet data to file with metadata"""
    try:
        # Create data structure with metadata
        data_with_metadata = {
            "data": vnet_data,
            "metadata": {
                "created_at": datetime.now().isoformat(),
                "source": "azure",
                "version": "1.0"
            }
        }
        
        with open(file_path, 'w') as f:
            json.dump(data_with_metadata, f, indent=2)
        
        logger.info(f"VNet data saved to {file_path}")
        return True
    except Exception as e:
        logger.error(f"Error saving VNet data to file: {e}")
        return False

def load_vnet_data_from_file(file_path="vnet_data.json"):
    """Load VNet data from file"""
    try:
        if os.path.exists(file_path):
            with open(file_path, 'r') as f:
                data = json.load(f)
            logger.info(f"VNet data loaded from {file_path}")
            return data
        return None
    except Exception as e:
        logger.error(f"Error loading VNet data from file: {e}")
        return None

def load_policy_from_file(file_path="firewall_policy.json"):
    """Load policy data from file"""
    try:
        if os.path.exists(file_path):
            with open(file_path, 'r') as f:
                data = json.load(f)
            logger.info(f"Policy data loaded from {file_path}")
            return data
        return None
    except Exception as e:
        logger.error(f"Error loading policy from file: {e}")
        return None

def initialize_azure_service():
    """Initialize Azure service and return the instance"""
    try:
        # Get configuration using the existing function
        config = get_azure_config()
        
        logger.info(f"Azure configuration: subscription_id={config['subscription_id']}, resource_group={config['resource_group']}, firewall_policy_name={config['firewall_policy_name']}")
        
        azure_service = AzureService(config)
        logger.info("✅ Azure service initialized successfully")
        return azure_service
    except Exception as e:
        logger.error(f"❌ Failed to initialize Azure service: {e}")
        return None

def refresh_azure_data():
    """Refresh data from Azure and return success status, message, and data"""
    try:
        # Get configuration using the existing function
        config = get_azure_config()
        
        logger.info(f"Refreshing Azure data with config: subscription_id={config['subscription_id']}, resource_group={config['resource_group']}, firewall_policy_name={config['firewall_policy_name']}")
        
        azure_service = AzureService(config)
        
        # Test connection first
        if not azure_service.test_connection():
            return False, "Azure connection failed", None
        
        # Get firewall policy
        policy_data = azure_service.get_firewall_policy(
            policy_name=config.get('firewall_policy_name', ''),
            resource_group_name=config.get('resource_group', ''),
            subscription_id=config.get('subscription_id', '')
        )
        if not policy_data:
            return False, "Failed to fetch firewall policy data", None
        
        # Save data to file
        save_success = save_policy_to_file(policy_data)
        if not save_success:
            logger.warning("Failed to save policy data to file, but continuing...")
        
        # Store data in session state
        st.session_state.policy_data = policy_data
        st.session_state.azure_policy_name = config.get('firewall_policy_name', 'Unknown Policy')
        st.session_state.loaded_file_name = "firewall_policy.json"
        st.session_state.file_creation_time = get_file_creation_time("firewall_policy.json")
        
        # Update policy source to Azure
        st.session_state.policy_source = "Connect to Azure"
        
        return True, "Data refreshed successfully from Azure", policy_data
        
    except Exception as e:
        logger.error(f"Error refreshing Azure data: {e}")
        return False, f"Error refreshing data: {str(e)}", None

def refresh_vnet_data():
    """Refresh VNet data from Azure across all accessible subscriptions and return success status, message, and data"""
    try:
        # Get configuration using the existing function
        config = get_azure_config()
        
        logger.info(f"Refreshing VNet data with config: subscription_id={config['subscription_id']}")
        
        azure_service = AzureService(config)
        
        # Test connection first
        if not azure_service.test_connection():
            return False, "Azure connection failed", None
        
        # Get all VNets across all accessible subscriptions
        logger.info("🔍 Fetching VNets from all accessible subscriptions...")
        all_vnets = azure_service.get_all_virtual_networks()
        
        if not all_vnets:
            return False, "No VNets found in any accessible subscription", None
        
        # Calculate total VNets
        total_vnets = sum(len(vnets) for vnets in all_vnets.values())
        total_subscriptions = len(all_vnets)
        
        logger.info(f"✅ Found {total_vnets} VNets across {total_subscriptions} subscriptions")
        
        # Save VNet data to file
        save_success = save_vnet_data_to_file(all_vnets)
        if not save_success:
            logger.warning("Failed to save VNet data to file, but continuing...")
        
        # Store data in session state
        st.session_state.vnet_data = all_vnets
        st.session_state.vnet_data_loaded = True
        st.session_state.vnet_file_creation_time = get_file_creation_time("vnet_data.json")
        
        return True, f"VNet data refreshed successfully from Azure ({total_vnets} VNets from {total_subscriptions} subscriptions)", all_vnets
        
    except Exception as e:
        logger.error(f"Error refreshing VNet data: {e}")
        return False, f"Error refreshing VNet data: {str(e)}", None

def load_policy_data(policy_source, azure_service, environment="local"):
    """Load policy data based on the selected source"""
    logger.info(f"🔄 Loading policy data - source: {policy_source}, environment: {environment}")
    policy_json = None
    rules = None
    
    if policy_source == "Auto-load JSON file":
        logger.info("📁 Using Auto-load JSON file mode")
        # In production mode, first try to load from firewall_policy.json
        if environment == "production":
            logger.info("🏭 Production mode - trying to load from firewall_policy.json")
            policy_data = load_policy_from_file("firewall_policy.json")
            if policy_data:
                # Extract actual policy data from metadata structure
                if isinstance(policy_data, dict) and 'data' in policy_data:
                    policy_json = policy_data['data']
                    logger.info(f"Extracted policy data from 'data' key, type: {type(policy_json)}")
                else:
                    policy_json = policy_data
                    logger.info(f"Using policy data directly, type: {type(policy_json)}")
                
                rules = parse_firewall_policy(policy_json)
                st.session_state.loaded_file_name = "firewall_policy.json"
                st.session_state.file_creation_time = get_file_creation_time("firewall_policy.json")
                logger.info("✅ Production policy data loaded from file successfully")
            else:
                # Fallback to sample data
                logger.info("⚠️ firewall_policy.json not found - falling back to sample data")
                policy_data = load_policy_from_file('sample_data/sample_policy.json')
                if policy_data:
                    if isinstance(policy_data, dict) and 'data' in policy_data:
                        policy_json = policy_data['data']
                    else:
                        policy_json = policy_data
                    
                    rules = parse_firewall_policy(policy_json)
                    st.session_state.loaded_file_name = "sample_policy.json"
                    st.session_state.file_creation_time = get_file_creation_time('sample_data/sample_policy.json')
                    logger.info("✅ Fallback to sample policy data loaded successfully")
        else:
            # Local mode - load sample data
            policy_data = load_policy_from_file('sample_data/sample_policy.json')
            if policy_data:
                if isinstance(policy_data, dict) and 'data' in policy_data:
                    policy_json = policy_data['data']
                else:
                    policy_json = policy_data
                
                rules = parse_firewall_policy(policy_json)
                st.session_state.loaded_file_name = "sample_policy.json"
                st.session_state.file_creation_time = get_file_creation_time('sample_data/sample_policy.json')
                logger.info("✅ Sample policy data loaded successfully")
    
    elif policy_source == "Upload JSON file":
        # Handle file upload
        uploaded_file = st.file_uploader("Choose a JSON file", type="json")
        if uploaded_file:
            try:
                policy_json = json.load(uploaded_file)
                rules = parse_firewall_policy(policy_json)
                st.session_state.loaded_file_name = uploaded_file.name
                st.session_state.file_creation_time = None  # Uploaded files don't have creation time
                logger.info(f"✅ Uploaded file {uploaded_file.name} processed successfully")
            except Exception as e:
                logger.error(f"Error processing uploaded file: {e}")
                st.error(f"Error processing uploaded file: {str(e)}")
    
    elif policy_source == "Connect to Azure":
        logger.info("☁️ Using Connect to Azure mode")
        # Load from Azure - fetch fresh data if not in session state
        if st.session_state.get('policy_data'):
            logger.info("📦 Using cached Azure data from session state")
            policy_data = st.session_state.policy_data
            
            # Extract actual policy data from metadata structure
            if isinstance(policy_data, dict) and 'data' in policy_data:
                policy_json = policy_data['data']
                logger.info(f"Extracted Azure policy data from 'data' key, type: {type(policy_json)}")
            else:
                policy_json = policy_data
                logger.info(f"Using Azure policy data directly, type: {type(policy_json)}")
            
            rules = parse_firewall_policy(policy_json)
            logger.info("✅ Azure policy data loaded from session state successfully")
        else:
            logger.info("🔄 No cached Azure data - fetching fresh data from Azure")
            # Fetch fresh data from Azure
            success, message, policy_data = refresh_azure_data()
            if success and policy_data:
                # Extract actual policy data from metadata structure
                if isinstance(policy_data, dict) and 'data' in policy_data:
                    policy_json = policy_data['data']
                    logger.info(f"Extracted fresh Azure policy data from 'data' key, type: {type(policy_json)}")
                else:
                    policy_json = policy_data
                    logger.info(f"Using fresh Azure policy data directly, type: {type(policy_json)}")
                
                rules = parse_firewall_policy(policy_json)
                logger.info("✅ Fresh Azure policy data loaded successfully")
            else:
                logger.error(f"❌ Failed to fetch Azure data: {message}")
                # Fallback to sample data
                logger.info("⚠️ Falling back to sample data")
                policy_data = load_policy_from_file('sample_data/sample_policy.json')
                if policy_data:
                    if isinstance(policy_data, dict) and 'data' in policy_data:
                        policy_json = policy_data['data']
                    else:
                        policy_json = policy_data
                    
                    rules = parse_firewall_policy(policy_json)
                    st.session_state.loaded_file_name = "sample_policy.json"
                    st.session_state.file_creation_time = get_file_creation_time('sample_data/sample_policy.json')
                    logger.info("✅ Fallback to sample policy data loaded successfully")
    
    return policy_json, rules

def load_vnet_data(environment="local"):
    """Load VNet data based on environment"""
    logger.info(f"🔄 Loading VNet data - environment: {environment}")
    
    # Try to load from cached file first
    vnet_data = load_vnet_data_from_file("vnet_data.json")
    if vnet_data:
        # Extract actual VNet data from metadata structure
        if isinstance(vnet_data, dict) and 'data' in vnet_data:
            actual_vnet_data = vnet_data['data']
            logger.info(f"Extracted VNet data from 'data' key, type: {type(actual_vnet_data)}")
        else:
            actual_vnet_data = vnet_data
            logger.info(f"Using VNet data directly, type: {type(actual_vnet_data)}")
        
        # Ensure data is in dict format (resource_group -> vnets)
        if isinstance(actual_vnet_data, list):
            # Convert list to dict format
            actual_vnet_data = {"sample": actual_vnet_data}
            logger.info("Converted list VNet data to dict format")
        
        # Store in session state
        st.session_state.vnet_data = actual_vnet_data
        st.session_state.vnet_data_loaded = True
        st.session_state.vnet_file_creation_time = get_file_creation_time("vnet_data.json")
        logger.info("✅ Cached VNet data loaded successfully")
        return actual_vnet_data
    
    # Fallback to sample data
    logger.info("⚠️ No cached VNet data found - using sample data")
    sample_data = load_vnet_data_from_file('sample_data/sample_vnets.json')
    if sample_data:
        if isinstance(sample_data, dict) and 'data' in sample_data:
            actual_vnet_data = sample_data['data']
        else:
            actual_vnet_data = sample_data
        
        # Ensure data is in dict format
        if isinstance(actual_vnet_data, list):
            actual_vnet_data = {"sample": actual_vnet_data}
            logger.info("Converted sample list VNet data to dict format")
        
        # Store in session state
        st.session_state.vnet_data = actual_vnet_data
        st.session_state.vnet_data_loaded = True
        st.session_state.vnet_file_creation_time = get_file_creation_time('sample_data/sample_vnets.json')
        logger.info("✅ Sample VNet data loaded successfully")
        return actual_vnet_data
    
    # No data available
    logger.warning("❌ No VNet data available")
    st.session_state.vnet_data = {}
    st.session_state.vnet_data_loaded = False
    return {}

def handle_background_refresh():
    """Handle background refresh when show_refresh_modal is True"""
    if st.session_state.get('show_refresh_modal', False):
        try:
            logger.info("🔄 Starting background refresh from Azure...")
            success, message, policy_data = refresh_azure_data()
            
            if success:
                # Update session state (policy_source already updated in refresh_azure_data)
                st.session_state.azure_refresh_success = True
                
                # Show success message briefly
                st.success("✅ Data refreshed successfully from Azure!")
                logger.info("✅ Background refresh completed successfully")
            else:
                st.error(f"❌ Refresh failed: {message}")
                logger.error(f"❌ Background refresh failed: {message}")
                
            # Close refresh modal
            st.session_state.show_refresh_modal = False
            st.rerun()
            
        except Exception as e:
            st.error(f"❌ Unexpected error during refresh: {str(e)}")
            logger.error(f"❌ Background refresh error: {e}")
            st.session_state.show_refresh_modal = False
            st.rerun()

def get_policy_summary_data(rules):
    """Get summary data for policy display"""
    if not rules:
        return {
            'network_rules': 0,
            'app_rules': 0,
            'total_rules': 0,
            'has_data': False
        }
    
    network_rules = len(rules.get('network', []))
    app_rules = len(rules.get('application', []))
    total_rules = network_rules + app_rules
    
    return {
        'network_rules': network_rules,
        'app_rules': app_rules,
        'total_rules': total_rules,
        'has_data': total_rules > 0
    }
