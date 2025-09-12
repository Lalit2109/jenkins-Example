import streamlit as st
import json
import logging
import sys
from datetime import datetime
from firewall_parser import parse_firewall_policy, search_rules, compare_sources
import pandas as pd
from vnet_config import (
    load_environment_config, calculate_vnet_range, divide_into_subnets, 
    check_ip_overlap, get_subnet_info, SUBNET_SIZES, extract_ip_ranges_from_vnets
)
from app_config import is_feature_enabled, get_azure_config
from azure_service import AzureService, load_policy_from_file, load_vnets_from_file, get_file_creation_time
import os

# Configure logging for Azure Web App
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)  # Force output to stdout
    ]
)

logger = logging.getLogger(__name__)

# Suppress verbose Azure SDK logging
logging.getLogger('azure').setLevel(logging.WARNING)
logging.getLogger('azure.core').setLevel(logging.WARNING)
logging.getLogger('azure.mgmt').setLevel(logging.WARNING)
logging.getLogger('urllib3').setLevel(logging.WARNING)

# Simple environment detection
ENVIRONMENT = os.environ.get('STREAMLIT_ENVIRONMENT', 'production').lower()
if ENVIRONMENT not in ['local', 'production']:
    ENVIRONMENT = 'production'

# Check if we're running in Azure Web App
is_azure_webapp = os.environ.get('WEBSITE_SITE_NAME') or os.environ.get('AZURE_WEBAPP_NAME')

# Log startup information
logger.info("=== Streamlit App Startup ===")
logger.info(f"Environment: {ENVIRONMENT}")
logger.info(f"Azure Web App: {is_azure_webapp}")
logger.info(f"Working directory: {os.getcwd()}")
logger.info(f"Python path: {sys.path[:3]}...")  # First 3 entries only
logger.info("=== Streamlit App Startup Complete ===")

st.set_page_config(page_title="Azure Firewall Policy Rule Analyzer", layout="wide")

st.title("Azure Firewall Policy Rule Analyzer")

# Initialize session state
if 'policy_source' not in st.session_state:
    st.session_state.policy_source = "Auto-load JSON file"
if 'show_network_table' not in st.session_state:
    st.session_state.show_network_table = False
if 'show_app_table' not in st.session_state:
    st.session_state.show_app_table = False

# Check if features are enabled
show_file_upload = is_feature_enabled("show_file_upload")
auto_load_json = is_feature_enabled("auto_load_json")

# Sidebar: Simple controls only
with st.sidebar:
    # Simple environment indicator
    if ENVIRONMENT == 'local':
        st.success("🌍 **Local Mode** - Using sample data only")
    else:
        st.success("🌍 **Production Mode** - Azure connectivity enabled")
    
    st.markdown("---")
    st.header("Policy Source")
    
    # Debug download feature
    if st.checkbox("🔧 Debug Mode", help="Enable to download raw policy data for debugging"):
        st.session_state.debug_mode = True
    else:
        st.session_state.debug_mode = False
    
    # Policy source selection
    if show_file_upload:
        policy_source = st.radio(
            "How would you like to load your policy?",
            ("Auto-load JSON file", "Upload JSON file")
        )
    else:
        policy_source = "Auto-load JSON file"
    
    st.session_state.policy_source = policy_source
    
    uploaded_file = None
    
    if policy_source == "Upload JSON file":
        uploaded_file = st.file_uploader("Choose a JSON file", type="json")
    
    # Azure connection section (simplified)
    if ENVIRONMENT != 'local':
        st.markdown("---")
        st.header("Azure Connection")
        
        if st.button("🔄 Auto-Refresh from Azure", type="primary"):
            st.session_state.policy_source = "Connect to Azure"
            st.rerun()

# Main area: Azure connection logic
if st.session_state.get('policy_source') == "Connect to Azure":
    st.markdown("---")
    st.header("🔄 Connect to Azure")
    
    # Check if we have Azure configuration
    azure_config = get_azure_config()
    is_webapp = os.environ.get('WEBSITE_SITE_NAME') or os.environ.get('AZURE_WEBAPP_NAME')
    
    if is_webapp or all([azure_config.get('tenant_id'), azure_config.get('client_id'), 
            azure_config.get('client_secret'), azure_config.get('subscription_id'), 
            azure_config.get('resource_group')]):
        
        with st.spinner("Connecting to Azure and refreshing data..."):
            try:
                # Initialize Azure service
                logger.info("Initializing Azure service for data refresh...")
                azure_service = AzureService(azure_config)
                logger.info(f"Azure service initialized. Authenticated: {azure_service.authenticated}")
                
                if azure_service.authenticated:
                    # Test the actual connection
                    logger.info("Testing Azure connection...")
                    if azure_service.test_connection():
                        st.success("✅ Azure authentication and connection successful!")
                        logger.info("Azure connection test passed")
                    else:
                        st.warning("⚠️ Azure authentication successful but connection test failed")
                        logger.warning("Azure connection test failed")
                    
                    if is_webapp:
                        st.info("🌐 **Web App Mode**: Using Managed Identity for cross-subscription access")
                    else:
                        st.info("💻 **Local Mode**: Using Service Principal for cross-subscription access")
                    
                    # Show target subscription information
                    target_subscription = azure_config.get('subscription_id')
                    if target_subscription:
                        st.info(f"🎯 **Target Subscription**: `{target_subscription}`")
                        st.info("📋 **Required Permissions**: The Managed Identity needs 'Network Contributor' or 'Reader' role on the target subscription")
                    else:
                        st.warning("⚠️ No target subscription configured - set AZURE_SUBSCRIPTION_ID environment variable")
                    
                    # Get resource group
                    resource_group = azure_config.get('resource_group') or st.text_input(
                        "Resource Group Name", 
                        help="Enter the Azure resource group containing your firewall policy"
                    )
                    
                    if resource_group:
                        # Get firewall policy name
                        policy_name = azure_config.get('firewall_policy_name') or st.text_input("Firewall Policy Name", 
                                                  help="Enter the name of your firewall policy to refresh")
                        
                        if policy_name:
                            if st.button("🔄 Refresh Firewall Policy", type="primary"):
                                with st.spinner("Refreshing firewall policy..."):
                                    # Get subscription ID from config
                                    subscription_id = azure_config.get('subscription_id')
                                    logger.info(f"Refreshing policy '{policy_name}' from resource group '{resource_group}' in subscription '{subscription_id}'")
                                    policy_data = azure_service.get_firewall_policy(policy_name, resource_group, subscription_id)
                                    if policy_data:
                                        azure_service.save_policy_to_file(policy_data)
                                        st.success("✅ Firewall policy refreshed successfully!")
                                        
                                        # Show authentication method used
                                        auth_method = policy_data.get('metadata', {}).get('auth_method', 'unknown')
                                        if auth_method == 'managed_identity':
                                            st.info("🔐 **Authentication**: Managed Identity (Web App)")
                                        else:
                                            st.info("🔐 **Authentication**: Service Principal (Local)")
                                        
                                        # Also refresh VNets if enabled
                                        if is_feature_enabled("enable_vnet_azure_integration"):
                                            vnet_data = azure_service.get_virtual_networks(resource_group)
                                            if vnet_data:
                                                azure_service.save_vnets_to_file(vnet_data)
                                                st.success("✅ VNet data also refreshed!")
                                        
                                        # Reset the trigger
                                        st.session_state.policy_source = "Auto-load JSON file"
                                        st.rerun()
                                    else:
                                        st.error("❌ Failed to refresh firewall policy")
                                        st.info("💡 **Troubleshooting**: Check the logs for detailed error information")
                    else:
                        st.warning("⚠️ Please enter a resource group name")
                else:
                    st.error("Azure authentication failed")
                    
            except Exception as e:
                st.error(f"Auto-refresh failed: {e}")
                if is_webapp:
                    st.info("Please check your Managed Identity permissions in Azure")
                else:
                    st.info("Please check your Azure configuration in app_config.py or environment variables")
    else:
        st.warning("⚠️ Azure configuration incomplete")
        st.info("**Required environment variables:**")
        st.code("""
AZURE_SUBSCRIPTION_ID=your-subscription-id
AZURE_RESOURCE_GROUP=your-resource-group-name
AZURE_FIREWALL_POLICY_NAME=your-firewall-policy-name
        """)

# Load policy data
policy_json = None
rules = None

# Get the current policy source from session state
current_policy_source = st.session_state.get('policy_source', 'Auto-load JSON file')

if current_policy_source == "Auto-load JSON file" and auto_load_json:
    # Load policy based on environment
    policy_data = None
    if ENVIRONMENT == 'local':
        # Local environment: use sample data
        if os.path.exists("sample_data/sample_policy.json"):
            logger.info("Loading sample policy data...")
            policy_data = load_policy_from_file("sample_data/sample_policy.json")
            logger.info("Sample policy data loaded successfully")
            st.success("✅ Loaded sample policy data")
        else:
            logger.error("Sample policy file not found")
            st.error("❌ Sample policy file not found")
    else:
        # Production environment: try real data first, fallback to sample
        logger.info("Production environment - attempting to load policy data")
        if os.path.exists("firewall_policy.json"):
            logger.info("Loading Azure policy data...")
            policy_data = load_policy_from_file("firewall_policy.json")
            logger.info("Azure policy data loaded successfully")
            st.success("✅ Loaded Azure policy data")
        elif os.path.exists("sample_data/sample_policy.json"):
            logger.info("Loading sample policy data as fallback...")
            policy_data = load_policy_from_file("sample_data/sample_policy.json")
            logger.info("Sample policy data loaded as fallback")
            st.warning("⚠️ Using sample data (real policy not found)")
    
    if policy_data:
        # Debug mode: Show download option
        if st.session_state.get('debug_mode', False):
            st.markdown("---")
            st.markdown("### 🔧 Debug Information")
            
            # Show policy metadata
            if 'metadata' in policy_data:
                st.json(policy_data['metadata'])
            
            # Download raw policy data
            policy_json_str = json.dumps(policy_data, indent=2)
            st.download_button(
                label="📥 Download Raw Policy Data (JSON)",
                data=policy_json_str,
                file_name=f"firewall_policy_raw_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json",
                help="Download the raw policy data as returned by Azure SDK for debugging"
            )
        
        # Extract actual policy data from metadata structure
        if 'data' in policy_data:
            policy_json = policy_data['data']
        else:
            policy_json = policy_data
        
        rules = parse_firewall_policy(policy_json)
elif uploaded_file:
    policy_json = json.load(uploaded_file)
    rules = parse_firewall_policy(policy_json)

# Main area: Policy preview (if loaded)
if rules:
    with st.expander("📊 Policy Summary", expanded=False):
        col1, col2, col3 = st.columns(3)
        with col1:
            if st.button(f"Network Rules: {len(rules['network'])}", key="network_rules_btn"):
                st.session_state.show_network_table = not st.session_state.get('show_network_table', False)
        with col2:
            if st.button(f"Application Rules: {len(rules['application'])}", key="app_rules_btn"):
                st.session_state.show_app_table = not st.session_state.get('show_app_table', False)
        with col3:
            st.metric("Total Rules", len(rules['network']) + len(rules['application']))
    
    
    # Network Rules Table
    if st.session_state.get('show_network_table', False):
        with st.expander("📋 Network Rules Details", expanded=True):
            network_data = []
            for rule in rules['network']:
                # Extract source information
                source_type = "IP/CIDR"
                source = ", ".join(rule.get('sourceAddresses', [])) if rule.get('sourceAddresses') else "Any"
                
                # Extract protocol information
                protocols = rule.get('protocols', [])
                if protocols:
                    protocol_info = []
                    for proto in protocols:
                        if isinstance(proto, dict):
                            proto_type = proto.get('protocolType', 'Unknown')
                            port = proto.get('port', 'Any')
                            protocol_info.append(f"{proto_type}:{port}")
                        else:
                            protocol_info.append(str(proto))
                    protocol = ", ".join(protocol_info)
                else:
                    protocol = "Any"
                
                # Extract destination information
                destination_type = "IP/CIDR"
                destination = ", ".join(rule.get('destinationAddresses', [])) if rule.get('destinationAddresses') else "Any"
                
                network_data.append({
                    'Name': rule.get('name', 'Unknown'),
                    'SourceType': source_type,
                    'Source': source,
                    'Protocol': protocol,
                    'DestinationType': destination_type,
                    'Destination': destination
                })
            
            if network_data:
                st.dataframe(
                    pd.DataFrame(network_data),
                    use_container_width=True,
                    hide_index=True,
                    column_config={
                        "Name": st.column_config.TextColumn("Rule Name", width="medium"),
                        "SourceType": st.column_config.TextColumn("Source Type", width="small"),
                        "Source": st.column_config.TextColumn("Source", width="medium"),
                        "Protocol": st.column_config.TextColumn("Protocol", width="medium"),
                        "DestinationType": st.column_config.TextColumn("Dest Type", width="small"),
                        "Destination": st.column_config.TextColumn("Destination", width="medium")
                    }
                )
            else:
                st.info("No network rules found.")
    
    # Application Rules Table
    if st.session_state.get('show_app_table', False):
        with st.expander("📋 Application Rules Details", expanded=True):
            app_data = []
            for rule in rules['application']:
                # Extract source information
                source_type = "IP/CIDR"
                source = ", ".join(rule.get('sourceAddresses', [])) if rule.get('sourceAddresses') else "Any"
                
                # Extract protocol information
                protocols = rule.get('protocols', [])
                if protocols:
                    protocol_info = []
                    for proto in protocols:
                        if isinstance(proto, dict):
                            proto_type = proto.get('protocolType', 'Unknown')
                            port = proto.get('port', 'Any')
                            protocol_info.append(f"{proto_type}:{port}")
                        else:
                            protocol_info.append(str(proto))
                    protocol = ", ".join(protocol_info)
                else:
                    protocol = "Any"
                
                # Extract destination information
                destination_type = "FQDN"
                destination = ", ".join(rule.get('targetFqdns', [])) if rule.get('targetFqdns') else "Any"
                
                app_data.append({
                    'Name': rule.get('name', 'Unknown'),
                    'SourceType': source_type,
                    'Source': source,
                    'Protocol': protocol,
                    'DestinationType': destination_type,
                    'Destination': destination
                })
            
            if app_data:
                st.dataframe(
                    pd.DataFrame(app_data),
                    use_container_width=True,
                    hide_index=True,
                    column_config={
                        "Name": st.column_config.TextColumn("Rule Name", width="medium"),
                        "SourceType": st.column_config.TextColumn("Source Type", width="small"),
                        "Source": st.column_config.TextColumn("Source", width="medium"),
                        "Protocol": st.column_config.TextColumn("Protocol", width="medium"),
                        "DestinationType": st.column_config.TextColumn("Dest Type", width="small"),
                        "Destination": st.column_config.TextColumn("Destination", width="medium")
                    }
                )
            else:
                st.info("No application rules found.")

# Tabs for Search, Compare, VNet Calculator, and Network Tools
search_tab, compare_tab, vnet_tab, tools_tab = st.tabs(["Search", "Compare", "VNet Calculator", "Network Tools"])

with search_tab:
    st.subheader("Search Rule Accessibility")
    # Search functionality would go here

with compare_tab:
    st.subheader("Compare Two Source IPs/CIDRs")
    # Compare functionality would go here

with vnet_tab:
    st.subheader("🌐 VNet Calculator Tool")
    # VNet calculator functionality would go here

with tools_tab:
    st.subheader("🛠️ Network Tools & Utilities")
    # Network tools functionality would go here
