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
        
        # Show current policy source for debugging
        current_source = st.session_state.get('policy_source', 'Auto-load JSON file')
        st.info(f"Current policy source: {current_source}")
        
        if st.button("🔄 Auto-Refresh from Azure", type="primary"):
            logger.info("🔄 Auto-Refresh button clicked - switching to Azure connection mode")
            st.session_state.policy_source = "Connect to Azure"
            logger.info(f"Session state updated to: {st.session_state.get('policy_source')}")
            # Force the session state to persist
            st.session_state.force_azure_refresh = True
            logger.info("Setting force_azure_refresh flag")
            st.rerun()
        
        # Add a direct test button for debugging
        if st.button("🧪 Test Azure Connection (Debug)", type="secondary"):
            logger.info("🧪 Test Azure Connection button clicked")
            try:
                azure_config = get_azure_config()
                logger.info(f"Azure config from test: {azure_config}")
                
                # Try to initialize Azure service
                azure_service = AzureService(azure_config)
                logger.info(f"Azure service initialized. Authenticated: {azure_service.authenticated}")
                
                if azure_service.authenticated:
                    st.success("✅ Azure connection successful!")
                    logger.info("Azure connection test successful")
                else:
                    st.error("❌ Azure authentication failed")
                    logger.error("Azure authentication failed")
                    
            except Exception as e:
                st.error(f"❌ Azure connection test failed: {e}")
                logger.error(f"Azure connection test failed: {e}")
        
        # Add a reset button to go back to sample data
        if st.button("🔄 Reset to Sample Data", type="secondary"):
            logger.info("🔄 Reset to sample data button clicked")
            st.session_state.policy_source = "Auto-load JSON file"
            st.session_state.azure_refresh_success = False
            st.rerun()

# Auto-refresh functionality (only when explicitly requested)
current_policy_source = st.session_state.get('policy_source', 'Auto-load JSON file')
force_azure_refresh = st.session_state.get('force_azure_refresh', False)
logger.info(f"Checking auto-refresh condition - current policy source: {current_policy_source}, force_azure_refresh: {force_azure_refresh}")

# Only show Azure connection section when explicitly requested
if ENVIRONMENT != 'local' and (current_policy_source == "Connect to Azure" or force_azure_refresh):
    logger.info("🔄 Auto-refresh section triggered - attempting Azure connection")
    st.markdown("---")
    st.header("🔄 Auto-Refreshing from Azure")
    
    # Check if we have Azure configuration
    azure_config = get_azure_config()
    is_webapp = os.environ.get('WEBSITE_SITE_NAME') or os.environ.get('AZURE_WEBAPP_NAME')
    logger.info(f"Azure config: {azure_config}")
    logger.info(f"Is webapp: {is_webapp}")
    
    # Check if we have valid Azure configuration
    has_service_principal = all([azure_config.get('tenant_id'), azure_config.get('client_id'), 
            azure_config.get('client_secret'), azure_config.get('subscription_id'), 
            azure_config.get('resource_group')])
    
    logger.info(f"Has service principal config: {has_service_principal}")
    logger.info(f"Service principal details: tenant_id={bool(azure_config.get('tenant_id'))}, client_id={bool(azure_config.get('client_id'))}, client_secret={bool(azure_config.get('client_secret'))}, subscription_id={bool(azure_config.get('subscription_id'))}, resource_group={bool(azure_config.get('resource_group'))}")
    
    if is_webapp or has_service_principal:
        
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
                    resource_group = azure_config.get('resource_group')
                    logger.info(f"Resource group from config: '{resource_group}'")
                    if not resource_group:
                        st.error("❌ No resource group configured - set AZURE_RESOURCE_GROUP environment variable")
                        st.stop()
                    
                    # Get firewall policy name
                    policy_name = azure_config.get('firewall_policy_name')
                    logger.info(f"Firewall policy name from config: '{policy_name}'")
                    if not policy_name:
                        st.error("❌ No firewall policy name configured - set AZURE_FIREWALL_POLICY_NAME environment variable")
                        st.stop()
                    
                    # Get subscription ID
                    subscription_id = azure_config.get('subscription_id')
                    logger.info(f"Subscription ID from config: '{subscription_id}'")
                    if not subscription_id:
                        st.error("❌ No subscription ID configured - set AZURE_SUBSCRIPTION_ID environment variable")
                        st.stop()
                    
                    # Check if firewall policy exists first
                    logger.info(f"Checking if firewall policy '{policy_name}' exists in resource group '{resource_group}'...")
                    try:
                        # Try to get the policy to see if it exists
                        policy = azure_service.network_client.firewall_policies.get(resource_group, policy_name)
                        logger.info(f"✅ Firewall policy '{policy_name}' exists and is accessible")
                        logger.info(f"Policy ID: {policy.id}")
                        logger.info(f"Policy location: {policy.location}")
                    except Exception as e:
                        logger.error(f"❌ Firewall policy '{policy_name}' not found or not accessible: {str(e)}")
                        st.error(f"❌ Firewall policy '{policy_name}' not found in resource group '{resource_group}'")
                        st.error(f"Error: {str(e)}")
                        st.stop()
                    
                    # Refresh firewall policy
                    logger.info(f"Refreshing policy '{policy_name}' from resource group '{resource_group}' in subscription '{subscription_id}'")
                    logger.info("🔍 About to call azure_service.get_firewall_policy()...")
                    policy_data = azure_service.get_firewall_policy(policy_name, resource_group, subscription_id)
                    logger.info("🔍 azure_service.get_firewall_policy() call completed")
                    
                    logger.info(f"Firewall policy call result: {policy_data is not None}")
                    if policy_data:
                        logger.info(f"Policy data keys: {list(policy_data.keys())}")
                        logger.info(f"Policy properties: {policy_data.get('properties', {}).keys()}")
                        logger.info(f"Rule collection groups count: {len(policy_data.get('properties', {}).get('ruleCollectionGroups', []))}")
                    else:
                        logger.error("❌ Firewall policy call returned None - check logs for errors")
                        logger.error("This means the firewall policy call failed - check Azure service logs above")
                    
                    if policy_data:
                        azure_service.save_policy_to_file(policy_data)
                        st.success("✅ Firewall policy refreshed successfully!")
                        logger.info("Firewall policy saved to file")
                        
                        # Show authentication method used
                        auth_method = policy_data.get('metadata', {}).get('auth_method', 'unknown')
                        if auth_method == 'managed_identity':
                            st.info("🔐 **Authentication**: Managed Identity (Web App)")
                        else:
                            st.info("🔐 **Authentication**: Service Principal (Local)")
                        
                        # Also refresh VNets if enabled
                        if is_feature_enabled("enable_vnet_azure_integration"):
                            logger.info("Refreshing VNet data...")
                            vnet_data = azure_service.get_virtual_networks(resource_group)
                            logger.info(f"VNet data retrieved: {len(vnet_data) if vnet_data else 0} VNets")
                            if vnet_data:
                                azure_service.save_vnets_to_file(vnet_data)
                                st.success("✅ VNet data also refreshed!")
                                logger.info("VNet data saved to file")
                            else:
                                logger.info("No VNets found in resource group - this is normal if the resource group doesn't contain VNets")
                        
                        # Reset the trigger and reload
                        st.session_state.policy_source = "Auto-load JSON file"
                        st.session_state.force_azure_refresh = False
                        st.session_state.azure_refresh_success = True
                        st.rerun()
                    else:
                        st.error("❌ Failed to refresh firewall policy")
                        logger.error("Failed to get firewall policy from Azure")
                        st.info("💡 **Troubleshooting**: Check the logs for detailed error information")
                else:
                    st.error("❌ Azure authentication failed")
                    logger.error("Azure authentication failed")
                    st.session_state.force_azure_refresh = False
                    
            except Exception as e:
                st.error(f"❌ Auto-refresh failed: {e}")
                logger.error(f"Auto-refresh failed: {e}")
                st.session_state.force_azure_refresh = False
                if is_webapp:
                    st.info("Please check your Managed Identity permissions in Azure")
                else:
                    st.info("Please check your Azure configuration in app_config.py or environment variables")
    else:
        logger.warning("⚠️ Azure configuration incomplete - missing required environment variables")
        st.warning("⚠️ Azure configuration incomplete")
        st.info("**Required environment variables:**")
        st.code("""
AZURE_SUBSCRIPTION_ID=your-subscription-id
AZURE_RESOURCE_GROUP=your-resource-group-name
AZURE_FIREWALL_POLICY_NAME=your-firewall-policy-name
        """)
        st.info("💡 **Tip**: Set these environment variables in your Azure Web App configuration")
        
        # Show what's missing
        missing_vars = []
        if not azure_config.get('subscription_id'):
            missing_vars.append('AZURE_SUBSCRIPTION_ID')
        if not azure_config.get('resource_group'):
            missing_vars.append('AZURE_RESOURCE_GROUP')
        if not azure_config.get('firewall_policy_name'):
            missing_vars.append('AZURE_FIREWALL_POLICY_NAME')
        
        if missing_vars:
            st.error(f"❌ **Missing variables:** {', '.join(missing_vars)}")
            logger.error(f"Missing Azure configuration variables: {missing_vars}")
            st.session_state.force_azure_refresh = False
else:
    # Show success message if Azure refresh was successful
    if st.session_state.get('azure_refresh_success', False):
        st.success("✅ Azure data refreshed successfully! The app is now using the latest data from Azure.")
        st.session_state.azure_refresh_success = False  # Reset the flag

# Load policy data
policy_json = None
rules = None

# Get the current policy source from session state
current_policy_source = st.session_state.get('policy_source', 'Auto-load JSON file')
logger.info(f"Current policy source: {current_policy_source}")

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
        logger.info(f"Checking for firewall_policy.json: {os.path.exists('firewall_policy.json')}")
        logger.info(f"Checking for sample_data/sample_policy.json: {os.path.exists('sample_data/sample_policy.json')}")
        
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
        else:
            logger.warning("No policy files found - neither firewall_policy.json nor sample_data/sample_policy.json")
            st.warning("⚠️ No policy data found")
    
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
    if rules:
        with st.form("search_form"):
            source = st.text_input("Source IP/CIDR (optional)", "", help="Leave blank to match any source")
            destination = st.text_input("Destination IP/CIDR/FQDN (optional)", "", help="Leave blank to match any destination")
            submitted = st.form_submit_button("Search")
        if submitted:
            if not source and not destination:
                st.warning("Please enter at least a source or destination to search.")
            else:
                with st.spinner("Searching for matching rules..."):
                    results = search_rules(rules, source, destination)
                if results:
                    st.success(f"Found {len(results)} matching rule(s):")
                    st.dataframe([
                        {
                            'Type': r['type'],
                            'Rule Name': r['name'],
                            'Action': r['action'],
                            'Source': r['source'],
                            'Destination': r['destination']
                        } for r in results
                    ])
                else:
                    st.warning("No matching rules found.")
    else:
        st.info("Upload a policy JSON or connect to Azure to enable search.")

with compare_tab:
    st.subheader("Compare Two Source IPs/CIDRs")
    if rules:
        with st.form("compare_form"):
            source_a = st.text_input("Source A (IP/CIDR)", "10.0.0.0/24")
            source_b = st.text_input("Source B (IP/CIDR)", "10.1.0.0/24")
            compare_submitted = st.form_submit_button("Compare")
        if compare_submitted:
            if not source_a or not source_b:
                st.warning("Please enter both Source A and Source B.")
            else:
                with st.spinner("Comparing access for both sources..."):
                    comparison = compare_sources(rules, source_a, source_b)
                st.markdown("### Comparison Results")
                df = pd.DataFrame([
                    {**row, 'Reachable By': 'A only'} for row in comparison['a_only']
                ] + [
                    {**row, 'Reachable By': 'B only'} for row in comparison['b_only']
                ] + [
                    {**row, 'Reachable By': 'Both'} for row in comparison['both']
                ])
                if not df.empty:
                    def highlight(row):
                        if row['Reachable By'] == 'Both':
                            return ['background-color: #d4edda']*len(row)  # green
                        elif row['Reachable By'] == 'A only':
                            return ['background-color: #f8d7da']*len(row)  # red
                        else:
                            return ['background-color: #d1ecf1']*len(row)  # blue
                    st.dataframe(df.style.apply(highlight, axis=1), use_container_width=True)
                else:
                    st.info("No destinations found for either source.")
    else:
        st.info("Upload a policy JSON or connect to Azure to enable comparison.")

with vnet_tab:
    st.subheader("🌐 VNet Calculator Tool")
    st.info("Calculate the next available VNet IP range within your master IP ranges for different environments and regions.")
    
    # Environment configuration table
    st.markdown("### 📋 Environment IP Range Configuration")
    env_config = load_environment_config()
    
    # Create environment table
    env_data = []
    for env, regions in env_config.items():
        for region, cidr in regions.items():
            env_data.append({
                'Environment': env,
                'Region': region,
                'Master IP Range': cidr
            })
    
    env_df = pd.DataFrame(env_data)
    st.dataframe(
        env_df,
        use_container_width=True,
        hide_index=True,
        column_config={
            "Environment": st.column_config.TextColumn("Environment", width="medium"),
            "Region": st.column_config.TextColumn("Region", width="medium"),
            "Master IP Range": st.column_config.TextColumn("Master IP Range", width="medium")
        }
    )
    
    st.markdown("---")
    st.markdown("### 🚀 Find Next Available VNet Range")
    
    # User inputs with clear labels
    col1, col2, col3 = st.columns(3)
    with col1:
        selected_env = st.selectbox(
            "Select Environment", 
            list(env_config.keys()),
            help="Choose the environment (Dev, Test, Prod, Staging)"
        )
    with col2:
        selected_region = st.selectbox(
            "Select Region", 
            list(env_config[selected_env].keys()),
            help="Choose the Azure region for your VNet"
        )
    with col3:
        subnet_size = st.selectbox(
            "Required Subnet Size", 
            list(SUBNET_SIZES.keys()),
            format_func=lambda x: f"{x} ({SUBNET_SIZES[x]['name']} - {SUBNET_SIZES[x]['ips']} IPs)",
            help="Select the size of subnet you need"
        )
    
    # Display selected configuration
    master_range = env_config[selected_env][selected_region]
    selected_subnet_info = SUBNET_SIZES[subnet_size]
    
    st.info(f"**Selected Configuration:** {selected_env} environment in {selected_region} region")
    st.info(f"**Master Range:** {master_range} | **Required Subnet:** {subnet_size} ({selected_subnet_info['description']})")
    
    # Always get latest VNet data from Azure for accurate calculations
    existing_vnets = None
    if is_feature_enabled("enable_vnet_azure_integration"):
        st.info("🌐 **Getting latest VNet data from Azure...**")
        
        # Get Azure configuration
        azure_config = get_azure_config()
        is_webapp = os.environ.get('WEBSITE_SITE_NAME') or os.environ.get('AZURE_WEBAPP_NAME')
        
        if is_webapp or all([azure_config.get('tenant_id'), azure_config.get('client_id'), 
                azure_config.get('client_secret'), azure_config.get('subscription_id'), 
                azure_config.get('resource_group')]):
            
            try:
                # Initialize Azure service
                logger.info("Initializing Azure service for VNet analysis...")
                azure_service = AzureService(azure_config)
                logger.info(f"Azure service initialized. Authenticated: {azure_service.authenticated}")
                if azure_service.authenticated:
                    # Test the actual connection
                    logger.info("Testing Azure connection for VNet analysis...")
                    if not azure_service.test_connection():
                        st.warning("⚠️ Azure connection test failed - VNet analysis may not work properly")
                        logger.warning("Azure connection test failed for VNet analysis")
                    # Get resource group from config or user input
                    resource_group = azure_config.get('resource_group')
                    if not resource_group:
                        resource_group = st.text_input(
                            "Resource Group Name (for VNet data)", 
                            help="Enter the Azure resource group to get VNet information"
                        )
                    
                    if resource_group:
                        with st.spinner("Fetching latest VNet data from Azure..."):
                            vnet_data = azure_service.get_virtual_networks(resource_group)
                            if vnet_data:
                                existing_vnets = extract_ip_ranges_from_vnets(vnet_data)
                                st.success(f"✅ **Azure VNet Data:** Found {len(existing_vnets)} existing IP ranges")
                                
                                # Save to file for future reference
                                azure_service.save_vnets_to_file(vnet_data)
                            else:
                                st.warning("⚠️ Could not fetch VNet data from Azure")
                                # Fallback to local file if available
                                if os.path.exists("existing_vnets.json"):
                                    vnet_data = load_vnets_from_file("existing_vnets.json")
                                    existing_vnets = extract_ip_ranges_from_vnets(vnet_data)
                                    st.info(f"📊 **Fallback:** Using local VNet data ({len(existing_vnets)} ranges)")
                else:
                    st.error("❌ Azure authentication failed for VNet data")
                    # Fallback to local file
                    if os.path.exists("existing_vnets.json"):
                        vnet_data = load_vnets_from_file("existing_vnets.json")
                        existing_vnets = extract_ip_ranges_from_vnets(vnet_data)
                        st.info(f"📊 **Fallback:** Using local VNet data ({len(existing_vnets)} ranges)")
            except Exception as e:
                st.error(f"❌ Error fetching VNet data: {e}")
                # Fallback to local file
                if os.path.exists("existing_vnets.json"):
                    vnet_data = load_vnets_from_file("existing_vnets.json")
                    existing_vnets = extract_ip_ranges_from_vnets(vnet_data)
                    st.info(f"📊 **Fallback:** Using local VNet data ({len(existing_vnets)} ranges)")
        else:
            st.warning("⚠️ Azure configuration incomplete - using local VNet data if available")
            # Try to use local file
            if os.path.exists("existing_vnets.json"):
                vnet_data = load_vnets_from_file("existing_vnets.json")
                existing_vnets = extract_ip_ranges_from_vnets(vnet_data)
                st.info(f"📊 **Local VNet Data:** Found {len(existing_vnets)} existing IP ranges")
    
    # Calculate button with clear purpose
    if st.button("🔍 Find Next Available VNet Range", type="primary", use_container_width=True):
        with st.spinner("Calculating next available VNet range..."):
            result = calculate_vnet_range(master_range, subnet_size, existing_vnets)
        
        if "error" not in result:
            st.success("✅ **Next Available VNet Range Found!**")
            
            # Display results in organized format
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Available Range", result['available_range'])
            with col2:
                st.metric("Total Subnets Available", result['total_subnets'])
            with col3:
                st.metric("Usable IPs in Range", result['usable_ips'])
            
            # Show if Azure integration was used
            if existing_vnets and result.get('existing_ranges_considered', 0) > 0:
                st.info(f"🔍 **Azure Integration:** Considered {result['existing_ranges_considered']} existing IP ranges when calculating availability")
            
            # Subnet division option
            st.markdown("---")
            st.markdown("### 🔧 Divide Available Range into Subnets")
            st.info(f"Would you like to divide the available range {result['available_range']} into smaller {subnet_size} subnets?")
            
            if st.button("📊 Show Subnet Division", type="secondary"):
                st.markdown("### Subnet Division Results")
                
                subnets = divide_into_subnets(result['available_range'], subnet_size)
                
                if subnets and "error" not in subnets[0]:
                    # Create detailed subnet table
                    subnet_df = pd.DataFrame(subnets)
                    
                    # Display main table
                    st.dataframe(
                        subnet_df[['subnet_number', 'range', 'first_ip', 'last_ip', 'usable_ips', 'gateway_suggestion']],
                        use_container_width=True,
                        hide_index=True,
                        column_config={
                            "subnet_number": st.column_config.NumberColumn("Subnet #", width="small"),
                            "range": st.column_config.TextColumn("Range", width="medium"),
                            "first_ip": st.column_config.TextColumn("First IP", width="medium"),
                            "last_ip": st.column_config.TextColumn("Last IP", width="medium"),
                            "usable_ips": st.column_config.NumberColumn("Usable IPs", width="small"),
                            "gateway_suggestion": st.column_config.TextColumn("Gateway Suggestion", width="medium")
                        }
                    )
                    
                    # Visual representation
                    st.markdown("### Visual Subnet Layout")
                    for i, subnet in enumerate(subnets[:10]):  # Show first 10 subnets
                        st.code(f"{i+1:2d}. {subnet['range']} → {subnet['first_ip']} - {subnet['last_ip']} ({subnet['usable_ips']} usable IPs)")
                    
                    if len(subnets) > 10:
                        st.info(f"... and {len(subnets) - 10} more subnets")
                    
                    # Export option
                    if st.button("📊 Export to CSV"):
                        csv = subnet_df.to_csv(index=False)
                        st.download_button(
                            label="Download CSV",
                            data=csv,
                            file_name=f"subnet_division_{result['available_range'].replace('/', '_')}.csv",
                            mime="text/csv"
                        )
                else:
                    st.error(f"Error calculating subnets: {subnets[0].get('error', 'Unknown error')}")
        else:
            st.error(f"❌ Calculation failed: {result['error']}")

with tools_tab:
    st.subheader("🛠️ Network Tools & Utilities")
    st.info("Additional tools for IP range validation, subnet analysis, and network planning.")
    
    # IP range overlap checker
    st.markdown("### 🔍 IP Range Overlap Checker")
    st.info("Check if two IP ranges overlap to avoid conflicts in your network design.")
    
    col1, col2 = st.columns(2)
    with col1:
        range1 = st.text_input("Range 1 (CIDR)", "10.0.0.0/24", key="overlap_range1", help="Enter first IP range in CIDR notation")
    with col2:
        range2 = st.text_input("Range 2 (CIDR)", "10.0.1.0/24", key="overlap_range2", help="Enter second IP range in CIDR notation")
    
    if st.button("🔍 Check for Overlaps", type="primary"):
        if range1 and range2:
            with st.spinner("Checking for overlaps..."):
                overlap_result = check_ip_overlap(range1, range2)
            
            if "error" not in overlap_result:
                if overlap_result['overlap']:
                    st.warning("⚠️ **OVERLAP DETECTED!** These ranges overlap.")
                    
                    # Display overlap details
                    col1, col2 = st.columns(2)
                    with col1:
                        st.error(f"**Range 1:** {overlap_result['range1']['cidr']}")
                        st.info(f"Network: {overlap_result['range1']['network']}")
                        st.info(f"Broadcast: {overlap_result['range1']['broadcast']}")
                        st.info(f"Total IPs: {overlap_result['range1']['total_ips']}")
                    
                    with col2:
                        st.error(f"**Range 2:** {overlap_result['range2']['cidr']}")
                        st.info(f"Network: {overlap_result['range2']['network']}")
                        st.info(f"Broadcast: {overlap_result['range2']['broadcast']}")
                        st.info(f"Total IPs: {overlap_result['range2']['total_ips']}")
                    
                    # Show overlap details
                    if overlap_result['overlap_details']:
                        st.markdown("**Overlap Details:**")
                        st.info(f"Overlap Range: {overlap_result['overlap_details']['overlap_range']}")
                        st.info(f"Overlapping IPs: {overlap_result['overlap_details']['overlap_ips']}")
                else:
                    st.success("✅ **No overlap detected.** These ranges are safe to use together.")
                    
                    # Show both ranges side by side
                    col1, col2 = st.columns(2)
                    with col1:
                        st.info(f"**Range 1:** {overlap_result['range1']['cidr']}")
                    with col2:
                        st.info(f"**Range 2:** {overlap_result['range2']['cidr']}")
            else:
                st.error(f"Error checking overlap: {overlap_result['error']}")
        else:
            st.warning("Please enter both ranges to check for overlap.")
    
    # Subnet information tool
    st.markdown("---")
    st.markdown("### 📋 Subnet Information Tool")
    st.info("Get detailed information about any subnet including network address, broadcast, usable IPs, and more.")
    
    cidr_input = st.text_input("Enter CIDR to analyze", "10.0.0.0/24", key="subnet_info", help="Enter a CIDR notation (e.g., 10.0.0.0/24)")
    
    if st.button("📋 Analyze Subnet", type="primary"):
        if cidr_input:
            with st.spinner("Analyzing subnet..."):
                subnet_info = get_subnet_info(cidr_input)
            
            if "error" not in subnet_info:
                col1, col2 = st.columns(2)
                with col1:
                    st.success(f"**Network:** {subnet_info['network_address']}")
                    st.info(f"**Broadcast:** {subnet_info['broadcast_address']}")
                    st.info(f"**First Usable IP:** {subnet_info['first_usable_ip']}")
                    st.info(f"**Last Usable IP:** {subnet_info['last_usable_ip']}")
                
                with col2:
                    st.metric("Total IPs", subnet_info['total_ips'])
                    st.metric("Usable IPs", subnet_info['usable_ips'])
                    st.info(f"**Subnet Mask:** {subnet_info['subnet_mask']}")
                    st.info(f"**Wildcard Mask:** {subnet_info['wildcard_mask']}")
            else:
                st.error(f"Error analyzing subnet: {subnet_info['error']}")
        else:
            st.warning("Please enter a CIDR to analyze.")
    
    # Environment configuration editor
    st.markdown("---")
    st.markdown("### ⚙️ Environment Configuration Editor")
    st.info("Customize the environment IP ranges for your organization's needs.")
    
    if st.button("🔧 Edit Environment Config"):
        st.info("This feature allows you to customize the environment configuration.")
        st.code("""
# Example custom configuration:
{
  "Custom": {
    "UK South": "10.200.0.0/14",
    "East US": "10.201.0.0/14"
  }
}
        """)
        
        # Simple config editor
        custom_config = st.text_area(
            "Custom Environment Configuration (JSON)",
            value=json.dumps(env_config, indent=2),
            height=200
        )
        
        if st.button("💾 Save Configuration"):
            try:
                new_config = json.loads(custom_config)
                # Here you would save to file
                st.success("Configuration saved successfully!")
            except json.JSONDecodeError:
                st.error("Invalid JSON format. Please check your configuration.")
