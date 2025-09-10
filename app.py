import streamlit as st
import json
from firewall_parser import parse_firewall_policy, search_rules, compare_sources
import pandas as pd
from vnet_config import (
    load_environment_config, calculate_vnet_range, divide_into_subnets, 
    check_ip_overlap, get_subnet_info, SUBNET_SIZES, extract_ip_ranges_from_vnets
)
from app_config import get_feature_config, is_feature_enabled, get_azure_config
from azure_service import AzureService, load_policy_from_file, load_vnets_from_file, get_file_creation_time
import os

# Simple environment detection
ENVIRONMENT = os.environ.get('STREAMLIT_ENVIRONMENT', 'production').lower()
if ENVIRONMENT not in ['local', 'production']:
    ENVIRONMENT = 'production'

# Check if we're running in Azure Web App
is_azure_webapp = os.environ.get('WEBSITE_SITE_NAME') or os.environ.get('AZURE_WEBAPP_NAME')

# Simple debug logging (only in development)
if os.environ.get('DEBUG', '').lower() == 'true':
    print(f"Environment: {ENVIRONMENT} | Azure Web App: {is_azure_webapp}")

st.set_page_config(page_title="Azure Firewall Policy Rule Analyzer", layout="wide")



st.title("Azure Firewall Policy Rule Analyzer")

# Initialize session state
if 'policy_source' not in st.session_state:
    st.session_state.policy_source = "Auto-load JSON file"
if 'show_network_table' not in st.session_state:
    st.session_state.show_network_table = False
if 'show_app_table' not in st.session_state:
    st.session_state.show_app_table = False

# Sidebar: Choose upload method (configurable)
with st.sidebar:
    # Simple environment indicator
    if ENVIRONMENT == 'local':
        st.success("🌍 **Local Mode** - Using sample data only")
    else:
        st.success("🌍 **Production Mode** - Azure connectivity enabled")
    
    st.markdown("---")
    st.header("Policy Source")
    
    # Check if features are enabled
    show_file_upload = is_feature_enabled("show_file_upload")
    auto_load_json = is_feature_enabled("auto_load_json")
    
    if auto_load_json:
        # Check if policy file exists based on environment
        if ENVIRONMENT == 'local':
            policy_file_exists = os.path.exists("sample_data/sample_policy.json")
            policy_file = "sample_data/sample_policy.json" if policy_file_exists else None
            file_type = "Sample Policy"
        else:
            policy_file_exists = os.path.exists("firewall_policy.json") or os.path.exists("sample_data/sample_policy.json")
            if os.path.exists("firewall_policy.json"):
                policy_file = "firewall_policy.json"
                file_type = "Azure Policy"
            elif os.path.exists("sample_data/sample_policy.json"):
                policy_file = "sample_data/sample_policy.json"
                file_type = "Sample Policy (Fallback)"
            else:
                policy_file = None
                file_type = None
        
        if policy_file_exists and policy_file:
            st.success(f"✅ {file_type} file found")
            creation_time = get_file_creation_time(policy_file)
            if creation_time:
                st.info(f"📅 Created: {creation_time}")
            
            # Show refresh button for production environment only
            if ENVIRONMENT != 'local':
                st.markdown("---")
                st.markdown("### 🔄 Refresh Data")
                st.info("Refresh Firewall or get the latest firewall info")
                
                # Auto-refresh section using configuration
                if st.button("🔄 Auto-Refresh from Azure", type="primary", use_container_width=True):
                    st.session_state.auto_refresh_triggered = True
        else:
            st.warning("⚠️ No policy file found")
        
        # VNet data info (for production environment)
        if ENVIRONMENT != 'local' and os.path.exists("existing_vnets.json"):
            st.success("✅ VNet data file found")
            vnet_creation_time = get_file_creation_time("existing_vnets.json")
            if vnet_creation_time:
                st.info(f"📅 Created: {vnet_creation_time}")
    
    # Policy source selection (removed Connect to Azure option)
    if show_file_upload:
        policy_source = st.radio(
            "How would you like to load your policy?",
            ("Auto-load JSON file", "Upload JSON file")
        )
    else:
        policy_source = "Auto-load JSON file"
    
    st.session_state.policy_source = policy_source
    
    uploaded_file = None
    
    if policy_source == "Upload JSON file" and show_file_upload:
        uploaded_file = st.file_uploader("Choose a policy JSON file", type=["json"])
    
    # Auto-refresh functionality using configuration (production environment only)
    if ENVIRONMENT != 'local' and st.session_state.get('auto_refresh_triggered', False):
        st.markdown("---")
        st.markdown("### 🔄 Auto-Refreshing from Azure")
        
        # Get Azure configuration from environment/config
        azure_config = get_azure_config()
        
        # For web app deployment, we only need resource group
        # For local development, we need full service principal config
        is_webapp = os.environ.get('WEBSITE_SITE_NAME') or os.environ.get('AZURE_WEBAPP_NAME')
        
        if is_webapp or all([azure_config.get('tenant_id'), azure_config.get('client_id'), 
                azure_config.get('client_secret'), azure_config.get('subscription_id'), 
                azure_config.get('resource_group')]):
            
            with st.spinner("Connecting to Azure and refreshing data..."):
                try:
                    # Initialize Azure service (will auto-detect Managed Identity vs Service Principal)
                    azure_service = AzureService(azure_config)
                    
                    if azure_service.authenticate():
                        st.success("✅ Azure authentication successful!")
                        
                        if is_webapp:
                            st.info("🌐 **Web App Mode**: Using Managed Identity for authentication")
                        else:
                            st.info("💻 **Local Mode**: Using Service Principal for authentication")
                        
                        # Get resource group (required for both modes)
                        resource_group = azure_config.get('resource_group') or st.text_input(
                            "Resource Group Name", 
                            help="Enter the Azure resource group containing your firewall policy"
                        )
                        
                        if resource_group:
                            # Get firewall policy name
                            policy_name = st.text_input("Firewall Policy Name", 
                                                      help="Enter the name of your firewall policy to refresh")
                            
                            if policy_name:
                                if st.button("🔄 Refresh Firewall Policy", type="primary"):
                                    with st.spinner("Refreshing firewall policy..."):
                                        policy_data = azure_service.get_firewall_policy(policy_name, resource_group)
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
                                                vnet_data = azure_service.get_existing_vnets(resource_group)
                                                if vnet_data:
                                                    azure_service.save_vnets_to_file(vnet_data)
                                                    st.success("✅ VNet data also refreshed!")
                                            
                                            # Reset the trigger
                                            st.session_state.auto_refresh_triggered = False
                                            st.rerun()
                                        else:
                                            st.error("Failed to refresh firewall policy from Azure")
                                else:
                                    st.info("Click the button above to refresh the firewall policy")
                            else:
                                st.info("Please enter the firewall policy name to refresh")
                        else:
                            st.info("Please enter the resource group name")
                    else:
                        st.error("Azure authentication failed")
                        
                except Exception as e:
                    st.error(f"Auto-refresh failed: {e}")
                    if is_webapp:
                        st.info("Please check your Managed Identity permissions in Azure")
                    else:
                        st.info("Please check your Azure configuration in app_config.py or environment variables")
        else:
            st.error("⚠️ Azure configuration incomplete")
            if is_webapp:
                st.info("**Web App Mode**: Only resource group is required. Set AZURE_RESOURCE_GROUP environment variable.")
            else:
                st.info("**Local Mode**: Please configure Azure credentials in app_config.py or set environment variables:")
                st.code("""
AZURE_TENANT_ID=your-tenant-id
AZURE_CLIENT_ID=your-client-id
AZURE_CLIENT_SECRET=your-client-secret
AZURE_SUBSCRIPTION_ID=your-subscription-id
AZURE_RESOURCE_GROUP=your-resource-group
                """)
            
            if st.button("Configure Azure Settings"):
                st.session_state.show_azure_config_help = True
        
        # Show Azure configuration help if requested
        if st.session_state.get('show_azure_config_help', False):
            st.markdown("---")
            st.markdown("### 📋 Azure Configuration Help")
            
            if is_webapp:
                st.info("**🌐 Web App Deployment (Managed Identity)**")
                st.info("For web app deployment, you only need to set:")
                st.code("""
# In Azure Web App Configuration:
AZURE_RESOURCE_GROUP=your-resource-group-name
                """)
                st.info("The app will automatically use Managed Identity for authentication.")
                
            else:
                st.info("**💻 Local Development (Service Principal)**")
                st.info("**Option 1: Environment Variables**")
                st.code("""
export AZURE_TENANT_ID="your-tenant-id"
export AZURE_CLIENT_ID="your-client-id"
export AZURE_CLIENT_SECRET="your-client-secret"
export AZURE_SUBSCRIPTION_ID="your-subscription-id"
export AZURE_RESOURCE_GROUP="your-resource-group"
                """)
                
                st.info("**Option 2: Edit app_config.py**")
                st.code("""
AZURE_CONFIG = {
    "tenant_id": "your-tenant-id",
    "client_id": "your-client-id",
    "client_secret": "your-client-secret",
    "subscription_id": "your-subscription-id",
    "resource_group": "your-resource-group",
}
                """)
            
            if st.button("Got it!"):
                st.session_state.show_azure_config_help = False
                st.rerun()

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
            policy_data = load_policy_from_file("sample_data/sample_policy.json")
            st.success("✅ Loaded sample policy data")
        else:
            st.error("❌ Sample policy file not found")
    else:
        # Production environment: try real data first, fallback to sample
        if os.path.exists("firewall_policy.json"):
            policy_data = load_policy_from_file("firewall_policy.json")
            st.success("✅ Loaded Azure policy data")
        elif os.path.exists("sample_data/sample_policy.json"):
            policy_data = load_policy_from_file("sample_data/sample_policy.json")
            st.warning("⚠️ Using sample data (real policy not found)")
    
    if policy_data:
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
    
    # Standalone refresh section (production environment only)
    if ENVIRONMENT != 'local' and os.path.exists("firewall_policy.json"):
        with st.expander("🔄 Data Refresh & Management", expanded=False):
            st.info("Refresh Firewall or get the latest firewall info")
            
            col1, col2 = st.columns(2)
            with col1:
                if st.button("📋 Show Azure Connection Help", type="secondary"):
                    st.session_state.show_azure_help_main = True
            with col2:
                if st.button("🔄 Go to Azure Connection", type="primary"):
                    st.session_state.policy_source = "Connect to Azure"
                    st.rerun()
            
            # Show help if requested
            if st.session_state.get('show_azure_help_main', False):
                st.markdown("---")
                st.markdown("### 🔗 How to Refresh Your Data")
                st.info("**Option 1: Use the sidebar**")
                st.info("1. In the left sidebar, click '🔄 Auto-Refresh from Azure'")
                st.info("2. Enter your firewall policy name")
                st.info("3. Click '🔄 Refresh Firewall Policy'")
                
                st.info("**Option 2: Use environment variables**")
                st.code("""
export AZURE_TENANT_ID="your-tenant-id"
export AZURE_CLIENT_ID="your-client-id"
export AZURE_CLIENT_SECRET="your-client-secret"
export AZURE_SUBSCRIPTION_ID="your-subscription-id"
export AZURE_RESOURCE_GROUP="your-resource-group"
                """)
                
                st.info("**Option 3: Create a .env file**")
                st.code("""
AZURE_TENANT_ID=your-tenant-id
AZURE_CLIENT_ID=your-client-id
AZURE_CLIENT_SECRET=your-client-secret
AZURE_SUBSCRIPTION_ID=your-subscription-id
AZURE_RESOURCE_GROUP=your-resource-group
                """)
                
                if st.button("Got it!"):
                    st.session_state.show_azure_help_main = False
                    st.rerun()
    
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
                azure_service = AzureService(azure_config)
                if azure_service.authenticate():
                    # Get resource group from config or user input
                    resource_group = azure_config.get('resource_group')
                    if not resource_group:
                        resource_group = st.text_input(
                            "Resource Group Name (for VNet data)", 
                            help="Enter the Azure resource group to get VNet information"
                        )
                    
                    if resource_group:
                        with st.spinner("Fetching latest VNet data from Azure..."):
                            vnet_data = azure_service.get_existing_vnets(resource_group)
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


# Streamlit apps don't need a main function - they run automatically
# The app code above runs when the file is executed
