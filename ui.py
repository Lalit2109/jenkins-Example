"""
UI Components for Azure Firewall Analyzer
Handles sidebar, main content layout, and policy summary display
"""

import streamlit as st
import logging
from app_config import is_feature_enabled

logger = logging.getLogger(__name__)

def render_sidebar(azure_service, environment):
    """Render the sidebar with data source selection and Azure connection controls"""
    # Check if sidebar should be shown based on feature config
    if not is_feature_enabled("show_sidebar"):
        return
    
    with st.sidebar:
        st.markdown("## 🔥 Azure Firewall Analyzer")
        
        # Environment indicator
        if environment == "local":
            st.markdown("🖥️ **Local Development Mode**")
        else:
            st.markdown("🌍 **Production Mode**")
        
        # Azure connectivity status
        if azure_service and azure_service.authenticated:
            st.markdown("🟢 **Azure connectivity enabled**")
        else:
            st.markdown("🔴 **Azure connectivity disabled**")
        
        st.divider()
        
        # Data Source Section
        st.markdown("### 📁 Data Source")
        policy_source = st.radio(
            "Select data source:",
            ["Auto-load JSON file", "Upload JSON file", "Connect to Azure"],
            index=0,
            help="Choose how to load firewall policy data"
        )
        
        # Update session state
        if st.session_state.get('policy_source') != policy_source:
            st.session_state.policy_source = policy_source
            st.session_state.azure_refresh_success = False
            st.session_state.azure_policy_name = None
            st.session_state.loaded_file_name = None
            st.rerun()
        
        st.divider()
        
        # Azure Connection Section
        st.markdown("### ☁️ Azure Connection")
        
        if policy_source == "Connect to Azure":
            st.info("Using: Connect to Azure")
            
            # Test and Refresh buttons
            col1, col2 = st.columns(2)
            with col1:
                if st.button("🔄 Refresh", type="primary", help="Fetch latest data from Azure"):
                    st.session_state.show_refresh_modal = True
                    st.rerun()
            
            with col2:
                if st.button("✅ Test", help="Test Azure connection"):
                    test_azure_connection(azure_service)
        else:
            st.info(f"Using: {policy_source}")
            
            if st.button("🔄 Reset to Sample Data", help="Switch back to sample data"):
                logger.info("🔄 Reset to sample data button clicked")
                st.session_state.policy_source = "Auto-load JSON file"
                st.session_state.azure_refresh_success = False
                st.session_state.azure_policy_name = None
                st.session_state.loaded_file_name = None
                st.rerun()

def test_azure_connection(azure_service):
    """Test Azure connection and show result"""
    try:
        if azure_service.test_connection():
            st.success("✅ Azure connection successful!")
        else:
            st.error("❌ Azure connection failed. Check your configuration.")
    except Exception as e:
        st.error(f"❌ Connection test error: {str(e)}")
        logger.error(f"Azure connection test error: {e}")

def render_policy_summary(rules, policy_source):
    """Render the policy summary section with clickable metrics"""
    # Calculate metrics
    network_rules = len(rules.get('network', [])) if rules else 0
    app_rules = len(rules.get('application', [])) if rules else 0
    total_rules = network_rules + app_rules
    
    # Create expandable policy summary
    with st.expander("📊 Policy Summary", expanded=True):
        if not rules:
            st.warning("⚠️ No policy data available")
            return
        
        # Create metrics columns
        col1, col2, col3 = st.columns(3)
        
        with col1:
            # Toggle network rules table
            is_network_active = st.session_state.get('show_network_table', False)
            button_type = "primary" if is_network_active else "secondary"
            button_text = f"**{network_rules}**\nNetwork Rules {'🔽' if is_network_active else '▶️'}"
            
            if st.button(button_text, type=button_type, use_container_width=True):
                # Toggle: if already showing, hide it; otherwise show it
                if is_network_active:
                    st.session_state.show_network_table = False
                    st.session_state.show_app_table = False
                    st.session_state.show_all_rules = False
                else:
                    st.session_state.show_network_table = True
                    st.session_state.show_app_table = False
                    st.session_state.show_all_rules = False
                st.rerun()
        
        with col2:
            # Toggle application rules table
            is_app_active = st.session_state.get('show_app_table', False)
            button_type = "primary" if is_app_active else "secondary"
            button_text = f"**{app_rules}**\nApplication Rules {'🔽' if is_app_active else '▶️'}"
            
            if st.button(button_text, type=button_type, use_container_width=True):
                # Toggle: if already showing, hide it; otherwise show it
                if is_app_active:
                    st.session_state.show_network_table = False
                    st.session_state.show_app_table = False
                    st.session_state.show_all_rules = False
                else:
                    st.session_state.show_network_table = False
                    st.session_state.show_app_table = True
                    st.session_state.show_all_rules = False
                st.rerun()
        
        with col3:
            # Toggle all rules table
            is_all_active = st.session_state.get('show_all_rules', False)
            button_type = "primary" if is_all_active else "secondary"
            button_text = f"**{total_rules}**\nTotal Rules {'🔽' if is_all_active else '▶️'}"
            
            if st.button(button_text, type=button_type, use_container_width=True):
                # Toggle: if already showing, hide it; otherwise show it
                if is_all_active:
                    st.session_state.show_network_table = False
                    st.session_state.show_app_table = False
                    st.session_state.show_all_rules = False
                else:
                    st.session_state.show_network_table = False
                    st.session_state.show_app_table = False
                    st.session_state.show_all_rules = True
                st.rerun()

def render_rule_tables(rules):
    """Render the rule tables based on session state"""
    if not rules:
        return
    
    # Network Rules Table
    if st.session_state.get('show_network_table', False):
        st.markdown("### 🌐 Network Rules Details")
        if rules.get('network'):
            network_df = create_network_rules_dataframe(rules['network'])
            st.dataframe(network_df, use_container_width=True)
        else:
            st.info("No network rules found")
    
    # Application Rules Table
    if st.session_state.get('show_app_table', False):
        st.markdown("### 🔥 Application Rules Details")
        if rules.get('application'):
            app_df = create_application_rules_dataframe(rules['application'])
            st.dataframe(app_df, use_container_width=True)
        else:
            st.info("No application rules found")
    
    # All Rules Overview
    if st.session_state.get('show_all_rules', False):
        st.markdown("### 📋 All Rules Overview")
        
        # Combine all rules into one table
        all_rules_data = []
        
        # Add network rules
        if rules.get('network'):
            for rule in rules['network']:
                all_rules_data.append({
                    'Type': 'Network',
                    'Name': rule.get('name', 'N/A'),
                    'Source': ', '.join(rule.get('sourceAddresses', []) + rule.get('sourceIpGroups', []) + rule.get('sourceServiceTags', [])),
                    'Destination': ', '.join(rule.get('destinationAddresses', []) + rule.get('destinationFqdns', []) + rule.get('destinationIpGroups', []) + rule.get('destinationServiceTags', [])),
                    'Ports': ', '.join(rule.get('destinationPorts', [])),
                    'Protocol': ', '.join(rule.get('ipProtocols', [])),
                    'Action': rule.get('ruleType', 'N/A')
                })
        
        # Add application rules
        if rules.get('application'):
            for rule in rules['application']:
                all_rules_data.append({
                    'Type': 'Application',
                    'Name': rule.get('name', 'N/A'),
                    'Source': ', '.join(rule.get('sourceAddresses', []) + rule.get('sourceIpGroups', []) + rule.get('sourceServiceTags', [])),
                    'Destination': ', '.join(rule.get('targetFqdns', []) + rule.get('targetUrls', [])),
                    'Ports': ', '.join([f"{p.get('protocolType', 'N/A')}:{p.get('port', 'N/A')}" for p in rule.get('protocols', [])]),
                    'Protocol': 'Application',
                    'Action': rule.get('ruleType', 'N/A')
                })
        
        if all_rules_data:
            import pandas as pd
            all_rules_df = pd.DataFrame(all_rules_data)
            all_rules_df.index = range(1, len(all_rules_df) + 1)
            st.dataframe(all_rules_df, use_container_width=True)
        else:
            st.info("No rules found")

def create_network_rules_dataframe(network_rules):
    """Create a DataFrame for network rules"""
    import pandas as pd
    
    data = []
    for rule in network_rules:
        data.append({
            'Name': rule.get('name', 'N/A'),
            'Source': ', '.join(rule.get('sourceAddresses', []) + rule.get('sourceIpGroups', []) + rule.get('sourceServiceTags', [])),
            'Destination': ', '.join(rule.get('destinationAddresses', []) + rule.get('destinationFqdns', []) + rule.get('destinationIpGroups', []) + rule.get('destinationServiceTags', [])),
            'Ports': ', '.join(rule.get('destinationPorts', [])),
            'Protocol': ', '.join(rule.get('ipProtocols', [])),
            'Action': rule.get('ruleType', 'N/A')
        })
    
    df = pd.DataFrame(data)
    if not df.empty:
        df.index = range(1, len(df) + 1)
    return df

def create_application_rules_dataframe(app_rules):
    """Create a DataFrame for application rules"""
    import pandas as pd
    
    data = []
    for rule in app_rules:
        data.append({
            'Name': rule.get('name', 'N/A'),
            'Source': ', '.join(rule.get('sourceAddresses', []) + rule.get('sourceIpGroups', []) + rule.get('sourceServiceTags', [])),
            'Target FQDNs': ', '.join(rule.get('targetFqdns', []) + rule.get('targetUrls', [])),
            'Protocols': ', '.join([f"{p.get('protocolType', 'N/A')}:{p.get('port', 'N/A')}" for p in rule.get('protocols', [])]),
            'Action': rule.get('ruleType', 'N/A')
        })
    
    df = pd.DataFrame(data)
    if not df.empty:
        df.index = range(1, len(df) + 1)
    return df

def render_download_section(policy_data, policy_source, enabled=True):
    """Render the download section for policy data"""
    # Check if download feature is enabled
    if not enabled:
        return
    
    if policy_data and policy_source == "Connect to Azure":
        st.markdown("### 📥 Download Raw Data")
        
        # Convert policy data to JSON string
        import json
        policy_json = json.dumps(policy_data, indent=2)
        
        st.download_button(
            label="📄 Download Azure Policy JSON",
            data=policy_json,
            file_name="azure_firewall_policy.json",
            mime="application/json",
            help="Download the raw Azure Firewall Policy data as JSON"
        )
