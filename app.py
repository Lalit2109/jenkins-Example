"""
Azure Firewall Policy Rule Analyzer - Refactored Main Application
A Streamlit web application for analyzing Azure Firewall policies
"""

import streamlit as st
import sys
import logging
import os
from app_config import is_feature_enabled

# Add the app directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import our custom modules
from ui_components import render_sidebar, render_policy_summary, render_rule_tables, render_download_section
from data_manager import initialize_azure_service, load_policy_data, handle_background_refresh
from azure_policies import list_firewall_policies
from policy_loader import load_policy_rules
from tabs import render_all_tabs
from app_config import is_feature_enabled

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)

def main():
    """Main application function"""
    # Page configuration
    st.set_page_config(
        page_title="Azure Firewall Analyzer",
        page_icon="🔥",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    
    # Custom CSS and JavaScript to remove top whitespace
    st.markdown("""
        <style>
        .stApp {
            margin-top: 0px !important;
        }
        .main .block-container {
            padding-top: 0px !important;
            padding-bottom: 0px !important;
        }
        .stApp > header {
            display: none !important;
            height: 0 !important;
        }
        .stApp > div:first-child {
            padding-top: 0px !important;
        }
        .stApp > div:first-child > div:first-child {
            padding-top: 0px !important;
        }
        .main .block-container > div:first-child {
            padding-top: 0px !important;
            margin-top: 0px !important;
        }
        .stApp > div:first-child > div:first-child > div:first-child {
            padding-top: 0px !important;
            margin-top: 0px !important;
        }
        </style>
        <script>
        // Force remove top whitespace
        window.addEventListener('load', function() {
            const app = document.querySelector('.stApp');
            if (app) {
                app.style.marginTop = '0px';
                app.style.paddingTop = '0px';
            }
            const container = document.querySelector('.main .block-container');
            if (container) {
                container.style.paddingTop = '0px';
                container.style.marginTop = '0px';
            }
        });
        </script>
        """, unsafe_allow_html=True)
    
    # Initialize session state
    initialize_session_state()
    
    # Get environment
    environment = os.getenv('STREAMLIT_ENVIRONMENT', 'local')
    
    # Initialize Azure service
    azure_service = initialize_azure_service()
    
    # Handle background refresh
    handle_background_refresh()
    
    # Policy selector (multi-policy support) - gated by feature flag
    if is_feature_enabled("enable_multi_policy"):
        if "policy_catalog" not in st.session_state:
            st.session_state.policy_catalog = []
        if "selected_policy_id" not in st.session_state:
            st.session_state.selected_policy_id = None
        if "current_policy" not in st.session_state:
            st.session_state.current_policy = None
        if "current_rules" not in st.session_state:
            st.session_state.current_rules = None

        with st.container():
            st.markdown("### Policy", unsafe_allow_html=True)
            if not st.session_state.policy_catalog:
                with st.spinner("Discovering Firewall Policies across subscriptions…"):
                    try:
                        st.session_state.policy_catalog = list_firewall_policies()
                    except Exception as e:
                        st.warning(f"Policy discovery failed: {e}")
                        st.session_state.policy_catalog = []

            catalog = st.session_state.policy_catalog
            if catalog:
                labels = [f"{p['name']} — {p['subscription_id']}/{p['resource_group']} ({p['location']})" for p in catalog]
                index = 0
                if st.session_state.selected_policy_id:
                    for i, p in enumerate(catalog):
                        if p["id"] == st.session_state.selected_policy_id:
                            index = i
                            break
                sel = st.selectbox("Select a Firewall Policy", labels, index=index, key="policy_selectbox")
                chosen = catalog[labels.index(sel)]
                if chosen["id"] != st.session_state.selected_policy_id:
                    st.session_state.selected_policy_id = chosen["id"]
                    st.session_state.current_policy = None
                    st.session_state.current_rules = None
                    # Clear all cached data when policy changes
                    clear_all_cached_data()
                    st.rerun()
            else:
                st.info("No policies discovered or Azure is not configured. The app will use the previous single-policy loader.")

    # Render sidebar
    render_sidebar(azure_service, environment)
    
    # Main content area with minimal whitespace
    # Use st.empty() to create a custom layout
    main_content = st.empty()
    with main_content.container():
        st.markdown("""
            <h1 style="margin-top: 0px; padding-top: 0px; margin-bottom: 1rem;">Azure Firewall Policy Rule Analyzer</h1>
            """, unsafe_allow_html=True)
    
    # Load policy data
    rules = None
    policy_json = None
    if st.session_state.get("selected_policy_id"):
        if st.session_state.current_rules is None:
            with st.spinner("Loading selected policy…"):
                try:
                    policy_json, rules = load_policy_rules(st.session_state.selected_policy_id)
                    # cache in session
                    st.session_state.current_policy = policy_json
                    st.session_state.current_rules = rules
                    # expose to legacy renderers that might read from session
                    st.session_state.rules = rules
                    st.session_state.policy_source = "Azure (selected policy)"
                    st.session_state.loaded_file_name = policy_json.get("policy", {}).get("name", "selected_policy")
                    
                    # Debug: show what was loaded
                    if rules:
                        network_count = len(rules.get('network', []))
                        app_count = len(rules.get('application', []))
                        if network_count == 0 and app_count == 0:
                            st.warning(f"⚠️ Policy loaded but no rules found. Policy has {len(policy_json.get('ruleCollectionGroups', []))} rule collection groups.")
                            logger.warning(f"No rules parsed from policy. RCGs: {len(policy_json.get('ruleCollectionGroups', []))}")
                        else:
                            st.success(f"✅ Loaded {network_count} network rules and {app_count} application rules")
                    else:
                        st.error("❌ Failed to parse policy rules")
                except Exception as e:
                    logger.error(f"Error loading policy: {e}", exc_info=True)
                    st.error(f"❌ Error loading policy: {str(e)}")
                    rules = {"network": [], "application": []}
                    policy_json = {"policy": {}, "ruleCollectionGroups": []}
        else:
            policy_json = st.session_state.current_policy
            rules = st.session_state.current_rules
            # keep session state synced for components using it
            st.session_state.rules = rules
            st.session_state.policy_source = "Azure (selected policy)"
        current_policy_source = "Azure (selected policy)"
    else:
        current_policy_source = st.session_state.get('policy_source', 'Auto-load JSON file')
        policy_json, rules = load_policy_data(current_policy_source, azure_service, environment)
    
    # Show file information
    display_file_information()
    
    # Render policy summary
    render_policy_summary(rules, current_policy_source)
    
    # Render rule tables
    render_rule_tables(rules)
    
    # Render download section (if enabled)
    if policy_json:
        download_enabled = is_feature_enabled("enable_download_section")
        render_download_section(policy_json, current_policy_source, download_enabled)
    
    # Render tabs
    render_all_tabs(rules)


def display_file_information():
    """Display information about the loaded file"""
    file_name = st.session_state.get('loaded_file_name', 'Unknown')
    file_creation_time = st.session_state.get('file_creation_time')
    
    # Create columns for file info and refresh button
    col1, col2 = st.columns([4, 1])
    
    with col1:
        if file_creation_time:
            formatted_time = file_creation_time.strftime("%Y-%m-%d %H:%M:%S")
            if file_name == "firewall_policy.json":
                st.success(f"✅ Loaded from {file_name} (created: {formatted_time})")
            elif file_name == "sample_policy.json":
                st.warning(f"⚠️ Using sample data from {file_name} (created: {formatted_time})")
            else:
                st.info(f"📄 Loaded from {file_name} (created: {formatted_time})")
        else:
            if file_name == "firewall_policy.json":
                st.success(f"✅ Loaded from {file_name}")
            elif file_name == "sample_policy.json":
                st.warning(f"⚠️ Using sample data from {file_name}")
            else:
                st.info(f"📄 Loaded from {file_name}")
    
    with col2:
        # Show refresh button when sidebar is hidden - always refreshes from Azure
        if not is_feature_enabled("show_sidebar"):
            if st.button("🔄 Refresh", key="main_refresh_button", help="Refresh data from Azure"):
                from data_manager import refresh_azure_data
                with st.spinner("Refreshing data from Azure..."):
                    try:
                        refresh_azure_data()
                        st.success("✅ Data refreshed successfully!")
                        st.rerun()
                    except Exception as e:
                        st.error(f"❌ Failed to refresh data: {str(e)}")

def clear_all_cached_data():
    """Clear all cached data when policy changes"""
    # Clear optimization cache
    cache_keys_to_clear = [
        'permissive_chart_data',
        'redundancy_chart_data',
        'selected_permissive_issue',
        'selected_redundancy_type',
        # Clear UI component toggles
        'show_network_table',
        'show_app_table',
        'show_all_rules',
        # Clear search form state (if any cached)
        'search_form',
        'compare_form',
    ]
    
    for key in cache_keys_to_clear:
        if key in st.session_state:
            del st.session_state[key]
    
    logger.info("Cleared all cached data for policy change")

def initialize_session_state():
    """Initialize session state variables"""
    if 'policy_source' not in st.session_state:
        st.session_state.policy_source = 'Auto-load JSON file'
    
    if 'azure_refresh_success' not in st.session_state:
        st.session_state.azure_refresh_success = False
    
    if 'show_refresh_modal' not in st.session_state:
        st.session_state.show_refresh_modal = False
    
    if 'show_network_table' not in st.session_state:
        st.session_state.show_network_table = False
    
    if 'show_app_table' not in st.session_state:
        st.session_state.show_app_table = False
    
    if 'show_all_rules' not in st.session_state:
        st.session_state.show_all_rules = False

if __name__ == "__main__":
    main()
