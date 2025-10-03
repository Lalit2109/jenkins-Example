"""
Tabs Module for Azure Firewall Analyzer
Handles all tab content including search, compare, VNet calculator, and tools
"""

import streamlit as st
import logging
import pandas as pd

logger = logging.getLogger(__name__)

def render_search_tab(rules):
    """Render the search tab for rule accessibility"""
    st.markdown("### 🔍 Search Rule Accessibility")
    
    if not rules:
        st.warning("⚠️ No policy data available for search")
        return
    
    # Search form
    with st.form("search_form"):
        col1, col2, col3 = st.columns(3)
        
        with col1:
            source_ip = st.text_input(
                "Source IP (Optional)",
                placeholder="e.g., 10.0.1.100 or 10.0.0.0/24",
                help="Enter the source IP address or CIDR to check (optional)"
            )
        
        with col2:
            destination_ip = st.text_input(
                "Destination IP/FQDN (Optional)",
                placeholder="e.g., 8.8.8.8 or api.sendgrid.com",
                help="Enter the destination IP address or FQDN to check (optional)"
            )
        
        with col3:
            rule_name = st.text_input(
                "Rule Name (Optional)",
                placeholder="e.g., AllowInternalWeb",
                help="Enter the rule name to search for (optional)"
            )
        
        search_button = st.form_submit_button("🔍 Search Rules", use_container_width=True)
    
    if search_button:
        if not source_ip.strip() and not destination_ip.strip() and not rule_name.strip():
            st.warning("⚠️ Please enter at least a source IP address, destination IP address, or rule name")
            return
        
        # Perform search
        results = search_rules(rules, source_ip, destination_ip, rule_name)
        display_search_results(results)

def search_rules(rules, source_ip, destination_ip, rule_name):
    """Search for matching rules based on criteria"""
    results = {
        'network_rules': [],
        'application_rules': [],
        'blocked_rules': [],
        'allowed_rules': []
    }
    
    # Search network rules
    if rules.get('network'):
        for rule in rules['network']:
            if matches_network_rule(rule, source_ip, destination_ip, rule_name):
                if rule.get('ruleType') == 'NetworkRule':
                    results['network_rules'].append(rule)
                elif rule.get('ruleType') == 'DenyRule':
                    results['blocked_rules'].append(rule)
                else:
                    results['allowed_rules'].append(rule)
    
    # Search application rules
    if rules.get('application'):
        for rule in rules['application']:
            if matches_application_rule(rule, source_ip, destination_ip, rule_name):
                results['application_rules'].append(rule)
    
    return results

def matches_network_rule(rule, source_ip, destination_ip, rule_name):
    """Check if a network rule matches the search criteria"""
    # Check source IP only if provided
    source_matches = True
    if source_ip and source_ip.strip():
        # Check all possible source fields that actually exist
        source_addresses = rule.get('sourceAddresses', [])
        source_ip_groups = rule.get('sourceIpGroups', [])
        source_service_tags = rule.get('sourceServiceTags', [])
        all_sources = source_addresses + source_ip_groups + source_service_tags
        
        source_matches = any(source_ip in addr for addr in all_sources)
    
    # Check destination IP/FQDN only if provided
    dest_matches = True
    if destination_ip and destination_ip.strip():
        # Check all possible destination fields that actually exist
        ip_destinations = rule.get('destinationAddresses', [])
        fqdn_destinations = rule.get('destinationFqdns', [])
        ip_group_destinations = rule.get('destinationIpGroups', [])
        service_tag_destinations = rule.get('destinationServiceTags', [])
        all_destinations = ip_destinations + fqdn_destinations + ip_group_destinations + service_tag_destinations
        
        dest_matches = any(destination_ip in dest for dest in all_destinations)
    
    # Check rule name only if provided
    name_matches = True
    if rule_name and rule_name.strip():
        rule_name_value = rule.get('name', '')
        name_matches = rule_name.strip().lower() in rule_name_value.lower()
    
    return source_matches and dest_matches and name_matches

def matches_application_rule(rule, source_ip, destination_ip, rule_name):
    """Check if an application rule matches the search criteria"""
    # Check source IP only if provided
    source_matches = True
    if source_ip and source_ip.strip():
        # Check all possible source fields that actually exist
        source_addresses = rule.get('sourceAddresses', [])
        source_ip_groups = rule.get('sourceIpGroups', [])
        source_service_tags = rule.get('sourceServiceTags', [])
        all_sources = source_addresses + source_ip_groups + source_service_tags
        
        source_matches = any(source_ip in addr for addr in all_sources)
    
    # Check destination FQDN only if provided
    dest_matches = True
    if destination_ip and destination_ip.strip():
        # Check all possible destination fields that actually exist
        fqdn_destinations = rule.get('targetFqdns', [])
        url_destinations = rule.get('targetUrls', [])
        service_tag_destinations = rule.get('destinationServiceTags', [])
        all_destinations = fqdn_destinations + url_destinations + service_tag_destinations
        
        dest_matches = any(destination_ip in dest for dest in all_destinations)
    
    # Check rule name only if provided
    name_matches = True
    if rule_name and rule_name.strip():
        rule_name_value = rule.get('name', '')
        name_matches = rule_name.strip().lower() in rule_name_value.lower()
    
    return source_matches and dest_matches and name_matches

def display_search_results(results):
    """Display search results in a formatted way"""
    total_matches = sum(len(rules) for rules in results.values())
    
    if total_matches == 0:
        st.info("ℹ️ No matching rules found for the given criteria")
        return
    
    st.success(f"✅ Found {total_matches} matching rules")
    
    # Display each category of results
    if results['network_rules']:
        st.markdown("#### 🌐 Network Rules")
        network_df = pd.DataFrame([
            {
                'Name': rule.get('name', 'N/A'),
                'Rule Collection': rule.get('ruleCollectionName', 'N/A'),
                'Source': ', '.join(rule.get('sourceAddresses', []) + rule.get('sourceIpGroups', []) + rule.get('sourceServiceTags', [])),
                'Destination': ', '.join(rule.get('destinationAddresses', []) + rule.get('destinationFqdns', []) + rule.get('destinationIpGroups', []) + rule.get('destinationServiceTags', [])),
                'Ports': ', '.join(rule.get('destinationPorts', [])),
                'Protocol': ', '.join(rule.get('ipProtocols', []))
            }
            for rule in results['network_rules']
        ])
        if not network_df.empty:
            network_df.index = range(1, len(network_df) + 1)
        st.dataframe(network_df, use_container_width=True)
    
    if results['application_rules']:
        st.markdown("#### 🔥 Application Rules")
        app_df = pd.DataFrame([
            {
                'Name': rule.get('name', 'N/A'),
                'Rule Collection': rule.get('ruleCollectionName', 'N/A'),
                'Source': ', '.join(rule.get('sourceAddresses', []) + rule.get('sourceIpGroups', []) + rule.get('sourceServiceTags', [])),
                'Target FQDNs': ', '.join(rule.get('targetFqdns', []) + rule.get('targetUrls', [])),
                'Protocols': ', '.join([f"{p.get('protocolType', 'N/A')}:{p.get('port', 'N/A')}" for p in rule.get('protocols', [])])
            }
            for rule in results['application_rules']
        ])
        if not app_df.empty:
            app_df.index = range(1, len(app_df) + 1)
        st.dataframe(app_df, use_container_width=True)
    
    if results['blocked_rules']:
        st.markdown("#### 🚫 Blocked Rules")
        blocked_df = pd.DataFrame([
            {
                'Name': rule.get('name', 'N/A'),
                'Rule Collection': rule.get('ruleCollectionName', 'N/A'),
                'Source': ', '.join(rule.get('sourceAddresses', []) + rule.get('sourceIpGroups', []) + rule.get('sourceServiceTags', [])),
                'Destination': ', '.join(rule.get('destinationAddresses', []) + rule.get('destinationFqdns', []) + rule.get('destinationIpGroups', []) + rule.get('destinationServiceTags', [])),
                'Reason': 'Blocked by deny rule'
            }
            for rule in results['blocked_rules']
        ])
        if not blocked_df.empty:
            blocked_df.index = range(1, len(blocked_df) + 1)
        st.dataframe(blocked_df, use_container_width=True)

def compare_sources(rules, source_a, source_b):
    """Compare access for two source IPs/CIDRs"""
    import ipaddress
    
    def cidr_overlaps(cidr1, cidr2):
        """Check if two CIDR ranges overlap"""
        try:
            if '/' in cidr1 and '/' in cidr2:
                # Both are CIDR ranges - check if they overlap
                net1 = ipaddress.ip_network(cidr1, strict=False)
                net2 = ipaddress.ip_network(cidr2, strict=False)
                return net1.overlaps(net2)
            elif '/' in cidr1:
                # cidr1 is a range, cidr2 is an IP
                network = ipaddress.ip_network(cidr1, strict=False)
                return ipaddress.ip_address(cidr2) in network
            elif '/' in cidr2:
                # cidr2 is a range, cidr1 is an IP
                network = ipaddress.ip_network(cidr2, strict=False)
                return ipaddress.ip_address(cidr1) in network
            else:
                # Both are single IPs
                return cidr1 == cidr2
        except:
            return False
    
    def get_destinations_for_source(rules, source):
        """Get all destinations reachable by a source"""
        destinations = []
        
        # Check network rules
        if rules.get('network'):
            for rule in rules['network']:
                source_addresses = rule.get('sourceAddresses', [])
                if any(cidr_overlaps(source, addr) for addr in source_addresses):
                    for dest in rule.get('destinationAddresses', []):
                        destinations.append({
                            'Name': rule.get('name', 'N/A'),
                            'Destination': dest,
                            'Ports': ', '.join(rule.get('destinationPorts', [])),
                            'Protocol': ', '.join(rule.get('ipProtocols', [])),
                            'Action': rule.get('ruleType', 'N/A'),
                            'Source': source  # Add source for clarity
                        })
        
        # Check application rules
        if rules.get('application'):
            for rule in rules['application']:
                source_addresses = rule.get('sourceAddresses', [])
                if any(cidr_overlaps(source, addr) for addr in source_addresses):
                    for dest in rule.get('targetFqdns', []):
                        destinations.append({
                            'Name': rule.get('name', 'N/A'),
                            'Destination': dest,
                            'Ports': ', '.join([f"{p.get('protocolType', 'N/A')}:{p.get('port', 'N/A')}" for p in rule.get('protocols', [])]),
                            'Protocol': 'Application',
                            'Action': rule.get('ruleType', 'N/A'),
                            'Source': source  # Add source for clarity
                        })
        
        return destinations
    
    # Get destinations for both sources
    dest_a = get_destinations_for_source(rules, source_a)
    dest_b = get_destinations_for_source(rules, source_b)
    
    # Find unique destinations
    dest_a_set = set(row['Destination'] for row in dest_a)
    dest_b_set = set(row['Destination'] for row in dest_b)
    
    # Categorize destinations - show both rules when they reach the same destination
    a_only = [row for row in dest_a if row['Destination'] not in dest_b_set]
    b_only = [row for row in dest_b if row['Destination'] not in dest_a_set]
    
    # For "both" category, show both rules that reach the same destination
    both = []
    for dest_a_row in dest_a:
        if dest_a_row['Destination'] in dest_b_set:
            # Find ALL corresponding rules from source B that reach the same destination
            dest_b_rows = [row for row in dest_b if row['Destination'] == dest_a_row['Destination']]
            if dest_b_rows:
                # Add the rule from source A
                both.append(dest_a_row)
                # Add all rules from source B that reach the same destination
                both.extend(dest_b_rows)
    
    return {
        'a_only': a_only,
        'b_only': b_only,
        'both': both
    }

def render_compare_tab(rules):
    """Render the compare tab for comparing two source IPs/CIDRs"""
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
                
                # Create the dataframe with better labeling
                all_results = []
                
                # A only results
                for row in comparison['a_only']:
                    all_results.append({
                        **row, 
                        'Reachable By': f'A only ({source_a})',
                        'Source IP': source_a
                    })
                
                # B only results  
                for row in comparison['b_only']:
                    all_results.append({
                        **row,
                        'Reachable By': f'B only ({source_b})',
                        'Source IP': source_b
                    })
                
                # Both results - show which rule each source uses
                for row in comparison['both']:
                    if row['Source'] == source_a:
                        reachable_by = f'Both (A: {source_a})'
                    else:
                        reachable_by = f'Both (B: {source_b})'
                    
                    all_results.append({
                        **row,
                        'Reachable By': reachable_by,
                        'Source IP': row['Source']
                    })
                
                df = pd.DataFrame(all_results)
                
                if not df.empty:
                    df.index = range(1, len(df) + 1)
                    def highlight(row):
                        if 'Both' in row['Reachable By']:
                            return ['background-color: #d4edda']*len(row)  # green
                        elif 'A only' in row['Reachable By']:
                            return ['background-color: #f8d7da']*len(row)  # red
                        else:
                            return ['background-color: #d1ecf1']*len(row)  # blue
                    
                    st.dataframe(df.style.apply(highlight, axis=1), use_container_width=True)
                else:
                    st.info("No destinations found for either source.")
    else:
        st.info("Upload a policy JSON or connect to Azure to enable comparison.")

def render_vnet_tab():
    """Render the VNet calculator tab"""
    st.subheader("🌐 VNet Calculator")
    
    # Import required functions
    try:
        from vnet_calculator import VNetCalculator, load_environment_config, calculate_vnet_range, divide_into_subnets, check_ip_overlap, validate_cidr, get_subnet_info
        from azure_service import AzureService
        from app_config import get_azure_config, is_feature_enabled
        from data_manager import load_vnet_data, refresh_vnet_data
        import os
        import plotly.express as px
        import plotly.graph_objects as go
    except ImportError as e:
        st.error(f"Required modules not available: {e}")
        return
    
    # Initialize VNet Calculator
    azure_config = get_azure_config()
    azure_service = None
    
    # Try to initialize Azure service if not in local mode
    if not os.environ.get('STREAMLIT_ENVIRONMENT', '').lower() == 'local':
        try:
            azure_service = AzureService(azure_config)
        except Exception as e:
            logger.warning(f"Failed to initialize Azure service: {e}")
    
    # Initialize VNet Calculator
    vnet_calculator = VNetCalculator(azure_service)
    
    # Load VNet data (cached or sample)
    vnet_data = load_vnet_data()
    
    # Get configurations
    env_config = vnet_calculator.get_environment_config()
    SUBNET_SIZES = vnet_calculator.get_subnet_sizes()
    
    # Master IP range configuration section (collapsible)
    with st.expander("📋 Master IP Ranges", expanded=False):
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
        
        # Display environment configuration
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
    
    # VNet Data Refresh Section
    st.markdown("---")
    col1, col2 = st.columns([3, 1])
    
    with col1:
        if st.session_state.get('vnet_data_loaded', False):
            file_time = st.session_state.get('vnet_file_creation_time')
            if file_time:
                st.info(f"Using sample data from sample_vnets.json (created: {file_time.strftime('%Y-%m-%d %H:%M:%S')})")
            else:
                st.info("Using sample data from sample_vnets.json")
        else:
            st.warning("No VNet data loaded")
    
    with col2:
        if st.button("🔄 Refresh VNet Data", type="secondary", use_container_width=True):
            with st.spinner("Refreshing VNet data from Azure..."):
                success, message, data = refresh_vnet_data()
                if success:
                    st.success(message)
                    st.rerun()
                else:
                    st.error(message)
    
    st.markdown("---")
    # Render only the specific size search functionality
    render_specific_size_tab(vnet_calculator, env_config, SUBNET_SIZES)

def render_specific_size_tab(vnet_calculator, env_config, SUBNET_SIZES):
    """Render specific size search tab"""
    st.markdown("#### 🔍 Specific Subnet Size Search")
    
    with st.form("specific_size_form"):
        col1, col2, col3 = st.columns(3)
        
        with col1:
            selected_env = st.selectbox(
                "Select Environment", 
                list(env_config.keys()),
                help="Choose the environment (Dev, Test, Prod, Staging)",
                key="specific_env"
            )
        
        with col2:
            selected_region = st.selectbox(
                "Select Region", 
                list(env_config[selected_env].keys()),
                help="Choose the Azure region for your VNet",
                key="specific_region"
            )
        
        with col3:
            subnet_size = st.selectbox(
                "Required Subnet Size", 
                list(SUBNET_SIZES.keys()),
                format_func=lambda x: f"{x} ({SUBNET_SIZES[x]['name']} - {SUBNET_SIZES[x]['ips']} IPs)",
                help="Select the size of subnet you need",
                key="specific_size"
            )
        
        # Display selected configuration
        master_range = env_config[selected_env][selected_region]
        selected_subnet_info = SUBNET_SIZES[subnet_size]
        
        
        search_button = st.form_submit_button("🔍 Search Available CIDRs", type="primary", use_container_width=True)
    
    if search_button:
        with st.spinner("🔍 Searching for available CIDR ranges..."):
            result = vnet_calculator.find_available_cidrs(selected_env, selected_region, subnet_size, 10)
        
        if "error" not in result:
            st.success(f"✅ **Found {result['suggestions_count']} available {subnet_size} CIDR ranges!**")
            
            # Display results
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Available Ranges", result['suggestions_count'])
            with col2:
                st.metric("Total Possible", result['total_possible'])
            with col3:
                st.metric("Used Ranges Checked", result['used_ranges_considered'])
            
            # Show suggestions
            suggestions_df = pd.DataFrame(result['available_subnets'])
            st.dataframe(
                suggestions_df[['cidr', 'usable_ips', 'first_usable_ip', 'last_usable_ip', 'gateway_suggestion']],
                use_container_width=True,
                hide_index=True,
                column_config={
                    "cidr": st.column_config.TextColumn("CIDR", width="medium"),
                    "usable_ips": st.column_config.NumberColumn("Usable IPs", width="small"),
                    "first_usable_ip": st.column_config.TextColumn("First IP", width="medium"),
                    "last_usable_ip": st.column_config.TextColumn("Last IP", width="medium"),
                    "gateway_suggestion": st.column_config.TextColumn("Gateway", width="medium")
                }
            )
            
            # Export option
            if st.button("📊 Export to CSV", key="specific_export"):
                csv_content, filename = vnet_calculator.export_suggestions_to_csv(result['available_subnets'])
                st.download_button(
                    label="Download CSV",
                    data=csv_content,
                    file_name=filename,
                    mime="text/csv"
                )
        
        else:
            st.error(f"❌ **Search failed:** {result['error']}")


def render_ip_overlap_checker():
    """Render IP overlap checker tool"""
    from vnet_calculator import validate_cidr, check_ip_overlap
    
    st.markdown("#### 🔍 IP Range Overlap Checker")
    st.info("Check if two IP ranges overlap and get detailed overlap information.")
    
    with st.form("ip_overlap_form"):
        col1, col2 = st.columns(2)
        
        with col1:
            range1 = st.text_input(
                "First IP Range (CIDR)",
                placeholder="e.g., 10.100.0.0/24",
                help="Enter the first IP range in CIDR notation"
            )
        
        with col2:
            range2 = st.text_input(
                "Second IP Range (CIDR)",
                placeholder="e.g., 10.100.1.0/24",
                help="Enter the second IP range in CIDR notation"
            )
        
        check_button = st.form_submit_button("🔍 Check Overlap", use_container_width=True)
    
    if check_button:
        if not range1 or not range2:
            st.warning("⚠️ Please enter both IP ranges")
            return
        
        # Validate inputs
        if not validate_cidr(range1) or not validate_cidr(range2):
            st.error("❌ Invalid CIDR notation. Please use format like 10.0.0.0/24")
            return
        
        # Check overlap
        overlap_result = check_ip_overlap(range1, range2)
        
        if "error" in overlap_result:
            st.error(f"❌ Error checking overlap: {overlap_result['error']}")
            return
        
        # Display results
        if overlap_result['overlap']:
            st.error("🚨 **OVERLAP DETECTED!** These ranges overlap.")
            
            # Show overlap details
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Overlap Range", overlap_result['overlap_details']['overlap_range'])
            with col2:
                st.metric("Overlapping IPs", overlap_result['overlap_details']['overlap_ips'])
            with col3:
                st.metric("Overlap Start", overlap_result['overlap_details']['overlap_start'])
            
            # Show detailed information
            st.markdown("#### 📊 Detailed Range Information")
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("**First Range:**")
                st.write(f"**CIDR:** {overlap_result['range1']['cidr']}")
                st.write(f"**Network:** {overlap_result['range1']['network']}")
                st.write(f"**Broadcast:** {overlap_result['range1']['broadcast']}")
                st.write(f"**Total IPs:** {overlap_result['range1']['total_ips']}")
            
            with col2:
                st.markdown("**Second Range:**")
                st.write(f"**CIDR:** {overlap_result['range2']['cidr']}")
                st.write(f"**Network:** {overlap_result['range2']['network']}")
                st.write(f"**Broadcast:** {overlap_result['range2']['broadcast']}")
                st.write(f"**Total IPs:** {overlap_result['range2']['total_ips']}")
        else:
            st.success("✅ **NO OVERLAP** - These ranges do not overlap.")
            
            # Show both ranges
            col1, col2 = st.columns(2)
            with col1:
                st.info(f"**Range 1:** {overlap_result['range1']['cidr']}")
            with col2:
                st.info(f"**Range 2:** {overlap_result['range2']['cidr']}")


def render_tools_tab():
    """Render the network tools tab"""
    # IP Overlap Checker
    render_ip_overlap_checker()


def render_all_tabs(rules):
    """Render all tabs using Streamlit's tab functionality"""
    tab1, tab2, tab3, tab4, tab5 = st.tabs(["🔍 Search", "🔄 Compare", "🌐 VNet Calculator", "🛠️ Network Tools", "⚡ Firewall Optimization"])
    
    with tab1:
        render_search_tab(rules)
    
    with tab2:
        render_compare_tab(rules)
    
    with tab3:
        render_vnet_tab()
    
    with tab4:
        render_tools_tab()
    
    with tab5:
        from firewall_optimization import render_optimization_tab
        render_optimization_tab(rules)

