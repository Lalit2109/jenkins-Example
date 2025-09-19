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
        col1, col2 = st.columns(2)
        
        with col1:
            source_ip = st.text_input(
                "Source IP Address (Optional)",
                placeholder="e.g., 10.0.1.100 or 10.0.0.0/24",
                help="Enter the source IP address or CIDR to check (optional)"
            )
        
        with col2:
            destination_ip = st.text_input(
                "Destination IP Address (Optional)",
                placeholder="e.g., 8.8.8.8 or api.sendgrid.com",
                help="Enter the destination IP address or FQDN to check (optional)"
            )
        
        search_button = st.form_submit_button("🔍 Search Rules", use_container_width=True)
    
    if search_button:
        if not source_ip and not destination_ip:
            st.warning("⚠️ Please enter at least a source IP address or destination IP address")
            return
        
        # Perform search
        results = search_rules(rules, source_ip, destination_ip)
        display_search_results(results)

def search_rules(rules, source_ip, destination_ip):
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
            if matches_network_rule(rule, source_ip, destination_ip):
                if rule.get('ruleType') == 'NetworkRule':
                    results['network_rules'].append(rule)
                elif rule.get('ruleType') == 'DenyRule':
                    results['blocked_rules'].append(rule)
                else:
                    results['allowed_rules'].append(rule)
    
    # Search application rules
    if rules.get('application'):
        for rule in rules['application']:
            if matches_application_rule(rule, source_ip, destination_ip):
                results['application_rules'].append(rule)
    
    return results

def matches_network_rule(rule, source_ip, destination_ip):
    """Check if a network rule matches the search criteria"""
    # Check source IP only if provided
    source_matches = True
    if source_ip:
        source_matches = any(source_ip in addr for addr in rule.get('sourceAddresses', []))
    
    # Check destination IP only if provided
    dest_matches = True
    if destination_ip:
        dest_matches = any(destination_ip in addr for addr in rule.get('destinationAddresses', []))
    
    return source_matches and dest_matches

def matches_application_rule(rule, source_ip, destination_ip):
    """Check if an application rule matches the search criteria"""
    # Check source IP only if provided
    source_matches = True
    if source_ip:
        source_matches = any(source_ip in addr for addr in rule.get('sourceAddresses', []))
    
    # Check destination FQDN only if provided
    dest_matches = True
    if destination_ip:
        dest_matches = any(destination_ip in fqdn for fqdn in rule.get('targetFqdns', []))
    
    return source_matches and dest_matches

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
                'Source': ', '.join(rule.get('sourceAddresses', [])),
                'Destination': ', '.join(rule.get('destinationAddresses', [])),
                'Ports': ', '.join(rule.get('destinationPorts', [])),
                'Protocol': ', '.join(rule.get('ipProtocols', []))
            }
            for rule in results['network_rules']
        ])
        st.dataframe(network_df, use_container_width=True)
    
    if results['application_rules']:
        st.markdown("#### 🔥 Application Rules")
        app_df = pd.DataFrame([
            {
                'Name': rule.get('name', 'N/A'),
                'Source': ', '.join(rule.get('sourceAddresses', [])),
                'Target FQDNs': ', '.join(rule.get('targetFqdns', [])),
                'Protocols': ', '.join([f"{p.get('protocolType', 'N/A')}:{p.get('port', 'N/A')}" for p in rule.get('protocols', [])])
            }
            for rule in results['application_rules']
        ])
        st.dataframe(app_df, use_container_width=True)
    
    if results['blocked_rules']:
        st.markdown("#### 🚫 Blocked Rules")
        blocked_df = pd.DataFrame([
            {
                'Name': rule.get('name', 'N/A'),
                'Source': ', '.join(rule.get('sourceAddresses', [])),
                'Destination': ', '.join(rule.get('destinationAddresses', [])),
                'Reason': 'Blocked by deny rule'
            }
            for rule in results['blocked_rules']
        ])
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
    st.subheader("🌐 VNet Calculator Tool")
    st.info("Calculate the next available VNet IP range within your master IP ranges for different environments and regions.")
    
    # Import required functions
    try:
        from vnet_config import load_environment_config, calculate_vnet_range, divide_into_subnets, extract_ip_ranges_from_vnets
        from azure_service import AzureService, load_vnets_from_file
        from app_config import get_azure_config, is_feature_enabled
        import os
    except ImportError as e:
        st.error(f"Required modules not available: {e}")
        return
    
    # Subnet sizes configuration
    SUBNET_SIZES = {
        "/16": {"name": "Large", "ips": 65536, "description": "Large VNet (65K+ IPs)"},
        "/20": {"name": "Medium", "ips": 4096, "description": "Medium VNet (4K IPs)"},
        "/24": {"name": "Small", "ips": 256, "description": "Small VNet (256 IPs)"},
        "/25": {"name": "Tiny", "ips": 128, "description": "Tiny VNet (128 IPs)"},
        "/26": {"name": "Micro", "ips": 64, "description": "Micro VNet (64 IPs)"},
        "/27": {"name": "Nano", "ips": 32, "description": "Nano VNet (32 IPs)"},
        "/28": {"name": "Pico", "ips": 16, "description": "Pico VNet (16 IPs)"},
        "/29": {"name": "Femto", "ips": 8, "description": "Femto VNet (8 IPs)"},
        "/30": {"name": "Atto", "ips": 4, "description": "Atto VNet (4 IPs)"}
    }
    
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

def render_tools_tab():
    """Render the network tools tab"""
    st.markdown("### 🛠️ Network Tools")
    
    # IP Address Utilities
    st.markdown("#### IP Address Utilities")
    
    with st.form("ip_utilities"):
        col1, col2 = st.columns(2)
        
        with col1:
            ip_address = st.text_input(
                "IP Address",
                placeholder="e.g., 192.168.1.1",
                help="Enter an IP address to analyze"
            )
        
        with col2:
            cidr_block = st.text_input(
                "CIDR Block",
                placeholder="e.g., 192.168.1.0/24",
                help="Enter a CIDR block to analyze"
            )
        
        analyze_button = st.form_submit_button("🔍 Analyze", use_container_width=True)
    
    if analyze_button:
        if ip_address:
            try:
                import ipaddress
                ip = ipaddress.ip_address(ip_address)
                
                st.success(f"✅ Valid IP Address: {ip_address}")
                
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Version", f"IPv{ip.version}")
                with col2:
                    st.metric("Type", "Private" if ip.is_private else "Public")
                with col3:
                    st.metric("Loopback", "Yes" if ip.is_loopback else "No")
                
                # Additional properties
                st.markdown("#### IP Properties")
                properties = {
                    "Is Private": ip.is_private,
                    "Is Global": ip.is_global,
                    "Is Link Local": ip.is_link_local,
                    "Is Loopback": ip.is_loopback,
                    "Is Multicast": ip.is_multicast,
                    "Is Reserved": ip.is_reserved,
                    "Is Unspecified": ip.is_unspecified
                }
                
                for prop, value in properties.items():
                    st.write(f"**{prop}:** {'Yes' if value else 'No'}")
                    
            except ValueError as e:
                st.error(f"❌ Invalid IP address: {str(e)}")
        
        if cidr_block:
            try:
                import ipaddress
                network = ipaddress.ip_network(cidr_block, strict=False)
                
                st.success(f"✅ Valid CIDR Block: {cidr_block}")
                
                col1, col2, col3, col4 = st.columns(4)
                with col1:
                    st.metric("Network Address", str(network.network_address))
                with col2:
                    st.metric("Broadcast Address", str(network.broadcast_address))
                with col3:
                    st.metric("Total Hosts", network.num_addresses)
                with col4:
                    st.metric("Usable Hosts", network.num_addresses - 2)
                
                # Show first and last usable IPs
                if network.num_addresses > 2:
                    first_usable = list(network.hosts())[0]
                    last_usable = list(network.hosts())[-1]
                    st.markdown("#### Usable IP Range")
                    st.code(f"First: {first_usable}\nLast: {last_usable}")
                
            except ValueError as e:
                st.error(f"❌ Invalid CIDR block: {str(e)}")
    
    # Port Scanner (Simulation)
    st.markdown("---")
    st.markdown("#### Port Scanner")
    
    with st.form("port_scanner"):
        col1, col2 = st.columns(2)
        
        with col1:
            target_ip = st.text_input(
                "Target IP",
                placeholder="e.g., 192.168.1.1",
                help="IP address to scan",
                key="scanner_ip"
            )
        
        with col2:
            port_range = st.selectbox(
                "Port Range",
                ["Common Ports (1-1024)", "All Ports (1-65535)", "Web Ports (80,443,8080)"],
                help="Select port range to scan"
            )
        
        scan_button = st.form_submit_button("🔍 Scan Ports", use_container_width=True)
    
    if scan_button and target_ip:
        try:
            import ipaddress
            ip = ipaddress.ip_address(target_ip)
            
            st.info("🔍 Port scanning simulation (this is a demo)")
            
            # Simulate port scanning
            if port_range == "Common Ports (1-1024)":
                ports_to_check = [22, 23, 25, 53, 80, 110, 143, 443, 993, 995]
            elif port_range == "Web Ports (80,443,8080)":
                ports_to_check = [80, 443, 8080]
            else:
                ports_to_check = [22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389, 5432, 3306]
            
            # Simulate results
            open_ports = []
            closed_ports = []
            
            for port in ports_to_check:
                # Simulate random results for demo
                import random
                if random.choice([True, False, False]):  # 33% chance of being open
                    open_ports.append(port)
                else:
                    closed_ports.append(port)
            
            col1, col2 = st.columns(2)
            with col1:
                st.metric("Open Ports", len(open_ports))
            with col2:
                st.metric("Closed Ports", len(closed_ports))
            
            if open_ports:
                st.markdown("#### Open Ports")
                open_df = pd.DataFrame([
                    {"Port": port, "Service": get_service_name(port), "Status": "Open"}
                    for port in open_ports
                ])
                st.dataframe(open_df, use_container_width=True)
            
        except ValueError as e:
            st.error(f"❌ Invalid IP address: {str(e)}")
    
    # Network Connectivity Tester
    st.markdown("---")
    st.markdown("#### Network Connectivity Tester")
    
    with st.form("connectivity_tester"):
        test_host = st.text_input(
            "Host to Test",
            placeholder="e.g., google.com or 8.8.8.8",
            help="Hostname or IP address to test connectivity"
        )
        
        test_button = st.form_submit_button("🌐 Test Connectivity", use_container_width=True)
    
    if test_button and test_host:
        st.info("🔍 Connectivity testing simulation (this is a demo)")
        
        # Simulate connectivity test
        import random
        is_reachable = random.choice([True, True, True, False])  # 75% chance of being reachable
        
        if is_reachable:
            st.success(f"✅ {test_host} is reachable")
            
            # Simulate ping results
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Response Time", f"{random.randint(10, 100)}ms")
            with col2:
                st.metric("Packet Loss", "0%")
            with col3:
                st.metric("Status", "Online")
        else:
            st.error(f"❌ {test_host} is not reachable")

def get_service_name(port):
    """Get service name for common ports"""
    services = {
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        993: "IMAPS",
        995: "POP3S",
        3389: "RDP",
        5432: "PostgreSQL",
        3306: "MySQL"
    }
    return services.get(port, "Unknown")

def render_all_tabs(rules):
    """Render all tabs using Streamlit's tab functionality"""
    tab1, tab2, tab3, tab4 = st.tabs(["🔍 Search", "🔄 Compare", "🌐 VNet Calculator", "🛠️ Network Tools"])
    
    with tab1:
        render_search_tab(rules)
    
    with tab2:
        render_compare_tab(rules)
    
    with tab3:
        render_vnet_tab()
    
    with tab4:
        render_tools_tab()
