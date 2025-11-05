"""
Firewall Optimization Analysis Module
Provides analysis for overly permissive rules and redundant/duplicate rules
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

def render_optimization_tab(rules):
    """Render the firewall optimization tab"""
    st.markdown("### ⚡ Firewall Optimization Analysis")
    st.info("This tool helps identify overly permissive rules and redundant/duplicate rules to optimize your firewall policy.")
    
    if not rules or (not rules.get('network') and not rules.get('application')):
        st.warning("⚠️ No rules found. Please load a firewall policy first.")
        return
    
    # Analyze rules
    overly_permissive = analyze_overly_permissive_rules(rules)
    redundant_rules = analyze_redundant_rules(rules)
    
    # Create charts
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("#### 🚨 Overly Permissive Rules")
        if overly_permissive:
            create_permissive_chart(overly_permissive)
        else:
            st.success("✅ No overly permissive rules found!")
    
    with col2:
        st.markdown("#### 🔄 Redundant/Duplicate Rules")
        if redundant_rules:
            create_redundancy_chart(redundant_rules)
        else:
            st.success("✅ No redundant rules found!")

def create_permissive_chart(overly_permissive):
    """Create a pie chart for overly permissive rules"""
    # Count issues by type
    issue_counts = {}
    for rule in overly_permissive:
        for issue in rule['issues']:
            issue_type = issue.split(':')[0].strip()
            issue_counts[issue_type] = issue_counts.get(issue_type, 0) + 1
    
    if not issue_counts:
        st.info("No issues found to display in chart.")
        return
    
    # Create pie chart with counts in names
    names_with_counts = [f"{name} ({count})" for name, count in issue_counts.items()]
    fig = px.pie(
        values=list(issue_counts.values()),
        names=names_with_counts,
        title="Overly Permissive Rule Issues",
        color_discrete_sequence=px.colors.qualitative.Set3
    )
    
    # Add percentage labels only (no counts)
    total_issues = sum(issue_counts.values())
    labels_with_percent = [f"{name}<br>({count/total_issues*100:.1f}%)" 
                          for name, count in issue_counts.items()]
    
    fig.update_traces(
        textposition='inside',
        text=labels_with_percent,
        textinfo='text',
        hovertemplate='<b>%{label}</b><br>Count: %{value}<br>Percentage: %{percent}<extra></extra>'
    )
    
    # Update legend to include counts
    fig.update_layout(
        showlegend=True,
        legend=dict(
            title=f"Total Issues: {total_issues}",
            title_font_size=14,
            font_size=12
        ),
        height=400,
        margin=dict(t=50, b=50, l=50, r=50)
    )
    
    # Legend labels already include counts from the names_with_counts
    
    # Store the chart data
    st.session_state.permissive_chart_data = {
        'issue_counts': issue_counts,
        'overly_permissive': overly_permissive
    }
    
    # Display chart
    st.plotly_chart(fig, use_container_width=True, key="permissive_chart")
    
    # Create a simple selectbox for interaction
    st.markdown("**Select an issue type to view details:**")
    
    # Get current selection from session state or default
    current_selection = st.session_state.get('selected_permissive_issue', "Select an issue type...")
    options = ["Select an issue type..."] + list(issue_counts.keys())
    
    # Find index of current selection
    try:
        default_index = options.index(current_selection) if current_selection in options else 0
    except ValueError:
        default_index = 0
    
    selected_issue = st.selectbox(
        "Choose an issue type:",
        options=options,
        index=default_index,
        key="permissive_issue_selector",
        help="Select an issue type to view detailed information about affected rules"
    )
    
    # Update session state only if selection changed
    if selected_issue and selected_issue != "Select an issue type...":
        if st.session_state.get('selected_permissive_issue') != selected_issue:
            st.session_state.selected_permissive_issue = selected_issue
    elif selected_issue == "Select an issue type..." and 'selected_permissive_issue' in st.session_state:
        # Clear selection if user selects the default option
        del st.session_state.selected_permissive_issue
    
    # Only show data panel if a selection has been made
    if 'selected_permissive_issue' in st.session_state:
        selected_issue = st.session_state.selected_permissive_issue
        
        # Filter rules that have this specific issue
        filtered_rules = []
        for rule in overly_permissive:
            for issue in rule['issues']:
                if issue.startswith(selected_issue):
                    filtered_rules.append(rule)
                    break
        
        if filtered_rules:
            st.markdown(f"**Rules with '{selected_issue}' issues ({len(filtered_rules)} found):**")
            for i, rule in enumerate(filtered_rules, 1):
                with st.expander(f"{i}. {rule['rule_name']} ({rule['rule_type']})"):
                    st.markdown("**Issues Found:**")
                    for issue in rule['issues']:
                        if issue.startswith(selected_issue):
                            st.error(f"• {issue}")
                        else:
                            st.warning(f"• {issue}")
                    
                    st.markdown("**Rule Details:**")
                    st.write(f"**Source:** {rule['source']}")
                    st.write(f"**Destination:** {rule['destination']}")
                    if 'ports' in rule:
                        st.write(f"**Ports:** {rule['ports']}")
                    st.write(f"**Protocols:** {rule['protocols']}")
        else:
            st.info(f"No rules found with '{selected_issue}' issues.")
        
        # Add clear selection button
        if st.button("❌ Clear Selection", key="clear_permissive_selection"):
            if 'selected_permissive_issue' in st.session_state:
                del st.session_state.selected_permissive_issue
            st.rerun()

def create_redundancy_chart(redundant_rules):
    """Create a pie chart for redundant rules"""
    # Count redundancy types
    redundancy_counts = {}
    for redundancy in redundant_rules:
        redundancy_type = redundancy['redundancy_type']
        if 'subset' in redundancy_type.lower():
            redundancy_type = 'Subset Relationship'
        elif 'exact' in redundancy_type.lower():
            redundancy_type = 'Exact Duplicate'
        elif 'overlapping' in redundancy_type.lower():
            redundancy_type = 'Overlapping Rules'
        
        redundancy_counts[redundancy_type] = redundancy_counts.get(redundancy_type, 0) + 1
    
    if not redundancy_counts:
        st.info("No redundancy found to display in chart.")
        return
    
    # Create pie chart with counts in names
    names_with_counts = [f"{name} ({count})" for name, count in redundancy_counts.items()]
    fig = px.pie(
        values=list(redundancy_counts.values()),
        names=names_with_counts,
        title="Redundant Rule Types",
        color_discrete_sequence=px.colors.qualitative.Pastel
    )
    
    # Add percentage labels only (no counts)
    total_redundant = sum(redundancy_counts.values())
    labels_with_percent = [f"{name}<br>({count/total_redundant*100:.1f}%)" 
                          for name, count in redundancy_counts.items()]
    
    fig.update_traces(
        textposition='inside',
        text=labels_with_percent,
        textinfo='text',
        hovertemplate='<b>%{label}</b><br>Count: %{value}<br>Percentage: %{percent}<extra></extra>'
    )
    
    # Update legend to include counts
    fig.update_layout(
        showlegend=True,
        legend=dict(
            title=f"Total Redundant Pairs: {total_redundant}",
            title_font_size=14,
            font_size=12
        ),
        height=400,
        margin=dict(t=50, b=50, l=50, r=50)
    )
    
    # Legend labels already include counts from the names_with_counts
    
    # Store the chart data
    st.session_state.redundancy_chart_data = {
        'redundancy_counts': redundancy_counts,
        'redundant_rules': redundant_rules
    }
    
    # Display chart
    st.plotly_chart(fig, use_container_width=True, key="redundancy_chart")
    
    # Create a simple selectbox for interaction
    st.markdown("**Select a redundancy type to view details:**")
    
    # Get current selection from session state or default
    current_selection = st.session_state.get('selected_redundancy_type', "Select a redundancy type...")
    options = ["Select a redundancy type..."] + list(redundancy_counts.keys())
    
    # Find index of current selection
    try:
        default_index = options.index(current_selection) if current_selection in options else 0
    except ValueError:
        default_index = 0
    
    selected_type = st.selectbox(
        "Choose a redundancy type:",
        options=options,
        index=default_index,
        key="redundancy_type_selector",
        help="Select a redundancy type to view detailed information about affected rule pairs"
    )
    
    # Update session state only if selection changed
    if selected_type and selected_type != "Select a redundancy type...":
        if st.session_state.get('selected_redundancy_type') != selected_type:
            st.session_state.selected_redundancy_type = selected_type
    elif selected_type == "Select a redundancy type..." and 'selected_redundancy_type' in st.session_state:
        # Clear selection if user selects the default option
        del st.session_state.selected_redundancy_type
    
    # Only show data panel if a selection has been made
    if 'selected_redundancy_type' in st.session_state:
        selected_type = st.session_state.selected_redundancy_type
        
        # Filter rules that match this redundancy type
        filtered_rules = []
        for redundancy in redundant_rules:
            redundancy_type = redundancy['redundancy_type']
            if 'subset' in redundancy_type.lower() and selected_type == 'Subset Relationship':
                filtered_rules.append(redundancy)
            elif 'exact' in redundancy_type.lower() and selected_type == 'Exact Duplicate':
                filtered_rules.append(redundancy)
            elif 'overlapping' in redundancy_type.lower() and selected_type == 'Overlapping Rules':
                filtered_rules.append(redundancy)
        
        if filtered_rules:
            st.markdown(f"**Rules with '{selected_type}' redundancy ({len(filtered_rules)} found):**")
            for i, redundancy in enumerate(filtered_rules, 1):
                rule1 = redundancy['rule1']
                rule2 = redundancy['rule2']
                
                with st.expander(f"{i}. {rule1['name']} ↔ {rule2['name']} ({redundancy['redundancy_type']})"):
                    st.markdown(f"**Redundancy Type:** {redundancy['redundancy_type']}")
                    
                    col1, col2 = st.columns(2)
                    with col1:
                        st.markdown("**Rule 1:**")
                        st.write(f"**Name:** {rule1['name']}")
                        st.write(f"**Type:** {rule1['type']}")
                        st.write(f"**Source:** {', '.join(rule1['source']) if rule1['source'] else 'Any'}")
                        st.write(f"**Destination:** {', '.join(rule1['destination']) if rule1['destination'] else 'Any'}")
                        if rule1['ports']:
                            st.write(f"**Ports:** {', '.join(rule1['ports'])}")
                        st.write(f"**Protocols:** {', '.join(rule1['protocols']) if rule1['protocols'] else 'Any'}")
                    
                    with col2:
                        st.markdown("**Rule 2:**")
                        st.write(f"**Name:** {rule2['name']}")
                        st.write(f"**Type:** {rule2['type']}")
                        st.write(f"**Source:** {', '.join(rule2['source']) if rule2['source'] else 'Any'}")
                        st.write(f"**Destination:** {', '.join(rule2['destination']) if rule2['destination'] else 'Any'}")
                        if rule2['ports']:
                            st.write(f"**Ports:** {', '.join(rule2['ports'])}")
                        st.write(f"**Protocols:** {', '.join(rule2['protocols']) if rule2['protocols'] else 'Any'}")
        else:
            st.info(f"No rules found with '{selected_type}' redundancy.")
        
        # Add clear selection button
        if st.button("❌ Clear Selection", key="clear_redundancy_selection"):
            if 'selected_redundancy_type' in st.session_state:
                del st.session_state.selected_redundancy_type
            st.rerun()

def analyze_overly_permissive_rules(rules):
    """Analyze and identify overly permissive rules"""
    overly_permissive = []
    
    # Check network rules
    if rules.get('network'):
        for rule in rules['network']:
            issues = []
            
            # Check for overly broad source ranges
            source_addresses = rule.get('sourceAddresses', [])
            for source in source_addresses:
                if is_overly_broad_source(source):
                    issues.append(f"Overly broad source: {source}")
            
            # Check for overly broad destination ranges
            dest_addresses = rule.get('destinationAddresses', [])
            for dest in dest_addresses:
                if is_overly_broad_destination(dest):
                    issues.append(f"Overly broad destination: {dest}")
            
            # Check for wildcard FQDNs
            dest_fqdns = rule.get('destinationFqdns', [])
            for fqdn in dest_fqdns:
                if is_wildcard_fqdn(fqdn):
                    issues.append(f"Wildcard FQDN: {fqdn}")
            
            # Check for any protocol
            protocols = rule.get('ipProtocols', [])
            if 'Any' in protocols or '*' in protocols:
                issues.append("Any protocol allowed")
            
            # Check for broad port ranges
            ports = rule.get('destinationPorts', [])
            for port in ports:
                if is_broad_port_range(port):
                    issues.append(f"Broad port range: {port}")
            
            if issues:
                overly_permissive.append({
                    'rule_name': rule.get('name', 'Unnamed'),
                    'rule_type': 'Network',
                    'issues': issues,
                    'source': ', '.join(source_addresses + rule.get('sourceIpGroups', []) + rule.get('sourceServiceTags', [])),
                    'destination': ', '.join(dest_addresses + dest_fqdns + rule.get('destinationIpGroups', []) + rule.get('destinationServiceTags', [])),
                    'ports': ', '.join(ports),
                    'protocols': ', '.join(protocols)
                })
    
    # Check application rules
    if rules.get('application'):
        for rule in rules['application']:
            issues = []
            
            # Check for overly broad source ranges
            source_addresses = rule.get('sourceAddresses', [])
            for source in source_addresses:
                if is_overly_broad_source(source):
                    issues.append(f"Overly broad source: {source}")
            
            # Check for wildcard FQDNs
            target_fqdns = rule.get('targetFqdns', [])
            for fqdn in target_fqdns:
                if is_wildcard_fqdn(fqdn):
                    issues.append(f"Wildcard FQDN: {fqdn}")
            
            # Check for wildcard URLs
            target_urls = rule.get('targetUrls', [])
            for url in target_urls:
                if is_wildcard_url(url):
                    issues.append(f"Wildcard URL: {url}")
            
            if issues:
                overly_permissive.append({
                    'rule_name': rule.get('name', 'Unnamed'),
                    'rule_type': 'Application',
                    'issues': issues,
                    'source': ', '.join(source_addresses + rule.get('sourceIpGroups', []) + rule.get('sourceServiceTags', [])),
                    'destination': ', '.join(target_fqdns + target_urls),
                    'protocols': ', '.join([f"{p.get('protocolType', 'N/A')}:{p.get('port', 'N/A')}" for p in rule.get('protocols', [])])
                })
    
    return overly_permissive

def analyze_redundant_rules(rules):
    """Analyze and identify redundant/duplicate rules"""
    redundant_rules = []
    
    # Get all rules
    all_rules = []
    if rules.get('network'):
        for rule in rules['network']:
            all_rules.append({
                'rule': rule,
                'type': 'Network',
                'name': rule.get('name', 'Unnamed'),
                'source': set(rule.get('sourceAddresses', []) + rule.get('sourceIpGroups', []) + rule.get('sourceServiceTags', [])),
                'destination': set(rule.get('destinationAddresses', []) + rule.get('destinationFqdns', []) + rule.get('destinationIpGroups', []) + rule.get('destinationServiceTags', [])),
                'ports': set(rule.get('destinationPorts', [])),
                'protocols': set(rule.get('ipProtocols', []))
            })
    
    if rules.get('application'):
        for rule in rules['application']:
            all_rules.append({
                'rule': rule,
                'type': 'Application',
                'name': rule.get('name', 'Unnamed'),
                'source': set(rule.get('sourceAddresses', []) + rule.get('sourceIpGroups', []) + rule.get('sourceServiceTags', [])),
                'destination': set(rule.get('targetFqdns', []) + rule.get('targetUrls', [])),
                'ports': set(),
                'protocols': set([f"{p.get('protocolType', 'N/A')}:{p.get('port', 'N/A')}" for p in rule.get('protocols', [])])
            })
    
    # Find redundant rules
    for i, rule1 in enumerate(all_rules):
        for j, rule2 in enumerate(all_rules[i+1:], i+1):
            if rule1['type'] == rule2['type']:  # Only compare same type
                redundancy_type = check_redundancy(rule1, rule2)
                if redundancy_type:
                    redundant_rules.append({
                        'rule1': rule1,
                        'rule2': rule2,
                        'redundancy_type': redundancy_type
                    })
    
    return redundant_rules

def is_overly_broad_source(source):
    """Check if a source IP range is overly broad"""
    if not source or source == '*':
        return True
    
    # Check for very broad private ranges
    broad_ranges = [
        '0.0.0.0/0',  # Any
        '10.0.0.0/8',  # Entire Class A private
        '172.16.0.0/12',  # Entire Class B private
        '192.168.0.0/16',  # Entire Class C private
    ]
    
    return source in broad_ranges

def is_overly_broad_destination(dest):
    """Check if a destination IP range is overly broad"""
    if not dest or dest == '*':
        return True
    
    # Check for very broad ranges
    broad_ranges = [
        '0.0.0.0/0',  # Any
        '10.0.0.0/8',  # Entire Class A private
        '172.16.0.0/12',  # Entire Class B private
        '192.168.0.0/16',  # Entire Class C private
    ]
    
    return dest in broad_ranges

def is_wildcard_fqdn(fqdn):
    """Check if an FQDN is a wildcard"""
    if not fqdn:
        return False
    
    return fqdn.startswith('*') or fqdn == '*'

def is_wildcard_url(url):
    """Check if a URL is a wildcard"""
    if not url:
        return False
    
    return url.startswith('*') or url == '*' or '/*' in url

def is_broad_port_range(port):
    """Check if a port range is overly broad"""
    if not port:
        return False
    
    # Check for broad port ranges
    broad_ranges = ['1-65535', '0-65535', '*', 'Any']
    return port in broad_ranges

def check_redundancy(rule1, rule2):
    """Check if two rules are redundant"""
    # Check for exact duplicates
    if (rule1['source'] == rule2['source'] and 
        rule1['destination'] == rule2['destination'] and 
        rule1['ports'] == rule2['ports'] and 
        rule1['protocols'] == rule2['protocols']):
        return "Exact Duplicate"
    
    # Check for subset relationships
    if (rule1['source'].issubset(rule2['source']) and 
        rule1['destination'].issubset(rule2['destination']) and 
        rule1['ports'].issubset(rule2['ports']) and 
        rule1['protocols'].issubset(rule2['protocols'])):
        return f"{rule1['name']} is subset of {rule2['name']}"
    
    if (rule2['source'].issubset(rule1['source']) and 
        rule2['destination'].issubset(rule1['destination']) and 
        rule2['ports'].issubset(rule1['ports']) and 
        rule2['protocols'].issubset(rule1['protocols'])):
        return f"{rule2['name']} is subset of {rule1['name']}"
    
    # Check for overlapping rules
    if (rule1['source'] & rule2['source'] and 
        rule1['destination'] & rule2['destination'] and 
        rule1['ports'] & rule2['ports'] and 
        rule1['protocols'] & rule2['protocols']):
        return "Overlapping Rules"
    
    return None

