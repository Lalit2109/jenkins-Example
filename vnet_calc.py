"""
Advanced VNet Calculator Module
Handles VNet range calculation, Azure integration, and intelligent CIDR suggestions
"""

import ipaddress
import json
import os
import logging
from typing import Dict, List, Tuple, Optional, Any
from datetime import datetime
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

logger = logging.getLogger(__name__)

class VNetCalculator:
    """Advanced VNet Calculator with Azure integration and intelligent suggestions"""
    
    def __init__(self, azure_service=None):
        """
        Initialize VNet Calculator
        
        Args:
            azure_service: Azure service instance for fetching VNet data
        """
        self.azure_service = azure_service
        self.environment_config = self._load_environment_config()
        self.subnet_sizes = self._get_subnet_sizes()
        self.used_ranges_cache = {}
        self.last_refresh = None
        
    def _load_environment_config(self) -> Dict:
        """Load environment configuration"""
        try:
            config_file = "sample_data/vnet_environment.json"
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    return json.load(f)
            else:
                # Return default config if file doesn't exist
                return {
                    "Dev": {
                        "UK South": "10.100.0.0/14",
                        "East US": "10.101.0.0/14",
                        "West Europe": "10.102.0.0/14",
                        "North Europe": "10.103.0.0/14"
                    },
                    "Test": {
                        "UK South": "10.108.0.0/14",
                        "East US": "10.109.0.0/14",
                        "West Europe": "10.110.0.0/14",
                        "North Europe": "10.111.0.0/14"
                    },
                    "Prod": {
                        "UK South": "10.116.0.0/14",
                        "East US": "10.117.0.0/14",
                        "West Europe": "10.118.0.0/14",
                        "North Europe": "10.119.0.0/14"
                    },
                    "Staging": {
                        "UK South": "10.124.0.0/14",
                        "East US": "10.125.0.0/14",
                        "West Europe": "10.126.0.0/14",
                        "North Europe": "10.127.0.0/14"
                    }
                }
        except Exception as e:
            logger.error(f"Error loading environment config: {e}")
            return {}
    
    def _get_subnet_sizes(self) -> Dict:
        """Get subnet size configurations"""
        return {
            "/16": {"name": "Very Large", "ips": 65536, "description": "Enterprise networks"},
            "/20": {"name": "Large", "ips": 4096, "description": "Large departments"},
            "/24": {"name": "Medium", "ips": 256, "description": "Standard subnets"},
            "/25": {"name": "Medium-Small", "ips": 128, "description": "Medium workloads"},
            "/26": {"name": "Small", "ips": 64, "description": "Small workloads"},
            "/27": {"name": "Very Small", "ips": 32, "description": "Small teams"},
            "/28": {"name": "Tiny", "ips": 16, "description": "Micro services"},
            "/29": {"name": "Micro", "ips": 8, "description": "Very small services"},
            "/30": {"name": "Point-to-Point", "ips": 4, "description": "VPN connections"}
        }
    
    def get_environment_config(self) -> Dict:
        """Get environment configuration"""
        return self.environment_config
    
    def get_subnet_sizes(self) -> Dict:
        """Get subnet size configurations"""
        return self.subnet_sizes
    
    def fetch_azure_vnets(self, resource_groups: List[str] = None, subscriptions: List[str] = None) -> Dict[str, List[Dict]]:
        """
        Fetch VNet data from Azure across all accessible subscriptions
        
        Args:
            resource_groups: List of resource groups to search (optional, ignored in multi-subscription mode)
            subscriptions: List of subscription IDs to search (optional, uses all accessible if not provided)
            
        Returns:
            Dictionary with subscription_id as key and list of VNets as value
        """
        if not self.azure_service or not self.azure_service.authenticated:
            logger.warning("Azure service not available, using sample data")
            return self._load_sample_vnets()
        
        try:
            # Use the new multi-subscription approach
            logger.info("🔍 Fetching VNets from all accessible subscriptions...")
            all_vnets = self.azure_service.get_all_virtual_networks()
            
            if not all_vnets:
                logger.warning("No VNets found in any accessible subscription")
                return self._load_sample_vnets()
            
            total_vnets = sum(len(vnets) for vnets in all_vnets.values())
            total_subscriptions = len(all_vnets)
            logger.info(f"✅ Found {total_vnets} VNets across {total_subscriptions} subscriptions")
            
            return all_vnets
        
        except Exception as e:
            logger.error(f"Error fetching Azure VNets: {e}")
            return self._load_sample_vnets()

    def get_cached_vnet_data(self) -> Dict[str, List[Dict]]:
        """
        Get VNet data from cache (session state) or fallback to sample data
        
        Returns:
            Dictionary with resource group as key and list of VNets as value
        """
        try:
            import streamlit as st
            
            # Check if VNet data is in session state
            if hasattr(st, 'session_state') and st.session_state.get('vnet_data'):
                vnet_data = st.session_state.vnet_data
                
                # Handle different data structures
                if isinstance(vnet_data, dict):
                    logger.info(f"Using cached VNet data: {len(vnet_data)} resource groups")
                    return vnet_data
                elif isinstance(vnet_data, list):
                    # Convert list format to dict format for compatibility
                    logger.info(f"Converting list VNet data to dict format: {len(vnet_data)} VNets")
                    return {"sample": vnet_data}
                else:
                    logger.warning(f"Unexpected VNet data format: {type(vnet_data)}")
                    return self._load_sample_vnets()
            else:
                logger.info("No cached VNet data found, using sample data")
                return self._load_sample_vnets()
        except Exception as e:
            logger.error(f"Error getting cached VNet data: {e}")
            return self._load_sample_vnets()
    
    def _load_sample_vnets(self) -> Dict[str, List[Dict]]:
        """Load sample VNet data for testing"""
        try:
            sample_file = "sample_data/sample_vnets.json"
            if os.path.exists(sample_file):
                with open(sample_file, 'r') as f:
                    vnets = json.load(f)
                return {"sample": vnets}
            else:
                return {"sample": []}
        except Exception as e:
            logger.error(f"Error loading sample VNets: {e}")
            return {"sample": []}
    
    def extract_used_ranges(self, vnet_data: Dict[str, List[Dict]]) -> List[str]:
        """
        Extract all used IP ranges from VNet data
        
        Args:
            vnet_data: Dictionary of VNet data by subscription
            
        Returns:
            List of used IP ranges in CIDR notation
        """
        used_ranges = []
        
        for subscription_id, vnets in vnet_data.items():
            for vnet in vnets:
                # Extract VNet address space - THIS IS THE KEY!
                # If a VNet has range 10.100.0.0/16, then the ENTIRE range is used
                # We don't need to track individual subnets because they're all within the VNet range
                if 'addressSpace' in vnet and 'addressPrefixes' in vnet['addressSpace']:
                    for prefix in vnet['addressSpace']['addressPrefixes']:
                        used_ranges.append(prefix)
                        logger.debug(f"Added VNet range: {prefix} (entire range is considered used)")
        
        # Remove duplicates and sort
        used_ranges = list(set(used_ranges))
        used_ranges.sort()
        
        logger.info(f"Extracted {len(used_ranges)} used VNet ranges (subnets are within VNet ranges)")
        return used_ranges
    
    def find_available_cidrs(self, environment: str, region: str, subnet_size: str, 
                           max_suggestions: int = 10, exclude_ranges: List[str] = None) -> Dict:
        """
        Find available CIDR ranges for a given environment, region, and subnet size
        
        Args:
            environment: Environment name (Dev, Test, Prod, Staging)
            region: Azure region (UK South, East US, etc.)
            subnet_size: Required subnet size (e.g., "/24")
            max_suggestions: Maximum number of suggestions to return
            exclude_ranges: Additional ranges to exclude
            
        Returns:
            Dictionary with available CIDR suggestions and metadata
        """
        try:
            # Get master range for environment and region
            if environment not in self.environment_config:
                return {"error": f"Environment '{environment}' not found"}
            
            if region not in self.environment_config[environment]:
                return {"error": f"Region '{region}' not found in {environment} environment"}
            
            master_cidr = self.environment_config[environment][region]
            master_network = ipaddress.ip_network(master_cidr, strict=False)
            subnet_bits = int(subnet_size.strip('/'))
            
            # Validate subnet size
            if subnet_bits < master_network.prefixlen:
                return {"error": f"Subnet size {subnet_size} is too large for master range {master_cidr}"}
            
            # Get used ranges from cached data
            vnet_data = self.get_cached_vnet_data()
            used_ranges = self.extract_used_ranges(vnet_data)
            
            # Add any additional ranges to exclude
            if exclude_ranges:
                used_ranges.extend(exclude_ranges)
            
            # Convert used ranges to network objects
            used_networks = []
            for range_str in used_ranges:
                try:
                    used_networks.append(ipaddress.ip_network(range_str, strict=False))
                except Exception:
                    continue  # Skip invalid ranges
            
            # Find available subnets
            available_subnets = self._find_available_subnets(
                master_network, subnet_bits, used_networks, max_suggestions
            )
            
            if not available_subnets:
                return {"error": f"No available {subnet_size} subnets found in {master_cidr}"}
            
            # Calculate total possible subnets
            total_possible = 2 ** (subnet_bits - master_network.prefixlen)
            
            return {
                "environment": environment,
                "region": region,
                "master_range": master_cidr,
                "subnet_size": subnet_size,
                "available_subnets": available_subnets,
                "total_possible": total_possible,
                "used_ranges_considered": len(used_networks),
                "suggestions_count": len(available_subnets)
            }
            
        except Exception as e:
            logger.error(f"Error finding available CIDRs: {e}")
            return {"error": str(e)}
    
    def _find_available_subnets(self, master_network: ipaddress.IPv4Network, 
                              subnet_bits: int, used_networks: List[ipaddress.IPv4Network],
                              max_suggestions: int) -> List[Dict]:
        """Find available subnets within master range"""
        available_subnets = []
        current_subnet = ipaddress.ip_network(f"{master_network.network_address}/{subnet_bits}", strict=False)
        
        while (current_subnet.network_address in master_network and 
               len(available_subnets) < max_suggestions):
            
            # Check if this subnet overlaps with any used networks
            overlap = False
            for used in used_networks:
                if current_subnet.overlaps(used):
                    overlap = True
                    break
            
            if not overlap:
                # This subnet is available
                subnet_info = {
                    "cidr": str(current_subnet),
                    "network_address": str(current_subnet.network_address),
                    "broadcast_address": str(current_subnet.broadcast_address),
                    "first_usable_ip": str(current_subnet.network_address + 1),
                    "last_usable_ip": str(current_subnet.broadcast_address - 1),
                    "total_ips": current_subnet.num_addresses,
                    "usable_ips": current_subnet.num_addresses - 2
                }
                available_subnets.append(subnet_info)
            
            # Move to next subnet
            next_network = current_subnet.network_address + current_subnet.num_addresses
            current_subnet = ipaddress.ip_network(f"{next_network}/{subnet_bits}", strict=False)
        
        return available_subnets
    
    def suggest_optimal_cidr(self, environment: str, region: str, required_ips: int) -> Dict:
        """
        Suggest optimal CIDR size based on required number of IPs
        
        Args:
            environment: Environment name
            region: Azure region
            required_ips: Number of IPs required
            
        Returns:
            Dictionary with suggested subnet size and available ranges
        """
        # Find appropriate subnet size
        suggested_size = None
        for size, config in self.subnet_sizes.items():
            if config['ips'] >= required_ips:
                suggested_size = size
                break
        
        if not suggested_size:
            return {"error": f"No subnet size available for {required_ips} IPs"}
        
        # Find available CIDRs with suggested size
        result = self.find_available_cidrs(environment, region, suggested_size)
        
        if "error" in result:
            return result
        
        # Add suggestion metadata
        result["suggested_size"] = suggested_size
        result["required_ips"] = required_ips
        result["efficiency"] = (required_ips / self.subnet_sizes[suggested_size]['ips']) * 100
        
        return result
    
    def check_cidr_availability(self, cidr: str, environment: str = None, region: str = None) -> Dict:
        """
        Check if a specific CIDR is available
        
        Args:
            cidr: CIDR to check
            environment: Environment to check against (optional)
            region: Region to check against (optional)
            
        Returns:
            Dictionary with availability status and details
        """
        try:
            target_network = ipaddress.ip_network(cidr, strict=False)
            
            # Get used ranges
            vnet_data = self.get_cached_vnet_data()
            used_ranges = self.extract_used_ranges(vnet_data)
            
            # Check for overlaps
            overlaps = []
            for range_str in used_ranges:
                try:
                    used_network = ipaddress.ip_network(range_str, strict=False)
                    if target_network.overlaps(used_network):
                        overlaps.append({
                            "range": range_str,
                            "overlap_type": self._get_overlap_type(target_network, used_network)
                        })
                except Exception:
                    continue
            
            # Check if within environment/region master range
            master_range_check = {}
            if environment and region:
                if (environment in self.environment_config and 
                    region in self.environment_config[environment]):
                    master_cidr = self.environment_config[environment][region]
                    master_network = ipaddress.ip_network(master_cidr, strict=False)
                    master_range_check = {
                        "master_range": master_cidr,
                        "within_master": target_network.network_address in master_network,
                        "completely_within": (target_network.network_address >= master_network.network_address and
                                            target_network.broadcast_address <= master_network.broadcast_address)
                    }
            
            return {
                "cidr": cidr,
                "available": len(overlaps) == 0,
                "overlaps": overlaps,
                "master_range_check": master_range_check,
                "used_ranges_checked": len(used_ranges)
            }
            
        except Exception as e:
            return {"error": str(e)}
    
    def _get_overlap_type(self, network1: ipaddress.IPv4Network, network2: ipaddress.IPv4Network) -> str:
        """Determine the type of overlap between two networks"""
        if network1.network_address >= network2.network_address and network1.broadcast_address <= network2.broadcast_address:
            return "completely_within"
        elif network2.network_address >= network1.network_address and network2.broadcast_address <= network1.broadcast_address:
            return "completely_contains"
        else:
            return "partial_overlap"
    
    def get_environment_summary(self) -> Dict:
        """Get summary of all environments and their configurations"""
        summary = {}
        
        for env, regions in self.environment_config.items():
            summary[env] = {
                "regions": list(regions.keys()),
                "total_regions": len(regions),
                "master_ranges": regions
            }
        
        return summary
    
    def export_suggestions_to_csv(self, suggestions: List[Dict], filename: str = None) -> str:
        """Export CIDR suggestions to CSV format"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"vnet_suggestions_{timestamp}.csv"
        
        df = pd.DataFrame(suggestions)
        csv_content = df.to_csv(index=False)
        
        return csv_content, filename
    
    def create_visualization(self, suggestions: List[Dict], title: str = "VNet CIDR Suggestions") -> go.Figure:
        """Create visualization for CIDR suggestions"""
        if not suggestions:
            return None
        
        # Prepare data for visualization
        data = []
        for i, suggestion in enumerate(suggestions):
            data.append({
                'Suggestion': f"Option {i+1}",
                'CIDR': suggestion['cidr'],
                'Usable IPs': suggestion['usable_ips'],
                'Network': suggestion['network_address']
            })
        
        # Create bar chart
        fig = px.bar(
            data,
            x='Suggestion',
            y='Usable IPs',
            title=title,
            color='Usable IPs',
            color_continuous_scale='viridis',
            hover_data=['CIDR', 'Network']
        )
        
        fig.update_layout(
            xaxis_title="Suggestion",
            yaxis_title="Usable IPs",
            height=400,
            showlegend=False
        )
        
        return fig

# Utility functions for backward compatibility
def load_environment_config(config_file: str = "sample_data/vnet_environment.json") -> Dict:
    """Load environment configuration from file"""
    calculator = VNetCalculator()
    return calculator.get_environment_config()

def calculate_vnet_range(master_cidr: str, subnet_size: str, existing_ranges: List[str] = None) -> Dict:
    """Calculate next available VNet range (legacy function)"""
    calculator = VNetCalculator()
    
    try:
        master_network = ipaddress.ip_network(master_cidr, strict=False)
        subnet_bits = int(subnet_size.strip('/'))
        
        if subnet_bits < master_network.prefixlen:
            return {"error": f"Subnet size {subnet_size} is too large for master range {master_cidr}"}
        
        used_networks = []
        if existing_ranges:
            for range_str in existing_ranges:
                try:
                    used_networks.append(ipaddress.ip_network(range_str, strict=False))
                except Exception:
                    continue
        
        available_subnets = calculator._find_available_subnets(master_network, subnet_bits, used_networks, 1)
        
        if not available_subnets:
            return {"error": f"No available {subnet_size} subnets found in {master_cidr}"}
        
        subnet = available_subnets[0]
        return {
            "available_range": subnet['cidr'],
            "total_subnets": 2 ** (subnet_bits - master_network.prefixlen),
            "subnet_size": subnet_size,
            "master_range": master_cidr,
            "usable_ips": subnet['usable_ips'],
            "network_address": subnet['network_address'],
            "broadcast_address": subnet['broadcast_address'],
            "existing_ranges_considered": len(existing_ranges) if existing_ranges else 0
        }
    except Exception as e:
        return {"error": str(e)}

def divide_into_subnets(network_cidr: str, subnet_size: str) -> List[Dict]:
    """Divide a network into subnets of specified size (legacy function)"""
    try:
        network = ipaddress.ip_network(network_cidr, strict=False)
        subnet_bits = int(subnet_size.strip('/'))
        
        if subnet_bits < network.prefixlen:
            return [{"error": f"Subnet size {subnet_size} is too large for network {network_cidr}"}]
        
        subnets = list(network.subnets(new_prefix=subnet_bits))
        subnet_data = []
        
        for i, subnet in enumerate(subnets):
            subnet_data.append({
                "subnet_number": i + 1,
                "network": str(subnet.network_address),
                "range": str(subnet),
                "first_ip": str(subnet.network_address + 1),
                "last_ip": str(subnet.broadcast_address - 1),
                "broadcast": str(subnet.broadcast_address),
                "total_ips": subnet.num_addresses,
                "usable_ips": subnet.num_addresses - 2,
                "gateway_suggestion": str(subnet.network_address + 1)
            })
        
        return subnet_data
    except Exception as e:
        return [{"error": str(e)}]

def check_ip_overlap(range1: str, range2: str) -> Dict:
    """Check if two IP ranges overlap (legacy function)"""
    try:
        net1 = ipaddress.ip_network(range1, strict=False)
        net2 = ipaddress.ip_network(range2, strict=False)
        
        overlap = net1.overlaps(net2)
        
        return {
            "overlap": overlap,
            "range1": {
                "cidr": str(net1),
                "network": str(net1.network_address),
                "broadcast": str(net1.broadcast_address),
                "total_ips": net1.num_addresses
            },
            "range2": {
                "cidr": str(net2),
                "network": str(net2.network_address),
                "broadcast": str(net2.broadcast_address),
                "total_ips": net2.num_addresses
            },
            "overlap_details": get_overlap_details(net1, net2) if overlap else None
        }
    except Exception as e:
        return {"error": str(e)}

def get_overlap_details(net1: ipaddress.IPv4Network, net2: ipaddress.IPv4Network) -> Dict:
    """Get detailed overlap information between two networks (legacy function)"""
    try:
        if net1.network_address <= net2.network_address:
            start = net2.network_address
        else:
            start = net1.network_address
        
        if net1.broadcast_address <= net2.broadcast_address:
            end = net1.broadcast_address
        else:
            end = net2.broadcast_address
        
        overlap_start = start
        overlap_end = end
        
        return {
            "overlap_range": f"{overlap_start}/{overlap_end}",
            "overlap_ips": int(overlap_end) - int(overlap_start) + 1,
            "overlap_start": str(overlap_start),
            "overlap_end": str(overlap_end)
        }
    except Exception:
        return {"error": "Could not calculate overlap details"}

def validate_cidr(cidr: str) -> bool:
    """Validate if a string is a valid CIDR notation (legacy function)"""
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except Exception:
        return False

def get_subnet_info(cidr: str) -> Dict:
    """Get detailed information about a subnet (legacy function)"""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return {
            "cidr": str(network),
            "network_address": str(network.network_address),
            "broadcast_address": str(network.broadcast_address),
            "first_usable_ip": str(network.network_address + 1),
            "last_usable_ip": str(network.broadcast_address - 1),
            "total_ips": network.num_addresses,
            "usable_ips": network.num_addresses - 2,
            "prefix_length": network.prefixlen,
            "subnet_mask": str(network.netmask),
            "wildcard_mask": str(network.hostmask)
        }
    except Exception as e:
        return {"error": str(e)}

def extract_ip_ranges_from_vnets(vnet_data: List[Dict]) -> List[str]:
    """Extract IP ranges from Azure VNet data (legacy function)"""
    calculator = VNetCalculator()
    return calculator.extract_used_ranges({"sample": vnet_data})

