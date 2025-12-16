#!/usr/bin/env python3
import csv
import re
import os
import ipaddress
import pandas as pd
from typing import Dict, List, Tuple, Optional
from io import StringIO

class PolicyMatcher:
    def __init__(self, policy_dir: str = None):
        if policy_dir is None:
            policy_dir = os.path.join(os.path.dirname(__file__), "POLICY_ID")
        self.policy_dir = policy_dir
    
    def parse_policy_file(self, policy_file_path: str) -> Dict[Tuple[str, str, str], Tuple[str, str]]:
        """
        Parse policy file and extract mappings.
        Supports both CSV and Excel files.
        Returns dict with (src_ip, dst_ip, port) -> (policy_id, interface)
        """
        policy_mappings = {}
        
        try:
            if policy_file_path.endswith('.xlsx'):
                # Handle Excel files - first try to find actual policy data in additional sheets
                xl_file = pd.ExcelFile(policy_file_path)
                
                # Look for sheets that contain actual policy results
                for sheet_name in xl_file.sheet_names:
                    df_sheet = pd.read_excel(policy_file_path, sheet_name=sheet_name)
                    
                    # Check if this sheet contains policy ID results
                    for col in df_sheet.columns:
                        sample_data = df_sheet[col].astype(str).str.cat(sep=' ')
                        if 'matches policy id:' in sample_data.lower():
                            print(f"Found policy results in sheet '{sheet_name}', column '{col}'")
                            
                            # Parse the policy results from this sheet
                            for idx, row in df_sheet.iterrows():
                                content = str(row[col])
                                
                                # Look for the policy pattern: <src [IP-PORT] dst [IP-PORT] proto PROTOCOL dev INTERFACE> matches policy id: ID
                                pattern = r'<src \[([0-9.]+)-(\d+)\] dst \[([0-9.]+)-(\d+)\] proto (\w+) dev ([^>]+)> matches policy id: (\d+)'
                                match = re.search(pattern, content)
                                
                                if match:
                                    src_ip, src_port, dst_ip, dst_port, protocol, interface, policy_id = match.groups()
                                    
                                    # Key: (src_ip, dst_ip, port) - using dst_port as the key port
                                    key = (src_ip, dst_ip, dst_port)
                                    value = (policy_id, interface)
                                    
                                    policy_mappings[key] = value
                                    print(f"Found mapping: {src_ip} -> {dst_ip}:{dst_port} = Policy {policy_id} on {interface}")
                            
                            # If we found policy data, return it
                            if policy_mappings:
                                return policy_mappings
                
                # If no policy results found in additional sheets, fall back to structured data approach
                df = pd.read_excel(policy_file_path)
                
                if df.empty:
                    return policy_mappings
                
                # Look for the firewall lookup commands in the columns
                firewall_col = None
                interface_col = None
                
                # Find columns containing complete firewall lookup commands (with IP addresses)
                for col in df.columns:
                    sample_data = df[col].astype(str).str.cat(sep=' ')
                    if 'diagnose firewall iprope lookup' in sample_data and any(char.isdigit() for char in sample_data):
                        # Check if this column contains complete commands with IP addresses
                        sample_values = df[col].dropna().astype(str).head(3).tolist()
                        if any(len(str(val).split()) >= 10 for val in sample_values):  # Complete command should have many parts
                            firewall_col = col
                            break
                
                # Find interface column - look for columns with interface names only
                for col in df.columns:
                    if col != firewall_col:  # Don't use the same column for both
                        sample_data = df[col].dropna().astype(str).tolist()
                        # Check if this looks like interface names (contains E2-EH- pattern and short strings)
                        if len(sample_data) > 0 and any('E2-EH-' in str(val) or 'EH-VDI' in str(val) for val in sample_data[:5]):
                            # Make sure these are short interface names, not full commands
                            if all(len(str(val).split()) <= 3 for val in sample_data[:5]):
                                interface_col = col
                                break
                
                if firewall_col:
                    # Extract policy information from firewall lookup commands
                    for idx, row in df.iterrows():
                        firewall_cmd = str(row[firewall_col])
                        interface = str(row[interface_col]) if interface_col else "Unknown"
                        
                        # Parse firewall lookup command
                        # Format: diagnose firewall iprope lookup SRC_IP SRC_PORT DST_IP DST_PORT PROTOCOL INTERFACE
                        if 'diagnose firewall iprope lookup' in firewall_cmd:
                            parts = firewall_cmd.split()
                            if len(parts) >= 8:
                                try:
                                    src_ip = parts[4]
                                    src_port = parts[5]
                                    dst_ip = parts[6]
                                    dst_port = parts[7]
                                    protocol = parts[8] if len(parts) > 8 else "tcp"
                                    
                                    # Use a synthetic policy ID based on the row index since Excel files don't have actual policy IDs
                                    policy_id = f"EXCEL_{idx + 1}"
                                    
                                    # Key: (src_ip, dst_ip, port) - using dst_port as the key port
                                    key = (src_ip, dst_ip, dst_port)
                                    value = (policy_id, interface)
                                    
                                    policy_mappings[key] = value
                                    print(f"Found mapping: {src_ip} -> {dst_ip}:{dst_port} = Policy {policy_id} on {interface}")
                                except (IndexError, ValueError) as e:
                                    print(f"Error parsing firewall command: {firewall_cmd} - {e}")
                
                return policy_mappings
            
            else:
                # Handle CSV files with raw text format
                with open(policy_file_path, 'r') as f:
                    content = f.read()
                
                # Pattern to match: <src [IP-PORT] dst [IP-PORT] proto PROTOCOL dev INTERFACE> matches policy id: ID
                pattern = r'<src \[([0-9.]+)-(\d+)\] dst \[([0-9.]+)-(\d+)\] proto (\w+) dev ([^>]+)> matches policy id: (\d+)'
                
                matches = re.findall(pattern, content)
                
                for match in matches:
                    src_ip, src_port, dst_ip, dst_port, protocol, interface, policy_id = match
                    
                    # Key: (src_ip, dst_ip, port) - using dst_port as the key port
                    key = (src_ip, dst_ip, dst_port)
                    value = (policy_id, interface)
                    
                    policy_mappings[key] = value
                    print(f"Found mapping: {src_ip} -> {dst_ip}:{dst_port} = Policy {policy_id} on {interface}")
                
                return policy_mappings
                
        except FileNotFoundError:
            print(f"Policy file not found: {policy_file_path}")
            return policy_mappings
        except Exception as e:
            print(f"Error reading policy file {policy_file_path}: {e}")
            return policy_mappings
    
    def ip_in_cidr(self, ip_str: str, cidr_str: str) -> bool:
        """
        Check if an IP address is within a CIDR range.
        """
        try:
            ip = ipaddress.ip_address(ip_str)
            network = ipaddress.ip_network(cidr_str, strict=False)
            return ip in network
        except:
            return False
    
    def find_matching_policies(self, cidr_ipv4: str, dst_ip: str, port: str, policy_mappings: Dict[Tuple[str, str, str], Tuple[str, str]]) -> List[Tuple[str, str, str]]:
        """
        Find all policy mappings that match the given CIDR and port.
        Returns list of (policy_id, interface, matched_src_ip)
        """
        matches = []
        
        for (src_ip, policy_dst_ip, policy_port), (policy_id, interface) in policy_mappings.items():
            # Check if destination IP and port match
            if policy_dst_ip == dst_ip and policy_port == port:
                # Check if source IP is within the CIDR range
                if self.ip_in_cidr(src_ip, cidr_ipv4):
                    matches.append((policy_id, interface, src_ip))
        
        return matches
    
    def find_policy_file(self, dst_ip: str) -> Optional[str]:
        """
        Find the policy file for a given destination IP.
        Looks for both CSV and XLSX files, preferring CSV.
        """
        # Try CSV first
        csv_file = os.path.join(self.policy_dir, f"{dst_ip}_ads.csv")
        if os.path.exists(csv_file):
            return csv_file
        
        # Try XLSX
        xlsx_file = os.path.join(self.policy_dir, f"{dst_ip}_ads.xlsx")
        if os.path.exists(xlsx_file):
            print(f"Found XLSX file: {xlsx_file}")
            return xlsx_file
        
        print(f"No policy file found for destination IP: {dst_ip}")
        return None
    
    def process_security_group_content(self, sg_content: str, dst_ip: str) -> Tuple[str, int, List[str]]:
        """
        Process security group content and match with policy IDs.
        Returns (updated_content, matches_found, log_messages)
        """
        log_messages = []
        
        # Find policy file for destination IP
        policy_file = self.find_policy_file(dst_ip)
        if not policy_file:
            return sg_content, 0, [f"No policy file found for destination IP: {dst_ip}"]
        
        # Parse policy mappings
        policy_mappings = self.parse_policy_file(policy_file)
        log_messages.append(f"Found {len(policy_mappings)} policy mappings from {policy_file}")
        
        if not policy_mappings:
            return sg_content, 0, log_messages + ["No policy mappings found in the policy file"]
        
        # Process CSV content
        updated_rows = []
        matches_found = 0
        
        # Parse CSV content
        csv_reader = csv.DictReader(StringIO(sg_content))
        fieldnames = csv_reader.fieldnames
        
        if not fieldnames:
            return sg_content, 0, log_messages + ["Invalid CSV format - no headers found"]
        
        for row in csv_reader:
            # Skip egress rules
            if row.get('type') == 'egress':
                updated_rows.append(row)
                continue
            
            # Extract CIDR and port information
            cidr_ipv4 = row.get('cidr_ipv4', '')
            from_port = row.get('from_port', '')
            to_port = row.get('to_port', '')
            
            # Skip if no CIDR or ports are -1 (all ports)
            if not cidr_ipv4 or from_port == '-1' or to_port == '-1':
                updated_rows.append(row)
                continue
            
            # Find matching policies for both from_port and to_port
            all_matches = []
            
            # Check from_port
            matches_from = self.find_matching_policies(cidr_ipv4, dst_ip, from_port, policy_mappings)
            all_matches.extend([(m[0], m[1], m[2], from_port) for m in matches_from])
            
            # Check to_port if different from from_port
            if from_port != to_port:
                matches_to = self.find_matching_policies(cidr_ipv4, dst_ip, to_port, policy_mappings)
                all_matches.extend([(m[0], m[1], m[2], to_port) for m in matches_to])
            
            # Update description if matches found
            if all_matches:
                original_desc = row.get('description', '')
                
                # Group by policy ID and collect unique interfaces for each policy
                policy_groups = {}
                for policy_id, interface, matched_src_ip, matched_port in all_matches:
                    if policy_id not in policy_groups:
                        policy_groups[policy_id] = set()
                    policy_groups[policy_id].add(interface)
                
                # Create policy info strings grouped by policy ID
                policy_infos = []
                for policy_id in sorted(policy_groups.keys()):
                    interfaces = sorted(policy_groups[policy_id])
                    if len(interfaces) == 1:
                        policy_infos.append(f"{policy_id} # {interfaces[0]}")
                    else:
                        interface_list = ", ".join(interfaces)
                        policy_infos.append(f"{policy_id} # {interface_list}")
                
                # Join all policy info and put it BEFORE the original description
                policy_info_str = " # ".join(policy_infos)
                new_desc = f"{policy_info_str} # {original_desc}"
                row['description'] = new_desc
                matches_found += 1
                
                log_messages.append(f"MATCH FOUND: {row.get('name', 'Unknown')} - CIDR {cidr_ipv4} contains {len(all_matches)} policy matches")
                for policy_id, interface, matched_src_ip, matched_port in all_matches:
                    log_messages.append(f"  -> {matched_src_ip}:{matched_port} = Policy {policy_id} on {interface}")
            
            updated_rows.append(row)
        
        # Convert back to CSV string
        output = StringIO()
        writer = csv.DictWriter(output, fieldnames=fieldnames, lineterminator='\n')
        writer.writeheader()
        writer.writerows(updated_rows)
        updated_content = output.getvalue()
        
        log_messages.append(f"Processing complete! Total matches found: {matches_found}")
        
        return updated_content, matches_found, log_messages