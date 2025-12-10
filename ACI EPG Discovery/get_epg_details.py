import requests
import json
import pandas as pd
import re
import urllib3
import getpass
import os
import sys
import argparse

# Import logger
try:
    # Add project root to sys.path to allow importing utils
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if project_root not in sys.path:
        sys.path.append(project_root)
    from utils.logger import setup_logger
    logger = setup_logger("get_epg_details")
except ImportError:
    import logging
    logger = logging.getLogger("get_epg_details")
    # print("Warning: Could not import centralized logger. Using default.")

# Add project root to sys.path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.append(project_root)

try:
    import credential_manager
except ImportError:
    credential_manager = None

# Disable warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def login_apic(apic_ip, username, password):
    """Logs into the APIC and returns the session."""
    base_ip = apic_ip.replace("https://", "").replace("http://", "").rstrip("/")
    url = f"https://{base_ip}/api/aaaLogin.json"
    payload = {
        "aaaUser": {
            "attributes": {
                "name": username,
                "pwd": password
            }
        }
    }
    session = requests.Session()
    session.verify = False
    try:
        response = session.post(url, json=payload, timeout=10)
        response.raise_for_status()
        token = response.json()['imdata'][0]['aaaLogin']['attributes']['token']
        session.headers.update({'APIC-Cookie': token})
        return session
    except Exception as e:
        logger.error(f"Login failed: {e}", exc_info=True)
        return None

def normalize_node(node):
    """Normalize node ID (handle floats, spaces)."""
    if pd.isna(node):
        return ""
    s = str(node).strip()
    if s.endswith(".0"):
        s = s[:-2]
    return s

def normalize_interface(interface):
    """Normalize interface name (handle spaces, case, eth prefix)."""
    if pd.isna(interface):
        return ""
    s = str(interface).strip().lower()
    # If format is "1/1", prepend "eth"
    if re.match(r'^\d+/\d+$', s):
        s = f"eth{s}"
    return s

def fetch_bulk_data(session, base_url):
    """
    Fetches all necessary data in 3 bulk API calls.
    Returns:
    - deployments: Dict {(node, interface): [epg_dn, ...]}
    - static_paths: Dict {epg_dn: [{tDn, encap}, ...]}
    """
    # 2. Fetch All VMM Domains (fvRsDomAtt) - REMOVED
    # vmm_domains = {} 

    # 2. Fetch Static Paths (fvRsPathAtt)
    logger.info("  Bulk Fetching 1/1: Static Paths (fvRsPathAtt)...")
    url = f"{base_url}/api/node/class/fvRsPathAtt.json"
    deployments = {} # Key: node_id, Value: [paths]
    static_paths = {} # Key: epg_dn, Value: dict
    
    try:
        response = session.get(url, timeout=120)
        response.raise_for_status()
        data = response.json()
        
        # Save Debug Data
        if not os.path.exists("debug_data"):
            os.makedirs("debug_data")
        with open("debug_data/static_paths.json", "w") as f:
            json.dump(data, f, indent=2)
        logger.info("  [DEBUG] Saved raw static paths to debug_data/static_paths.json")
        
        for item in data.get('imdata', []):
            if 'fvRsPathAtt' in item:
                attr = item['fvRsPathAtt']['attributes']
                # DN format: uni/tn-X/ap-Y/epg-Z/rspathAtt-[...]
                epg_dn = re.split(r'/rspathAtt-', attr.get('dn'))[0] 
                # Extract Data
                tDn = attr.get('tDn')
                instrImedcy = attr.get('instrImedcy', '')
                mode = attr.get('mode', '')
                modTs = attr.get('modTs', '')
                
                # Extract Pod from tDn (topology/pod-1/...)
                pod_match = re.search(r'pod-(\d+)', tDn)
                pod_id = f"pod-{pod_match.group(1)}" if pod_match else ""

                # Store in static_paths map
                if epg_dn not in static_paths:
                    static_paths[epg_dn] = []
                
                static_paths[epg_dn].append({
                    'tDn': tDn,
                    'encap': attr.get('encap'),
                    'instrImedcy': instrImedcy,
                    'mode': mode,
                    'modTs': modTs,
                    'pod': pod_id
                })
                
                # POPULATE DEPLOYMENTS MAP (Node-Centric)
                # Store ALL paths for a node in a list.
                # Key: node_id (str)
                # Value: List of dicts {'epg_dn': ..., 'tDn': ..., 'encap': ...}
                
                path_data = {
                    'epg_dn': epg_dn,
                    'tDn': tDn,
                    'encap': attr.get('encap'),
                    'instrImedcy': instrImedcy,
                    'mode': mode,
                    'modTs': modTs,
                    'pod': pod_id
                }

                # 1. Single Node Path (paths-101)
                match = re.search(r'paths-(\d+)/pathep-\[(.+?)\]', tDn)
                if match:
                    node = normalize_node(match.group(1))
                    
                    if node not in deployments:
                        deployments[node] = []
                    
                    # Avoid duplicates
                    exists = any(d['epg_dn'] == epg_dn and d['tDn'] == tDn for d in deployments[node])
                    if not exists:
                        deployments[node].append(path_data)
                
                # 2. VPC Path (protpaths-A-B)
                match_vpc = re.search(r'protpaths-(\d+)-(\d+)/pathep-\[(.+?)\]', tDn)
                if match_vpc:
                    node_a = normalize_node(match_vpc.group(1))
                    node_b = normalize_node(match_vpc.group(2))
                    vpc_pair = f"{node_a}-{node_b}"
                    
                    path_data['vpc_nodes'] = vpc_pair

                    # Add to Node A
                    if node_a not in deployments:
                        deployments[node_a] = []
                    exists_a = any(d['epg_dn'] == epg_dn and d['tDn'] == tDn for d in deployments[node_a])
                    if not exists_a:
                        deployments[node_a].append(path_data)
                        
                    # Add to Node B
                    if node_b not in deployments:
                        deployments[node_b] = []
                    exists_b = any(d['epg_dn'] == epg_dn and d['tDn'] == tDn for d in deployments[node_b])
                    if not exists_b:
                         deployments[node_b].append(path_data)

    except Exception as e:
        logger.error(f"Error fetching static paths: {e}")

    # 2. Fetch All VMM Domains (fvRsDomAtt) - REMOVED
    # logger.info("  Bulk Fetching 2/2: VMM Domains (fvRsDomAtt)...")
    # url = f"{base_url}/api/node/class/fvRsDomAtt.json"
    # try:
    #     response = session.get(url, timeout=120)
    #     response.raise_for_status()
    #     data = response.json()
        
    #     # DEBUG: Save raw data
    #     with open("debug_data/vmm_domains.json", "w") as f:
    #         json.dump(data, f, indent=2)
    #     logger.info("  [DEBUG] Saved raw VMM domains to debug_data/vmm_domains.json")
        
    #     for item in data.get('imdata', []):
    #         if 'fvRsDomAtt' in item:
    #             attr = item['fvRsDomAtt']['attributes']
    # 2. Fetch All VMM Domains (fvRsDomAtt)
    logger.info("  Bulk Fetching 2/3: VMM Domains (fvRsDomAtt)...")
    vmm_domains = {}
    url = f"{base_url}/api/node/class/fvRsDomAtt.json"
    try:
        response = session.get(url, timeout=120)
        response.raise_for_status()
        data = response.json()
        
        # DEBUG: Save raw data
        if not os.path.exists("debug_data"):
            os.makedirs("debug_data")
        with open("debug_data/vmm_domains.json", "w") as f:
            json.dump(data, f, indent=2)
        logger.info("  [DEBUG] Saved raw VMM domains to debug_data/vmm_domains.json")
        
        for item in data.get('imdata', []):
            if 'fvRsDomAtt' in item:
                attr = item['fvRsDomAtt']['attributes']
                epg_dn = re.split(r'/rsdomAtt-', attr.get('dn'))[0]
                
                if epg_dn not in vmm_domains:
                    vmm_domains[epg_dn] = []
                
                vmm_domains[epg_dn].append(attr.get('tDn'))
    except Exception as e:
        logger.error(f"Error fetching VMM domains: {e}")


    # 3. Fetch Interface Selectors (infraHPortS) for VPC Port Resolution
    logger.info("  Bulk Fetching 3/3: Interface Selectors (infraHPortS)...")
    vpc_ipg_map = {} # Key: PolicyGroup Name, Value: set of port strings
    url = f"{base_url}/api/node/class/infraHPortS.json?rsp-subtree=children"
    try:
        response = session.get(url, timeout=120)
        response.raise_for_status()
        data = response.json()
        
        # DEBUG: Save raw data
        if not os.path.exists("debug_data"):
            os.makedirs("debug_data")
        with open("debug_data/infra_selectors.json", "w") as f:
            json.dump(data, f, indent=2)
        logger.info("  [DEBUG] Saved raw infra selectors to debug_data/infra_selectors.json")
        
        for item in data.get('imdata', []):
            children = item.get('infraHPortS', {}).get('children', [])
            pol_grp_name = None
            ports = set()
            
            for child in children:
                # Link to Policy Group
                if 'infraRsAccBaseGrp' in child:
                    tDn = child['infraRsAccBaseGrp']['attributes'].get('tDn', "")
                    # Extract name from tDn: uni/infra/funcprof/accbundle-NAME or accportgrp-NAME
                    # Capture both types to be safe
                    match = re.search(r'(accbundle|accportgrp)-(.+)$', tDn)
                    if match:
                        pol_grp_name = match.group(2)
                
                # Port Block Definition
                elif 'infraPortBlk' in child:
                    attr = child['infraPortBlk']['attributes']
                    start = attr.get('fromPort', '0')
                    end = attr.get('toPort', '0')
                    try:
                        # Add range
                        for p in range(int(start), int(end) + 1):
                            ports.add(str(p))
                    except ValueError:
                        pass
            
            if pol_grp_name and ports:
                if pol_grp_name not in vpc_ipg_map:
                    vpc_ipg_map[pol_grp_name] = set()
                vpc_ipg_map[pol_grp_name].update(ports)
                
    except Exception as e:
         logger.error(f"Error fetching infraHPortS: {e}")

    return deployments, static_paths, vmm_domains, vpc_ipg_map


def parse_epg_name(epg_dn):
    """Extract Tenant, AppProfile, EPG from DN."""
    # DN: uni/tn-Tenant/ap-Profile/epg-Name
    parts = epg_dn.split('/')
    tenant = ""
    app_profile = ""
    epg_name = ""
    
    for part in parts:
        if part.startswith('tn-'):
            tenant = part[3:]
        elif part.startswith('ap-'):
            app_profile = part[3:]
        elif part.startswith('epg-'):
            epg_name = part[4:]
            
    return tenant, app_profile, epg_name

def run(session, apic_url, input_file=None, output_file='output_epgs.xlsx', username=None, password=None): # input_file is ignored in dump mode
    
    base_url = apic_url.rstrip("/")
    
    # 1. Bulk Fetch (Static Paths)
    # deployments: Dict[node] -> List of path objects
    deployments_map, static_paths_map, vmm_domains_map, vpc_ipg_map = fetch_bulk_data(session, base_url)
    
    all_results = []
    
    logger.info("  Processing All Discovered Static Paths (Dump Mode)...")
    
    # Iterate over ALL nodes and their paths
    for node, paths in deployments_map.items():
        for path_data in paths:
            tDn = path_data['tDn']
            epg_dn = path_data['epg_dn']
            
            # Determine Interface / IPG from tDn
            # Single: .../paths-101/pathep-[eth1/1]
            # VPC: .../protpaths-101-102/pathep-[IPG_NAME]
            
            raw_interface = ""
            pathep_match = re.search(r'pathep-\[(.+?)\]', tDn)
            if pathep_match:
                raw_interface = pathep_match.group(1)
            
            path_type = "Single Port"
            resolved_ports = ""
            vpc_nodes = path_data.get('vpc_nodes', '')
            
            if "protpaths-" in tDn:
                path_type = "VPC"
                # raw_interface is IPG Name. Resolve to ports.
                if raw_interface in vpc_ipg_map:
                    ports = sorted(list(vpc_ipg_map[raw_interface]), key=lambda x: int(x) if x.isdigit() else x)
                    resolved_ports = ",".join([f"eth1/{p}" for p in ports])
                else:
                    resolved_ports = "Unresolved IPG"
            else:
                # Single Port
                path_type = "Single Port"
                resolved_ports = raw_interface # It is the port itself
            
            # Get Domains
            domains = vmm_domains_map.get(epg_dn, [])
            clean_domains = []
            for d_dn in domains:
                parts = d_dn.split('/')
                if parts:
                    clean_domains.append(parts[-1].split('-', 1)[1] if '-' in parts[-1] else parts[-1])
            domains_str = ", ".join(clean_domains)
            
            tenant, app_profile, epg = parse_epg_name(epg_dn)
            
            all_results.append({
                'Node': node,
                'Interface': raw_interface, # Port or IPG
                'Resolved Ports': resolved_ports,
                'Tenant': tenant,
                'ANP': app_profile,
                'EPG': epg,
                'VLAN': path_data['encap'],
                'PathType': path_type,
                'PathDN': tDn,
                'Domains': domains_str,
                'IPG': raw_interface if path_type == "VPC" else "",
                'vpc_nodes': vpc_nodes,
                'instrImedcy': path_data.get('instrImedcy'),
                'mode': path_data.get('mode'),
                'pod': path_data.get('pod'),
                'modTs': path_data.get('modTs'),
                'DN': epg_dn
            })

    # Save Results into 3 Sheets
    if all_results:
        df_all = pd.DataFrame(all_results)
        
        # 1. Sheet "All" (Comprehensive)
        cols_all = ['Node', 'Interface', 'Resolved Ports', 'Tenant', 'ANP', 'EPG', 'VLAN', 'PathType', 'Domains', 'IPG', 'vpc_nodes', 'instrImedcy', 'mode', 'pod', 'modTs', 'PathDN']
        # Ensure cols exist
        for c in cols_all:
             if c not in df_all.columns: df_all[c] = ""
        
        # 2. Sheet "Single Port"
        # Request: pod,teant,anp,epg,node,interface,vlan,immediacy, and mode, modTs
        single_cols_ordered = ['pod', 'Tenant', 'ANP', 'EPG', 'Node', 'Interface', 'VLAN', 'instrImedcy', 'mode', 'modTs']
        
        # 3. Sheet "VPC"
        # Request: pod,tenant,anp,epg, node, interface (IPG), physical ports, vlan, immediacy,and mode, modTs
        vpc_col_mapping = {
            'vpc_nodes': 'Nodes',
            'IPG': 'Interface (IPG)',
            'Resolved Ports': 'Physical Ports'
        }
        vpc_target_cols = ['pod', 'Tenant', 'ANP', 'EPG', 'Nodes', 'Interface (IPG)', 'Physical Ports', 'VLAN', 'instrImedcy', 'mode', 'modTs']

        try:
             with pd.ExcelWriter(output_file, engine='openpyxl') as writer:
                 
                 # Sheet 1: All
                 df_all[cols_all].to_excel(writer, sheet_name='All Results', index=False)
                 
                 # Sheet 2: Single Port
                 df_single = df_all[df_all['PathType'] == 'Single Port'].copy()
                 if not df_single.empty:
                      for c in single_cols_ordered:
                          if c not in df_single.columns: df_single[c] = ""
                      
                      rename_single = {'instrImedcy': 'Immediacy', 'mode': 'Mode', 'pod': 'Pod', 'modTs': 'ModTS'}
                      df_single = df_single[single_cols_ordered].rename(columns=rename_single)
                      df_single.to_excel(writer, sheet_name='Single Port', index=False)
                 else:
                      pd.DataFrame(columns=[c for c in single_cols_ordered]).to_excel(writer, sheet_name='Single Port', index=False) 

                 # Sheet 3: VPC
                 df_vpc = df_all[df_all['PathType'] == 'VPC'].copy()
                 if not df_vpc.empty:
                      df_vpc = df_vpc.rename(columns=vpc_col_mapping)
                      for c in vpc_target_cols:
                          if c not in df_vpc.columns: df_vpc[c] = ""
                      
                      rename_vpc = {'instrImedcy': 'Immediacy', 'mode': 'Mode', 'pod': 'Pod', 'modTs': 'ModTS'}
                      df_vpc = df_vpc[vpc_target_cols].rename(columns=rename_vpc)
                      df_vpc.to_excel(writer, sheet_name='VPC', index=False)
                 else:
                      pd.DataFrame(columns=vpc_target_cols).to_excel(writer, sheet_name='VPC', index=False)
                      
             logger.info(f"\nResults saved to {output_file} (Sheets: All Results, Single Port, VPC)")
             print(f"Success! Found {len(all_results)} static paths.")
             
        except Exception as e:
            logger.error(f"Error saving Excel: {e}")
            
    else:
        logger.info("\nNo EPGs found.")
        print("No paths found.")

def main():
    print("ACI Static path (Physical) - Dump Mode")
    parser = argparse.ArgumentParser()
    # parser.add_argument('-i', '--input', default='input_interfaces.xlsx', help='Input Excel file') # Ignored
    parser.add_argument('-o', '--output', default='output_epgs.xlsx', help='Output Excel file')
    args = parser.parse_args()
    
    # Get credentials
    apic_ip, username, password = get_credentials()
    if not all([apic_ip, username, password]):
        logger.error("Error: Missing credentials")
        return

    # Login
    logger.info(f"\nLogging in to {apic_ip}...")
    session = login_apic(apic_ip, username, password)
    if not session:
        return

    logger.info("Login successful.")
    
    run(session, apic_ip, output_file=args.output)

if __name__ == "__main__":
    main()
