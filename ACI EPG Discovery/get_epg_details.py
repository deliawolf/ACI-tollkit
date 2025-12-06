import requests
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
    print("Warning: Could not import centralized logger. Using default.")

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

def fetch_bulk_data(session, base_url):
    """
    Fetches all necessary data in 3 bulk API calls.
    Returns:
    - deployments: Dict {(node, interface): [epg_dn, ...]}
    - static_paths: Dict {epg_dn: [{tDn, encap}, ...]}
    - vmm_domains: Dict {epg_dn: [tDn, ...]}
    """
    deployments = {}
    static_paths = {}
    vmm_domains = {}

    # 1. Fetch All EPG Deployments (pconsResourceCtx) - For Dynamic/Deployed State
    logger.info("  Bulk Fetching 1/3: EPG Deployments (pconsResourceCtx)...")
    url = f"{base_url}/api/node/class/pconsResourceCtx.json" # Removed filter to be safe
    try:
        response = session.get(url, timeout=120)
        response.raise_for_status()
        data = response.json()
        
        for item in data.get('imdata', []):
            if 'pconsResourceCtx' in item:
                attr = item['pconsResourceCtx']['attributes']
                dn = attr.get('dn')
                epg_dn = attr.get('ctxDn')
                
                # Verify usage is EPG
                if attr.get('ctxClass') != 'fvAEPg':
                    continue

                # Extract Node and Interface from DN
                # Format: topology/pod-1/node-101/sys/phys-[eth1/34]/pcons/ctx-[uni/...]
                match = re.search(r'node-(\d+)/sys/phys-\[(.+?)\]', dn)
                if match and epg_dn:
                    node = match.group(1)
                    interface = match.group(2)
                    
                    key = (node, interface)
                    if key not in deployments:
                        deployments[key] = []
                    if epg_dn not in deployments[key]:
                        deployments[key].append(epg_dn)
                    
    except Exception as e:
        logger.error(f"Error fetching deployments: {e}")

    # 2. Fetch All Static Paths (fvRsPathAtt) - For Configured State
    logger.info("  Bulk Fetching 2/3: Static Paths (fvRsPathAtt)...")
    url = f"{base_url}/api/node/class/fvRsPathAtt.json"
    try:
        response = session.get(url, timeout=120)
        response.raise_for_status()
        data = response.json()
        
        for item in data.get('imdata', []):
            if 'fvRsPathAtt' in item:
                attr = item['fvRsPathAtt']['attributes']
                epg_dn = re.split(r'/rspathAtt-', attr.get('dn'))[0] # Parent EPG DN
                tDn = attr.get('tDn')
                
                # Store in static_paths map
                if epg_dn not in static_paths:
                    static_paths[epg_dn] = []
                
                static_paths[epg_dn].append({
                    'tDn': tDn,
                    'encap': attr.get('encap')
                })
                
                # CRITICAL: Also populate deployments map for Static Paths
                # This ensures we find the EPG even if pcons query fails or is empty
                # tDn format: topology/pod-1/paths-101/pathep-[eth1/1]
                # vPC format: topology/pod-1/protpaths-101-102/pathep-[PolicyGroup]
                
                # Check for Single Node Path
                match = re.search(r'paths-(\d+)/pathep-\[(.+?)\]', tDn)
                if match:
                    node = match.group(1)
                    interface = match.group(2)
                    
                    # Normalize interface (remove 'eth' if needed? No, keep as is for now, standard is eth1/1)
                    if not interface.startswith("eth"):
                         # Sometimes it's just '1/1', add 'eth'
                         if re.match(r'\d+/\d+', interface):
                             interface = f"eth{interface}"

                    key = (node, interface)
                    if key not in deployments:
                        deployments[key] = []
                    if epg_dn not in deployments[key]:
                        deployments[key].append(epg_dn)
                
                # Note: vPC paths (protpaths) are harder to map to a single "Node/Interface" key 
                # because they map to a logical entity. 
                # For now, we focus on recovering the Single Node static paths.

    except Exception as e:
        logger.error(f"Error fetching static paths: {e}")

    # 3. Fetch All VMM Domains (fvRsDomAtt)
    logger.info("  Bulk Fetching 3/3: VMM Domains (fvRsDomAtt)...")
    url = f"{base_url}/api/node/class/fvRsDomAtt.json"
    try:
        response = session.get(url, timeout=120)
        response.raise_for_status()
        data = response.json()
        
        for item in data.get('imdata', []):
            if 'fvRsDomAtt' in item:
                attr = item['fvRsDomAtt']['attributes']
                epg_dn = re.split(r'/rsdomAtt-', attr.get('dn'))[0]
                
                if epg_dn not in vmm_domains:
                    vmm_domains[epg_dn] = []
                
                vmm_domains[epg_dn].append(attr.get('tDn'))
    except Exception as e:
        logger.error(f"Error fetching VMM domains: {e}")

    return deployments, static_paths, vmm_domains

def resolve_vlan_details(epg_dn, node, interface, static_paths_map, vmm_domains_map):
    """Local matching logic to find VLAN/PathType from pre-fetched data."""
    vlan = "Not Found"
    path_type = "None"
    path_dn_found = "N/A"
    domains_str = ""
    
    # Get Domains
    domains = vmm_domains_map.get(epg_dn, [])
    if domains:
        # Extract domain names from tDn (e.g., uni/vmmp-VMware/dom-vCenter -> vCenter)
        clean_domains = []
        for d_dn in domains:
            parts = d_dn.split('/')
            if parts:
                last_part = parts[-1]
                if '-' in last_part:
                    clean_domains.append(last_part.split('-', 1)[1])
                else:
                    clean_domains.append(last_part)
        domains_str = ", ".join(clean_domains)
        path_type = "VMM Domain" # Default if dynamic
        
    # Check Static Paths matches
    # Interface format from Excel: "eth1/1"
    # Static Path tDn formats:
    # - topology/pod-1/paths-101/pathep-[eth1/1] (Single Leaf)
    # - topology/pod-1/protpaths-101-102/pathep-[name] (vPC)
    
    paths = static_paths_map.get(epg_dn, [])
    
    # Normalize interface for matching (Ethernet -> eth)
    clean_interface = str(interface).strip()
    norm_interface = clean_interface.replace("Ethernet", "eth")

    for path in paths:
        tDn = path['tDn']
        encap = path['encap']
        
        # Check Direct Match (Single Node)
        # paths-101 ... pathep-[eth1/1]
        if f"paths-{node}/pathep-[{norm_interface}]" in tDn:
            return encap, "Static Path", tDn, domains_str

        # Check vPC Match
        # protpaths-101-102 ...
        # We need to check if the node is part of the vPC and if the interface matches
        if "protpaths-" in tDn:
            try:
                # 1. Verify Node ID matches VPC
                node_match = False
                parts = tDn.split('/')
                for part in parts:
                    if part.startswith('protpaths-'):
                        nodes_str = part[10:] # e.g., "101-102"
                        vpc_nodes = nodes_str.split('-')
                        if str(node) in vpc_nodes:
                            node_match = True
                            break
                
                if node_match:
                    # 2. Extract Port Number from Input
                    port_num = None
                    match = re.search(r'(\d+)$', norm_interface)
                    if match:
                        port_num = match.group(1)
                    
                    if port_num:
                        # 3. Extract all numbers from the Path Suffix (inside pathep-[...])
                        suffix_match = re.search(r'pathep-\[(.*?)\]', tDn)
                        if suffix_match:
                            suffix_content = suffix_match.group(1)
                            path_numbers = re.findall(r'\d+', suffix_content)
                            
                            # 4. Check if port_num is in path_numbers
                            if port_num in path_numbers:
                                return encap, "VPC", tDn, domains_str
            except Exception:
                pass # Continue to next path if parsing fails

    # If no static match, and we have domains
    if domains:
        return "Dynamic (VMM)", "VMM Domain", "N/A", domains_str

    return vlan, path_type, path_dn_found, domains_str

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

def run(session, apic_ip, input_file='input_interfaces.xlsx', output_file='output_epgs.xlsx', username=None, password=None):
    """Entry point for main.py"""
    
    # Load Input
    try:
        if not os.path.exists(input_file):
            script_dir = os.path.dirname(os.path.abspath(__file__))
            input_file = os.path.join(script_dir, os.path.basename(input_file))
        df_input = pd.read_excel(input_file)
    except FileNotFoundError:
        logger.error(f"Error: {input_file} not found.")
        return

    # Bulk Fetch
    print("Fetching bulk data from APIC (this may take a moment)...")
    base_url = apic_ip.rstrip('/')
    # Handle full URL if passed
    if not base_url.startswith("http"):
         base_url = f"https://{base_url}"
         
    deployments_map, static_paths_map, vmm_domains_map = fetch_bulk_data(session, base_url)
    
    # DEBUG: Diagnostic Prints
    print(f"\n[DEBUG] Deployments Found: {len(deployments_map)}")
    print(f"[DEBUG] Static Paths Found: {len(static_paths_map)}")
    print(f"[DEBUG] VMM Domains Found: {len(vmm_domains_map)}")
    
    if len(deployments_map) > 0:
        sample_key = list(deployments_map.keys())[0]
        print(f"[DEBUG] Sample APIC Key: {sample_key} (Type: {type(sample_key[0])}, {type(sample_key[1])})")
    
    if not df_input.empty:
        first_row = df_input.iloc[0]
        print(f"[DEBUG] Sample Input Row: Node='{first_row['Node']}' Interface='{first_row['Interface']}'")
        print(f"[DEBUG] Lookup Key would correspond to: ('{str(first_row['Node'])}', '{str(first_row['Interface'])}')")
    
    logger.info(f"Bulk data loaded. Processing {len(df_input)} interfaces locally...")

    all_results = []

    # Process Locally
    from tqdm import tqdm # Import tqdm here as it's only used in run
    for index, row in tqdm(df_input.iterrows(), total=len(df_input), unit="iface"):
        node = str(row['Node'])
        interface = str(row['Interface'])
        
        epg_dns = deployments_map.get((node, interface), [])
        
        if epg_dns:
            for epg_dn in epg_dns:
                tenant, app_profile, epg = parse_epg_name(epg_dn)
                vlan, path_type, path_dn, domains = resolve_vlan_details(epg_dn, node, interface, static_paths_map, vmm_domains_map)
                
                all_results.append({
                    'Node': node,
                    'Interface': interface,
                    'Tenant': tenant,
                    'AppProfile': app_profile,
                    'EPG': epg,
                    'VLAN': vlan,
                    'PathType': path_type,
                    'PathDN': path_dn,
                    'Domains': domains,
                    'DN': epg_dn
                })
        # else:
            # No EPGs found for this interface, no need to add to results if nothing found.
            # If user wants to see interfaces with no EPGs, this logic would need to change.

    # Save Results
    if all_results:
        df_output = pd.DataFrame(all_results)
        cols = ['Node', 'Interface', 'Tenant', 'AppProfile', 'EPG', 'VLAN', 'PathType', 'PathDN', 'Domains']
        for col in cols:
            if col not in df_output.columns:
                df_output[col] = ""
        df_output = df_output[cols]
        df_output.to_excel(output_file, index=False)
        logger.info(f"\nResults saved to {output_file}")
    else:
        logger.info("\nNo EPGs found for any of the provided interfaces.")

def main():
    parser = argparse.ArgumentParser(description='ACI EPG Discovery Tool')
    parser.add_argument('-i', '--input', default='input_interfaces.xlsx', help='Input Excel file')
    parser.add_argument('-o', '--output', default='output_epgs.xlsx', help='Output Excel file')
    args = parser.parse_args()

    print("ACI EPG Discovery Tool")
    
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
    
    run(session, apic_ip, args.input, args.output)

if __name__ == "__main__":
    main()
