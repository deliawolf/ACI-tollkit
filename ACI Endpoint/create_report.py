#!/usr/bin/env python3

import json
import pandas as pd
from typing import Dict, List, Tuple
import os
from datetime import datetime
import re

def load_json_file(filename: str) -> List[Dict]:
    """Load JSON data from file"""
    try:
        with open(filename, 'r') as f:
            data = json.load(f)
            print(f"\nLoading {filename}:")
            print(f"Raw data type: {type(data)}")
            if isinstance(data, dict):
                total_count = data.get('totalCount', '0')
                items = data.get('imdata', [])
                print(f"Total count from data: {total_count}")
                print(f"Actual items count: {len(items)}")
                
                return items
            else:
                print(f"Unexpected data format in {filename}")
                return []
    except Exception as e:
        print(f"Error loading {filename}: {str(e)}")
        return []

def extract_tenant_vrf_from_dn(vrf_dn: str) -> Tuple[str, str]:
    """Extract tenant and VRF names from VRF DN"""
    tenant = ''
    vrf = ''
    if not vrf_dn:
        return tenant, vrf
        
    parts = vrf_dn.split('/')
    for part in parts:
        if part.startswith('tn-'):
            tenant = part[3:]  # Remove 'tn-' prefix
        elif part.startswith('ctx-'):
            vrf = part[4:]     # Remove 'ctx-' prefix
    return tenant, vrf

def extract_ap_epg_bd_from_dn(dn: str) -> Tuple[str, str, str]:
    """
    Extract Application Profile, EPG, and BD from DN.
    - If ap- and epg- exist, take as AP and EPG.
    - If l2out- and instP- exist, treat l2out as BD and instP as EPG.
    - If BD- exists, treat as BD.
    """
    ap = ''
    epg = ''
    bd = ''
    parts = dn.split('/')
    for part in parts:
        if part.startswith('ap-'):
            ap = part[3:]
        elif part.startswith('epg-'):
            epg = part[4:]
        elif part.startswith('l2out-'):
            bd = part[6:]  # treat l2out as BD
        elif part.startswith('instP-'):
            epg = part[6:]  # treat instP as EPG
        elif part.startswith('BD-'):
            bd = part[3:]
    return ap, epg, bd

def extract_bd_from_dn(bd_dn: str) -> str:
    """Extract BD name from BD DN"""
    if not bd_dn:
        return ''
        
    parts = bd_dn.split('/')
    for part in parts:
        if part.startswith('BD-'):
            return part[3:]    # Remove 'BD-' prefix
    return ''

def extract_interface_info(tdn: str) -> Tuple[str, str]:
    """Extract node and interface from tDn
    Examples:
    - Single node: topology/pod-1/paths-248/pathep-[eth1/33] -> ('Node-248', 'eth1/33')
    - VPC: topology/pod-1/protpaths-403-404/pathep-[VPC_Name] -> ('Node-403-404', 'VPC_Name')
    """
    if not tdn:
        return '', ''
        
    # Handle VPC paths (two nodes)
    vpc_match = re.search(r'/protpaths-(\d+)-(\d+)/pathep-\[(.*?)\]', tdn)
    if vpc_match:
        node1, node2, interface = vpc_match.groups()
        return f"Node-{node1}-{node2}", interface
        
    # Handle single node paths
    node_match = re.search(r'/paths-(\d+)/', tdn)
    interface_match = re.search(r'pathep-\[(.*?)\]', tdn)
    
    node = f"Node-{node_match.group(1)}" if node_match else ''
    interface = interface_match.group(1) if interface_match else ''
    
    return node, interface

def get_cep_dn_from_ip_dn(ip_dn: str) -> str:
    """Extract the CEP DN from an IP DN by removing the IP part"""
    # IP DN format: .../cep-XX:XX:XX:XX:XX:XX/ip-[x.x.x.x]
    # We want to keep everything up to and including the cep part
    parts = ip_dn.split('/')
    cep_index = -1
    for i, part in enumerate(parts):
        if part.startswith('cep-'):
            cep_index = i
            break
    
    if cep_index >= 0:
        return '/'.join(parts[:cep_index + 1])
    return ''

def extract_hypervisor_info(dn: str) -> Tuple[str, str, str, str]:
    """Extract hypervisor information from fvRsHyper DN"""
    provider = ''
    controller = ''
    vcenter = ''
    host = ''
    
    # Look for the rshyper section
    match = re.search(r'rshyper-\[comp/prov-([^/]+)/ctrlr-\[([^\]]+)\]-([^/]+)/hv-([^\]]+)\]', dn)
    if match:
        provider = match.group(1)
        controller = match.group(2)
        vcenter = match.group(3)
        host = match.group(4)
    
    return provider, controller, vcenter, host

def extract_nodes_interfaces_from_dn(dn: str) -> List[Tuple[str, str]]:
    """Extract node and interface information from fvRsHyper DN"""
    node_interfaces = []
    
    # Find all paths-XXX/pathep-[YYY] patterns
    matches = re.finditer(r'paths-(\d+)/pathep-\[([\w\-/]+)\]', dn)
    for match in matches:
        node = f"Node-{match.group(1)}"
        interface = match.group(2)
        node_interfaces.append((node, interface))
    
    return node_interfaces

def extract_mac_from_dn(dn: str) -> str:
    """Extract MAC address from DN"""
    mac_match = re.search(r'cep-([0-9A-Fa-f:]{17})', dn)
    return mac_match.group(1) if mac_match else ''

def extract_node_interface_from_path(path_dn: str) -> Tuple[str, str]:
    """
    Extract node and interface from path DN
    Example: topology/pod-1/paths-101/pathep-[eth1/34] -> (Node-101, eth1/34)
    """
    node_match = re.search(r'paths-(\d+)', path_dn)
    interface_match = re.search(r'pathep-\[(.*?)\]', path_dn)
    
    node = f"Node-{node_match.group(1)}" if node_match else ''
    interface = interface_match.group(1) if interface_match else ''
    
    return node, interface

def process_fvcep_data(fvcep_data: List[Dict]) -> Dict[str, Dict]:
    """Process fvCEp data into a dictionary keyed by DN"""
    endpoints = {}
    for item in fvcep_data:
        if 'fvCEp' not in item:
            continue
        ep = item['fvCEp']['attributes']
        dn = ep.get('dn', '')
        if not dn:
            continue
        # Extract tenant, VRF, AP, EPG, BD from DN
        tenant, vrf = extract_tenant_vrf_from_dn(ep.get('vrfDn', ''))
        ap, epg, bd = extract_ap_epg_bd_from_dn(dn)
        if not bd:
            bd = extract_bd_from_dn(ep.get('bdDn', ''))
        # Handle encap logic
        cep_encap = ep.get('encap', '')
        primary_encap = ''
        children = item['fvCEp'].get('children', [])
        for child in children:
            if 'fvPrimaryEncap' in child:
                primary_encap = child['fvPrimaryEncap']['attributes'].get('primaryEncap', '')
                break
        if primary_encap:
            encap_info = {
                'primary': primary_encap,
                'secondary': cep_encap,
                'display': f"{primary_encap} (P), {cep_encap} (S)"
            }
        else:
            encap_info = {
                'primary': cep_encap,
                'secondary': '',
                'display': f"{cep_encap} (P)"
            }
        endpoints[dn] = {
            'MAC': ep.get('mac', ''),
            'DN': dn,
            'encap_info': encap_info,
            'VRF': vrf,
            'Tenant': tenant,
            'Application': ap,
            'EPG': epg,
            'BD': bd,
            'Node': '',
            'Interface': '',
            'Controller': ep.get('reportingControllerName', ''),
            'Source': ep.get('vmmSrc', ''),
            'Hosting Server': ep.get('hostingServer', ''),
            'Container Name': ep.get('contName', ''),
            'Last Updated': ep.get('modTs', ''),
            'IPs': [],
            'hypervisor_provider': '',
            'hypervisor_controller': '',
            'hypervisor_vcenter': '',
            'hypervisor_host': '',
            'hypervisor_info': [],
            'additional_nodes_interfaces': [],
            'vm_info': []
        }
    return endpoints

def process_fvip_data(fvip_data: List[Dict], endpoints: Dict[str, Dict]) -> None:
    """Process fvIp data and add IP information to existing endpoints"""
    for item in fvip_data:
        ip = item.get('fvIp', {}).get('attributes', {})
        ip_dn = ip.get('dn', '')
        if ip_dn:
            # Extract CEP DN from IP DN
            cep_dn = get_cep_dn_from_ip_dn(ip_dn)
            if cep_dn in endpoints:
                # Add IP info to existing endpoint
                if 'IPs' not in endpoints[cep_dn]:
                    endpoints[cep_dn]['IPs'] = []
                
                # Add IP address with its DN and last updated timestamp
                ip_info = {
                    'addr': ip.get('addr', ''),
                    'dn': ip_dn,
                    'last_updated': ip.get('modTs', '')  # Capture IP last updated timestamp
                }
                endpoints[cep_dn]['IPs'].append(ip_info)
                
                # Also store the most recent IP update time for the endpoint
                ip_mod_ts = ip.get('modTs', '')
                if ip_mod_ts:
                    if 'ip_last_updated' not in endpoints[cep_dn] or ip_mod_ts > endpoints[cep_dn]['ip_last_updated']:
                        endpoints[cep_dn]['ip_last_updated'] = ip_mod_ts

def process_fvrshyper_data(fvrshyper_data: List[Dict], endpoints: Dict[str, Dict]):
    """Process fvRsHyper data and add hypervisor information to existing endpoints"""
    print("\nProcessing fvRsHyper data:")  # Debug print
    
    # First, create a dictionary to collect all node/interface combinations for each CEP DN
    node_interface_map = {}
    
    for item in fvrshyper_data:
        if 'fvRsHyper' not in item:
            continue
            
        attrs = item['fvRsHyper']['attributes']
        dn = attrs.get('dn', '')
        print(f"\nProcessing fvRsHyper DN: {dn}")  # Debug print
        
        # Try all three formats:
        # 1. Direct CEP format: uni/tn-XX/ap-XX/epg-XX/cep-XX/rshyper...
        # 2. EPP format: uni/epp/fv-[uni/tn-XX/ap-XX/epg-XX]/...epdefref-XX/rshyper...
        # 3. Topology format: topology/pod-1/node-XXX/.../fv-[uni/tn-XX/ap-XX/epg-XX]/...epdefref-XX/rshyper...
        
        # First try direct CEP format
        cep_match = re.search(r'uni/tn-([^/]+)/ap-([^/]+)/epg-([^/]+)/cep-([^/]+)', dn)
        if cep_match:
            tenant = cep_match.group(1)
            ap = cep_match.group(2)
            epg = cep_match.group(3)
            mac = cep_match.group(4)
            cep_dn = f"uni/tn-{tenant}/ap-{ap}/epg-{epg}/cep-{mac}"
        else:
            # Try EPP or Topology format
            epp_match = re.search(r'(?:uni/epp|topology/pod-\d+/node-\d+/local/svc-policyelem-id-\d+/uni/epp)/fv-\[uni/tn-([^/]+)/ap-([^/]+)/epg-([^/]+)\].*?epdefref-([^/]+)', dn)
            if epp_match:
                tenant = epp_match.group(1)
                ap = epp_match.group(2)
                epg = epp_match.group(3)
                mac = epp_match.group(4)
                cep_dn = f"uni/tn-{tenant}/ap-{ap}/epg-{epg}/cep-{mac}"
            else:
                continue
        
        # Extract node and interface information
        node_interfaces = extract_nodes_interfaces_from_dn(dn)
        if node_interfaces:
            # Initialize the set for this CEP DN if not exists
            if cep_dn not in node_interface_map:
                node_interface_map[cep_dn] = set()
            # Add all node/interface combinations to the set
            for node, interface in node_interfaces:
                node_interface_map[cep_dn].add((node, interface))
                print(f"Found node/interface: {node} - {interface}")  # Debug print
        
        if cep_dn and cep_dn in endpoints:
            # Extract hypervisor information
            provider, controller, vcenter, host = extract_hypervisor_info(dn)
            
            # Create a complete hypervisor info dictionary
            hypervisor_info = {
                'dn': dn,
                'provider': provider,
                'controller': controller,
                'vcenter': vcenter,
                'host': host
            }
            
            # Add to hypervisor_info list if not already present
            if not any(h['dn'] == dn for h in endpoints[cep_dn]['hypervisor_info']):
                endpoints[cep_dn]['hypervisor_info'].append(hypervisor_info)
            
            # Update the main hypervisor fields with a summary if needed
            if not endpoints[cep_dn]['hypervisor_provider']:
                # Get unique values for each field
                providers = {h['provider'] for h in endpoints[cep_dn]['hypervisor_info']}
                controllers = {h['controller'] for h in endpoints[cep_dn]['hypervisor_info']}
                vcenters = {h['vcenter'] for h in endpoints[cep_dn]['hypervisor_info']}
                hosts = {h['host'] for h in endpoints[cep_dn]['hypervisor_info']}
                
                # Update with summary information
                endpoints[cep_dn].update({
                    'hypervisor_provider': ', '.join(sorted(providers)) if len(providers) > 1 else next(iter(providers), ''),
                    'hypervisor_controller': ', '.join(sorted(controllers)) if len(controllers) > 1 else next(iter(controllers), ''),
                    'hypervisor_vcenter': ', '.join(sorted(vcenters)) if len(vcenters) > 1 else next(iter(vcenters), ''),
                    'hypervisor_host': ', '.join(sorted(hosts)) if len(hosts) > 1 else next(iter(hosts), '')
                })
    
    print("\nProcessing node/interface map:")  # Debug print
    # Now process the collected node/interface data
    for cep_dn, node_interfaces_set in node_interface_map.items():
        if cep_dn not in endpoints:
            continue
        
        print(f"Processing {cep_dn} with interfaces: {node_interfaces_set}")  # Debug print
        
        # Convert set to list for consistent ordering
        node_interfaces = sorted(list(node_interfaces_set))
        
        # Get the endpoint's current node/interface
        current_node = endpoints[cep_dn].get('Node', '')
        current_interface = endpoints[cep_dn].get('Interface', '')
        
        # If endpoint doesn't have node/interface info, use the first one from collected data
        if not current_node or not current_interface:
            if node_interfaces:
                endpoints[cep_dn]['Node'] = node_interfaces[0][0]
                endpoints[cep_dn]['Interface'] = node_interfaces[0][1]
        
        # Store all unique node/interface combinations
        # If current node/interface exists, make sure it's included
        if current_node and current_interface:
            node_interfaces_set.add((current_node, current_interface))
            node_interfaces = sorted(list(node_interfaces_set))
        
        endpoints[cep_dn]['additional_nodes_interfaces'] = node_interfaces

def process_fvrsvm_data(fvrsvm_data: List[Dict], endpoints: Dict[str, Dict]) -> None:
    """Process fvRsVm data and add VM information to existing endpoints"""
    for item in fvrsvm_data:
        vm = item.get('fvRsVm', {}).get('attributes', {})
        vm_dn = vm.get('dn', '')
        if vm_dn:
            # Extract MAC from DN (format: .../cep-[MAC]/rsvm)
            mac_match = re.search(r'cep-([0-9A-Fa-f:]{17})', vm_dn)
            if mac_match:
                mac = mac_match.group(1)
                # Find endpoint by MAC
                for ep in endpoints.values():
                    if ep['MAC'] == mac:
                        # Initialize vm_info list if not exists
                        if 'vm_info' not in ep:
                            ep['vm_info'] = []
                        
                        # Extract VM OID
                        tdn = vm.get('tDn', '')
                        vm_oid = extract_vm_oid(tdn)
                        
                        # Add VM info
                        vm_info = {
                            'dn': vm_dn,
                            'tdn': tdn,
                            'state': vm.get('state', ''),
                            'vm_oid': vm_oid
                        }
                        
                        # Add compVm data if available
                        comp_vm_data = vm.get('compVmData', {})
                        if comp_vm_data:
                            vm_info.update({
                                'name': comp_vm_data.get('name', ''),
                                'os': comp_vm_data.get('cfgdOs', ''),
                                'state': comp_vm_data.get('state', ''),
                                'os_type': comp_vm_data.get('os', ''),
                                'modTs': comp_vm_data.get('modTs', '')
                            })
                        
                        ep['vm_info'].append(vm_info)
                        break

def process_fvrsceptopath_data(fvrsceptopath_data: List[Dict], endpoints: Dict[str, Dict]) -> None:
    """Process fvRsCEpToPathEp data and add interface information to existing endpoints"""
    # First pass: collect all interfaces for each MAC+context combination
    mac_interfaces = {}  # Key will be (mac, tenant, vrf, bd, epg)
    
    # Create a lookup from DN to endpoint info
    dn_to_endpoint = {ep['DN']: {
        'tenant': ep['Tenant'],
        'vrf': ep['VRF'],
        'bd': ep['BD'],
        'epg': ep['EPG']
    } for ep in endpoints.values()}
    
    print("\nProcessing fvRsCEpToPathEp data:")
    print(f"Total items: {len(fvrsceptopath_data)}")
    
    for item in fvrsceptopath_data:
        path = item.get('fvRsCEpToPathEp', {}).get('attributes', {})
        path_dn = path.get('dn', '')
        lc_c = path.get('lcC', '')
        
        if path_dn:
            # Extract the CEP DN from the path DN to lookup endpoint info
            cep_dn_match = re.match(r'(.+)/rscEpToPathEp-', path_dn)
            if cep_dn_match:
                cep_dn = cep_dn_match.group(1)
                ep_info = dn_to_endpoint.get(cep_dn, {})
                
                mac_match = re.search(r'cep-([0-9A-Fa-f:]{17})', path_dn)
                if mac_match:
                    mac = mac_match.group(1)
                    # Create a unique key using MAC and context
                    context_key = (
                        mac,
                        ep_info.get('tenant', ''),
                        ep_info.get('vrf', ''),
                        ep_info.get('bd', ''),
                        ep_info.get('epg', '')
                    )
                    
                    if context_key not in mac_interfaces:
                        mac_interfaces[context_key] = []
                    
                    # Extract interface info
                    tdn = path.get('tDn', '')
                    node, interface = extract_interface_info(tdn)
                    learning_modes = [mode.strip() for mode in lc_c.split(',') if mode.strip()]
                    ownership = path.get('lcOwn', '')
                    
                    interface_info = {
                        'node': node,
                        'interface': interface,
                        'learning_modes': learning_modes,
                        'ownership': ownership,
                        'dn': path_dn,
                        'is_learned': 'learned' in learning_modes
                    }
                    
                    # Update or add to interfaces list
                    existing_interface = next(
                        (i for i in mac_interfaces[context_key] if i['node'] == node and i['interface'] == interface),
                        None
                    )
                    
                    if existing_interface:
                        existing_interface.update(interface_info)
                    else:
                        mac_interfaces[context_key].append(interface_info)
    
    # Second pass: update endpoints with interface information
    for ep in endpoints.values():
        context_key = (
            ep['MAC'],
            ep['Tenant'],
            ep['VRF'],
            ep['BD'],
            ep['EPG']
        )
        
        if context_key in mac_interfaces:
            interfaces = mac_interfaces[context_key]
            ep['interfaces'] = interfaces
            
            # Find learned interfaces
            learned_interfaces = [iface for iface in interfaces if iface['is_learned']]
            
            if learned_interfaces:
                # Sort learned interfaces by node and interface for consistency
                learned_interfaces.sort(key=lambda x: (x['node'], x['interface']))
                # Take the first learned interface as primary
                primary = learned_interfaces[0]
                ep['Node'] = primary['node']
                ep['Interface'] = primary['interface']
                
                ep['Interface'] = primary['interface']
            else:
                # No learned interfaces found
                ep['Node'] = ''
                ep['Interface'] = ''
                
                ep['Node'] = ''
                ep['Interface'] = ''
    
    print(f"\nTotal entries with learned mode: {sum(1 for interfaces in mac_interfaces.values() for iface in interfaces if iface['is_learned'])}")

def process_fvnsencapblk_data(fvnsencapblk_data: List[Dict]) -> Dict[str, str]:
    """
    Process fvnsEncapBlk data to create a mapping of VLAN numbers to their pool names
    Returns a dictionary mapping VLAN numbers to their pool names
    """
    vlan_pool_mapping = {}
    
    for item in fvnsencapblk_data:
        encap_blk = item.get('fvnsEncapBlk', {}).get('attributes', {})
        dn = encap_blk.get('dn', '')
        
        # Extract pool name from DN (e.g., "L2OUT_VLPL" from "uni/infra/vlanns-[L2OUT_VLPL]-static/...")
        pool_name_match = re.search(r'vlanns-\[(.*?)\]', dn)
        if not pool_name_match:
            continue
        
        pool_name = pool_name_match.group(1)
        
        # Get from and to VLAN numbers
        from_vlan = encap_blk.get('from', '')
        to_vlan = encap_blk.get('to', '')
        
        # Extract VLAN numbers
        from_num = int(from_vlan.replace('vlan-', '')) if from_vlan.startswith('vlan-') else None
        to_num = int(to_vlan.replace('vlan-', '')) if to_vlan.startswith('vlan-') else None
        
        if from_num is not None and to_num is not None:
            # Map all VLANs in the range to this pool name
            for vlan_num in range(from_num, to_num + 1):
                vlan_pool_mapping[str(vlan_num)] = pool_name
    
    return vlan_pool_mapping

def get_vlan_pool(encap: str, vlan_pool_mapping: Dict[str, str]) -> str:
    """Get the VLAN pool name for a given encap"""
    if not encap.startswith('vlan-'):
        return ''
    
    vlan_num = encap.replace('vlan-', '')
    return vlan_pool_mapping.get(vlan_num, '')

def extract_vm_oid(tdn: str) -> str:
    """Extract VM OID from tDn
    Example: comp/prov-VMware/ctrlr-[VDS-GTI-VMM-BACKREP]-GTI-DC01-vCenter/vm-vm-354558
    Returns: vm-354558
    """
    vm_match = re.search(r'vm-(?:vm-)?(\d+)', tdn)
    return f"vm-{vm_match.group(1)}" if vm_match else ''

def create_endpoint_report():
    """Create a comprehensive endpoint report"""
    # Define data directory
    data_dir = os.path.join('data', 'raw')
    
    # Load JSON data
    fvcep_data = load_json_file(os.path.join(data_dir, 'fvCEp.json'))
    fvip_data = load_json_file(os.path.join(data_dir, 'fvIp.json'))
    fvrshyper_data = load_json_file(os.path.join(data_dir, 'fvRsHyper.json'))
    fvrsvm_data = load_json_file(os.path.join(data_dir, 'fvRsVm.json'))
    fvnsencapblk_data = load_json_file(os.path.join(data_dir, 'fvnsEncapBlk.json'))
    fvrsceptopath_data = load_json_file(os.path.join(data_dir, 'fvRsCEpToPathEp.json'))
    
    # Process data
    endpoints = process_fvcep_data(fvcep_data)
    process_fvip_data(fvip_data, endpoints)
    process_fvrshyper_data(fvrshyper_data, endpoints)
    process_fvrsvm_data(fvrsvm_data, endpoints)
    process_fvrsceptopath_data(fvrsceptopath_data, endpoints)  # Process interface data
    
    # Process VLAN pools
    vlan_pool_mapping = process_fvnsencapblk_data(fvnsencapblk_data)
    
    # Create DataFrame for main data
    df = pd.DataFrame([
        {
            'MAC': ep['MAC'],
            'IPs': format_multi_value([ip['addr'] for ip in ep['IPs']]),
            'IP Count': len(ep['IPs']),
            'Encap': ep['encap_info']['display'],
            'VLAN Pool': get_vlan_pool(ep['encap_info']['primary'], vlan_pool_mapping),
            'VRF': ep['VRF'],
            'Tenant': ep['Tenant'],
            'Application': ep['Application'],
            'EPG': ep['EPG'],
            'BD': ep['BD'],
            'Node': ep['Node'],
            'Primary Interface': ep['Interface'],
            'Learning Modes': next(
                (', '.join(iface['learning_modes'])
                 for iface in ep.get('interfaces', [])
                 if iface['node'] == ep['Node'] and iface['interface'] == ep['Interface']),
                ''  # default if no match found
            ),
            'Ownership': next(
                (iface['ownership']
                 for iface in ep.get('interfaces', [])
                 if iface['node'] == ep['Node'] and iface['interface'] == ep['Interface']),
                ''  # default if no match found
            ),
            'Additional Interfaces': format_multi_value([
                f"{iface['node']}:{iface['interface']} ({', '.join(iface['learning_modes'])}/{iface['ownership']})"
                for iface in ep.get('interfaces', [])
                if not (iface['node'] == ep['Node'] and iface['interface'] == ep['Interface'])  # Skip primary interface
            ]),
            'Controller/vCenter': format_multi_value(list(set(filter(None, [
                ep['Controller'],
                ep['hypervisor_controller'],
                format_multi_value(ep['hypervisor_vcenter'].split(', ') if ep['hypervisor_vcenter'] else [])
            ])))),
            'Source': ep['Source'],
            'Hosting Server': ep['Hosting Server'],
            'Container/VM Name': format_multi_value(list(set(filter(None, [
                ep['Container Name'],
                *[vm.get('name', '') for vm in ep.get('vm_info', [])]
            ])))),
            'Last Updated': ep['Last Updated'],
            'IP Last Updated': ep.get('ip_last_updated', ''),
            'Hypervisor Provider': format_multi_value(ep['hypervisor_provider'].split(', ') if ep['hypervisor_provider'] else []),
            'Hypervisor OID': format_multi_value(ep['hypervisor_host'].split(', ') if ep['hypervisor_host'] else []),
            'VM OID': format_multi_value([vm.get('vm_oid', '') for vm in ep.get('vm_info', [])]),
            'VM Config OS': format_multi_value([vm.get('os', '') for vm in ep.get('vm_info', [])]),
            'VM Running OS': format_multi_value([vm.get('os_type', '') for vm in ep.get('vm_info', [])]),
            'VM State': format_multi_value([vm.get('state', '') for vm in ep.get('vm_info', [])]),
            'VM Last Updated': format_multi_value([vm.get('modTs', '') for vm in ep.get('vm_info', [])])
        }
        for ep in endpoints.values()
    ])

    # Define column order for main sheet
    columns_order = [
        'MAC', 'IPs', 'IP Count', 'Encap', 'VLAN Pool', 'Tenant', 'VRF', 'Application', 'EPG', 'BD',
        'Node', 'Primary Interface', 'Learning Modes', 'Ownership', 'Additional Interfaces',
        'Controller/vCenter', 'Source', 'Hosting Server', 'Container/VM Name', 'Last Updated',
        'IP Last Updated', 'Hypervisor Provider', 'Hypervisor OID', 'VM OID', 'VM Config OS', 'VM Running OS', 
        'VM State', 'VM Last Updated'
    ]
    
    # Create summary data
    summary_data = {
        'Metric': [
            'Total endpoints',
            'Total IP addresses',
            'Endpoints without IPs',
            'Unique MAC addresses',
            'Unique VRFs',
            'Unique Tenants',
            'Unique EPGs',
            'Unique Applications',
            'Unique BDs',
            'Unique Nodes',
            'Unique Controllers/vCenters',
            'Unique Sources',
            'Unique Container/VM Names',
            'Unique Hypervisor Providers',
            'Unique Hypervisor Hosts'
        ],
        'Value': [
            str(len(endpoints)),
            str(sum(len(ep['IPs']) for ep in endpoints.values())),  # Total number of IPs
            str(sum(1 for ep in endpoints.values() if not ep['IPs'])),  # Endpoints with no IPs
            str(df["MAC"].replace("", pd.NA).nunique()),
            str(df["VRF"].replace("", pd.NA).nunique()),
            str(df["Tenant"].replace("", pd.NA).nunique()),
            str(df["EPG"].replace("", pd.NA).nunique()),
            str(df["Application"].replace("", pd.NA).nunique()),
            str(df["BD"].replace("", pd.NA).nunique()),
            str(df["Node"].replace("", pd.NA).nunique()),
            str(df["Controller/vCenter"].replace("", pd.NA).nunique()),
            str(df["Source"].replace("", pd.NA).nunique()),
            str(df["Container/VM Name"].replace("", pd.NA).nunique()),
            str(df["Hypervisor Provider"].replace("", pd.NA).nunique()),
            str(df["Hypervisor OID"].replace("", pd.NA).nunique())
        ]
    }

    # Create DataFrame for DNs
    dn_records = []
    for ep in endpoints.values():
        # Add fvCEp DN
        dn_records.append({
            'MAC': ep['MAC'],
            'DN Type': 'fvCEp',
            'DN': ep.get('DN', '')
        })
        
        # Add fvIp DNs
        for ip in ep['IPs']:
            dn_records.append({
                'MAC': ep['MAC'],
                'DN Type': 'fvIp',
                'DN': ip.get('dn', '')
            })
        
        # Add fvRsHyper DNs
        for hyper in ep['hypervisor_info']:
            dn_records.append({
                'MAC': ep['MAC'],
                'DN Type': 'fvRsHyper',
                'DN': hyper['dn']
            })
            
        # Add fvRsVm DNs
        for vm in ep.get('vm_info', []):
            dn_records.append({
                'MAC': ep['MAC'],
                'DN Type': 'fvRsVm',
                'DN': vm['dn']
            })
            if 'tdn' in vm:
                dn_records.append({
                    'MAC': ep['MAC'],
                    'DN Type': 'compVm',
                    'DN': vm['tdn']
                })
    
    df_dns = pd.DataFrame(dn_records)

    # Create summary DataFrame
    df_summary = pd.DataFrame(summary_data)

    # Create Excel writer with xlsxwriter engine
    # Ensure the data/current directory exists
    os.makedirs('data/current', exist_ok=True)
    
    with pd.ExcelWriter('data/current/endpoint_report.xlsx', engine='xlsxwriter') as writer:
        # Write the main DataFrame
        df.to_excel(writer, sheet_name='Endpoints', index=False)
        
        # Write the DNs DataFrame
        df_dns.to_excel(writer, sheet_name='DNs', index=False)
        
        # Write the summary DataFrame
        df_summary.to_excel(writer, sheet_name='Summary', index=False)
        
        # Get the xlsxwriter workbook and worksheet objects
        workbook = writer.book
        worksheet = writer.sheets['Endpoints']
        dn_worksheet = writer.sheets['DNs']
        summary_worksheet = writer.sheets['Summary']
        
        # Add text wrapping format with vertical alignment at top
        wrap_format = workbook.add_format({
            'text_wrap': True,
            'valign': 'top'
        })
        
        # Format all columns in main sheet
        for col_num, column in enumerate(df.columns):
            # Set column width based on maximum length in the column
            max_length = max(
                df[column].astype(str).apply(len).max(),
                len(column)
            )
            worksheet.set_column(col_num, col_num, min(max_length + 2, 50), wrap_format)
        
        # Set row height for header
        worksheet.set_row(0, 30)
        
        # Set row height for data rows based on content
        for row_num in range(1, len(df) + 1):
            max_lines = 1
            for col_num, column in enumerate(df.columns):
                value = str(df.iloc[row_num-1, col_num])
                lines = len(value.split('\n'))
                max_lines = max(max_lines, lines)
            worksheet.set_row(row_num, max_lines * 15)
        
        # Format DNs worksheet
        dn_worksheet.set_column('A:A', 20)  # MAC
        dn_worksheet.set_column('B:B', 15)  # DN Type
        dn_worksheet.set_column('C:C', 100, wrap_format)  # DN
        
        # Set row height for header in DNs sheet
        dn_worksheet.set_row(0, 30)
        
        # Set row height for data rows in DNs sheet based on content
        for row_num in range(1, len(df_dns) + 1):
            dn_value = str(df_dns.iloc[row_num-1, 2])  # DN column
            lines = len(dn_value.split('\n'))
            dn_worksheet.set_row(row_num, max(lines, 1) * 15)
        
        # Format summary worksheet
        summary_worksheet.set_column('A:A', 30)  # Metric
        summary_worksheet.set_column('B:B', 15)  # Value
        
        # Set row height for header in summary sheet
        summary_worksheet.set_row(0, 30)
        
        # Set row height for data rows in summary sheet
        for row_num in range(1, len(df_summary) + 1):
            summary_worksheet.set_row(row_num, 15)  # Fixed height for summary rows
    
    # Print statistics to console
    print(f"\nReport generated: data/current/endpoint_report.xlsx")
    
    # Count MACs in fvRsHyper before integration
    hyper_macs = set()
    hyper_mac_count = 0
    for item in fvrshyper_data:
        if 'fvRsHyper' in item:
            dn = item['fvRsHyper']['attributes'].get('dn', '')
            # Try both formats for MAC extraction
            mac_match = re.search(r'cep-([0-9A-Fa-f:]{17})', dn) or re.search(r'epdefref-([0-9A-Fa-f:]{17})', dn)
            if mac_match:
                hyper_mac_count += 1
                hyper_macs.add(mac_match.group(1))
    
    # Count successfully integrated MACs
    integrated_macs = set()
    for ep in endpoints.values():
        if ep.get('hypervisor_provider') or ep.get('hypervisor_vcenter') or ep.get('hypervisor_host'):
            integrated_macs.add(ep.get('MAC'))
    
    # Print statistics
    print("\nfvRsHyper Statistics:")
    print(f"Total MAC entries: {hyper_mac_count}")
    print(f"Unique MACs: {len(hyper_macs)}")
    print(f"Successfully integrated: {len(integrated_macs)}")
    print(f"Not integrated: {len(hyper_macs - integrated_macs)}")
    print(f"Integration success rate: {(len(integrated_macs) / len(hyper_macs) * 100):.2f}%" if hyper_macs else "0%")
    
    print("\nGeneral Statistics:")
    print(f"Total endpoints (DNs): {len(endpoints)}")
    print(f"Total IP addresses: {sum(len(ep['IPs']) for ep in endpoints.values())}")
    print(f"Endpoints without IPs: {sum(1 for ep in endpoints.values() if not ep['IPs'])}")
    print(f"Unique MAC addresses: {df['MAC'].replace('', pd.NA).nunique()}")
    print(f"Unique VRFs: {df['VRF'].replace('', pd.NA).nunique()}")
    print(f"Unique Tenants: {df['Tenant'].replace('', pd.NA).nunique()}")
    print(f"Unique EPGs: {df['EPG'].replace('', pd.NA).nunique()}")
    print(f"Unique Applications: {df['Application'].replace('', pd.NA).nunique()}")
    print(f"Unique BDs: {df['BD'].replace('', pd.NA).nunique()}")
    print(f"Unique Nodes: {df['Node'].replace('', pd.NA).nunique()}")
    print(f"Unique Controllers/vCenters: {df['Controller/vCenter'].replace('', pd.NA).nunique()}")
    print(f"Unique Sources: {df['Source'].replace('', pd.NA).nunique()}")
    print(f"Unique Container/VM Names: {df['Container/VM Name'].replace('', pd.NA).nunique()}")
    print(f"Unique Hypervisor Providers: {df['Hypervisor Provider'].replace('', pd.NA).nunique()}")
    print(f"Unique Hypervisor Hosts: {df['Hypervisor OID'].replace('', pd.NA).nunique()}")

def format_multi_value(values, separator='\n'):
    if not values:
        return ''
    if isinstance(values, str):
        values = [values]
    values = [v for v in values if v]  # Remove empty values
    return separator.join(values) if values else ''

if __name__ == "__main__":
    create_endpoint_report()
