#!/usr/bin/env python3

import requests
import json
import concurrent.futures
import time
from urllib3.exceptions import InsecureRequestWarning
import csv
import os
import sys
import urllib3
from tqdm import tqdm
from tqdm import tqdm


# Import logger
try:
    # Add project root to sys.path to allow importing utils
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if project_root not in sys.path:
        sys.path.append(project_root)
    from utils.logger import setup_logger
    logger = setup_logger("get_endpoints")
except ImportError:
    import logging
    logger = logging.getLogger("get_endpoints")
    print("Warning: Could not import centralized logger. Using default.")

# Global credential loading moved to main()


# Suppress only the single warning from urllib3 needed.
urllib3.disable_warnings(InsecureRequestWarning)

class ApicEndpointCollector:
    def __init__(self, apic_url, session=None, username=None, password=None):
        # Handle URL construction safely
        if apic_url.startswith("https://"):
            self.base_url = apic_url.rstrip('/')
        elif apic_url.startswith("http://"):
             self.base_url = apic_url.rstrip('/')
        else:
            self.base_url = f"https://{apic_url}"

        if session:
            self.session = session
            # Check for token in cookies first, then headers
            self.token = session.cookies.get("APIC-Cookie")
            if not self.token:
                self.token = session.headers.get("APIC-Cookie")
                
            self.username = None
            self.password = None
        else:
            self.username = username
            self.password = password
            self.session = requests.Session()
            self.session.verify = False
            self.token = None

    def get_token(self):
        """Login to APIC and get authentication token"""
        if self.token:
            return True
            
        login_url = f"{self.base_url}/api/aaaLogin.json"
        payload = {
            "aaaUser": {
                "attributes": {
                    "name": self.username,
                    "pwd": self.password
                }
            }
        }

        try:
            response = self.session.post(login_url, json=payload)
            response.raise_for_status()
            self.token = response.json()['imdata'][0]['aaaLogin']['attributes']['token']
            self.session.cookies.set("APIC-Cookie", self.token)
            return True
        except Exception as e:
            logger.error(f"Failed to get token: {str(e)}", exc_info=True)
            return False

    def get_headers(self):
        """Return headers with authentication token"""
        return {
            "Cookie": f"APIC-Cookie={self.token}"
        }

    def fetch_endpoint_data(self, class_name):
        """Fetch endpoint data from APIC"""
        if class_name == "fvCEp":
            url = f"{self.base_url}/api/node/class/fvCEp.json?rsp-subtree=children&rsp-subtree-class=fvIp,fvRsToVm,fvRsHyper,fvPrimaryEncap&order-by=fvCEp.modTs|desc"
        elif class_name == "fvIp":
            url = f"{self.base_url}/api/node/class/fvIp.json?&order-by=fvIp.modTs|desc"
        elif class_name == "fvRsHyper":
            url = f"{self.base_url}/api/node/class/fvRsHyper.json?&order-by=fvRsHyper.modTs|desc"
        elif class_name == "fvRsVm":
            url = f"{self.base_url}/api/node/class/fvRsVm.json?&order-by=fvRsVm.modTs|desc"
        elif class_name == "compVm":
            url = f"{self.base_url}/api/node/class/compVm.json?&order-by=compVm.modTs|desc"
        elif class_name == "fvnsEncapBlk":
            url = f"{self.base_url}/api/node/class/fvnsEncapBlk.json?&order-by=fvnsEncapBlk.modTs|desc"
        elif class_name == "fvRsCEpToPathEp":
            url = f"{self.base_url}/api/node/class/fvRsCEpToPathEp.json?&order-by=fvRsCEpToPathEp.modTs|desc"
        else:
            url = f"{self.base_url}/api/class/{class_name}.json"
        try:
            response = self.session.get(url)
            
            # Handle Token Expiry
            if response.status_code == 403:
                logger.info(f"Token expired while fetching {class_name}. Refreshing...")
                if self.get_token():
                    # Retry
                    response = self.session.get(url)
            
            response.raise_for_status()
            
            # Get the raw text and handle potential control characters
            text = response.text
            # Remove any null bytes and other control characters except newlines and tabs
            text = ''.join(char for char in text if char >= ' ' or char in '\n\t')
            
            try:
                return json.loads(text)
            except json.JSONDecodeError as je:
                logger.error(f"JSON decode error for {class_name}. Error location: line {je.lineno}, column {je.colno}")
                logger.error(f"Error message: {je.msg}")
                # Try a more lenient parsing approach
                try:
                    import ast
                    # Use ast.literal_eval as a fallback for more lenient parsing
                    text_dict = ast.literal_eval(text)
                    return text_dict
                except:
                    logger.error(f"Failed to parse response even with lenient parsing for {class_name}")
                    return None
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching {class_name} data: {e}")
            return None

    def _save_json(self, data, filename):
        # Ensure data/raw directory exists
        output_dir = os.path.join('data', 'raw')
        os.makedirs(output_dir, exist_ok=True)
        
        filepath = os.path.join(output_dir, filename)
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        logger.info(f"Saved data to {filepath}")

    def get_endpoints(self):
        """Get endpoint data from APIC"""
        try:
            # Create a ThreadPoolExecutor
            with concurrent.futures.ThreadPoolExecutor() as executor:
                # Create futures for API calls
                futures = {
                    executor.submit(self.fetch_endpoint_data, class_name): class_name
                    for class_name in ['fvCEp', 'fvIp', 'fvRsHyper', 'fvRsVm', 'compVm', 'fvnsEncapBlk', 'fvRsCEpToPathEp']
                }

                # Process results as they complete
                for future in concurrent.futures.as_completed(futures):
                    class_name = futures[future]
                    try:
                        data = future.result()
                        if data:
                            # Process compVm data separately
                            if class_name == 'compVm':
                                # Create a mapping of DN to compVm data
                                comp_vm_data = {}
                                for item in data.get('imdata', []):
                                    vm = item.get('compVm', {}).get('attributes', {})
                                    dn = vm.get('dn')
                                    if dn:
                                        comp_vm_data[dn] = {
                                            'cfgdOs': vm.get('cfgdOs', ''),
                                            'state': vm.get('state', ''),
                                            'name': vm.get('name', ''),
                                            'os': vm.get('os', ''),
                                            'modTs': vm.get('modTs', '')
                                        }
                                
                                # Save the mapping for later use
                                self._save_json({'compVmData': comp_vm_data}, 'compVm.json')
                            else:
                                # Save other data as is
                                self._save_json(data, f'{class_name}.json')
                                
                    except Exception as e:
                        logger.error(f"Error processing {class_name} data: {e}", exc_info=True)

                # Now process fvRsVm data to link with compVm data
                try:
                    # Define paths to the files in data/raw/
                    fvrsvm_path = os.path.join('data', 'raw', 'fvRsVm.json')
                    compvm_path = os.path.join('data', 'raw', 'compVm.json')
                    
                    with open(fvrsvm_path, 'r') as f:
                        fvrsvm_data = json.load(f)
                    with open(compvm_path, 'r') as f:
                        comp_vm_data = json.load(f)['compVmData']
                    
                    # Link fvRsVm with compVm data
                    logger.info("Processing endpoint data...")
                    for item in tqdm(fvrsvm_data.get('imdata', []), desc="Linking VMs", unit="vm"):
                        vm = item.get('fvRsVm', {}).get('attributes', {})
                        tdn = vm.get('tDn')
                        if tdn and tdn in comp_vm_data:
                            vm['compVmData'] = comp_vm_data[tdn]
                    
                    # Save the enriched fvRsVm data
                    self._save_json(fvrsvm_data, 'fvRsVm.json')
                    
                except Exception as e:
                    logger.error(f"Error linking fvRsVm with compVm data: {e}", exc_info=True)

        except Exception as e:
            logger.error(f"Error in get_endpoints: {e}", exc_info=True)

    def collect_endpoints(self):
        """Collect all endpoint data using concurrent API calls"""
        if not self.get_token():
            return

        start_time = time.time()

        self.get_endpoints()

        end_time = time.time()
        logger.info(f"\nTotal execution time: {end_time - start_time:.2f} seconds")
        
        # Generate report
        logger.info("\nGenerating report...")
        try:
            from create_report import create_endpoint_report
            create_endpoint_report()
        except Exception as e:
            logger.error(f"Error generating report: {e}", exc_info=True)

def run(session, apic_url, username=None, password=None):
    """Entry point for main.py"""
    collector = ApicEndpointCollector(apic_url, session=session, username=username, password=password)
    collector.collect_endpoints()

def get_credentials_from_manager():
    """Try to get credentials from credential manager"""
    try:
        # Add project root to sys.path
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if project_root not in sys.path:
            sys.path.append(project_root)
        
        import credential_manager
        # credential_manager loads .env, so we don't need to do it here explicitly
        logger.info("\nChecking for saved profiles...")
        creds = credential_manager.get_profile()
        if creds:
            apic_ip, apic_username, apic_password = creds
    except ImportError:
        pass # credential_manager not available, fallback to .env
    except Exception as e:
        logger.warning(f"Warning: Could not load from credential manager: {e}")

    # Fallback to environment variables (if credential manager didn't load them or failed)
    if not apic_ip:
        # Load environment variables if not already loaded by credential_manager
        load_dotenv() 
        apic_ip = os.getenv('APIC_IP')
        apic_username = os.getenv('APIC_USERNAME')
        apic_password = os.getenv('APIC_PASSWORD')

    if not all([apic_ip, apic_username, apic_password]):
        logger.error("Error: APIC credentials not found in Profile or .env file")
        logger.error("Please use 'Manage Credentials' in main menu or set APIC_IP, APIC_USERNAME, and APIC_PASSWORD in .env")
        sys.exit(1)

    collector = ApicEndpointCollector(apic_ip, username=apic_username, password=apic_password)
    collector.collect_endpoints()

if __name__ == "__main__":
    main()
