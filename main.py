#!/usr/bin/env python3

import os
import sys
import subprocess
import requests
import getpass
import urllib3
from urllib3.exceptions import InsecureRequestWarning

# Disable SSL warnings
urllib3.disable_warnings(InsecureRequestWarning)

# Add subdirectories to sys.path to allow importing tools
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(PROJECT_ROOT, "ACI Endpoint"))
sys.path.append(os.path.join(PROJECT_ROOT, "ACI Inventory Interface"))
sys.path.append(os.path.join(PROJECT_ROOT, "ACI EPG Discovery"))
sys.path.append(os.path.join(PROJECT_ROOT, "utils"))

# Import tools
try:
    from logger import setup_logger
    import credential_manager
    import get_endpoints
    import get_interface
    import get_epg_details
except ImportError as e:
    print(f"Error importing modules: {e}")
    print("Ensure all directories and files are present.")
    sys.exit(1)

# Initialize Logger
logger = setup_logger("main")

VERSION = "v1.2.0"

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_header():
    print("=" * 40)
    print(f"      ACI Toolkit - Main Menu ({VERSION})")
    print("=" * 40)

def view_patch_notes():
    clear_screen()
    try:
        with open("PATCH_NOTES.md", "r") as f:
            print(f.read())
    except FileNotFoundError:
        print("Error: PATCH_NOTES.md not found.")
    
    input("\nPress Enter to return to menu...")

def login_to_apic():
    """Handle APIC login and return session and URL"""
    logger.info("\n--- APIC Login ---")
    
    # Try to get credentials from manager
    try:
        creds = credential_manager.get_profile()
        if creds:
            apic_ip, username, password = creds
            logger.info(f"Using profile for {apic_ip}")
        else:
            raise ValueError("No profile selected")
    except Exception:
        # Manual entry
        logger.info("Enter APIC connection details:")
        apic_ip = input("APIC IP/hostname [https://172.24.207.2]: ").strip()
        if not apic_ip:
            apic_ip = "https://172.24.207.2"
        if not apic_ip.startswith("https://"):
            apic_ip = f"https://{apic_ip}"
            
        username = input("Username [admin]: ").strip() or "admin"
        password = getpass.getpass("Password: ")

    # Create session
    session = requests.Session()
    session.verify = False
    
    login_url = f"{apic_ip}/api/aaaLogin.json"
    payload = {
        "aaaUser": {
            "attributes": {
                "name": username,
                "pwd": password
            }
        }
    }
    
    try:
        logger.info(f"Logging in to {apic_ip}...")
        response = session.post(login_url, json=payload, timeout=10)
        response.raise_for_status()
        token = response.json()['imdata'][0]['aaaLogin']['attributes']['token']
        session.headers.update({'APIC-Cookie': token})
        logger.info("Login successful!")
        return session, apic_ip
    except Exception as e:
        logger.error(f"Login failed: {e}")
        input("Press Enter to continue...")
        return None, None

def run_aci_collector(session, apic_url):
    logger.info("\nStarting ACI Endpoint Collector...")
    try:
        # Change directory to ensure output files go to the right place
        cwd = os.getcwd()
        target_dir = os.path.join(PROJECT_ROOT, "ACI Endpoint")
        os.chdir(target_dir)
        
        get_endpoints.run(session, apic_url)
        
        # Restore CWD
        os.chdir(cwd)
    except Exception as e:
        logger.error(f"Error running collector: {e}", exc_info=True)
    
    input("\nPress Enter to return to menu...")

def run_interface_summary(session, apic_url):
    logger.info("\nStarting ACI Interface Summary...")
    try:
        cwd = os.getcwd()
        target_dir = os.path.join(PROJECT_ROOT, "ACI Inventory Interface")
        os.chdir(target_dir)
        
        get_interface.run(session, apic_url)
        
        os.chdir(cwd)
    except Exception as e:
        logger.error(f"Error running interface summary: {e}", exc_info=True)
    
    input("\nPress Enter to return to menu...")

def run_epg_discovery(session, apic_url):
    logger.info("\nStarting ACI EPG Discovery...")
    try:
        cwd = os.getcwd()
        target_dir = os.path.join(PROJECT_ROOT, "ACI EPG Discovery")
        os.chdir(target_dir)
        
        get_epg_details.run(session, apic_url)
        
        os.chdir(cwd)
    except Exception as e:
        logger.error(f"Error running EPG discovery: {e}", exc_info=True)
    
    input("\nPress Enter to return to menu...")

def run_backup_manager():
    logger.info("\nStarting Backup Manager...")
    try:
        subprocess.run([sys.executable, "backup_manager.py"], check=False)
    except Exception as e:
        logger.error(f"Error running script: {e}", exc_info=True)
    
    input("\nPress Enter to return to menu...")

def run_credential_manager():
    logger.info("\nStarting Credential Manager...")
    try:
        subprocess.run([sys.executable, "credential_manager.py"], check=False)
    except Exception as e:
        logger.error(f"Error running script: {e}", exc_info=True)
    
    input("\nPress Enter to return to menu...")

def main():
    session = None
    apic_url = None
    
    while True:
        clear_screen()
        print_header()
        
        if session:
            logger.info(f"Status: Logged in to {apic_url}")
        else:
            logger.info("Status: Not logged in")
            
        print("\nAvailable Tools:")
        print("1. Run ACI Endpoint Collector (Fetch Data & Generate Report)")
        print("2. Run Backup Manager")
        print("3. Run ACI Interface Summary")
        print("4. Run ACI EPG Discovery")
        print("5. Manage Credentials")
        print("6. View Patch Notes")
        print("7. Login / Relogin")
        print("8. Exit")
        
        choice = input("\nEnter your choice (1-8): ")
        
        if choice == '1':
            if not session:
                session, apic_url = login_to_apic()
            if session:
                run_aci_collector(session, apic_url)
        elif choice == '2':
            run_backup_manager()
        elif choice == '3':
            if not session:
                session, apic_url = login_to_apic()
            if session:
                run_interface_summary(session, apic_url)
        elif choice == '4':
            if not session:
                session, apic_url = login_to_apic()
            if session:
                run_epg_discovery(session, apic_url)
        elif choice == '5':
            run_credential_manager()
        elif choice == '6':
            view_patch_notes()
        elif choice == '7':
            session, apic_url = login_to_apic()
        elif choice == '8':
            logger.info("\nGoodbye!")
            sys.exit(0)
        else:
            input("\nInvalid choice. Press Enter to try again...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nExiting...")
        sys.exit(0)
