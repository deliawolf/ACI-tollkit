#!/usr/bin/env python3

import os
import sys
import subprocess

VERSION = "v1.1.0"

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

def run_aci_collector():
    print("\nStarting ACI Endpoint Collector...")
    # Get the absolute path to the script
    script_path = os.path.join(os.getcwd(), "ACI Endpoint", "get_endpoints.py")
    script_dir = os.path.dirname(script_path)
    
    if not os.path.exists(script_path):
        print(f"Error: Script not found at {script_path}")
        input("\nPress Enter to continue...")
        return

    try:
        # Run the script with the correct working directory
        subprocess.run([sys.executable, "get_endpoints.py"], cwd=script_dir, check=False)
    except Exception as e:
        print(f"Error running script: {e}")
    
    input("\nPress Enter to return to menu...")

def run_backup_manager():
    print("\nStarting Backup Manager...")
    script_path = os.path.join(os.getcwd(), "backup_manager.py")
    
    if not os.path.exists(script_path):
        print(f"Error: Script not found at {script_path}")
        input("\nPress Enter to continue...")
        return

    try:
        subprocess.run([sys.executable, "backup_manager.py"], check=False)
    except Exception as e:
        print(f"Error running script: {e}")
    
    input("\nPress Enter to return to menu...")

def main():
    while True:
        clear_screen()
        print_header()
        print("\nAvailable Tools:")
        print("1. Run ACI Endpoint Collector (Fetch Data & Generate Report)")
        print("2. Run Backup Manager")
        print("3. View Patch Notes")
        print("4. Exit")
        
        choice = input("\nEnter your choice (1-4): ")
        
        if choice == '1':
            run_aci_collector()
        elif choice == '2':
            run_backup_manager()
        elif choice == '3':
            view_patch_notes()
        elif choice == '4':
            print("\nGoodbye!")
            sys.exit(0)
        else:
            input("\nInvalid choice. Press Enter to try again...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nExiting...")
        sys.exit(0)
