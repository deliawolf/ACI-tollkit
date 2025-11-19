import json
import os
import getpass
from tabulate import tabulate

CONFIG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config')
PROFILES_FILE = os.path.join(CONFIG_DIR, 'profiles.json')

def ensure_config_dir():
    if not os.path.exists(CONFIG_DIR):
        os.makedirs(CONFIG_DIR)

def load_profiles():
    ensure_config_dir()
    if not os.path.exists(PROFILES_FILE):
        return {}
    try:
        with open(PROFILES_FILE, 'r') as f:
            return json.load(f)
    except json.JSONDecodeError:
        return {}

def save_profiles(profiles):
    ensure_config_dir()
    with open(PROFILES_FILE, 'w') as f:
        json.dump(profiles, f, indent=4)

def add_profile():
    print("\n--- Add New APIC Profile ---")
    name = input("Profile Name (e.g., Prod-APIC-1): ").strip()
    if not name:
        print("Profile name cannot be empty.")
        return

    profiles = load_profiles()
    if name in profiles:
        overwrite = input(f"Profile '{name}' already exists. Overwrite? (y/n): ").lower()
        if overwrite != 'y':
            return

    ip = input("APIC IP/URL (e.g., https://10.1.1.1): ").strip()
    # Ensure URL starts with https://
    if ip and not ip.startswith("https://"):
        ip = f"https://{ip}"
        
    username = input("Username: ").strip()
    password = getpass.getpass("Password: ")

    profiles[name] = {
        'ip': ip,
        'username': username,
        'password': password
    }
    save_profiles(profiles)
    print(f"Profile '{name}' saved successfully.")

def list_profiles():
    profiles = load_profiles()
    if not profiles:
        print("\nNo profiles found.")
        return

    table_data = []
    for name, data in profiles.items():
        table_data.append([name, data.get('ip'), data.get('username')])
    
    print("\n--- Saved Profiles ---")
    print(tabulate(table_data, headers=["Profile Name", "APIC URL", "Username"], tablefmt="pretty"))

def get_profile():
    """
    Interactive prompt to select a profile.
    Returns: (ip, username, password) or None
    """
    profiles = load_profiles()
    if not profiles:
        print("\nNo profiles found. Please add a profile first.")
        if input("Do you want to add a profile now? (y/n): ").lower() == 'y':
            add_profile()
            profiles = load_profiles() # Reload after adding
            if not profiles:
                return None
        else:
            return None

    print("\n--- Select APIC Profile ---")
    profile_names = list(profiles.keys())
    for i, name in enumerate(profile_names, 1):
        print(f"{i}. {name} ({profiles[name].get('ip')})")
    
    print(f"{len(profile_names) + 1}. Enter Credentials Manually")

    while True:
        try:
            choice = input(f"\nEnter choice (1-{len(profile_names) + 1}): ")
            choice_idx = int(choice) - 1
            
            if 0 <= choice_idx < len(profile_names):
                selected_name = profile_names[choice_idx]
                data = profiles[selected_name]
                return data['ip'], data['username'], data['password']
            elif choice_idx == len(profile_names):
                # Manual entry
                return None
            else:
                print("Invalid choice.")
        except ValueError:
            print("Please enter a number.")

def delete_profile():
    profiles = load_profiles()
    if not profiles:
        print("\nNo profiles found.")
        return

    print("\n--- Delete Profile ---")
    profile_names = list(profiles.keys())
    for i, name in enumerate(profile_names, 1):
        print(f"{i}. {name}")
    
    try:
        choice = int(input(f"\nSelect profile to delete (1-{len(profile_names)}): "))
        if 1 <= choice <= len(profile_names):
            name_to_delete = profile_names[choice-1]
            if input(f"Are you sure you want to delete '{name_to_delete}'? (y/n): ").lower() == 'y':
                del profiles[name_to_delete]
                save_profiles(profiles)
                print(f"Profile '{name_to_delete}' deleted.")
        else:
            print("Invalid choice.")
    except ValueError:
        print("Invalid input.")

if __name__ == "__main__":
    # Simple menu for testing
    while True:
        print("\n1. List Profiles")
        print("2. Add Profile")
        print("3. Delete Profile")
        print("4. Exit")
        c = input("Choice: ")
        if c == '1': list_profiles()
        elif c == '2': add_profile()
        elif c == '3': delete_profile()
        elif c == '4': break
