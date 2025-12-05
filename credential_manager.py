import json
import os
import base64
import getpass
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from typing import Optional, Tuple, List, Dict, Any

# Initialize Console
console = Console()

# Load environment variables
load_dotenv()

# Constants
CONFIG_DIR = "config"
PROFILES_FILE = os.path.join(CONFIG_DIR, "profiles.json")
ENV_FILE = ".env"

def get_or_create_key() -> str:

    """
    Get the encryption key from .env or generate a new one.
    Ensures the key is saved to .env for persistence.
    """
    key = os.getenv("ACI_ENCRYPTION_KEY")
    if not key:
        print("Generating new encryption key...")
        key = Fernet.generate_key().decode()
        
        # Save to .env
        try:
            # Read existing .env content
            env_content = ""
            if os.path.exists(ENV_FILE):
                with open(ENV_FILE, "r") as f:
                    env_content = f.read()
            
            # Append key if not present (double check)
            if "ACI_ENCRYPTION_KEY" not in env_content:
                with open(ENV_FILE, "a") as f:
                    if env_content and not env_content.endswith("\n"):
                        f.write("\n")
                    f.write(f"ACI_ENCRYPTION_KEY={key}\n")
                console.print(f"[green]Encryption key saved to {ENV_FILE}[/green]")
        except Exception as e:
            console.print(f"[yellow]Warning: Could not save key to .env: {e}[/yellow]")
            console.print("You will need to re-login next time if the key is lost.")
    
    return key

# Initialize Cipher
try:
    ENCRYPTION_KEY = get_or_create_key()
    cipher_suite = Fernet(ENCRYPTION_KEY)
except Exception as e:
    console.print(f"[red]Error initializing encryption: {e}[/red]")
    cipher_suite = None

def encrypt_password(password: str) -> str:

    """Encrypt password using Fernet (AES)"""
    if not cipher_suite:
        return base64.b64encode(password.encode()).decode() # Fallback
    return cipher_suite.encrypt(password.encode()).decode()

def decrypt_password(encrypted_password: str) -> str:

    """
    Decrypt password. 
    Handles:
    1. Fernet Encrypted (New)
    2. Base64 Encoded (Legacy)
    3. Plaintext (Fallback)
    """
    if not encrypted_password:
        return ""
        
    try:
        # Try Fernet first
        if cipher_suite:
            return cipher_suite.decrypt(encrypted_password.encode()).decode()
    except Exception:
        pass # Not Fernet encrypted or wrong key

    try:
        # Try Base64 (Legacy)
        return base64.b64decode(encrypted_password).decode()
    except Exception:
        pass # Not Base64

    # Return as-is (Plaintext)
    return encrypted_password

def ensure_config_dir() -> None:

    """Ensure config directory exists"""
    if not os.path.exists(CONFIG_DIR):
        try:
            os.makedirs(CONFIG_DIR)
        except OSError as e:
            print(f"Error creating config directory: {e}")

def load_profiles() -> List[Dict[str, Any]]:

    """Load profiles from JSON file. Returns empty list if file missing."""
    if not os.path.exists(PROFILES_FILE):
        return []
    
    try:
        with open(PROFILES_FILE, 'r') as f:
            data = json.load(f)
            
            # Handle legacy dictionary format
            if isinstance(data, dict):
                normalized_profiles = []
                for name, profile_data in data.items():
                    # Handle key mismatch (ip vs apic_ip)
                    if 'ip' in profile_data:
                        profile_data['apic_ip'] = profile_data.pop('ip')
                    # Preserve the key as 'name' if not present
                    if 'name' not in profile_data:
                        profile_data['name'] = name
                    normalized_profiles.append(profile_data)
                return normalized_profiles
            
            # Handle list format
            elif isinstance(data, list):
                # Ensure compatibility for items in list
                for p in data:
                    if 'ip' in p and 'apic_ip' not in p:
                        p['apic_ip'] = p.pop('ip')
                return data
                
            return []
    except (json.JSONDecodeError, IOError):
        return []

def save_profiles(profiles: List[Dict[str, Any]]) -> bool:

    """Save profiles to JSON file"""
    ensure_config_dir()
    try:
        with open(PROFILES_FILE, 'w') as f:
            json.dump(profiles, f, indent=4)
        return True
    except IOError as e:
        console.print(f"[red]Error saving profiles: {e}[/red]")
        return False

def add_profile() -> None:

    """Add a new APIC profile"""
    console.print(Panel("Add New Profile", style="bold blue"))
    apic_ip = Prompt.ask("APIC IP/URL")
    username = Prompt.ask("Username")
    password = getpass.getpass("Password: ")
    
    if not all([apic_ip, username, password]):
        console.print("[red]Error: All fields are required.[/red]")
        return

    # Normalize URL
    if not apic_ip.startswith("https://"):
        apic_ip = f"https://{apic_ip}"

    profiles = load_profiles()
    
    # Check for duplicate
    for p in profiles:
        if p['apic_ip'] == apic_ip and p['username'] == username:
            if Confirm.ask("Profile already exists. Update password?"):
                p['password'] = encrypt_password(password)
                save_profiles(profiles)
                console.print("[green]Profile updated.[/green]")
            return

    # Add new
    profiles.append({
        "apic_ip": apic_ip,
        "username": username,
        "password": encrypt_password(password)
    })
    
    if save_profiles(profiles):
        console.print("[bold green]Profile added successfully.[/bold green]")

def list_profiles() -> None:

    """List all saved profiles"""
    profiles = load_profiles()
    if not profiles:
        console.print("[yellow]No profiles found.[/yellow]")
        return

    table = Table(title="Saved Profiles")
    table.add_column("Index", justify="center", style="cyan")
    table.add_column("APIC URL", style="white")
    table.add_column("Username", style="green")

    for i, p in enumerate(profiles, 1):
        table.add_row(str(i), p['apic_ip'], p['username'])
    
    console.print(table)

def get_profile() -> Optional[Tuple[str, str, str]]:

    """Select a profile and return credentials"""
    profiles = load_profiles()
    if not profiles:
        return None

    list_profiles()
    
    try:
        choice = Prompt.ask("Select Profile (Index)", default="")
        if not choice:
            return None
            
        idx = int(choice) - 1
        if 0 <= idx < len(profiles):
            p = profiles[idx]
            # Decrypt password on retrieval
            return p['apic_ip'], p['username'], decrypt_password(p['password'])
        else:
            console.print("[red]Invalid choice.[/red]")
    except ValueError:
        console.print("[red]Invalid input.[/red]")
    
    return None

def delete_profile() -> None:

    """Delete a profile"""
    profiles = load_profiles()
    if not profiles:
        console.print("[yellow]No profiles found.[/yellow]")
        return

    list_profiles()
    
    try:
        choice = Prompt.ask("Select Profile to Delete (Index)", default="")
        if not choice:
            return

        idx = int(choice) - 1
        if 0 <= idx < len(profiles):
            removed = profiles.pop(idx)
            save_profiles(profiles)
            console.print(f"[green]Removed profile for {removed['apic_ip']}[/green]")
        else:
            console.print("[red]Invalid choice.[/red]")
    except ValueError:
        console.print("[red]Invalid input.[/red]")

if __name__ == "__main__":
    while True:
        console.print("\n[bold cyan]--- Credential Manager ---[/bold cyan]")
        
        table = Table(show_header=False, box=None)
        table.add_row("1. Add/Update Profile")
        table.add_row("2. List Profiles")
        table.add_row("3. Delete Profile")
        table.add_row("4. Exit")
        console.print(table)
        
        choice = Prompt.ask("Enter choice", choices=["1", "2", "3", "4"])
        
        if choice == '1':
            add_profile()
        elif choice == '2':
            list_profiles()
        elif choice == '3':
            delete_profile()
        elif choice == '4':
            break
