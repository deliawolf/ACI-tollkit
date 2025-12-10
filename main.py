#!/usr/bin/env python3

import os
import sys
import subprocess
import requests
import getpass
import urllib3
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import print as rprint
from rich.prompt import Prompt, IntPrompt
from rich import box
from typing import Optional, Tuple

# Initialize Rich Console
console = Console()
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

def clear_screen() -> None:
    os.system('cls' if os.name == 'nt' else 'clear')

def print_header() -> None:
    clear_screen()
    console.print(Panel.fit(
        f"[bold cyan]ACI Toolkit[/bold cyan] [dim]{VERSION}[/dim]\n[italic]Automated ACI Management & Reporting[/italic]",
        border_style="cyan",
        title="Welcome",
        subtitle="Developed by Deliawolf"
    ))

def view_patch_notes() -> None:
    clear_screen()
    try:
        with open("PATCH_NOTES.md", "r") as f:
            console.print(Panel(f.read(), title="Patch Notes", border_style="blue"))
    except FileNotFoundError:
        console.print("[red]Error: PATCH_NOTES.md not found.[/red]")
    
    console.input("\n[dim]Press Enter to return to menu...[/dim]")

def login_to_apic() -> Tuple[Optional[requests.Session], Optional[str]]:
    """Handle APIC login and return session and URL"""
    console.print("\n[bold blue]--- APIC Login ---[/bold blue]")
    
    apic_ip = None
    username = None
    password = None

    # Try to get credentials from manager
    try:
        creds = credential_manager.get_profile()
        if creds:
            apic_ip, username, password = creds
            console.print(f"[green]Using profile for {apic_ip}[/green]")
    except Exception as e:
        console.print(f"[yellow]Warning: Could not load profiles: {e}[/yellow]")

    # Fallback to Manual entry if no credentials loaded
    if not apic_ip or not username or not password:
        console.print("[yellow]Enter APIC connection details:[/yellow]")
        apic_ip = Prompt.ask("APIC IP/hostname", default="https://172.24.207.2")
        if not apic_ip:
            apic_ip = "https://172.24.207.2"
        if not apic_ip.startswith("https://"):
            apic_ip = f"https://{apic_ip}"
            
        username = Prompt.ask("Username", default="admin")
        if not username:
            username = "admin"
            
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
        with console.status(f"[bold green]Logging in to {apic_ip}...[/bold green]", spinner="dots"):
            response = session.post(login_url, json=payload, timeout=10)
            response.raise_for_status()
            token = response.json()['imdata'][0]['aaaLogin']['attributes']['token']
            session.headers.update({'APIC-Cookie': token})
            
        console.print("[bold green]Login successful![/bold green]")
        return session, apic_ip, username, password
    except Exception as e:
        console.print(f"[bold red]Login failed:[/bold red] {e}")
        console.input("[dim]Press Enter to continue...[/dim]")
        return None, None, None, None

def run_aci_collector(session: requests.Session, apic_url: str, username: str, password: str) -> None:
    console.print("\n[bold cyan]Starting ACI Endpoint Collector...[/bold cyan]")
    try:
        # Change directory to ensure output files go to the right place
        cwd = os.getcwd()
        target_dir = os.path.join(PROJECT_ROOT, "ACI Endpoint")
        os.chdir(target_dir)
        
        get_endpoints.run(session, apic_url, username=username, password=password)
        
        # Restore CWD
        os.chdir(cwd)
    except Exception as e:
        logger.error(f"Error running collector: {e}", exc_info=True)
        console.print(f"[bold red]Error running collector:[/bold red] {e}")
    
    console.input("\n[dim]Press Enter to return to menu...[/dim]")

def run_interface_summary(session: requests.Session, apic_url: str, username: str, password: str) -> None:
    console.print("\n[bold cyan]Starting ACI Interface Summary...[/bold cyan]")
    try:
        cwd = os.getcwd()
        target_dir = os.path.join(PROJECT_ROOT, "ACI Inventory Interface")
        os.chdir(target_dir)
        
        get_interface.run(session, apic_url, username=username, password=password)
        
        os.chdir(cwd)
    except Exception as e:
        logger.error(f"Error running interface summary: {e}", exc_info=True)
        console.print(f"[bold red]Error running interface summary:[/bold red] {e}")
    
    console.input("\n[dim]Press Enter to return to menu...[/dim]")

def run_epg_discovery(session: requests.Session, apic_url: str, username: str, password: str) -> None:
    console.print("\n[bold cyan]Starting ACI Static path (Physical)...[/bold cyan]")
    try:
        cwd = os.getcwd()
        target_dir = os.path.join(PROJECT_ROOT, "ACI EPG Discovery")
        os.chdir(target_dir)
        
        get_epg_details.run(session, apic_url, username=username, password=password)
        
        os.chdir(cwd)
    except Exception as e:
        logger.error(f"Error running EPG discovery: {e}", exc_info=True)
        console.print(f"[bold red]Error running EPG discovery:[/bold red] {e}")
    
    console.input("\n[dim]Press Enter to return to menu...[/dim]")

def run_credential_manager() -> None:
    console.print("\n[bold cyan]Starting Credential Manager...[/bold cyan]")
    try:
        subprocess.run([sys.executable, "credential_manager.py"], check=False)
    except Exception as e:
        logger.error(f"Error running script: {e}", exc_info=True)
        console.print(f"[bold red]Error running script:[/bold red] {e}")
    
    console.input("\n[dim]Press Enter to return to menu...[/dim]")

def main() -> None:
    session = None
    apic_url = None
    username = "admin" # Default or track actual username
    password = None
    
    while True:
        print_header()
        
        # Status Line
        if session:
            console.print(Panel(f"[bold green]Connected to {apic_url} as {username}[/bold green]", border_style="green"))
        else:
            console.print(Panel("[bold red]Not Logged In - Functionality Restricted[/bold red]", border_style="red"))
            
        # Create Menu Table
        table = Table(show_header=True, header_style="bold white", border_style="bright_black", box=box.ROUNDED, expand=True)
        table.add_column("No.", style="cyan", width=4, justify="right")
        table.add_column("Tool / Action", justify="left")

        # Section 1: Authentication
        if session:
            table.add_row("1", "[dim green]Login / Relogin[/dim green]")
        else:
            table.add_row("1", "[bold white on red] Login / Relogin (START HERE) [/bold white on red]")
        table.add_section()

        # Section 2: Operational Tools
        if session:
            table.add_row("2", "[bold cyan]ACI Endpoint Collector[/bold cyan] [dim](Fetch Data & Generate Report)[/dim]")
            table.add_row("3", "[bold blue]ACI Interface Summary[/bold blue]")
            table.add_row("4", "[bold magenta]ACI Static path (Physical)[/bold magenta]")
        else:
            # Dimmed state
            table.add_row("2", "[dim]ACI Endpoint Collector (Fetch Data & Generate Report)[/dim]")
            table.add_row("3", "[dim]ACI Interface Summary[/dim]")
            table.add_row("4", "[dim]ACI Static path (Physical)[/dim]")
        
        table.add_section()

        # Section 3: Configuration & Info
        table.add_row("5", "[yellow]Manage Credentials[/yellow]")
        table.add_row("6", "[dim]View Patch Notes[/dim]")
        
        # Section 4: Exit
        table.add_section()
        table.add_row("7", "[red]Exit[/red]")

        console.print(table)
        
        choice = Prompt.ask("Select Option", choices=["1", "2", "3", "4", "5", "6", "7"], default="1" if not session else "2")
        
        if choice == '1':
             session, apic_url, username, password = login_to_apic()
        elif choice == '2':
            if not session:
                console.print("[red]Access Denied: Please Login First (Option 1)[/red]")
                console.input("[dim]Press Enter to continue...[/dim]")
            else:
                run_aci_collector(session, apic_url, username, password)
        elif choice == '3':
            if not session:
                console.print("[red]Access Denied: Please Login First (Option 1)[/red]")
                console.input("[dim]Press Enter to continue...[/dim]")
            else:
                run_interface_summary(session, apic_url, username, password)
        elif choice == '4':
            if not session:
                console.print("[red]Access Denied: Please Login First (Option 1)[/red]")
                console.input("[dim]Press Enter to continue...[/dim]")
            else:
                run_epg_discovery(session, apic_url, username, password)
        elif choice == '5':
            run_credential_manager()
        elif choice == '6':
            try:
                with open("PATCH_NOTES.md", "r") as f:
                    console.print(Panel(f.read(), title="Patch Notes", border_style="blue"))
            except FileNotFoundError:
                console.print("[red]Patch notes not found.[/red]")
            console.input("\n[dim]Press Enter to return to menu...[/dim]")
        elif choice == '7':
            console.print("\n[bold cyan]Goodbye![/bold cyan]")
            sys.exit(0)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
