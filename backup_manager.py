#!/usr/bin/env python3

import os
import shutil
import argparse
from datetime import datetime
import sys

# Configuration
BACKUP_ROOT = "Backup"
IGNORE_DIRS = {BACKUP_ROOT, '.git', '.idea', '.vscode', '__pycache__', 'venv', '.DS_Store'}

def get_subdirectories(path='.'):
    """Get a list of subdirectories in the current directory, excluding ignored ones."""
    return sorted([
        d for d in os.listdir(path)
        if os.path.isdir(os.path.join(path, d)) and d not in IGNORE_DIRS and not d.startswith('.')
    ])

def select_folder(prompt_text="Select a folder:"):
    """Interactive folder selection."""
    folders = get_subdirectories()
    if not folders:
        print("No suitable folders found in the current directory.")
        return None

    print(f"\n{prompt_text}")
    for i, folder in enumerate(folders):
        print(f"{i + 1}. {folder}")
    
    try:
        choice = input("\nEnter number (or 0 to cancel): ")
        if choice == '0':
            return None
        idx = int(choice) - 1
        if 0 <= idx < len(folders):
            return folders[idx]
        else:
            print("Invalid selection.")
            return None
    except ValueError:
        print("Invalid input.")
        return None

def create_backup(target_folder=None):
    """Create a timestamped backup of the target directory."""
    if not target_folder:
        target_folder = select_folder("Select folder to backup:")
        if not target_folder:
            return

    if not os.path.exists(target_folder):
        print(f"Error: Source directory '{target_folder}' not found.")
        return

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    # New structure: Backup/TargetFolder/Timestamp
    backup_dir = os.path.join(BACKUP_ROOT, target_folder, timestamp)

    try:
        shutil.copytree(target_folder, backup_dir)
        print(f"Backup created successfully for '{target_folder}' at:\n{backup_dir}")
    except Exception as e:
        print(f"Error creating backup: {e}")

def list_backups(target_folder=None):
    """List available backups for a folder."""
    if not os.path.exists(BACKUP_ROOT):
        print("No backups found.")
        return

    # If no folder specified, show folders that have backups
    if not target_folder:
        backed_up_folders = sorted([
            d for d in os.listdir(BACKUP_ROOT) 
            if os.path.isdir(os.path.join(BACKUP_ROOT, d)) and not d.startswith('.')
        ])
        
        if not backed_up_folders:
            print("No backups found.")
            return

        print("\nFolders with backups:")
        for i, folder in enumerate(backed_up_folders):
            print(f"{i + 1}. {folder}")
        
        try:
            choice = input("\nSelect folder to list backups (or 0 to cancel): ")
            if choice == '0':
                return
            idx = int(choice) - 1
            if 0 <= idx < len(backed_up_folders):
                target_folder = backed_up_folders[idx]
            else:
                print("Invalid selection.")
                return
        except ValueError:
            print("Invalid input.")
            return

    # List timestamps for the selected folder
    folder_backup_path = os.path.join(BACKUP_ROOT, target_folder)
    if not os.path.exists(folder_backup_path):
        print(f"No backups found for '{target_folder}'.")
        return

    backups = sorted([
        d for d in os.listdir(folder_backup_path) 
        if os.path.isdir(os.path.join(folder_backup_path, d))
    ], reverse=True) # Show newest first

    if not backups:
        print(f"No backups found for '{target_folder}'.")
        return

    print(f"\nBackups for '{target_folder}':")
    for i, backup in enumerate(backups):
        print(f"{i + 1}. {backup}")
    
    return target_folder, backups

def restore_backup(target_folder=None, backup_name=None):
    """Restore a backup."""
    # Step 1: Select Folder and Backup
    result = list_backups(target_folder)
    if not result:
        return
    
    target_folder, backups = result
    
    if not backup_name:
        try:
            choice = input("\nEnter number to restore (or 0 to cancel): ")
            if choice == '0':
                return
            idx = int(choice) - 1
            if 0 <= idx < len(backups):
                backup_name = backups[idx]
            else:
                print("Invalid selection.")
                return
        except ValueError:
            print("Invalid input.")
            return

    backup_path = os.path.join(BACKUP_ROOT, target_folder, backup_name)
    if not os.path.exists(backup_path):
        print(f"Error: Backup '{backup_name}' not found for '{target_folder}'.")
        return

    # Step 2: Confirm
    print(f"\nWARNING: This will OVERWRITE everything in '{target_folder}' with contents from '{backup_name}'.")
    confirm = input("Are you sure? (yes/no): ")
    
    if confirm.lower() != 'yes':
        print("Restore cancelled.")
        return

    # Step 3: Restore
    try:
        # Remove existing source directory
        if os.path.exists(target_folder):
            shutil.rmtree(target_folder)
        
        # Copy backup to source
        shutil.copytree(backup_path, target_folder)
        print(f"Successfully restored '{target_folder}' from '{backup_name}'.")
    except Exception as e:
        print(f"Error restoring backup: {e}")

def main():
    parser = argparse.ArgumentParser(description="Multi-Folder Backup Manager")
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')

    # Backup command
    backup_parser = subparsers.add_parser('backup', help='Create a new backup')
    backup_parser.add_argument('folder', nargs='?', help='Folder to backup')

    # List command
    list_parser = subparsers.add_parser('list', help='List available backups')
    list_parser.add_argument('folder', nargs='?', help='Folder to list backups for')

    # Restore command
    restore_parser = subparsers.add_parser('restore', help='Restore a backup')
    restore_parser.add_argument('folder', nargs='?', help='Folder to restore')

    args = parser.parse_args()

    if args.command == 'backup':
        create_backup(args.folder)
    elif args.command == 'list':
        list_backups(args.folder)
    elif args.command == 'restore':
        restore_backup(args.folder)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
