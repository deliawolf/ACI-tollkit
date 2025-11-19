# ACI Toolkit

This toolkit contains scripts for managing and reporting on ACI Endpoints.

## Backup System

A simple local backup system is included to version control your `ACI Endpoint` scripts.

### Usage

The backup manager script is located at `backup_manager.py`.

#### 1. Create a Backup
To create a snapshot of a specific folder:

```bash
python3 backup_manager.py backup <folder_name>
```
Example: `python3 backup_manager.py backup "ACI Endpoint"`

If you run it without arguments, it will ask you to select a folder:
```bash
python3 backup_manager.py backup
```

#### 2. List Backups
To see available backups for a folder:

```bash
python3 backup_manager.py list <folder_name>
```

#### 3. Restore a Backup
To restore a previous version (this will **overwrite** the target folder):

```bash
python3 backup_manager.py restore <folder_name>
```
It will list the available backups for that folder and ask you to choose one.

## Scripts

*   **`ACI Endpoint/get_endpoints.py`**: Fetches endpoint data from the APIC.
*   **`ACI Endpoint/create_endpoint_report(without-clearing).py`**: Generates an Excel report from the fetched data.
