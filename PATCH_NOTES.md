# Patch Notes

## v1.1.0 (2025-11-19)
### New Features
- **Credential Manager**: Added support for multiple APIC profiles.
    - Store multiple accounts (Name, IP, Username, Password).
    - Interactive selection at runtime.
    - Securely stored in `config/profiles.json` (git-ignored).
- **Interface Summary Tool**:
    - Switched to optimized `get_interface.py`.
    - Implemented **Parallel Processing** (20 threads) for significantly faster data collection.
    - Added `.env` and Credential Manager support.
    - Output saved to `ACI Inventory Interface/data/`.

### Improvements
- **Main Menu**: Added "Manage Credentials" option.
- **Endpoint Collector**: Integrated with Credential Manager.
- **Cleanup**: Removed legacy scripts and reorganized file structure.

## v1.0.1 (2025-11-19)
- **New Feature**: Added Main Menu (`main.py`) for easy navigation.
- **Refactor**: Automated report generation after data collection.
- **Refactor**: Reorganized data files into `data/raw/` and `data/current/`.
- **Security**: Moved credentials to `.env` file.
- **Backup**: Added `backup_manager.py` with multi-folder support.

## v1.0.0 (Initial Release)
- Initial release of ACI Endpoint Collector.
- `get_endpoints.py` for data fetching.
- `create_report.py` for Excel report generation.
