# Patch Notes

## v1.1.0 (2025-11-19)
- **New Feature**: Added Main Menu (`main.py`) for easy navigation.
- **Refactor**: Automated report generation after data collection.
- **Refactor**: Reorganized data files into `data/raw/` and `data/current/`.
- **Security**: Moved credentials to `.env` file.
- **Backup**: Added `backup_manager.py` with multi-folder support.

## v1.0.0 (Initial Release)
- Initial release of ACI Endpoint Collector.
- `get_endpoints.py` for data fetching.
- `create_report.py` for Excel report generation.
