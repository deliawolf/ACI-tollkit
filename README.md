# ACI Toolkit

A modern, secure, and automated toolkit for managing Cisco ACI environments.

## 🚀 Features

- **Endpoint Collector**: Fetch and analyze endpoint data.
- **Interface Summary**: Get a snapshot of interface statuses across the fabric.
- **EPG Discovery**: Detailed EPG vs VLAN mapping.
- **Secure Credential Manager**:
  - **AES-128 Encryption** (Fernet) for stored passwords.
  - **Auto-generated Keys** stored securely in `.env`.
- **Rich CLI**: Beautiful, interactive terminal UI powered by the `rich` library.
- **Shared Sessions**: Single login for all tools (no more re-authenticating for every script).

## 🛠️ Installation

1.  **Clone the valid repository**:

    ```bash
    git clone https://github.com/deliawolf/ACI-tollkit.git
    cd ACI-tollkit
    ```

2.  **Create a Virtual Environment** (Recommended):

    ```bash
    python3 -m venv .venv
    source .venv/bin/activate  # On Windows: .venv\Scripts\activate
    ```

3.  **Install Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

## 📖 Usage

### Main Menu

The easiest way to use the toolkit is via the main orchestrator:

```bash
python3 main.py
```

This will launch the interactive menu where you can:

- **Login** to your APIC (Session is cached in memory).
- **Manage Credentials** (Save profiles for one-click login).
- **Run Tools** (Collector, Interface Summary, etc.).

### Credential Manager

You can also run the credential manager directly:

```bash
python3 credential_manager.py
```

- **Add Profile**: Safely store APIC URL, Username, and Password.
- **Security**: Passwords are encrypted _before_ being written to `config/profiles.json`. The encryption key is generated automatically in your `.env` file.

## 📂 Project Structure

- `main.py`: The heart of the application.
- `credential_manager.py`: Handles secure storage and retrieval.
- `ACI Endpoint/`: Tools for endpoint analysis.
- `ACI Inventory Interface/`: Tools for interface reporting.
- `config/`: Stores encrypted profiles (Git-ignored).
- `.env`: Stores the encryption key (Git-ignored).

## 🛡️ Security

- **Encryption**: We use `cryptography.fernet` (AES-128) to secure credentials at rest.
- **SSL**: By default, `verify=False` is used to support internal labs with self-signed certificates.
- **Git Safety**: Critical files (`config/`, `.env`, `Backup/`) are excluded from version control to prevent leaks.
