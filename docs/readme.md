# Scarpa Connection Manager – User & Technical Guide[cite: 2]

## Table of Contents[cite: 2]
1. [Introduction](#1-introduction)[cite: 2]
2. [Core Features](#2-core-features)[cite: 2]
   - [Server & Folder Management](#21-server--folder-management)[cite: 2]
   - [Connection & Automation](#22-connection--automation)[cite: 2]
   - [Data Management & Logging](#23-data-management--logging)[cite: 2]
   - [SFTP File Manager](#24-sftp-file-manager)[cite: 2]
3. [The "Super Safe" Encryption System](#3-the-super-safe-encryption-system)[cite: 2]
   - [How It Works](#31-how-it-works)[cite: 2]
   - [Data Storage Location](#32-data-storage-location)[cite: 2]
   - [Changing Your Passphrase](#33-changing-your-passphrase)[cite: 2]
4. [Appearance & Customization](#4-appearance--customization)[cite: 2]
   - [Per-Server Customization](#41-per-server-customization)[cite: 2]
   - [Global Settings](#42-global-settings)[cite: 2]
5. [Importing & Exporting Data](#5-importing--exporting-data)[cite: 2]
6. [Getting Started](#6-getting-started)[cite: 2]
7. [Installation Instructions](#7-installation-instructions)[cite: 2]
8. [Troubleshooting & Dependencies](#8-troubleshooting--dependencies)[cite: 2]

---

## 1. Introduction[cite: 2]
Scarpa Connection Manager is a secure GTK3-based desktop application for managing and launching SSH and SFTP connections.[cite: 2] It organizes server configurations into folders, automates complex login sequences, and supports advanced port forwarding.[cite: 2] 
Sensitive data is heavily protected using a robust GnuPG-based local encryption system.[cite: 2]

---

## 2. Core Features[cite: 2]

### 2.1 Server & Folder Management[cite: 2]
- **Hierarchical Organization:** Structure your servers deeply into categorized folders.[cite: 2]
- **Quick Actions:** Add, edit, and delete servers and folders via intuitive top-bar menus or right-click context menus.[cite: 2]
- **Multi-selection Support:** Use `Ctrl+Click` / `Shift+Click` for batch operations.[cite: 2]
- **Inline Renaming:** Slow double-click any item to rename it directly in the tree view (fast double-click to connect).[cite: 2]
- **Drag-and-Drop:** Seamlessly reorganize your structure by dragging items between folders.[cite: 2]
- **Keyboard Shortcuts:** Quick copy/paste via `Ctrl+C` / `Ctrl+V`, and fast deletion via `Delete`.[cite: 2]
- **Natural Sorting:** Alphanumeric sorting ensures `server10` correctly appears after `server9`.[cite: 2]

### 2.2 Connection & Automation[cite: 2]
- **Multi-Protocol:** Direct access to standard SSH interactive terminals, CLI SFTP sessions, and full Windows RDP desktop environments.[cite: 2, 3]
- **Remote Desktop (RDP):** Native integration for Windows servers including clipboard sharing, audio redirection, dynamic resolution, and local home folder sharing.[cite: 3]
- **Embedded VTE Terminal:** Features smart copy/paste, context menus, and auto-resize syncing with the remote host.[cite: 2]
- **Authentication Options:** Securely authenticate via standard passwords or Private Key files (e.g., RSA/ED25519).[cite: 2]
- **Automated Login Sequences:** Build robust Expect/Send steps to automate jump-servers or secondary prompts (passwords can be visually hidden as dots in the UI).[cite: 2]
- **Advanced Port Forwarding & Tunnels:** Visually configure Local (-L), Remote (-R), and Dynamic (-D) SOCKS proxies, plus multi-hop SSH Jump Hosts for securely routing RDP traffic.[cite: 2, 3]

### 2.3 Data Management & Logging[cite: 2]
- **GUI Log Pane:** Real-time feedback on application events, transfers, and connection statuses at the bottom of the main window.[cite: 2]
- **Session Logging:** Save permanent, timestamped records of your SSH terminal output to local text files.[cite: 2]

### 2.4 SFTP File Manager[cite: 2]
- **Dual-Pane Interface:** Visually manage files between your Local machine (left) and Remote server (right) side-by-side.[cite: 2]
- **Intuitive Navigation:** Clickable breadcrumb paths and dedicated refresh buttons keep both panes up to date.[cite: 2]
- **Drag & Drop Transfers:** Seamlessly upload, download, or move files by dragging them between panes or directly onto breadcrumb folders.[cite: 2]
- **Smart Transfers (Stop & Resume):** Instantly abort accidental transfers (Red X) or resume partially downloaded/uploaded files to save bandwidth.[cite: 2]
- **Recursive Search:** Search deeply through subfolders with the binoculars tool, and double-click any result to navigate there instantly.[cite: 2]
- **Open Default File Types (Auto-Sync):** Double-click any recognized file (local or remote) to open it in your system's default application (e.g., text editor).[cite: 2] Remote files are securely downloaded to a temporary folder, and any saves you make are automatically synced back to the server in the background![cite: 2]
- **Context Menus & Shortcuts:** Use `Ctrl+C`, `Ctrl+X`, `Ctrl+V`, `Delete` (moves to Trash), and `Shift+Delete` (permanent destruction) to manage files at lightning speed.[cite: 2]

---

## 3. The "Super Safe" Encryption System[cite: 2]

### 3.1 How It Works[cite: 2]
1. A Master Passphrase is created on the very first launch.[cite: 2]
2. The passphrase is mathematically hashed using PBKDF2-HMAC-SHA256 (600,000 iterations, locally salted).[cite: 2]
3. Server data is stored in `ssh_servers.json.gpg` encrypted with AES256 via GnuPG.[cite: 2]
4. Your passwords and keys are decrypted *only in memory* during active sessions.[cite: 2]

### 3.2 Data Storage Location[cite: 2]
- **Path:** `~/.local/share/scarpa_connection_manager/`[cite: 2]
- **Files:**[cite: 2]
  - `scarpa_cm_settings.json` → Global settings, hash + salt of the Master Passphrase.[cite: 2]
  - `ssh_servers.json.gpg` → Encrypted server configurations.[cite: 2]

### 3.3 Changing Your Passphrase[cite: 2]
- Accessible via `File -> Change Passphrase...`[cite: 2]
- Requires your current passphrase to verify identity, then securely re-encrypts the entire database atomically with your new passphrase (generating a fresh cryptographic salt).[cite: 2]

---

## 4. Appearance & Customization[cite: 2]

### 4.1 Per-Server Customization[cite: 2]
- **Color Schemes:** Apply pre-built palettes (Tango, Solarized, Dracula) or pick custom foreground/background colors for specific environments (e.g., Red for Production).[cite: 2]
- **Typography:** Choose custom monospace fonts and sizing per terminal.[cite: 2]
- **Scrollback Buffer:** Define how many lines of history the terminal retains (default: 10,000 lines).[cite: 2]

### 4.2 Global Settings[cite: 2]
Accessed via `File -> Global Settings...`, this defines the application's baseline defaults:[cite: 2]
- Sets the default appearance (font, colors, palette) applied automatically to all *new* servers.[cite: 2]
- Defines the default log folder for session logs.[cite: 2]
- Features a "Reset to Defaults" button in the server editor to instantly apply these global settings to any existing server.[cite: 2]

---

## 5. Importing & Exporting Data[cite: 2]

- **Importing (Migrating):** Easily switch to Scarpa by importing existing configurations from other tools like MobaXterm, SecureCRT, and PuTTY via `File -> Import`.[cite: 2]
- **Exporting (Backups):** Export your entire database via `File -> Export`.[cite: 2] Choose between a highly secure **GPG Encrypted (.gpg)** file for safe cloud storage, or a **Plaintext JSON (.json)** file (which strips all passwords for security) for scripting and bulk editing.[cite: 2]

---

## 6. Getting Started[cite: 2]
1. Launch the app and set your Master Passphrase.[cite: 2]
2. Add servers by right-clicking on the “Session” folder → **Add Server**.[cite: 2]
3. Connect by double-clicking a server or right-clicking to choose SSH, SFTP (CLI), or SFTP (GUI).[cite: 2]

---

## 7. Installation Instructions[cite: 2]

Scarpa Connection Manager is officially hosted on an Ubuntu Personal Package Archive (PPA) for easy installation and automatic updates, as well as the Canonical Snap Store.[cite: 2]

### 🚀 Install via PPA (Recommended)[cite: 2]
Because this uses standard Debian packaging, the application has unrestricted access to your host file system.[cite: 2]

**1. Add the repository:**[cite: 2]

    sudo add-apt-repository ppa:larre-b-larsson/scarpa-connection-manager

**2. Update and install:**[cite: 2]

    sudo apt update
    sudo apt install scarpa-connection-manager

### 📦 Install via Snap Store[cite: 2]
For users who prefer sandboxed containers. *(Note: The Snap sandbox restricts application access to hidden dot-folders and areas outside your user home directory).*[cite: 2]

    sudo snap install connection-manager-scarpa

---

## 8. Troubleshooting & Dependencies[cite: 2]
- **Lost Master Passphrase:** Because encryption is strictly local, a lost passphrase is unrecoverable.[cite: 2] You must delete `~/.local/share/scarpa_connection_manager/` to reset the application.[cite: 2]
- **Dependencies required:**[cite: 2]
  - `python3-gi`[cite: 2]
  - `gir1.2-gtk-3.0`[cite: 2]
  - `gir1.2-vte-2.91`[cite: 2]
  - `python3-paramiko`[cite: 2]
  - `python3-pexpect`  *(Handles the robust terminal automation)*[cite: 2]
  - `gnupg`[cite: 2]
  - `openssh-client`[cite: 2]
  - `freerdp3-x11` *(Required for native RDP protocol and jump-host integrations)*[cite: 2, 3]

---
*Riposa in pace, Aquila di Filottrano. Sarai sempre con noi!*[cite: 2]
