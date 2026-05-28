# Scarpa Connection Manager – User & Technical Guide

## Table of Contents
1. [Introduction](#1-introduction)  
2. [Core Features](#2-core-features)  
   - [Server & Folder Management](#21-server--folder-management)  
   - [Connection & Automation](#22-connection--automation)  
   - [Data Management & Logging](#23-data-management--logging)  
   - [SFTP File Manager](#24-sftp-file-manager)
3. [The "Super Safe" Encryption System](#3-the-super-safe-encryption-system)  
   - [How It Works](#31-how-it-works)  
   - [Data Storage Location](#32-data-storage-location)  
   - [Changing Your Passphrase](#33-changing-your-passphrase)  
4. [Appearance & Customization](#4-appearance--customization)  
   - [Per-Server Customization](#41-per-server-customization)  
   - [Global Settings](#42-global-settings)  
5. [Importing & Exporting Data](#5-importing--exporting-data)  
6. [Getting Started](#6-getting-started)  
7. [Installation Instructions](#7-installation-instructions)  
8. [Troubleshooting & Dependencies](#8-troubleshooting--dependencies)

---

## 1. Introduction
Scarpa Connection Manager is a secure GTK3-based desktop application for managing and launching SSH and SFTP connections. It organizes server configurations into folders, automates complex login sequences, and supports advanced port forwarding.  
Sensitive data is heavily protected using a robust GnuPG-based local encryption system.

---

## 2. Core Features

### 2.1 Server & Folder Management
- **Hierarchical Organization:** Structure your servers deeply into categorized folders.  
- **Quick Actions:** Add, edit, and delete servers and folders via intuitive top-bar menus or right-click context menus.  
- **Multi-selection Support:** Use `Ctrl+Click` / `Shift+Click` for batch operations.  
- **Inline Renaming:** Slow double-click any item to rename it directly in the tree view (fast double-click to connect).  
- **Drag-and-Drop:** Seamlessly reorganize your structure by dragging items between folders.  
- **Keyboard Shortcuts:** Quick copy/paste via `Ctrl+C` / `Ctrl+V`, and fast deletion via `Delete`.  
- **Natural Sorting:** Alphanumeric sorting ensures `server10` correctly appears after `server9`.

### 2.2 Connection & Automation
- **Multi-Protocol:** Direct access to standard SSH interactive terminals and CLI SFTP sessions.  
- **Embedded VTE Terminal:** Features smart copy/paste, context menus, and auto-resize syncing with the remote host.  
- **Authentication Options:** Securely authenticate via standard passwords or Private Key files (e.g., RSA/ED25519).  
- **Automated Login Sequences:** Build robust Expect/Send steps to automate jump-servers or secondary prompts (passwords can be visually hidden as dots in the UI).  
- **Advanced Port Forwarding:** Visually configure Local (-L), Remote (-R), and Dynamic (-D) SOCKS proxies.  

### 2.3 Data Management & Logging
- **GUI Log Pane:** Real-time feedback on application events, transfers, and connection statuses at the bottom of the main window.  
- **Session Logging:** Save permanent, timestamped records of your SSH terminal output to local text files.  

### 2.4 SFTP File Manager
- **Dual-Pane Interface:** Visually manage files between your Local machine (left) and Remote server (right) side-by-side.
- **Intuitive Navigation:** Clickable breadcrumb paths and dedicated refresh buttons keep both panes up to date.
- **Drag & Drop Transfers:** Seamlessly upload, download, or move files by dragging them between panes or directly onto breadcrumb folders.
- **Smart Transfers (Stop & Resume):** Instantly abort accidental transfers (Red X) or resume partially downloaded/uploaded files to save bandwidth.
- **Recursive Search:** Search deeply through subfolders with the binoculars tool, and double-click any result to navigate there instantly.
- **Open Default File Types (Auto-Sync):** Double-click any recognized file (local or remote) to open it in your system's default application (e.g., text editor). Remote files are securely downloaded to a temporary folder, and any saves you make are automatically synced back to the server in the background!
- **Context Menus & Shortcuts:** Use `Ctrl+C`, `Ctrl+X`, `Ctrl+V`, `Delete` (moves to Trash), and `Shift+Delete` (permanent destruction) to manage files at lightning speed.

---

## 3. The "Super Safe" Encryption System

### 3.1 How It Works
1. A Master Passphrase is created on the very first launch.  
2. The passphrase is mathematically hashed using PBKDF2-HMAC-SHA256 (600,000 iterations, locally salted).  
3. Server data is stored in `ssh_servers.json.gpg` encrypted with AES256 via GnuPG.  
4. Your passwords and keys are decrypted *only in memory* during active sessions.  

### 3.2 Data Storage Location
- **Path:** `~/.local/share/scarpa_connection_manager/`  
- **Files:** 
  - `scarpa_cm_settings.json` → Global settings, hash + salt of the Master Passphrase.  
  - `ssh_servers.json.gpg` → Encrypted server configurations.  

### 3.3 Changing Your Passphrase
- Accessible via `File -> Change Passphrase...`  
- Requires your current passphrase to verify identity, then securely re-encrypts the entire database atomically with your new passphrase (generating a fresh cryptographic salt).  

---

## 4. Appearance & Customization

### 4.1 Per-Server Customization
- **Color Schemes:** Apply pre-built palettes (Tango, Solarized, Dracula) or pick custom foreground/background colors for specific environments (e.g., Red for Production).  
- **Typography:** Choose custom monospace fonts and sizing per terminal.  
- **Scrollback Buffer:** Define how many lines of history the terminal retains (default: 10,000 lines).  

### 4.2 Global Settings
Accessed via `File -> Global Settings...`, this defines the application's baseline defaults:
- Sets the default appearance (font, colors, palette) applied automatically to all *new* servers.  
- Defines the default log folder for session logs.  
- Features a "Reset to Defaults" button in the server editor to instantly apply these global settings to any existing server.

---

## 5. Importing & Exporting Data

- **Importing (Migrating):** Easily switch to Scarpa by importing existing configurations from other tools like MobaXterm, SecureCRT, and PuTTY via `File -> Import`.
- **Exporting (Backups):** Export your entire database via `File -> Export`. Choose between a highly secure **GPG Encrypted (.gpg)** file for safe cloud storage, or a **Plaintext JSON (.json)** file (which strips all passwords for security) for scripting and bulk editing.

---

## 6. Getting Started
1. Launch the app and set your Master Passphrase.  
2. Add servers by right-clicking on the “Session” folder → **Add Server**.  
3. Connect by double-clicking a server or right-clicking to choose SSH, SFTP (CLI), or SFTP (GUI).  

---

## 7. Installation Instructions

Scarpa Connection Manager is officially hosted on an Ubuntu Personal Package Archive (PPA) for easy installation and automatic updates, as well as the Canonical Snap Store.

### 🚀 Install via PPA (Recommended)
Because this uses standard Debian packaging, the application has unrestricted access to your host file system.

**1. Add the repository:**
```bash
sudo add-apt-repository ppa:larre-b-larsson/scarpa-connection-manager
```
**2. Update and install:**
```bash
sudo apt update
sudo apt install scarpa-connection-manager
```

### 📦 Install via Snap Store 
For users who prefer sandboxed containers. *(Note: The Snap sandbox restricts application access to hidden dot-folders and areas outside your user home directory).*
```bash
sudo snap install connection-manager-scarpa
```

---

## 8. Troubleshooting & Dependencies
- **Lost Master Passphrase:** Because encryption is strictly local, a lost passphrase is unrecoverable. You must delete `~/.local/share/scarpa_connection_manager/` to reset the application.  
- **Dependencies required:** 
  - `python3-gi`  
  - `gir1.2-gtk-3.0`  
  - `gir1.2-vte-2.91`  
  - `python3-paramiko`
  - `python3-pexpect`  *(Handles the robust terminal automation)*
  - `gnupg`  
  - `openssh-client`

---
*Riposa in pace, Aquila di Filottrano. Sarai sempre con noi!*
