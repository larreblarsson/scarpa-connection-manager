#!/usr/bin/env python3

import os
import json
import shutil
import subprocess
import tempfile
import re
import gi
import hashlib
import secrets
import sys
import webbrowser
import http.server 
import socketserver
import threading 
import paramiko
import stat
import getpass
import uuid
import xml.etree.ElementTree as ET
import urllib.parse
import copy
import traceback
import time
import warnings
import urllib.parse

from datetime import datetime

gi.require_version('Gtk', '3.0')
try:
    gi.require_version('Secret', '1')
    from gi.repository import Secret
    HAS_SECRET = True
except (ValueError, ImportError):
    HAS_SECRET = False
    print("WARNING: libsecret not found. 'Remember Me' will be disabled.", file=sys.stderr)
try:
    gi.require_version('Vte', '2.91')
    from gi.repository import Vte
except (ValueError, ImportError):
    print("ERROR: VTE library not found. Please install gir1.2-vte-2.91", file=sys.stderr)
    sys.exit(1)
from gi.repository import Gtk, Gio, GLib, GdkPixbuf
from gi.repository import Gdk
from gi.repository import Pango # Moved here as it's used in init_ui_elements

# --- Globals & Paths ---
def natural_key(s):
    """Provides a key for natural sorting (e.g., sorts 'file10' after 'file9')."""
    parts = re.split(r'(\d+)', s)
    return [int(p) if p.isdigit() else p.lower() for p in parts]

def get_user_data_dir():
    """
    Determines the appropriate user-specific data directory based on XDG Base Directory Specification.
    """
    xdg_data_home = os.environ.get('XDG_DATA_HOME')
    if xdg_data_home:
        return os.path.join(xdg_data_home, 'scarpa_connection_manager')
    return os.path.join(os.path.expanduser('~'), '.local', 'share', 'scarpa_connection_manager')

APP_DATA_DIR = get_user_data_dir()
SERVER_FILE    = os.path.join(APP_DATA_DIR, "ssh_servers.json")
SETTINGS_FILE  = os.path.join(APP_DATA_DIR, "scarpa_cm_settings.json")
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR) 

def get_asset_path(filename, top_folder="docs"):
    """
    Dynamically finds static assets across Debian (.deb), Snap, or Local Development.
    """
    # 1. Debian system path (Debian usually installs files flat in this directory)
    system_path = os.path.join("/usr/share/scarpa_connection_manager", filename)
    if os.path.exists(system_path):
        return system_path
        
    # 2. Snap environment path
    snap_base = os.environ.get("SNAP")
    if snap_base:
        # Check inside the specific folder in the snap
        snap_path = os.path.join(snap_base, top_folder, filename)
        if os.path.exists(snap_path):
            return snap_path
            
    # 3. Local Development path (running via python3 locally)
    local_path = os.path.join(PROJECT_ROOT, top_folder, filename)
    return local_path

# --- Apply the dynamic function to your assets ---
# Now we tell it explicitly to look in the "docs" folder!
FOLDER_ICON    = get_asset_path("folder.png", "docs")
SERVER_ICON    = get_asset_path("server.png", "docs")
HELP_FILE_PATH = get_asset_path("user_guide.html", "docs")
APP_ID         = "com.example.scarpacm"
APP_TITLE      = "Scarpa Connection Manager"
ROOT_FOLDER    = "Session"
DEFAULT_TERM_FONT = "Ubuntu Mono 12"
DEFAULT_TERM_FG = "#000000"
DEFAULT_TERM_BG = "#FFFFDD"
DEFAULT_TERM_PALETTE = "None"
DEFAULT_TERM_SCROLLBACK = 10000
# Terminal color schemes used by the Appearance tab / server dialog
BUILTIN_SCHEMES = {
    "Black on light yellow": {"term_fg": "#000000", "term_bg": "#FFFFDD", "term_palette": "None"},
    "Black on white":        {"term_fg": "#000000", "term_bg": "#FFFFFF", "term_palette": "None"},
    "Gray on black":         {"term_fg": "#AAAAAA", "term_bg": "#000000", "term_palette": "None"},
    "Green on black":        {"term_fg": "#00FF00", "term_bg": "#000000", "term_palette": "None"},
    "White on black":        {"term_fg": "#FFFFFF", "term_bg": "#000000", "term_palette": "None"},
    "GNOME light":           {"term_fg": "#2E3436", "term_bg": "#EEEEEC", "term_palette": "Tango"},
    "GNOME dark":            {"term_fg": "#D3D7CF", "term_bg": "#2E3436", "term_palette": "Tango"},
    "Tango light":           {"term_fg": "#2E3436", "term_bg": "#F7F7F7", "term_palette": "Tango"},
    "Tango dark":            {"term_fg": "#D3D7CF", "term_bg": "#2E3436", "term_palette": "Tango"},
    "Solarized light":       {"term_fg": "#586E75", "term_bg": "#FDF6E3", "term_palette": "Solarized Light"},
    "Solarized dark":        {"term_fg": "#839496", "term_bg": "#002B36", "term_palette": "Solarized Dark"},
    "Custom": None,
}
# --- CHAMELEON MODE: Detect Environment ---
IS_SNAP = 'SNAP' in os.environ

# ---  Hashing Globals ---
PBKDF2_ITERATIONS = 600000  # Number of iterations for PBKDF2. Higher = more secure but slower.
SALT_SIZE = 16              # Salt size in bytes (16 bytes = 128 bits)
# --- End Passphrase Hashing Globals ---

def parse_securecrt_xml(file_path):
    """
    Parses native SecureCRT (VanDyke) XML export files.
    Extracts Host, User, Port, Port Forwarding (Array & Key formats), and Login Actions.
    """
    servers = []
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
    except Exception as e:
        print(f"Error reading XML: {e}")
        return servers

    # Ensure it's actually a SecureCRT file
    if root.tag != "VanDyke":
        print("Not a valid SecureCRT (VanDyke) XML file.")
        return servers

    sessions_root = None
    for key in root.findall("key"):
        if key.get("name") == "Sessions":
            sessions_root = key
            break
            
    if sessions_root is not None:
        def traverse_nodes(node, current_folder_path):
            for child_key in node.findall("key"):
                node_name = child_key.get("name")
                if not node_name: continue
                
                is_server = len(child_key.findall("string")) > 0 or len(child_key.findall("dword")) > 0
                
                if is_server:
                    hostname = ""
                    username = ""
                    port = "22"
                    port_forwards = []
                    auto_sequence = []
                    
                    # 1. Parse standard connection properties
                    for prop in child_key:
                        if not isinstance(prop.tag, str): continue
                        attr_name = prop.get("name")
                        if not attr_name: continue
                        
                        attr_lower = attr_name.lower()
                        clean_text = prop.text.strip() if prop.text else ""
                        
                        if attr_lower == "hostname":
                            hostname = clean_text
                        elif attr_lower == "username":
                            username = clean_text
                        elif attr_lower == "port" or attr_lower == "[ssh2] port":
                            if prop.tag.lower() == "dword" and clean_text:
                                try: port = str(int(clean_text, 16))
                                except: port = clean_text
                            elif clean_text:
                                port = clean_text

                    # 2. Extract Port Forwarding (New Array Format)
                    for arr in child_key.findall("array"):
                        arr_name = arr.get("name", "").lower()
                        if "port forward table" in arr_name:
                            for string_elem in arr.findall("string"):
                                text = string_elem.text
                                if text:
                                    # Example: fre-cpg-sftp|2014|1|10.32.180.53|22||
                                    parts = text.split("|")
                                    if len(parts) >= 5:
                                        try: src_port = int(parts[1])
                                        except ValueError: continue
                                        
                                        dst_host = parts[3]
                                        try: dst_port = int(parts[4]) if parts[4] else 0
                                        except ValueError: dst_port = 0
                                        
                                        pf_type = "Dynamic" if "socks" in dst_host.lower() else "Local"
                                        
                                        if src_port > 0:
                                            port_forwards.append({
                                                "type": pf_type,
                                                "source_port": src_port,
                                                "dest_host": dst_host if pf_type != "Dynamic" else "localhost",
                                                "dest_port": dst_port if pf_type != "Dynamic" else 0
                                            })

                    # 3. Drill into Sub-Keys for Logon Data
                    for subkey in child_key.findall("key"):
                        subkey_name = subkey.get("name", "").lower()

                        # --- Extract Login Actions (Expect/Send) ---
                        if "logon" in subkey_name or "automate" in subkey_name:
                            expects = {}
                            sends = {}
                            for prop in subkey.findall("string") + subkey.findall("dword"):
                                name = prop.get("name", "").lower()
                                text = prop.text.strip() if prop.text else ""
                                if not text: continue
                                
                                match = re.search(r'(expect|send)\s*(\d+)?', name)
                                if match:
                                    action_type = match.group(1)
                                    idx = int(match.group(2)) if match.group(2) else 1
                                    if action_type == "expect":
                                        expects[idx] = text
                                    else:
                                        sends[idx] = text
                            
                            all_indices = sorted(set(expects.keys()).union(sends.keys()))
                            for idx in all_indices:
                                auto_sequence.append({
                                    "expect": expects.get(idx, ""),
                                    "send": sends.get(idx, ""),
                                    "hide": False
                                })

                    final_host = hostname if hostname else node_name
                    folder = current_folder_path.strip("/")
                    
                    if node_name == "Default" and not folder:
                        continue

                    server_data = {
                        "name": node_name,
                        "host": final_host,
                        "port": port,
                        "user": username,
                        "port_forwards": port_forwards,
                        "auto_sequence": auto_sequence
                    }
                    
                    if folder:
                        server_data["folder"] = folder
                        
                    servers.append(server_data)
                else:
                    new_folder_path = f"{current_folder_path}/{node_name}" if current_folder_path else node_name
                    traverse_nodes(child_key, new_folder_path)

        traverse_nodes(sessions_root, "")
        
    return servers

def parse_putty_reg(file_path):
    """
    Parses native Windows PuTTY (.reg) export files.
    Extracts Host, User, Port, and Port Forwarding Rules.
    """
    import urllib.parse
    servers = []
    try:
        # Windows Registry files are often exported in UTF-16 format, 
        # but sometimes UTF-8. We try both to be safe!
        try:
            with open(file_path, 'r', encoding='utf-16') as f:
                lines = f.readlines()
        except UnicodeError:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()

        current_server = None

        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Detect a new Session block in the registry
            if line.startswith('[') and line.endswith(']'):
                if '\\PuTTY\\Sessions\\' in line:
                    # Save the previous server if it had a valid host
                    if current_server and current_server.get('host'):
                        servers.append(current_server)

                    # Extract session name and decode spaces (e.g., My%20Server -> My Server)
                    session_part = line.split('\\PuTTY\\Sessions\\')[-1].rstrip(']')
                    session_name = urllib.parse.unquote(session_part)

                    # Skip PuTTY's default configuration template
                    if not session_name or session_name.lower() == "default settings":
                        current_server = None
                        continue

                    current_server = {
                        "name": session_name,
                        "host": "",
                        "user": "",
                        "port": "22",
                        "port_forwards": [],
                        "auto_sequence": []
                    }
                else:
                    # If it's some other registry key, save our current server and move on
                    if current_server and current_server.get('host'):
                        servers.append(current_server)
                    current_server = None

            elif current_server is not None:
                # Extract the connection properties
                if line.startswith('"HostName"='):
                    raw_host = line.split('=', 1)[1].strip('"')
                    # PuTTY sometimes saves the user inside the host (user@192.168.1.1)
                    if '@' in raw_host:
                        user_part, host_part = raw_host.split('@', 1)
                        current_server['user'] = user_part
                        current_server['host'] = host_part
                    else:
                        current_server['host'] = raw_host

                elif line.startswith('"UserName"='):
                    user_val = line.split('=', 1)[1].strip('"')
                    if user_val: 
                        current_server['user'] = user_val

                elif line.startswith('"PortNumber"='):
                    # Convert Hexadecimal DWORD to standard Port (e.g., 00000016 -> 22)
                    try:
                        hex_val = line.split('dword:')[1]
                        current_server['port'] = str(int(hex_val, 16))
                    except (IndexError, ValueError):
                        pass

                elif line.startswith('"PortForwardings"='):
                    # PuTTY Format: "L8080=127.0.0.1:80,D9090=,R2222=192.168.1.5:22"
                    pf_string = line.split('=', 1)[1].strip('"')
                    if pf_string:
                        rules = pf_string.split(',')
                        for rule in rules:
                            try:
                                if not rule: continue
                                
                                type_char = rule[0].upper() # L, R, or D
                                
                                if type_char == 'D':
                                    # Dynamic rules look like "D3000" or "D3000="
                                    src_port = int(rule[1:].strip('='))
                                    current_server['port_forwards'].append({
                                        "type": "Dynamic",
                                        "source_port": src_port,
                                        "dest_host": "localhost",
                                        "dest_port": 0
                                    })
                                elif type_char in ['L', 'R']:
                                    # Local/Remote rules look like "L8080=10.0.0.5:80"
                                    pf_type = "Local" if type_char == 'L' else "Remote"
                                    src_str, dest_str = rule[1:].split('=', 1)
                                    src_port = int(src_str)
                                    
                                    if ':' in dest_str:
                                        # Split from the right in case of weird hostname formatting
                                        dest_host, dest_port_str = dest_str.rsplit(':', 1)
                                        dest_port = int(dest_port_str)
                                        current_server['port_forwards'].append({
                                            "type": pf_type,
                                            "source_port": src_port,
                                            "dest_host": dest_host,
                                            "dest_port": dest_port
                                        })
                            except Exception as parse_err:
                                print(f"Warning: Failed to parse PuTTY port forward rule '{rule}': {parse_err}")

        # Catch the very last server in the file
        if current_server and current_server.get('host'):
            servers.append(current_server)

    except Exception as e:
        print(f"Error parsing PuTTY file: {e}")

    return servers

def parse_putty_linux(directory_path):
    """
    Parses a directory of native Linux PuTTY session files.
    Extracts Host, User, Port, and Port Forwarding Rules.
    """
    servers = []
    
    if not os.path.isdir(directory_path):
        print(f"Directory not found: {directory_path}")
        return servers

    # Iterate through every file in the selected directory
    for filename in os.listdir(directory_path):
        file_path = os.path.join(directory_path, filename)
        
        # Skip subdirectories (PuTTY doesn't use them for sessions)
        if not os.path.isfile(file_path):
            continue
            
        # In Linux PuTTY, the filename IS the URL-encoded session name
        session_name = urllib.parse.unquote(filename)
        
        # Skip the default configuration template
        if not session_name or session_name.lower() == "default settings":
            continue

        current_server = {
            "name": session_name,
            "host": "",
            "user": "",
            "port": "22",
            "port_forwards": [],
            "auto_sequence": []
        }

        try:
            # PuTTY config files are plain text on Linux
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line or '=' not in line:
                        continue
                        
                    key, val = line.split('=', 1)
                    
                    if key == "HostName":
                        # Catch the user@host edge case
                        if '@' in val:
                            user_part, host_part = val.split('@', 1)
                            current_server['user'] = user_part
                            current_server['host'] = host_part
                        else:
                            current_server['host'] = val
                            
                    elif key == "UserName":
                        if val:
                            current_server['user'] = val
                            
                    elif key == "PortNumber":
                        if val:
                            current_server['port'] = val
                            
                    elif key == "PortForwardings":
                        # Exact same logic as the Windows version!
                        if val:
                            rules = val.split(',')
                            for rule in rules:
                                try:
                                    if not rule: continue
                                    type_char = rule[0].upper()
                                    
                                    if type_char == 'D':
                                        src_port = int(rule[1:].strip('='))
                                        current_server['port_forwards'].append({
                                            "type": "Dynamic",
                                            "source_port": src_port,
                                            "dest_host": "localhost",
                                            "dest_port": 0
                                        })
                                    elif type_char in ['L', 'R']:
                                        pf_type = "Local" if type_char == 'L' else "Remote"
                                        src_str, dest_str = rule[1:].split('=', 1)
                                        src_port = int(src_str)
                                        if ':' in dest_str:
                                            dest_host, dest_port_str = dest_str.rsplit(':', 1)
                                            dest_port = int(dest_port_str)
                                            current_server['port_forwards'].append({
                                                "type": pf_type,
                                                "source_port": src_port,
                                                "dest_host": dest_host,
                                                "dest_port": dest_port
                                            })
                                except Exception as parse_err:
                                    print(f"Warning: Failed to parse Linux PuTTY port forward rule '{rule}': {parse_err}")

            # Only append the server if we actually found a Host IP/Domain
            if current_server.get('host'):
                servers.append(current_server)

        except Exception as e:
            print(f"Error reading Linux PuTTY file {filename}: {e}")

    return servers

def is_safe_sandbox_path(filename, parent_dialog):
    # CHAMELEON: If installed via Debian (.deb) or run locally, bypass the sandbox rules entirely!
    if not IS_SNAP:
        return True 

    # --- Standard Snap Sandbox Checks ---
    real_home = os.environ.get('SNAP_REAL_HOME', os.path.expanduser('~'))
    
    # 1. Fully resolve symlinks for both the target path and the home directory
    resolved_path = os.path.realpath(os.path.abspath(filename))
    resolved_home = os.path.realpath(os.path.abspath(real_home))
    
    # 2. Check if the resolved path is inside the user's real home folder
    if resolved_path.startswith(resolved_home):
        return True
        
    # 3. Allow access to USB drives and external mounts (if using removable-media plug)
    if resolved_path.startswith('/media/') or resolved_path.startswith('/mnt/') or resolved_path.startswith('/run/media/'):
        return True
        
    # If we get here, it's a restricted folder! Show the warning.
    warning = Gtk.MessageDialog(
        transient_for=parent_dialog, 
        modal=True,
        message_type=Gtk.MessageType.WARNING,
        buttons=Gtk.ButtonsType.OK,
        text="Sandbox Security Restriction"
    )
    warning.format_secondary_markup(
        "You are running the Snap version of Scarpa Connection Manager.\n\n"
        "Due to strict security sandboxing, local file access is restricted "
         f"to your home directory:\n<b>{real_home}</b>\n\n"
        "If you need full local file-system access, we recommend installing the PPA version:\n\n"
        "<tt>sudo add-apt-repository ppa:larre-b-larsson/scarpa-connection-manager\n"
        "sudo apt update\n"
        "sudo apt install scarpa-connection-manager</tt>"
    )
    warning.run()
    warning.destroy()
    
    return False
    
# --- Passphrase Hashing Helper Functions ---
def generate_salt(size=SALT_SIZE):
    """Generates a random salt as bytes."""
    return secrets.token_bytes(size)

def hash_passphrase(passphrase, salt_bytes, iterations=PBKDF2_ITERATIONS):
    """
    Hashes the passphrase using PBKDF2-HMAC-SHA256.
    Expects salt_bytes as bytes. Returns the hash as a hex string.
    """
    dk = hashlib.pbkdf2_hmac(
        'sha256',
        passphrase.encode('utf-8'), # Passphrase converted to bytes
        salt_bytes,                 # Salt as bytes
        iterations
    )
    return dk.hex()
# --- End Passphrase Hashing Helper Functions ---

# --- File Operations (load/save settings and servers) ---
def load_settings():
    """Loads application settings from JSON."""
    try:
        if os.path.exists(SETTINGS_FILE):
            with open(SETTINGS_FILE, "r") as f:
                settings_data = json.load(f)
            return settings_data
        return {}
    except Exception as ex:
        # For initial load, if settings file is corrupted or unreadable, we return empty settings
        print(f"Warning: Could not load settings from {SETTINGS_FILE}: {ex}", file=sys.stderr)
        return {}


def save_settings(settings):
    """Saves application settings to JSON."""
    try:
        # Create a copy to handle salt conversion for saving
        settings_to_save = settings.copy()
        if "master_passphrase_salt" in settings_to_save and isinstance(settings_to_save["master_passphrase_salt"], bytes):
            settings_to_save["master_passphrase_salt"] = settings_to_save["master_passphrase_salt"].hex() # Convert salt to hex string for JSON
        
        with open(SETTINGS_FILE, "w") as f:
            json.dump(settings_to_save, f, indent=4)
    except Exception as ex:
        # Display a GTK error dialog here, as save_settings might be called from various places
        # For now, print to stderr as GUI might not be ready
        print(f"Error: Could not save settings to {SETTINGS_FILE}: {ex}", file=sys.stderr)


def load_servers(passphrase): 
    """
    Decrypts ssh_servers.json.gpg and loads the server list from it.
    """
    enc_path = SERVER_FILE + ".gpg"
    if not os.path.exists(enc_path):
        return []

    tf = None # Initialize tf to None
    try:
        # Create a temp file to decrypt into
        tf = tempfile.NamedTemporaryFile("w", delete=False)
        tf.close()
        
        # --- CHAMELEON GPG LOGIC ---
        if IS_SNAP:
            gpg_cmd = [
                "gpg1", "--batch", "--yes",
                "--passphrase", passphrase,
                "--output", tf.name,
                "--decrypt", enc_path
            ]
        else:
            gpg_cmd = [
                "gpg", "--batch", "--yes",
                "--no-tty", "--pinentry-mode", "loopback",
                "--passphrase", passphrase,
                "--output", tf.name,
                "--decrypt", enc_path
            ]

        # Run GPG to decrypt the file
        result = subprocess.run(
            gpg_cmd,
            check=False,
            capture_output=True,
            text=True
        )
        # ---------------------------

        if result.returncode != 0:
            # Handle decryption failure specifically
            if os.path.exists(tf.name): # Clean up temp file on GPG error
                os.remove(tf.name)
            
            # Use a more specific error message for passphrase issues if stderr indicates it
            err_msg = result.stderr.strip()
            if "bad passphrase" in err_msg.lower() or "invalid passphrase" in err_msg.lower():
                raise ValueError("Incorrect master passphrase.")
            else:
                raise RuntimeError(f"GPG decryption failed with exit code {result.returncode}.\n\n"
                                   f"STDOUT:\n{result.stdout}\n\n"
                                   f"STDERR:\n{err_msg}") 

        # Load the data from the decrypted temp file
        with open(tf.name, "r") as f:
            data = json.load(f)
            # Ensure folder and auto_sequence defaults are set, as in your original load_servers
            for s in data:
                s.setdefault("folder", ROOT_FOLDER)
                s.setdefault("auto_sequence", [])
                s.setdefault("port_forwards", [])
        
        # Clean up the temp file
        os.remove(tf.name)
        
        return data

    except Exception as ex:
        # Clean up the temp file if an error occurred before it was removed
        if tf and os.path.exists(tf.name):
            os.remove(tf.name)

        # Re-raise the exception for ScarpaConnectionManager to handle with its _error method
        raise ex

def save_servers(servers, passphrase): # NOW REQUIRES PASSPHRASE
    """
    Serialize servers to a temp JSON, then encrypt it symmetrically with GPG.
    """
    tf = None # Initialize tf to None
    try:
        # 1) write JSON to a temp file
        tf = tempfile.NamedTemporaryFile("w", delete=False, suffix=".json")
        json.dump(servers, tf, indent=4)
        tf.flush()
        tf.close()

        # 2) encrypt with GPG → ssh_servers.json.gpg
        enc_path = SERVER_FILE + ".gpg"
        
        # --- CHAMELEON GPG LOGIC ---
        if IS_SNAP:
            gpg_cmd = [
                "gpg1", "--batch", "--yes",
                "--symmetric", "--cipher-algo", "AES256",
                "--passphrase", passphrase,
                "-o", enc_path,
                tf.name
            ]
        else:
            gpg_cmd = [
                "gpg", "--batch", "--yes",
                "--no-tty", "--pinentry-mode", "loopback",
                "--symmetric", "--cipher-algo", "AES256",
                "--passphrase", passphrase,
                "-o", enc_path,
                tf.name
            ]

        result = subprocess.run(
            gpg_cmd,
            check=False,
            capture_output=True,
            text=True
        )
        # ---------------------------

        # 3) clean up temp and any old plaintext
        os.remove(tf.name)
        if os.path.exists(SERVER_FILE): # Remove old plaintext file if it exists
            os.remove(SERVER_FILE)

        if result.returncode != 0:
            raise RuntimeError(f"GPG encryption failed with exit code {result.returncode}.\n\n"
                               f"STDOUT:\n{result.stdout}\n\n"
                               f"STDERR:\n{result.stderr.strip()}") # Strip whitespace from stderr

    except Exception as ex:
        if tf and os.path.exists(tf.name): # Clean up temp file on GPG error
            os.remove(tf.name)
        # Re-raise the exception for ScarpaConnectionManager to handle with its _error method
        raise ex

def browse_key(parent_dialog, key_entry):
    # 1. Create the FileChooser dialog
    dlg = Gtk.FileChooserDialog(
        title="Select SSH Key",
        parent=parent_dialog,
        action=Gtk.FileChooserAction.OPEN,
    )
    
    # 2. Force it to the real home directory
    real_home = os.environ.get('SNAP_REAL_HOME', os.path.expanduser('~'))
    dlg.set_current_folder(real_home)

    # 3. Add buttons
    dlg.add_buttons(
        Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
        Gtk.STOCK_OPEN,   Gtk.ResponseType.OK,
    )

    # 4. Run the dialog and wait for the user
    if dlg.run() == Gtk.ResponseType.OK:
        # User clicked Open! Grab the filename FIRST:
        filename = dlg.get_filename()
        
        # Now check if the filename they chose is safe:
        if not is_safe_sandbox_path(filename, dlg):
            dlg.destroy()
            return # It was outside the home folder, stop here!
            
        # It is safe! Update the text box:
        key_entry.set_text(filename)
        
    # Always destroy the dialog when done
    dlg.destroy()

def center(window):
    """Centers the window. Only call if window is already shown."""
    # Ensure window is not None before calling show_all or set_position
    if window:
        window.show_all()
        window.set_position(Gtk.WindowPosition.CENTER)

class SFTPWindow(Gtk.Window):
    def __init__(self, parent_win, host, port, username, password=None, private_key=None):
        super().__init__(title=f"SFTP: {username}@{host}")
        self.set_default_size(1100, 600) 
        self.set_transient_for(parent_win)
        self.set_position(Gtk.WindowPosition.CENTER_ON_PARENT)

        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.private_key = private_key
        
        self.sftp = None
        self.transport = None
        
        self.current_remote_dir = "/"
        self.current_local_dir = os.path.expanduser("~")

        self.clipboard_action = None 
        self.clipboard_files = []   
        self.clipboard_source = None 

        # --- Interactivity Trackers ---
        self.drag_cached_paths = None
        self._clearing_selection = False
        self.active_pane = "local" 
        
        # --- Task Trackers ---
        self.transfer_active = False
        self._cancel_transfer = False
        self.search_active = False
        self._cancel_search = False

        # --- Slow Double-Click Trackers ---
        self._last_click_time = 0
        self._rename_candidate_path = None
        self._rename_candidate_treeview = None
        
        # --- File Monitor Trackers ---
        self.local_monitor = None
        self._local_refresh_timeout_id = None        

        # --- Icon Engine Setup ---
        self.icon_theme = Gtk.IconTheme.get_default()
        self.yellow_folder_pixbuf = self._create_yellow_folder_pixbuf()
        self.transparent_pixbuf = self._create_transparent_pixbuf()
        self.setup_ui()
        self.connect("destroy", self.on_close)
        
        self.load_local_directory(self.current_local_dir)
        GLib.idle_add(self.connect_to_server)

    # --- CUSTOM ICON GENERATION ---
    def _create_yellow_folder_pixbuf(self):
        svg_data = b"""<svg width="16" height="16" viewBox="0 0 16 16" xmlns="http://www.w3.org/2000/svg">
            <path d="M2 2C1 2 0 3 0 4v9c0 1 1 2 2 2h12c1 0 2-1 2-2V5.5C16 4.5 15 3.5 14 3.5H7.5L5.5 2H2z" fill="#e5a50a"/>
            <path d="M0 6v7c0 1 1 2 2 2h12c1 0 2-1 2-2V6H0z" fill="#f6d32d"/>
        </svg>"""
        stream = Gio.MemoryInputStream.new_from_data(svg_data, None)
        return GdkPixbuf.Pixbuf.new_from_stream(stream, None)

    def _create_search_pixbuf(self):
        # A sleek magnifying glass colored in a bright emerald green (#2ecc71)
        svg_data = b"""<svg width="16" height="16" viewBox="0 0 16 16" xmlns="http://www.w3.org/2000/svg">
        <path d="M 6.5 1 C 3.462 1 1 3.462 1 6.5 C 1 9.538 3.462 12 6.5 12 C 7.746 12 8.896 11.583 9.805 10.893 L 13.646 14.734 C 13.842 14.93 14.158 14.93 14.354 14.734 C 14.55 14.538 14.55 14.222 14.354 14.025 L 10.537 10.209 C 11.442 9.278 12 8.016 12 6.5 C 12 3.462 9.538 1 6.5 1 Z M 6.5 3 C 8.433 3 10 4.567 10 6.5 C 10 8.433 8.433 10 6.5 10 C 4.567 10 3 8.433 3 6.5 C 3 4.567 4.567 3 6.5 3 Z" fill="#2ecc71"/>
        </svg>"""
        stream = Gio.MemoryInputStream.new_from_data(svg_data, None)
        return GdkPixbuf.Pixbuf.new_from_stream(stream, None)

    def _create_transparent_pixbuf(self):
        pixbuf = GdkPixbuf.Pixbuf.new(GdkPixbuf.Colorspace.RGB, True, 8, 16, 16)
        pixbuf.fill(0x00000000)
        return pixbuf

    def get_icon_pixbuf(self, filename, is_dir):
        if filename == "..": 
            return self.transparent_pixbuf
        if is_dir: 
            return self.yellow_folder_pixbuf
            
        content_type, _ = Gio.content_type_guess(filename, None)
        icon = Gio.content_type_get_icon(content_type)
        if icon:
            for name in icon.get_names():
                if self.icon_theme.has_icon(name):
                    try:
                        return self.icon_theme.load_icon(name, 16, 0)
                    except GLib.Error: pass
        
        try:
            return self.icon_theme.load_icon("text-x-generic", 16, 0)
        except GLib.Error:
            return self.transparent_pixbuf

    def setup_ui(self):
        css_provider = Gtk.CssProvider()
        css = b"""
        #transfer_btn_upload image { color: #2ea043; } 
        #transfer_btn_download image { color: #3794ff; } 
        #stop_btn_active image { color: #e5534b; } 
        #resume_btn_active image { color: #f39c12; } 

        .active-pane { 
            border-top: 3px solid #C0C0C0; 
            border-bottom: none; 
            border-left: none; 
            border-right: none; 
            border-radius: 0px; 
        }
        .inactive-pane { 
            border-top: 3px solid transparent; 
            border-bottom: none; 
            border-left: none; 
            border-right: none; 
            border-radius: 0px; 
        } 
       
        /* Hyperlink style for path breadcrumbs */
        .breadcrumb-btn { 
            background: transparent; 
            color: #000000; 
            font-weight: normal;
            padding: 2px 2px;
            border: none;
            box-shadow: none;
        }
        .breadcrumb-drag-hover {
            font-weight: bold;
            color: #003d82;
            text-decoration: underline;
        }        
        .breadcrumb-btn:hover { 
            text-decoration: underline;
            color: #003d82;
            background: transparent;
        }
        .breadcrumb-sep {
            color: #888888;
            font-weight: bold;
        }
        """
        css_provider.load_from_data(css)
        Gtk.StyleContext.add_provider_for_screen(
            Gdk.Screen.get_default(),
            css_provider,
            Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
        )

        main_vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        self.add(main_vbox)

        # --- GLOBAL UNIFIED TOOLBAR ---
        self.global_toolbar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        self.global_toolbar.set_border_width(4)
        main_vbox.pack_start(self.global_toolbar, False, False, 0)

        self.global_refresh_btn = Gtk.Button()
        self.global_refresh_btn.set_relief(Gtk.ReliefStyle.NONE)
        self.global_refresh_btn.set_image(Gtk.Image.new_from_icon_name("view-refresh", Gtk.IconSize.BUTTON))
        self.global_refresh_btn.set_tooltip_text("Refresh Both (Local & Remote)")
        self.global_refresh_btn.connect("clicked", self.on_global_refresh_clicked)
        self.global_toolbar.pack_start(self.global_refresh_btn, False, False, 0)

        self.mkdir_btn = Gtk.Button()
        self.mkdir_btn.set_relief(Gtk.ReliefStyle.NONE)
        self.mkdir_btn.set_image(Gtk.Image.new_from_icon_name("folder-new", Gtk.IconSize.BUTTON))
        self.mkdir_btn.set_tooltip_text("Create New Directory in Active Pane")
        self.mkdir_btn.connect("clicked", self.on_mkdir_button_clicked)
        self.global_toolbar.pack_start(self.mkdir_btn, False, False, 0)

        self.transfer_btn = Gtk.Button()
        self.transfer_btn.set_relief(Gtk.ReliefStyle.NONE) 
        self.transfer_icon = Gtk.Image.new_from_icon_name("network-transmit-receive", Gtk.IconSize.BUTTON)
        self.transfer_btn.set_image(self.transfer_icon)
        self.transfer_btn.set_sensitive(False)
        self.transfer_btn.set_tooltip_text("Select items to transfer")
        self.transfer_btn.connect("clicked", self.on_transfer_button_clicked)
        self.global_toolbar.pack_start(self.transfer_btn, False, False, 0)

        self.resume_btn = Gtk.Button()
        self.resume_btn.set_relief(Gtk.ReliefStyle.NONE)
        self.resume_btn.set_image(Gtk.Image.new_from_icon_name("media-seek-forward", Gtk.IconSize.BUTTON))
        self.resume_btn.set_tooltip_text("Resume Partial Transfer (Skips existing bytes)")
        self.resume_btn.set_sensitive(False)
        self.resume_btn.connect("clicked", self.on_resume_button_clicked)
        self.global_toolbar.pack_start(self.resume_btn, False, False, 0)

        self.stop_btn = Gtk.Button()
        self.stop_btn.set_relief(Gtk.ReliefStyle.NONE)
        self.stop_btn.set_image(Gtk.Image.new_from_icon_name("process-stop", Gtk.IconSize.BUTTON))
        self.stop_btn.set_tooltip_text("Cancel Ongoing Task")
        self.stop_btn.set_sensitive(False)
        self.stop_btn.connect("clicked", self.on_stop_button_clicked)
        self.global_toolbar.pack_start(self.stop_btn, False, False, 0)

        self.search_btn = Gtk.Button()
        self.search_btn.set_relief(Gtk.ReliefStyle.NONE)
        self.search_icon = Gtk.Image.new_from_pixbuf(self._create_search_pixbuf())
        self.search_btn.set_image(self.search_icon)
        self.search_btn.set_tooltip_text("Search recursively in Active Pane")
        self.search_btn.connect("clicked", self.on_search_button_clicked)
        self.global_toolbar.pack_start(self.search_btn, False, False, 0)

        main_vbox.pack_start(Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL), False, False, 0)

        # --- MAIN SPLIT PANES ---
        self.paned = Gtk.Paned(orientation=Gtk.Orientation.HORIZONTAL)
        main_vbox.pack_start(self.paned, True, True, 2)

        # --- LEFT PANE (LOCAL) ---
        local_vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        self.paned.pack1(local_vbox, True, False)

        local_hbox = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        local_vbox.pack_start(local_hbox, False, False, 2)

        local_scroll_bc = Gtk.ScrolledWindow()
        local_scroll_bc.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.NEVER)
        self.local_breadcrumb_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=0)
        local_scroll_bc.add(self.local_breadcrumb_box)
        local_scroll_bc.get_child().set_shadow_type(Gtk.ShadowType.NONE) 
        local_hbox.pack_start(local_scroll_bc, True, True, 0)

        self.local_liststore = Gtk.ListStore(GdkPixbuf.Pixbuf, str, str, bool, str, float, float, str)
        self.local_treeview = Gtk.TreeView(model=self.local_liststore)
        self.local_treeview.get_selection().set_mode(Gtk.SelectionMode.MULTIPLE) 
        self.local_treeview.connect("row-activated", self.on_local_row_double_clicked)
        self.local_treeview.connect("key-press-event", self.on_key_press, "local")
        self.local_treeview.connect("button-press-event", self.on_button_press, "local")
        self.local_treeview.connect("button-release-event", self.on_button_release, "local")
        self.local_treeview.get_selection().connect("changed", self.on_selection_changed, "local")

        self._add_columns(self.local_treeview, is_local=True)

        self.local_scroll_tv = Gtk.ScrolledWindow()
        self.local_scroll_tv.set_vexpand(True)
        self.local_scroll_tv.add(self.local_treeview)
        self.local_scroll_tv.get_style_context().add_class("active-pane")
        local_vbox.pack_start(self.local_scroll_tv, True, True, 0)

        # --- RIGHT PANE (REMOTE) ---
        remote_vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        self.paned.pack2(remote_vbox, True, False)

        remote_hbox = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        remote_vbox.pack_start(remote_hbox, False, False, 2)

        remote_scroll_bc = Gtk.ScrolledWindow()
        remote_scroll_bc.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.NEVER)
        self.remote_breadcrumb_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=0)
        remote_scroll_bc.add(self.remote_breadcrumb_box)
        remote_scroll_bc.get_child().set_shadow_type(Gtk.ShadowType.NONE)
        remote_hbox.pack_start(remote_scroll_bc, True, True, 0)

        self.remote_liststore = Gtk.ListStore(GdkPixbuf.Pixbuf, str, str, bool, str, float, float, str)
        self.remote_treeview = Gtk.TreeView(model=self.remote_liststore)
        self.remote_treeview.get_selection().set_mode(Gtk.SelectionMode.MULTIPLE) 
        self.remote_treeview.connect("row-activated", self.on_remote_row_double_clicked)
        self.remote_treeview.connect("key-press-event", self.on_key_press, "remote") 
        self.remote_treeview.connect("button-press-event", self.on_button_press, "remote")
        self.remote_treeview.connect("button-release-event", self.on_button_release, "remote")
        self.remote_treeview.get_selection().connect("changed", self.on_selection_changed, "remote")

        self._add_columns(self.remote_treeview, is_local=False)

        self.remote_scroll_tv = Gtk.ScrolledWindow()
        self.remote_scroll_tv.set_vexpand(True)
        self.remote_scroll_tv.add(self.remote_treeview)
        self.remote_scroll_tv.get_style_context().add_class("inactive-pane")
        remote_vbox.pack_start(self.remote_scroll_tv, True, True, 0)

        self.paned.set_position(550)

        # --- STATUS BAR ---
        self.statusbar = Gtk.Statusbar()
        self.context_id = self.statusbar.get_context_id("sftp_status")
        main_vbox.pack_start(self.statusbar, False, False, 0)

        # --- DRAG AND DROP SETUP ---
        # Target 0: Internal drag and drop between our own panes/breadcrumbs
        self.internal_target = Gtk.TargetEntry.new("text/plain", Gtk.TargetFlags.SAME_APP, 0)
        # Target 1: External drag and drop from OS file managers (Nautilus, etc.)
        self.external_target = Gtk.TargetEntry.new("text/uri-list", 0, 1)

        for tv in (self.local_treeview, self.remote_treeview):
            # Source (Dragging out of the pane)
            tv.enable_model_drag_source(Gdk.ModifierType.BUTTON1_MASK, [self.internal_target], Gdk.DragAction.COPY | Gdk.DragAction.MOVE)
            # Destination (Dropping into the main treeview pane)
            tv.enable_model_drag_dest([self.internal_target, self.external_target], Gdk.DragAction.COPY | Gdk.DragAction.MOVE)
        
        self.local_treeview.connect("drag-data-get", self.on_drag_data_get, "local")
        self.local_treeview.connect("drag-data-received", self.on_drag_data_received, "local")
        self.local_treeview.connect_after("drag-begin", self.on_drag_begin) 
        
        self.remote_treeview.connect("drag-data-get", self.on_drag_data_get, "remote")
        self.remote_treeview.connect("drag-data-received", self.on_drag_data_received, "remote")
        self.remote_treeview.connect_after("drag-begin", self.on_drag_begin)

    def _update_pane_highlight(self):
        if self.active_pane == "local":
            self.local_scroll_tv.get_style_context().remove_class("inactive-pane")
            self.local_scroll_tv.get_style_context().add_class("active-pane")
            self.remote_scroll_tv.get_style_context().remove_class("active-pane")
            self.remote_scroll_tv.get_style_context().add_class("inactive-pane")
        else:
            self.remote_scroll_tv.get_style_context().remove_class("inactive-pane")
            self.remote_scroll_tv.get_style_context().add_class("active-pane")
            self.local_scroll_tv.get_style_context().remove_class("active-pane")
            self.local_scroll_tv.get_style_context().add_class("inactive-pane")

    # --- UI HELPERS: Updated to set up breadcrumb drops ---
    def update_breadcrumbs(self, box, path, callback, pane):
        """
        Updated to pass the pane string ('local'/'remote') to add_link,
        which then sets up the buttons as drop targets.
        """
        for child in box.get_children(): box.remove(child)
        normalized_path = path.replace('\\', '/')
        parts = [p for p in normalized_path.split('/') if p]
        
        def add_link(label, target_path):
            btn = Gtk.Button(label=label)
            btn.set_relief(Gtk.ReliefStyle.NONE)
            btn.get_style_context().add_class("breadcrumb-btn")
            btn.connect("clicked", lambda w: callback(target_path))
            
            # --- Make individual breadcrumb buttons drag targets ---
            btn.drag_dest_set(Gtk.DestDefaults.ALL, [self.internal_target], Gdk.DragAction.COPY | Gdk.DragAction.MOVE)
            btn.connect("drag-data-received", self.on_breadcrumb_drop_received, target_path, pane)
            
            # --- NEW: Visual feedback signals ---
            btn.connect("drag-motion", self._on_breadcrumb_drag_motion)
            btn.connect("drag-leave", self._on_breadcrumb_drag_leave)
            
            box.pack_start(btn, False, False, 0)
            
        def add_separator():
            lbl = Gtk.Label(label="/")
            lbl.get_style_context().add_class("breadcrumb-sep")
            box.pack_start(lbl, False, False, 0)
            
        if normalized_path.startswith("/"):
            add_link("/", "/")
            
        current_path = "/" if normalized_path.startswith("/") else ""
        if not normalized_path.startswith("/") and parts:
            current_path = parts[0] + "/"
            add_link(parts[0], current_path)
            if len(parts) > 1: add_separator()
            parts = parts[1:]

        for i, part in enumerate(parts):
            current_path = os.path.join(current_path, part).replace('\\', '/')
            add_link(part, current_path)
            if i < len(parts) - 1: add_separator()
            
        box.show_all()

    def _on_breadcrumb_drag_motion(self, widget, context, x, y, time):
        # Add the bold styling when hovering
        widget.get_style_context().add_class("breadcrumb-drag-hover")
        return False # Let GTK handle the standard drag defaults as well

    def _on_breadcrumb_drag_leave(self, widget, context, time):
        # Remove the bold styling when moving away
        widget.get_style_context().remove_class("breadcrumb-drag-hover")

    # --- New Method: Handling drops on breadcrumb buttons ---
    def on_breadcrumb_drop_received(self, button, context, x, y, selection, info, time, target_path, dest_pane):
    
        button.get_style_context().remove_class("breadcrumb-drag-hover")
        # 1. Parse the dragged data (same format as treeview drops)
        data = selection.get_text()
        if not data or ":" not in data:
            context.finish(False, False, time)
            return

        source_pane, paths_str = data.split(":", 1)
        source_paths = paths_str.split("|") 
        
        # 2. Determine if move or copy (reusing the logic from treeview drops for keyboard modifiers)
        window = self.paned.get_window()
        display = Gdk.Display.get_default()
        seat = display.get_default_seat()
        pointer = seat.get_pointer()
        
        if window:
            _, _, _, state = window.get_device_position(pointer)
            if source_pane == dest_pane:
                # Same Pane:default to Move, Hold Ctrl to force Copy.
                action = 'copy' if state & Gdk.ModifierType.CONTROL_MASK else 'move'
            else:
                # Different Panes: default to Copy, Hold Shift to force Move.
                action = 'move' if state & Gdk.ModifierType.SHIFT_MASK else 'copy'
        else:
            action = 'move' if source_pane == dest_pane else 'copy'

        # 3. Fire up the engine! Use start_transfer_thread with our specific target path
        GLib.idle_add(self.set_status, f"Dropping onto parent folder: {target_path}")
        self.start_transfer_thread(source_pane, source_paths, dest_pane, target_path, action, resume=False)
        context.finish(True, False, time)

    def _add_columns(self, treeview, is_local):
        col_name = Gtk.TreeViewColumn("Filename")
        
        renderer_pixbuf = Gtk.CellRendererPixbuf()
        col_name.pack_start(renderer_pixbuf, False)
        col_name.add_attribute(renderer_pixbuf, "pixbuf", 0) 
        
        renderer_text = Gtk.CellRendererText()
        renderer_text.set_property("editable", False)
        renderer_text.connect("edited", self.on_filename_cell_edited, treeview, is_local)
        renderer_text.connect("editing-canceled", self.on_filename_editing_canceled)
        
        if is_local: self.local_text_renderer = renderer_text
        else: self.remote_text_renderer = renderer_text

        col_name.pack_start(renderer_text, True)
        col_name.add_attribute(renderer_text, "text", 1) 
        col_name.set_sort_column_id(7) 
        col_name.set_resizable(True)
        treeview.append_column(col_name)

        renderer_text_right = Gtk.CellRendererText(xalign=1.0) 
        col_size = Gtk.TreeViewColumn("Size", renderer_text_right, text=2)
        col_size.set_sort_column_id(5) 
        col_size.set_resizable(True)
        treeview.append_column(col_size)
        
        renderer_text_time = Gtk.CellRendererText()
        col_mtime = Gtk.TreeViewColumn("Last Modified", renderer_text_time, text=4)
        col_mtime.set_sort_column_id(6) 
        col_mtime.set_resizable(True)
        treeview.append_column(col_mtime)

    def format_size(self, size_bytes):
        if size_bytes <= 0: return ""
        sizes = ["B", "KB", "MB", "GB", "TB"]
        i = 0
        while size_bytes >= 1024 and i < len(sizes) - 1:
            size_bytes /= 1024.0
            i += 1
        return f"{size_bytes:.1f} {sizes[i]}"

    def format_time(self, timestamp):
        if timestamp <= 0: return ""
        return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")

    def get_sort_category(self, filename, is_dir):
        if filename == "..": return 0
        is_hidden = filename.startswith('.')
        if is_dir and not is_hidden: return 1
        if is_dir and is_hidden: return 2
        if not is_dir and not is_hidden: return 3
        return 4

    def get_selected_items(self, treeview, pane):
        model, paths = treeview.get_selection().get_selected_rows()
        items = []
        for p in paths:
            iter_ = model.get_iter(p)
            filename = model.get_value(iter_, 1)
            if filename != "..":
                if pane == "local":
                    items.append(os.path.join(self.current_local_dir, filename))
                else:
                    items.append(os.path.join(self.current_remote_dir, filename).replace('\\', '/'))
        return items

    # --- ACTION BUTTONS ---
    def on_selection_changed(self, selection, pane):
        if self._clearing_selection: return
        
        self.active_pane = pane
        self._update_pane_highlight()
        self._clearing_selection = True
        
        if pane == "local":
            self.remote_treeview.get_selection().unselect_all()
        else:
            self.local_treeview.get_selection().unselect_all()
            
        self._clearing_selection = False
        
        model, paths = selection.get_selected_rows()
        valid_count = sum(1 for p in paths if model.get_value(model.get_iter(p), 1) != "..")
        
        if valid_count > 0 and not self.transfer_active and not self.search_active:
            self.transfer_btn.set_sensitive(True)
            self.resume_btn.set_sensitive(True)
            self.resume_btn.set_name("resume_btn_active")
            
            if pane == "local":
                self.transfer_btn.set_name("transfer_btn_upload") 
                self.transfer_icon.set_from_icon_name("pan-end-symbolic", Gtk.IconSize.BUTTON)
                self.transfer_btn.set_tooltip_text(f"Upload {valid_count} item(s) to Remote")
            else:
                self.transfer_btn.set_name("transfer_btn_download")
                self.transfer_icon.set_from_icon_name("pan-start-symbolic", Gtk.IconSize.BUTTON)
                self.transfer_btn.set_tooltip_text(f"Download {valid_count} item(s) to Local")
        else:
            self.transfer_btn.set_sensitive(False)
            self.transfer_btn.set_name("") 
            self.resume_btn.set_sensitive(False)
            self.resume_btn.set_name("")
            self.transfer_icon.set_from_icon_name("network-transmit-receive", Gtk.IconSize.BUTTON)
            self.transfer_btn.set_tooltip_text("Select items to transfer")

    def on_transfer_button_clicked(self, btn):
        self._initiate_transfer(resume=False)

    def on_resume_button_clicked(self, btn):
        self._initiate_transfer(resume=True)

    def _initiate_transfer(self, resume):
        if not self.active_pane or self.transfer_active or self.search_active: return
        treeview = self.local_treeview if self.active_pane == "local" else self.remote_treeview
        dest_pane = "remote" if self.active_pane == "local" else "local"
        dest_dir = self.current_remote_dir if dest_pane == "remote" else self.current_local_dir
        
        items = self.get_selected_items(treeview, self.active_pane)
        if items:
            self.start_transfer_thread(self.active_pane, items, dest_pane, dest_dir, "copy", resume=resume)

    def on_stop_button_clicked(self, btn):
        self._cancel_transfer = True
        self._cancel_search = True
        self.set_status("Stopping active tasks...")
        self.stop_btn.set_sensitive(False)

    def on_global_refresh_clicked(self, btn):
        self.load_local_directory(self.current_local_dir)
        if self.sftp:
            self.load_remote_directory(self.current_remote_dir)
        self.set_status("Both directories refreshed.")

    def on_mkdir_button_clicked(self, btn):
        pane = self.active_pane if self.active_pane else "local"
        self.create_new_directory(pane)

    def create_new_directory(self, pane):
        base_dir = self.current_local_dir if pane == "local" else self.current_remote_dir
        treeview = self.local_treeview if pane == "local" else self.remote_treeview
        
        base_name = "Add Folder"
        new_name = base_name
        counter = 1
        
        def exists(name):
            if pane == "local":
                return os.path.exists(os.path.join(base_dir, name))
            else:
                try:
                    self.sftp.stat(f"{base_dir}/{name}".replace('//', '/'))
                    return True
                except Exception:
                    return False
        
        while exists(new_name):
            new_name = f"{base_name} ({counter})"
            counter += 1
            
        try:
            if pane == "local":
                os.mkdir(os.path.join(base_dir, new_name))
                self.load_local_directory(self.current_local_dir)
            else:
                self.sftp.mkdir(f"{base_dir}/{new_name}".replace('//', '/'))
                self.load_remote_directory(self.current_remote_dir)
        except Exception as e:
            self.set_status(f"Failed to create directory: {e}")
            return
            
        GLib.idle_add(self._select_and_edit_new_folder, treeview, new_name)

    def _select_and_edit_new_folder(self, treeview, folder_name):
        model = treeview.get_model()
        for i, row in enumerate(model):
            if row[1] == folder_name:
                path = Gtk.TreePath.new_from_indices([i])
                selection = treeview.get_selection()
                selection.unselect_all()
                selection.select_path(path)
                treeview.scroll_to_cell(path, None, False, 0, 0)
                self.trigger_inline_rename(treeview, path)
                break

    # --- RECURSIVE SEARCH ---
    def on_search_button_clicked(self, btn):
        pane = self.active_pane if self.active_pane else "local"
        base_dir = self.current_local_dir if pane == "local" else self.current_remote_dir
        self._open_search_dialog(pane, base_dir)

    def _open_search_dialog(self, pane, base_dir):
        if self.transfer_active or self.search_active:
            self.set_status("Please wait for current task to finish.")
            return

        dialog = Gtk.Dialog(title=f"Search in {pane.capitalize()}", transient_for=self, modal=True)
        dialog.add_buttons(Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL, "Search", Gtk.ResponseType.OK)
        
        box = dialog.get_content_area()
        box.set_spacing(10)
        box.set_border_width(15)
        
        label = Gtk.Label(label=f"Search recursively down from:\n<b>{base_dir}</b>")
        label.set_use_markup(True)
        label.set_halign(Gtk.Align.START)
        box.pack_start(label, False, False, 0)
        
        entry = Gtk.Entry()
        entry.set_placeholder_text("Enter filename or part of it...")
        entry.connect("activate", lambda w: dialog.response(Gtk.ResponseType.OK))
        box.pack_start(entry, True, True, 0)
        
        dialog.show_all()
        response = dialog.run()
        query = entry.get_text().strip()
        dialog.destroy()
        
        if response == Gtk.ResponseType.OK and query:
            self.start_search_thread(pane, base_dir, query)

    def start_search_thread(self, pane, base_dir, query):
        self.search_active = True
        self._cancel_search = False
        
        self.stop_btn.set_sensitive(True)
        self.stop_btn.set_name("stop_btn_active")
        self.search_btn.set_sensitive(False)
        self.transfer_btn.set_sensitive(False)
        self.resume_btn.set_sensitive(False)
        
        self.set_status(f"Searching for '{query}' in {pane}...")
        
        thread = threading.Thread(target=self._search_worker, args=(pane, base_dir, query))
        thread.daemon = True
        thread.start()

    def _search_worker(self, pane, base_dir, query):
        results = []
        query_lower = query.lower()
        try:
            if pane == "local":
                for root, dirs, files in os.walk(base_dir):
                    if self._cancel_search: break
                    for name in files + dirs:
                        if query_lower in name.lower():
                            results.append(os.path.join(root, name))
            elif pane == "remote":
                def sftp_walk(remotedir):
                    if self._cancel_search: return
                    try:
                        for entry in self.sftp.listdir_attr(remotedir):
                            if self._cancel_search: break
                            path = f"{remotedir}/{entry.filename}".replace('//', '/')
                            if query_lower in entry.filename.lower():
                                results.append(path)
                            if stat.S_ISDIR(entry.st_mode) and entry.filename not in ('.', '..'):
                                sftp_walk(path)
                    except IOError:
                        pass # Skip folders without permission
                sftp_walk(base_dir)
        except Exception as e:
            GLib.idle_add(self.set_status, f"Search error: {e}")
            
        GLib.idle_add(self._on_search_finished, results, pane, query)

    def _on_search_finished(self, results, pane, query):
        self.search_active = False
        self.stop_btn.set_sensitive(False)
        self.stop_btn.set_name("")
        self.search_btn.set_sensitive(True)
        
        # Trigger normal selection check to re-enable transfer buttons if needed
        active_tv = self.local_treeview if self.active_pane == "local" else self.remote_treeview
        self.on_selection_changed(active_tv.get_selection(), self.active_pane)
        
        if self._cancel_search:
            self.set_status("Search cancelled.")
            return
            
        self.set_status(f"Search finished: {len(results)} items found.")
        
        if not results:
            self.show_error_dialog("Search Results", f"No items found matching '{query}'.")
            return
            
        # Show Results Dialog
        dialog = Gtk.Dialog(title=f"Search Results ({len(results)} found)", transient_for=self, flags=Gtk.DialogFlags.DESTROY_WITH_PARENT)
        dialog.set_default_size(700, 400)
        dialog.add_button("Close", Gtk.ResponseType.CLOSE)
        
        liststore = Gtk.ListStore(str, str)
        for r in results:
            liststore.append([os.path.basename(r), r])
            
        treeview = Gtk.TreeView(model=liststore)
        
        renderer = Gtk.CellRendererText()
        col1 = Gtk.TreeViewColumn("Filename", renderer, text=0)
        col1.set_sort_column_id(0)
        col1.set_resizable(True)
        treeview.append_column(col1)
        
        renderer2 = Gtk.CellRendererText()
        col2 = Gtk.TreeViewColumn("Full Path", renderer2, text=1)
        col2.set_sort_column_id(1)
        col2.set_resizable(True)
        treeview.append_column(col2)
        
        # Navigate to file on double click
        def on_row_activated(tv, path, col):
            iter_ = liststore.get_iter(path)
            full_path = liststore.get_value(iter_, 1)
            target_dir = os.path.dirname(full_path)
            target_file = os.path.basename(full_path)
            
            if pane == "local":
                self.load_local_directory(target_dir)
                GLib.idle_add(self._select_item_in_treeview, self.local_treeview, target_file)
            else:
                self.load_remote_directory(target_dir.replace('\\', '/'))
                GLib.idle_add(self._select_item_in_treeview, self.remote_treeview, target_file)
                
            dialog.response(Gtk.ResponseType.CLOSE)
            
        treeview.connect("row-activated", on_row_activated)
        
        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        scroll.add(treeview)
        
        box = dialog.get_content_area()
        
        hint_label = Gtk.Label(label="<i>Double-click an item to navigate to its folder.</i>")
        hint_label.set_use_markup(True)
        hint_label.set_margin_top(5)
        hint_label.set_margin_bottom(5)
        box.pack_start(hint_label, False, False, 0)
        
        box.pack_start(scroll, True, True, 0)
        dialog.show_all()
        dialog.run()
        dialog.destroy()

    def _select_item_in_treeview(self, treeview, filename):
        model = treeview.get_model()
        for i, row in enumerate(model):
            if row[1] == filename:
                path = Gtk.TreePath.new_from_indices([i])
                selection = treeview.get_selection()
                selection.unselect_all()
                selection.select_path(path)
                treeview.scroll_to_cell(path, None, True, 0.5, 0.0)
                break

    # --- SHOW ERROR DIALOG ---
    def show_error_dialog(self, title, message):
        dialog = Gtk.MessageDialog(
            transient_for=self,
            flags=0,
            message_type=Gtk.MessageType.ERROR,
            buttons=Gtk.ButtonsType.OK,
            text=title
        )
        dialog.format_secondary_text(message)
        dialog.run()
        dialog.destroy()

    # --- INLINE RENAMING LOGIC ---
    def on_filename_editing_canceled(self, renderer):
        renderer.set_property("editable", False)

    def on_filename_cell_edited(self, renderer, path_str, new_text, treeview, is_local):
        renderer.set_property("editable", False) 
        if not new_text or new_text.strip() == "": return

        model = treeview.get_model()
        path = Gtk.TreePath.new_from_string(path_str)
        iter_ = model.get_iter(path)
        old_name = model.get_value(iter_, 1)

        if old_name == ".." or new_text == old_name: return

        base_dir = self.current_local_dir if is_local else self.current_remote_dir
        old_path = os.path.join(base_dir, old_name)
        new_path = os.path.join(base_dir, new_text)

        if not is_local:
            old_path = old_path.replace('\\', '/')
            new_path = new_path.replace('\\', '/')

        pane = "local" if is_local else "remote"
        self._execute_rename(pane, old_path, new_text)

    def trigger_inline_rename(self, treeview, path):
        renderer = self.local_text_renderer if treeview == self.local_treeview else self.remote_text_renderer
        renderer.set_property("editable", True)
        treeview.set_cursor(path, treeview.get_column(0), True)

    def _execute_rename(self, pane, old_path, new_name):
        try:
            if pane == "local":
                new_path = os.path.join(os.path.dirname(old_path), new_name)
                if os.path.exists(new_path):
                    self.show_error_dialog("Name Conflict", f"A file or folder named '{new_name}' already exists.")
                    return
            elif pane == "remote":
                old_dir = os.path.dirname(old_path).replace('\\', '/')
                new_path = f"{old_dir}/{new_name}"
                
                exists_on_remote = False
                try:
                    self.sftp.stat(new_path)
                    exists_on_remote = True
                except IOError:
                    pass
                
                if exists_on_remote:
                    self.show_error_dialog("Name Conflict", f"A file or folder named '{new_name}' already exists.")
                    return

            if pane == "local":
                os.rename(old_path, new_path)
                self.load_local_directory(self.current_local_dir)
            elif pane == "remote":
                self.sftp.rename(old_path, new_path)
                self.load_remote_directory(self.current_remote_dir)
                
            self.set_status(f"Renamed to '{new_name}'")
        except Exception as e:
            self.set_status(f"Rename failed: {e}")

    def _open_system_file(self, filepath, filename):
        self.set_status(f"Launching {filename}...")
        try:
            # Use 'gio open' (the Ubuntu/GNOME standard) to launch the file
            # DEVNULL hides any background DBus/Wayland warnings from polluting your terminal
            subprocess.Popen(
                ['gio', 'open', filepath],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
        except Exception as e:
            self.show_error_dialog("Cannot Open File", f"Failed to launch '{filename}':\n{str(e)}")

    # --- LOCAL LOGIC ---
    def load_local_directory(self, path):
        abs_path = os.path.abspath(path)
        if os.environ.get('SNAP'):
            real_home = os.environ.get('SNAP_REAL_HOME', os.path.expanduser('~'))
            # Prevent navigating "above" the home directory
            if not abs_path.startswith(real_home):
                dialog = Gtk.MessageDialog(
                    transient_for=self,
                    flags=0,
                    message_type=Gtk.MessageType.INFO,
                    buttons=Gtk.ButtonsType.OK,
                    text="Sandboxed Environment"
                )
                dialog.format_secondary_markup(
                    "You are running the Snap version of Scarpa Connection Manager.\n\n"
                    "Due to strict security sandboxing, local file access is restricted "
                    f"to your home directory:\n<b>{real_home}</b>\n\n"
                    "If you need full local file-system access, we recommend installing the PPA version:\n\n"
                    "<tt>sudo add-apt-repository ppa:larre-b-larsson/scarpa-connection-manager\n"
                    "sudo apt update\n"
                    "sudo apt install scarpa-connection-manager</tt>"
                )
                dialog.run()
                dialog.destroy()
                return # Block the navigation and stay in the current directory

        # 1. Clean up existing monitor before changing folders
        if self.local_monitor:
            self.local_monitor.cancel()
            self.local_monitor = None

        self.local_liststore.clear()
        try:
            entries = []
            
            # --- NEW FIX: Hide the ".." (Up) folder if we are at the sandbox root limit ---
            is_at_sandbox_root = False
            if os.environ.get('SNAP'):
                real_home = os.environ.get('SNAP_REAL_HOME', os.path.expanduser('~'))
                if abs_path == real_home:
                    is_at_sandbox_root = True

            # Only add the ".." folder if we are not at the very top of the system OR sandbox
            if os.path.dirname(abs_path) != abs_path and not is_at_sandbox_root: 
                entries.append({'pixbuf': self.transparent_pixbuf, 'name': '..', 'size': '', 'is_dir': True, 'mtime': '', 'raw_size': -1.0, 'raw_time': 0.0, 'sort_key': '0_..'})

            for filename in os.listdir(abs_path):
                full_path = os.path.join(abs_path, filename)
                
                # --- PREVIOUS FIX: Safely check file stats and catch Permission/Symlink Errors ---
                is_dir = False
                raw_size, raw_time = 0.0, 0.0
                try:
                    st = os.lstat(full_path)
                    is_dir = stat.S_ISDIR(st.st_mode)
                    raw_size, raw_time = float(st.st_size or 0), float(st.st_mtime or 0)
                except OSError:
                    is_dir = True 
                
                category = self.get_sort_category(filename, is_dir)
                pixbuf = self.get_icon_pixbuf(filename, is_dir)
                
                entries.append({
                    'pixbuf': pixbuf, 'name': filename, 
                    'size': self.format_size(raw_size) if not is_dir else "", 'is_dir': is_dir, 
                    'mtime': self.format_time(raw_time), 'raw_size': raw_size, 'raw_time': raw_time,
                    'sort_key': f"{category}_{filename.lower()}"
                })
                
            entries.sort(key=lambda x: x['sort_key'])
            for e in entries:
                self.local_liststore.append([e['pixbuf'], e['name'], e['size'], e['is_dir'], e['mtime'], e['raw_size'], e['raw_time'], e['sort_key']])
                
            self.current_local_dir = abs_path
            
            # --- UPDATED: Pass 'local' as the 4th argument ---
            self.update_breadcrumbs(self.local_breadcrumb_box, abs_path, self.load_local_directory, 'local')

            # 2. Setup the new File Monitor for the current directory
            gfile = Gio.File.new_for_path(abs_path)
            self.local_monitor = gfile.monitor_directory(Gio.FileMonitorFlags.NONE, None)
            self.local_monitor.connect("changed", self._on_local_file_changed)

        except Exception as e:
            self.set_status(f"Error loading local: {str(e)}")

    def _on_local_file_changed(self, monitor, file, other_file, event_type):
        # We only trigger a refresh if a file is Created, Deleted, Renamed, or Moved
        # We ignore simple "CHANGED" events to prevent UI lag during active downloads
        valid_events = [
            Gio.FileMonitorEvent.CREATED,
            Gio.FileMonitorEvent.DELETED,
            Gio.FileMonitorEvent.MOVED_IN,
            Gio.FileMonitorEvent.MOVED_OUT,
            Gio.FileMonitorEvent.RENAMED
        ]
        
        if event_type in valid_events:
            # Debounce: Cancel the previous timer if events are firing rapidly
            if self._local_refresh_timeout_id:
                GLib.source_remove(self._local_refresh_timeout_id)
            
            # Wait 500ms after the file system settles down before refreshing the UI
            self._local_refresh_timeout_id = GLib.timeout_add(500, self._do_debounced_local_refresh)

    def _do_debounced_local_refresh(self):
        self._local_refresh_timeout_id = None
        
        # Prevent refreshing if the user is currently renaming a file inline
        if self._rename_candidate_path:
            return False 
            
        # Refresh the directory silently
        if self.current_local_dir and os.path.exists(self.current_local_dir):
            self.load_local_directory(self.current_local_dir)
            
        return False # Returning False stops the GTK timeout from repeating

    def on_local_row_double_clicked(self, treeview, path, column):
        model = treeview.get_model()
        iter_ = model.get_iter(path)
        filename = model.get_value(iter_, 1)
        
        if model.get_value(iter_, 3): # If it's a directory
            new_path = os.path.dirname(self.current_local_dir) if filename == ".." else os.path.join(self.current_local_dir, filename)
            self.load_local_directory(new_path)
        else:
            # --- NEW: Use our bulletproof helper ---
            filepath = os.path.join(self.current_local_dir, filename)
            self._open_system_file(filepath, filename)

    # --- REMOTE LOGIC ---
    def connect_to_server(self):
        self.set_status("Connecting...")
        try:
            self.transport = paramiko.Transport((self.host, self.port))
            if self.private_key and os.path.exists(self.private_key):
                key = paramiko.RSAKey.from_private_key_file(self.private_key)
                self.transport.connect(username=self.username, pkey=key)
            else:
                self.transport.connect(username=self.username, password=self.password)
            self.sftp = paramiko.SFTPClient.from_transport(self.transport)
            self.current_remote_dir = self.sftp.normalize('.')
            self.load_remote_directory(self.current_remote_dir)
        except Exception as e:
            self.set_status(f"Connection failed: {str(e)}")

    # --- REMOTE LOGIC ---
    def load_remote_directory(self, path):
        if not self.sftp: return
        self.set_status(f"Loading remote {path}...")
        self.remote_liststore.clear()
        try:
            entries = []
            if path != "/":
                entries.append({'pixbuf': self.transparent_pixbuf, 'name': '..', 'size': '', 'is_dir': True, 'mtime': '', 'raw_size': -1.0, 'raw_time': 0.0, 'sort_key': '0_..'})

            for entry in self.sftp.listdir_attr(path):
                is_dir = stat.S_ISDIR(entry.st_mode)
                raw_size, raw_time = float(entry.st_size or 0), float(entry.st_mtime or 0)
                category = self.get_sort_category(entry.filename, is_dir)
                pixbuf = self.get_icon_pixbuf(entry.filename, is_dir)
                
                entries.append({
                    'pixbuf': pixbuf, 'name': entry.filename, 
                    'size': self.format_size(raw_size) if not is_dir else "", 'is_dir': is_dir, 
                    'mtime': self.format_time(raw_time), 'raw_size': raw_size, 'raw_time': raw_time,
                    'sort_key': f"{category}_{entry.filename.lower()}"
                })
                
            entries.sort(key=lambda x: x['sort_key'])
            for e in entries:
                self.remote_liststore.append([e['pixbuf'], e['name'], e['size'], e['is_dir'], e['mtime'], e['raw_size'], e['raw_time'], e['sort_key']])
                
            self.current_remote_dir = path
            
            # --- UPDATED: Pass 'remote' as the 4th argument ---
            self.update_breadcrumbs(self.remote_breadcrumb_box, path, self.load_remote_directory, 'remote')
            self.set_status("Connected.")
        except Exception as e:
            self.set_status(f"Error loading remote: {str(e)}")

    def on_remote_row_double_clicked(self, treeview, path, column):
        model = treeview.get_model()
        iter_ = model.get_iter(path)
        filename = model.get_value(iter_, 1)
        
        if model.get_value(iter_, 3): # If it's a directory
            new_path = os.path.dirname(self.current_remote_dir) if filename == ".." else os.path.join(self.current_remote_dir, filename).replace('\\', '/')
            self.load_remote_directory(new_path)
        else:
            # --- NEW: Block opening and show descriptive message ---
            self.show_error_dialog(
                "Remote File Access", 
                "Cannot open a remote file locally!\n\nPlease download the file to your local system to open or edit it, and then upload it back to the server."
            )

    # --- MOUSE CLICK & CONTEXT MENU ---
    def on_button_press(self, treeview, event, pane):
        if event.type == Gdk.EventType.BUTTON_PRESS:
            
            # --- NEW: Mouse Back Button (Navigate UP) ---
            if event.button == 8: 
                if pane == "local":
                    self.load_local_directory(os.path.dirname(self.current_local_dir))
                else:
                    new_path = os.path.dirname(self.current_remote_dir).replace('\\', '/')
                    self.load_remote_directory(new_path if new_path else "/")
                return True
                
            # --- NEW: Mouse Forward Button (Navigate INTO selected folder) ---
            elif event.button == 9: 
                model, paths = treeview.get_selection().get_selected_rows()
                if len(paths) == 1:
                    iter_ = model.get_iter(paths[0])
                    if model.get_value(iter_, 3): # If the selected item is a directory
                        filename = model.get_value(iter_, 1)
                        if pane == "local":
                            new_path = os.path.dirname(self.current_local_dir) if filename == ".." else os.path.join(self.current_local_dir, filename)
                            self.load_local_directory(new_path)
                        else:
                            new_path = os.path.dirname(self.current_remote_dir) if filename == ".." else f"{self.current_remote_dir}/{filename}".replace('//', '/')
                            self.load_remote_directory(new_path)
                return True

            # --- Existing Left Click Logic ---
            elif event.button == 1:
                path_info = treeview.get_path_at_pos(int(event.x), int(event.y))
                if path_info:
                    path = path_info[0]
                    selection = treeview.get_selection()
                    model, paths = selection.get_selected_rows()
                    
                    if len(paths) > 1 and selection.path_is_selected(path):
                        self.drag_cached_paths = paths
                    else:
                        self.drag_cached_paths = None

                    if selection.path_is_selected(path) and len(paths) == 1:
                        if event.time - self._last_click_time > 400: 
                            self._rename_candidate_path = path
                            self._rename_candidate_treeview = treeview
                    
                    self._last_click_time = event.time
                    return False
                else:
                    # --- THE FIX: User clicked the empty space! Clear the selection ---
                    # 1. Update the visual border to this pane
                    self.active_pane = pane
                    self._update_pane_highlight()
                    
                    # 2. Deselect everything in BOTH panes
                    self._clearing_selection = True
                    treeview.get_selection().unselect_all()
                    other_tv = self.remote_treeview if pane == "local" else self.local_treeview
                    other_tv.get_selection().unselect_all()
                    self._clearing_selection = False
                    
                    # 3. Manually update buttons (grey out transfer buttons)
                    self.on_selection_changed(treeview.get_selection(), pane)
                    
                    self._rename_candidate_path = None
                    return True

            # --- Existing Right Click Logic ---
            elif event.button == 3:
                path_info = treeview.get_path_at_pos(int(event.x), int(event.y))
                if path_info:
                    path = path_info[0]
                    selection = treeview.get_selection()
                    if not selection.path_is_selected(path):
                        selection.unselect_all()
                        selection.select_path(path)
                    
                    model = treeview.get_model()
                    if model.get_value(model.get_iter(path), 1) != "..":
                        self.show_context_menu(event, pane)
                else:
                    self.show_context_menu(event, pane, empty_space=True)
                return True 
                
        # --- Existing Double Click Logic ---
        elif event.type == Gdk.EventType._2BUTTON_PRESS: 
            self._rename_candidate_path = None
            return False
            
        return False

    def on_button_release(self, treeview, event, pane):
        if event.button == 1: 
            self.drag_cached_paths = None
            if self._rename_candidate_path and self._rename_candidate_treeview == treeview:
                path_info = treeview.get_path_at_pos(int(event.x), int(event.y))
                if path_info and path_info[0] == self._rename_candidate_path:
                    self.trigger_inline_rename(treeview, self._rename_candidate_path)
            self._rename_candidate_path = None 
        return False

    def show_context_menu(self, event, pane, empty_space=False):
        treeview = self.local_treeview if pane == "local" else self.remote_treeview
        selection = treeview.get_selection()
        model, paths = selection.get_selected_rows()
        selected_items = self.get_selected_items(treeview, pane)

        menu = Gtk.Menu()

        # Search functionality logic based on selection type
        search_item = Gtk.MenuItem(label="Search Here...")
        if paths and len(paths) == 1:
            iter_ = model.get_iter(paths[0])
            is_dir = model.get_value(iter_, 3)
            filename = model.get_value(iter_, 1)
            
            if is_dir:
                search_item.set_sensitive(True)
                target_dir = os.path.join(self.current_local_dir, filename) if pane == "local" else f"{self.current_remote_dir}/{filename}".replace('//', '/')
                if filename == "..":
                    target_dir = os.path.dirname(self.current_local_dir) if pane == "local" else os.path.dirname(self.current_remote_dir)
                search_item.connect("activate", lambda w: self._open_search_dialog(pane, target_dir))
            else:
                search_item.set_sensitive(False) # Greyed out if it's a file
        elif empty_space:
            search_item.set_sensitive(True)
            target_dir = self.current_local_dir if pane == "local" else self.current_remote_dir
            search_item.connect("activate", lambda w: self._open_search_dialog(pane, target_dir))
        else:
            search_item.set_sensitive(False)
            
        menu.append(search_item)
        menu.append(Gtk.SeparatorMenuItem())

        if not empty_space and paths:
            rename_item = Gtk.MenuItem(label="Rename")
            if len(paths) > 1: rename_item.set_sensitive(False) 
            else: rename_item.connect("activate", lambda w, p=paths[0]: self.trigger_inline_rename(treeview, p))
            menu.append(rename_item)

            if pane == "local":
                trash_item = Gtk.MenuItem(label="Move to Trash")
                trash_item.connect("activate", lambda w: self.start_delete_thread(pane, selected_items, permanent=False))
                menu.append(trash_item)
                
                delete_item = Gtk.MenuItem(label="Delete Permanently")
                delete_item.connect("activate", lambda w: self.start_delete_thread(pane, selected_items, permanent=True))
                menu.append(delete_item)
            else:
                delete_item = Gtk.MenuItem(label="Delete (Permanent on Remote)")
                delete_item.connect("activate", lambda w: self.start_delete_thread(pane, selected_items, permanent=True))
                menu.append(delete_item)
                
            menu.append(Gtk.SeparatorMenuItem()) 

        mkdir_item = Gtk.MenuItem(label="Create Directory")
        mkdir_item.connect("activate", lambda w: self.create_new_directory(pane))
        menu.append(mkdir_item)
        menu.append(Gtk.SeparatorMenuItem()) 
        

        if not empty_space and paths:
            if pane == "local":
                transfer_item = Gtk.MenuItem(label="Upload to Remote")
                transfer_item.connect("activate", lambda w: self.start_transfer_thread("local", selected_items, "remote", self.current_remote_dir, "copy", resume=False))
            else:
                transfer_item = Gtk.MenuItem(label="Download to Local")
                transfer_item.connect("activate", lambda w: self.start_transfer_thread("remote", selected_items, "local", self.current_local_dir, "copy", resume=False))
            menu.append(transfer_item)

        menu.show_all()
        menu.popup_at_pointer(event)

    # --- DRAG AND DROP ---
    def on_drag_begin(self, widget, context):
        self._rename_candidate_path = None 
        
        if self.drag_cached_paths:
            selection = widget.get_selection()
            for path in self.drag_cached_paths: selection.select_path(path)
            self.drag_cached_paths = None

        model, paths = widget.get_selection().get_selected_rows()
        if not paths: return
        
        num_files, num_folders = 0, 0
        for path in paths:
            if model.get_value(model.get_iter(path), 3): num_folders += 1
            else: num_files += 1

        theme = Gtk.IconTheme.get_default()
        icon_name = "text-x-generic" 
        
        if num_files == 1 and num_folders == 0: icon_name = "text-x-generic"
        elif num_folders == 1 and num_files == 0: icon_name = "folder"
        elif num_files > 1 and num_folders == 0: icon_name = "document-multiple" if theme.has_icon("document-multiple") else "edit-copy"
        elif num_folders > 1 and num_files == 0: icon_name = "folder-saved-search" if theme.has_icon("folder-saved-search") else "folder"
        else: icon_name = "folder-documents" if theme.has_icon("folder-documents") else "folder"

        Gtk.drag_set_icon_name(context, icon_name, 0, 0)

    # ── Build drag payload: serialize selected row-paths ────────────────────
    def on_drag_data_get(self, treeview, context, selection, info, time, pane):
        try:
            model, paths = treeview.get_selection().get_selected_rows()
            if not paths: return
            
            # Get the absolute paths of all selected items using our helper
            selected_items = self.get_selected_items(treeview, pane)
            if not selected_items: return
            
            # Package the source pane and paths into a single string
            # Format: "local:/path/1|/path/2" or "remote:/path/1|/path/2"
            paths_str = "|".join(selected_items)
            payload = f"{pane}:{paths_str}"
            
            # Send the payload to the drop receiver
            selection.set_text(payload, -1)
            
        except Exception as e:
            self.set_status(f"Error starting Drag & Drop: {e}")

    def on_drag_data_received(self, treeview, context, x, y, selection, info, time, dest_pane):
        # 1. Default to the pane's current directory
        base_target_dir = self.current_local_dir if dest_pane == "local" else self.current_remote_dir
        target_dir = base_target_dir

        # 2. SMART TARGETING: Did the user drop this ON a specific folder in the list?
        drop_info = treeview.get_dest_row_at_pos(x, y)
        if drop_info:
            path, position = drop_info
            model = treeview.get_model()
            iter_ = model.get_iter(path)
            is_dir = model.get_value(iter_, 3)
            filename = model.get_value(iter_, 1)
            
            # If they dropped it on a folder, make THAT folder the target destination
            if is_dir:
                if filename == "..":
                    # Dropped on the "Up" folder
                    target_dir = os.path.dirname(base_target_dir) if dest_pane == "local" else os.path.dirname(base_target_dir).replace('\\', '/')
                else:
                    # Dropped on a subfolder
                    target_dir = os.path.join(base_target_dir, filename) if dest_pane == "local" else f"{base_target_dir}/{filename}".replace('//', '/')

        # --- EXTERNAL DROP (From Ubuntu/OS File Manager) ---
        if info == 1: 
            uris = selection.get_uris()
            if not uris:
                context.finish(False, False, time)
                return
                
            source_paths = []
            for uri in uris:
                if uri.startswith("file://"):
                    path = urllib.parse.unquote(uri[7:])
                    source_paths.append(path)
            
            if source_paths:
                self.start_transfer_thread("local", source_paths, dest_pane, target_dir, "copy", resume=False)
                context.finish(True, False, time)
            else:
                context.finish(False, False, time)
            return

        # --- INTERNAL DROP (Between Left/Right panes OR inside the same pane) ---
        data = selection.get_text()
        if not data or ":" not in data:
            context.finish(False, False, time)
            return

        source_pane, paths_str = data.split(":", 1)
        source_paths = paths_str.split("|") 
        
        # 3. Determine if we are Moving or Copying based on shortcuts and panes
        window = treeview.get_window()
        display = Gdk.Display.get_default()
        seat = display.get_default_seat()
        pointer = seat.get_pointer()
        
        if window:
            _, _, _, state = window.get_device_position(pointer)
            if source_pane == dest_pane:
                # Same Pane: Default to Move (Organizing). Hold Ctrl to force Copy.
                action = 'copy' if state & Gdk.ModifierType.CONTROL_MASK else 'move'
            else:
                # Different Panes: Default to Copy (Transferring). Hold Shift to force Move.
                action = 'move' if state & Gdk.ModifierType.SHIFT_MASK else 'copy'
        else:
            action = 'move' if source_pane == dest_pane else 'copy'

        # 4. Safety Check: Prevent moving a file into the exact directory it is already in
        if source_pane == dest_pane:
            current_src_dir = self.current_local_dir if source_pane == "local" else self.current_remote_dir
            if target_dir == current_src_dir and action == 'move':
                # User dropped a file into empty space in the same folder it already lives in. Ignore.
                context.finish(False, False, time)
                return

        # Fire up the engine!
        self.start_transfer_thread(source_pane, source_paths, dest_pane, target_dir, action, resume=False)
        context.finish(True, False, time)

    # --- KEYBOARD SHORTCUTS ---
    def on_key_press(self, widget, event, source_pane):
        state = event.state & Gdk.ModifierType.MODIFIER_MASK
        ctrl_pressed = bool(state & Gdk.ModifierType.CONTROL_MASK)
        shift_pressed = bool(state & Gdk.ModifierType.SHIFT_MASK)
        keyval = event.keyval
        
        selected_items = self.get_selected_items(widget, source_pane)

        if ctrl_pressed:
            if keyval == Gdk.KEY_c and selected_items:  
                self.clipboard_action, self.clipboard_files, self.clipboard_source = 'copy', selected_items, source_pane
                self.set_status(f"Copied {len(selected_items)} item(s) from {source_pane}")
                return True
            elif keyval == Gdk.KEY_x and selected_items:  
                self.clipboard_action, self.clipboard_files, self.clipboard_source = 'cut', selected_items, source_pane
                self.set_status(f"Cut {len(selected_items)} item(s) from {source_pane}")
                return True
            elif keyval == Gdk.KEY_v and self.clipboard_files and self.clipboard_action:  
                target_dir = self.current_local_dir if source_pane == "local" else self.current_remote_dir
                self.start_transfer_thread(self.clipboard_source, self.clipboard_files, source_pane, target_dir, self.clipboard_action, resume=False)
                return True
                
        if keyval == Gdk.KEY_F2:
            model, paths = widget.get_selection().get_selected_rows()
            if paths and len(paths) == 1:
                self.trigger_inline_rename(widget, paths[0])
            return True

        if keyval == Gdk.KEY_Delete and selected_items:
            self.start_delete_thread(source_pane, selected_items, permanent=shift_pressed)
            return True
            
        return False

    # --- TRANSFER ENGINE (WITH RESUME LOGIC) ---
    def _sftp_progress_callback(self, transferred, total):
        if self._cancel_transfer:
            raise Exception("TRANSFER_CANCELLED_BY_USER")

    def _prompt_for_new_name(self, old_name):
        dialog = Gtk.Dialog(title="Rename Transfer", transient_for=self, flags=Gtk.DialogFlags.MODAL)
        dialog.add_buttons("Cancel", Gtk.ResponseType.CANCEL, "Rename", Gtk.ResponseType.OK)
        
        box = dialog.get_content_area()
        box.set_spacing(10)
        box.set_border_width(15)
        
        label = Gtk.Label(label="Enter a new name for the destination:")
        box.pack_start(label, False, False, 0)
        
        entry = Gtk.Entry()
        entry.set_text(old_name)
        box.pack_start(entry, True, True, 0)
        
        dialog.show_all()
        response = dialog.run()
        new_name = entry.get_text().strip()
        dialog.destroy()
        
        if response == Gtk.ResponseType.OK and new_name and new_name != old_name:
            return new_name
        return None

    def _wipe_path(self, pane, path):
        # Safely deletes the destination before an "Overwrite" to prevent merge conflicts
        try:
            if pane == "local":
                if os.path.isdir(path): shutil.rmtree(path)
                else: os.remove(path)
            elif pane == "remote" and self.sftp:
                remote_stat = self.sftp.stat(path)
                if stat.S_ISDIR(remote_stat.st_mode):
                    chan = self.transport.open_session()
                    chan.exec_command(f'rm -rf "{path}"')
                    chan.recv_exit_status()
                else:
                    self.sftp.remove(path)
        except Exception:
            pass # Ignore if it doesn't exist

    def start_transfer_thread(self, src_pane, src_paths, dst_pane, dst_dir, action, resume=False):
        if self.transfer_active or self.search_active:
            self.set_status("A task is already active!")
            return

        # 1. If Uploading (Local -> Remote): Check the local source files
        if src_pane == "local":
            for src_path in src_paths:
                if not is_safe_sandbox_path(src_path, self):
                    return # A file is outside the sandbox, stop the transfer!

        # 2. If Downloading (Remote -> Local): Check the local destination folder
        if dst_pane == "local":
            if not is_safe_sandbox_path(dst_dir, self):
                return # The destination folder is outside the sandbox, stop the transfer!

        # Pre-calculate destinations and check for conflicts before starting
        transfer_tasks = []
        for src_path in src_paths:
            filename = os.path.basename(src_path)
            dst_path = os.path.join(dst_dir, filename) if dst_pane == "local" else f"{dst_dir}/{filename}".replace('//', '/')

            conflict = False
            if dst_pane == "local":
                conflict = os.path.exists(dst_path)
            elif dst_pane == "remote" and self.sftp:
                try:
                    self.sftp.stat(dst_path)
                    conflict = True
                except IOError:
                    conflict = False

            # If resuming, we WANT the conflict so we can append to the file. Otherwise, ask user.
            if conflict and not resume:
                dialog = Gtk.MessageDialog(
                    transient_for=self, flags=Gtk.DialogFlags.MODAL, message_type=Gtk.MessageType.WARNING,
                    text="File Conflict Detected"
                )
                dialog.format_secondary_markup(f"An item named <b>{filename}</b> already exists in the destination.\nWhat would you like to do?")
                dialog.add_buttons("Cancel", Gtk.ResponseType.CANCEL, "Rename", Gtk.ResponseType.APPLY, "Overwrite", Gtk.ResponseType.YES)
                
                response = dialog.run()
                dialog.destroy()
                
                if response == Gtk.ResponseType.YES:
                    # Overwrite - mark it for deletion before transfer
                    transfer_tasks.append((src_path, dst_path, True))
                elif response == Gtk.ResponseType.APPLY:
                    # Rename
                    new_name = self._prompt_for_new_name(filename)
                    if new_name:
                        new_dst_path = os.path.join(dst_dir, new_name) if dst_pane == "local" else f"{dst_dir}/{new_name}".replace('//', '/')
                        transfer_tasks.append((src_path, new_dst_path, False))
                    else:
                        self.set_status("Transfer cancelled.")
                        return
                else:
                    # Cancel
                    self.set_status("Transfer cancelled.")
                    return
            else:
                transfer_tasks.append((src_path, dst_path, False))
        
        if not transfer_tasks:
            return

        self.transfer_active = True
        self._cancel_transfer = False
        
        self.stop_btn.set_sensitive(True)
        self.stop_btn.set_name("stop_btn_active")
        self.transfer_btn.set_sensitive(False)
        self.resume_btn.set_sensitive(False)
        self.search_btn.set_sensitive(False)

        mode_text = "Resuming" if resume else ("Moving" if action in ['move', 'cut'] else "Copying")
        self.set_status(f"{mode_text} {len(transfer_tasks)} item(s)...")
        
        # Note: We now pass transfer_tasks instead of src_paths/dst_dir
        thread = threading.Thread(target=self._transfer_worker, args=(src_pane, transfer_tasks, dst_pane, action, resume))
        thread.daemon = True
        thread.start()

    def _put_file(self, src_path, dst_path, resume):
        if resume:
            try:
                remote_size = self.sftp.stat(dst_path).st_size
                local_size = os.path.getsize(src_path)
                
                if 0 < remote_size < local_size:
                    with open(src_path, 'rb') as lf, self.sftp.file(dst_path, 'ab') as rf:
                        lf.seek(remote_size)
                        rf.set_pipelined(True)
                        while True:
                            if self._cancel_transfer: raise Exception("TRANSFER_CANCELLED_BY_USER")
                            chunk = lf.read(32768)
                            if not chunk: break
                            rf.write(chunk)
                    return
            except Exception:
                pass 
                
        self.sftp.put(src_path, dst_path, callback=self._sftp_progress_callback)

    def _get_file(self, src_path, dst_path, resume):
        if resume:
            try:
                local_size = os.path.getsize(dst_path) if os.path.exists(dst_path) else 0
                remote_size = self.sftp.stat(src_path).st_size
                
                if 0 < local_size < remote_size:
                    with self.sftp.file(src_path, 'rb') as rf, open(dst_path, 'ab') as lf:
                        rf.seek(local_size)
                        rf.prefetch(remote_size)
                        while True:
                            if self._cancel_transfer: raise Exception("TRANSFER_CANCELLED_BY_USER")
                            chunk = rf.read(32768)
                            if not chunk: break
                            lf.write(chunk)
                    return
            except Exception:
                pass 
        
        self.sftp.get(src_path, dst_path, callback=self._sftp_progress_callback)

    def _upload_dir(self, local_dir, remote_dir, resume):
        if self._cancel_transfer: raise Exception("TRANSFER_CANCELLED_BY_USER")
        try: self.sftp.mkdir(remote_dir)
        except IOError: pass 
        for item in os.listdir(local_dir):
            if self._cancel_transfer: raise Exception("TRANSFER_CANCELLED_BY_USER")
            l_path = os.path.join(local_dir, item)
            r_path = f"{remote_dir}/{item}"
            if os.path.isdir(l_path): self._upload_dir(l_path, r_path, resume)
            else: self._put_file(l_path, r_path, resume)

    def _download_dir(self, remote_dir, local_dir, resume):
        if self._cancel_transfer: raise Exception("TRANSFER_CANCELLED_BY_USER")
        os.makedirs(local_dir, exist_ok=True)
        for item in self.sftp.listdir_attr(remote_dir):
            if self._cancel_transfer: raise Exception("TRANSFER_CANCELLED_BY_USER")
            r_path = f"{remote_dir}/{item.filename}"
            l_path = os.path.join(local_dir, item.filename)
            if stat.S_ISDIR(item.st_mode): self._download_dir(r_path, l_path, resume)
            else: self._get_file(r_path, l_path, resume)

    def _transfer_worker(self, src_pane, transfer_tasks, dst_pane, action, resume):
        try:
            total = len(transfer_tasks)
            for idx, (src_path, dst_path, do_overwrite) in enumerate(transfer_tasks):
                if self._cancel_transfer: raise Exception("TRANSFER_CANCELLED_BY_USER")
                
                filename = os.path.basename(src_path)
                GLib.idle_add(self.set_status, f"Processing {idx+1}/{total}: {filename}...")

                # If user chose Overwrite, wipe the destination first so Python/SFTP doesn't throw a FileExistsError
                if do_overwrite and not resume:
                    self._wipe_path(dst_pane, dst_path)

                if src_pane == "local" and dst_pane == "remote":
                    if os.path.isdir(src_path):
                        self._upload_dir(src_path, dst_path, resume)
                        if action in ['move', 'cut']: shutil.rmtree(src_path)
                    else:
                        self._put_file(src_path, dst_path, resume)
                        if action in ['move', 'cut']: os.remove(src_path)

                elif src_pane == "remote" and dst_pane == "local":
                    remote_stat = self.sftp.stat(src_path)
                    if stat.S_ISDIR(remote_stat.st_mode):
                        self._download_dir(src_path, dst_path, resume)
                        if action in ['move', 'cut']:
                            chan = self.transport.open_session()
                            chan.exec_command(f'rm -rf "{src_path}"')
                            chan.recv_exit_status()
                    else:
                        self._get_file(src_path, dst_path, resume)
                        if action in ['move', 'cut']: self.sftp.remove(src_path)

                elif src_pane == "local" and dst_pane == "local":
                    if action == 'copy':
                        shutil.copytree(src_path, dst_path) if os.path.isdir(src_path) else shutil.copy2(src_path, dst_path)
                    elif action in ['move', 'cut']: shutil.move(src_path, dst_path)

                elif src_pane == "remote" and dst_pane == "remote":
                    chan = self.transport.open_session()
                    cmd = f'cp -r "{src_path}" "{dst_path}"' if action == 'copy' else f'mv "{src_path}" "{dst_path}"'
                    chan.exec_command(cmd)
                    chan.recv_exit_status()

            if action in ['cut', 'move']:
                self.clipboard_files, self.clipboard_action = [], None

            GLib.idle_add(self.set_status, f"Successfully transferred {total} item(s).")

        except Exception as e:
            if str(e) == "TRANSFER_CANCELLED_BY_USER":
                GLib.idle_add(self.set_status, "Transfer was cancelled by the user.")
            else:
                GLib.idle_add(self.set_status, f"Transfer failed: {str(e)}")
        finally:
            self.transfer_active = False
            
            def _reset_ui_after_transfer():
                self.stop_btn.set_sensitive(False)
                self.stop_btn.set_name("")
                self.search_btn.set_sensitive(True)
                self.load_local_directory(self.current_local_dir)
                self.load_remote_directory(self.current_remote_dir)
                
                active_tv = self.local_treeview if self.active_pane == "local" else self.remote_treeview
                self.on_selection_changed(active_tv.get_selection(), self.active_pane)
                
            GLib.idle_add(_reset_ui_after_transfer)

    def start_delete_thread(self, pane, paths, permanent=False):
        action_text = "Permanently deleting" if permanent or pane == "remote" else "Moving to Trash"
        self.set_status(f"{action_text} {len(paths)} item(s)...")
        thread = threading.Thread(target=self._delete_worker, args=(pane, paths, permanent))
        thread.daemon = True
        thread.start()

    def _delete_worker(self, pane, paths, permanent):
        try:
            for path in paths:
                if pane == "local":
                    if permanent:
                        if os.path.isdir(path): shutil.rmtree(path)
                        else: os.remove(path)
                    else:
                        file_to_trash = Gio.File.new_for_path(path)
                        file_to_trash.trash(None)
                elif pane == "remote":
                    remote_stat = self.sftp.stat(path)
                    if stat.S_ISDIR(remote_stat.st_mode):
                        chan = self.transport.open_session()
                        chan.exec_command(f'rm -rf "{path}"')
                        chan.recv_exit_status()
                    else:
                        self.sftp.remove(path)
                        
            GLib.idle_add(self.load_local_directory, self.current_local_dir)
            GLib.idle_add(self.load_remote_directory, self.current_remote_dir)
            
            action_done = "permanently deleted" if permanent or pane == "remote" else "moved to Trash"
            GLib.idle_add(self.set_status, f"Successfully {action_done} {len(paths)} item(s).")
        except Exception as e:
            GLib.idle_add(self.set_status, f"Delete failed: {str(e)}")

    def set_status(self, message):
        self.statusbar.push(self.context_id, message)

    def on_close(self, widget):
        # Clean up the monitor
        if self.local_monitor:
            self.local_monitor.cancel()
            self.local_monitor = None
        if self._local_refresh_timeout_id:
            GLib.source_remove(self._local_refresh_timeout_id)

        # Close connections
        if self.sftp: self.sftp.close()
        if self.transport: self.transport.close()


if HAS_SECRET:
    SECRET_SCHEMA = Secret.Schema.new("org.scarpa.ConnectionManager",
        Secret.SchemaFlags.NONE,
        {
            "application": Secret.SchemaAttributeType.STRING,
            "purpose": Secret.SchemaAttributeType.STRING
        }
    )

def get_saved_master_passphrase():
    if not HAS_SECRET:
        return None
    try:
        return Secret.password_lookup_sync(
            SECRET_SCHEMA,
            {"application": "scarpacm", "purpose": "master_passphrase"},
            None
        )
    except Exception as e:
        print(f"Failed to read from Keyring: {e}")
        return None

def save_master_passphrase(password):
    if not HAS_SECRET:
        return
    try:
        Secret.password_store_sync(
            SECRET_SCHEMA,
            {"application": "scarpacm", "purpose": "master_passphrase"},
            Secret.COLLECTION_DEFAULT,
            "SCARPA Master Passphrase",
            password,
            None
        )
    except Exception as e:
        print(f"Failed to save to Keyring: {e}")

def clear_master_passphrase():
    if not HAS_SECRET:
        return
    try:
        Secret.password_clear_sync(
            SECRET_SCHEMA,
            {"application": "scarpacm", "purpose": "master_passphrase"},
            None
        )
    except Exception as e:
        print(f"Failed to clear Keyring: {e}")

class PassphraseInputDialog(Gtk.Dialog):
    def __init__(self, parent, title, prompt_text, confirm_text=None, show_retry_message=False, show_remember_me=False, prefill_passphrase="", remember_me_active=False):
        super().__init__(
            title=title,
            transient_for=parent, 
            modal=True
        )        
        
        self.add_buttons(
            Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
            Gtk.STOCK_OK, Gtk.ResponseType.OK
        )
        self.set_default_size(350, -1)
        self.set_resizable(False)
        self.set_default_response(Gtk.ResponseType.OK)

        box = self.get_content_area()
        box.set_spacing(5)
        box.set_margin_top(10)
        box.set_margin_bottom(10)
        box.set_margin_start(10)
        box.set_margin_end(10)
        
        # Main prompt label
        lbl_prompt = Gtk.Label(label=prompt_text)
        lbl_prompt.set_halign(Gtk.Align.START)
        box.pack_start(lbl_prompt, False, False, 0)

        # Passphrase input entry (PRE-FILL LOGIC ADDED HERE)
        self.entry_pass = Gtk.Entry(visibility=False, primary_icon_name="security-high")
        if prefill_passphrase:
            self.entry_pass.set_text(prefill_passphrase)
        self.entry_pass.set_activates_default(True)
        box.pack_start(self.entry_pass, False, False, 5)

        # Confirmation field
        self.entry_confirm = None
        if confirm_text:
            lbl_confirm = Gtk.Label(label=confirm_text)
            lbl_confirm.set_halign(Gtk.Align.START)
            box.pack_start(lbl_confirm, False, False, 0)
            self.entry_confirm = Gtk.Entry(visibility=False, primary_icon_name="security-high")
            self.entry_confirm.set_activates_default(True)
            box.pack_start(self.entry_confirm, False, False, 5)

        # Remember Me Checkbox (PRE-CHECK LOGIC ADDED HERE)
        self.chk_remember = None
        if show_remember_me and HAS_SECRET:
            self.chk_remember = Gtk.CheckButton(label="Remember password")
            self.chk_remember.set_active(remember_me_active)
            box.pack_start(self.chk_remember, False, False, 5)

        # Retry error message
        self.lbl_retry_msg = Gtk.Label()
        self.lbl_retry_msg.set_markup("<span foreground='red'>Incorrect passphrase. Please try again.</span>")
        self.lbl_retry_msg.set_no_show_all(True) 
        if show_retry_message:
            self.lbl_retry_msg.show() 
        box.pack_start(self.lbl_retry_msg, False, False, 5)

        self.show_all()
 
    def get_passphrases(self):
        """Returns passphrase, confirm_passphrase, and remember_me status."""
        passphrase = self.entry_pass.get_text()
        confirm_passphrase = self.entry_confirm.get_text() if self.entry_confirm else None
        remember = self.chk_remember.get_active() if self.chk_remember else False
        return passphrase, confirm_passphrase, remember

    def show_retry_error(self):
        """Shows the retry error message."""
        self.lbl_retry_msg.show()
  
# ── Helper: Required Placeholder for VTE ────────────────────────────────────
# This function is strictly required by Vte.Terminal.spawn_async (Argument 9).
# Even though we don't use the result here, the app will crash if this is missing.
def _vte_spawn_callback(terminal, pid, error, user_data):
    pass

class ScarpaConnectionManager(Gtk.Application):
    def __init__(self):
        super().__init__(application_id=APP_ID, flags=Gio.ApplicationFlags.NON_UNIQUE)
        # Initialize log_buffer early so log() method can always write to it
        self.log_buffer = Gtk.TextBuffer() 
        self.log_text_view = None # Will be set in init_ui_elements

        # Settings are loaded immediately to check for passphrase status
        # Servers will be loaded AFTER passphrase verification in do_startup
        self.settings     = load_settings() 
        self.servers      = [] # Initialize empty, actual load happens later
        self.user_folders = self.settings.get("folders", [])
        self.subfolders   = []
        # Initialize logging parameters
        self.current_logging_enabled = False
        self.current_log_path = ""
        self.win = None # Initialize main window to None

        # load folder/server icons
        self.folder_icon = GdkPixbuf.Pixbuf.new_from_file(FOLDER_ICON)
        self.server_icon = GdkPixbuf.Pixbuf.new_from_file(SERVER_ICON)

        self.rename_timer = None 
        self.rename_path = None      # The specific path currently allowed to edit
        self.deferred_path = None    # The path waiting for the timer        

        # register actions
        for name, handler in (
            ("import",   self.on_import),
            ("export",   self.on_export),
            ("quit",     self.on_quit),
            ("add_srv",  self.on_add_server),
            ("edit_srv", self.on_edit_server),
            ("del_srv",  self.on_delete_selected),
            ("new_fld",  self.on_new_folder),
            ("ren_fld",  self.on_rename_folder),
            ("del_fld",  self.on_delete_selected),
            ("ssh",      self.on_ssh),
            ("sftp",     self.on_sftp),
            ("sftpgui",  self.on_sftpgui),
            ("about",    self.on_about),
            ("user_guide", self.on_user_guide),
            ("change_pass", self.on_change_passphrase),
            ("copy_srv", self.execute_smart_copy),
            ("paste_srv", self.execute_smart_paste), 
        ):
            act = Gio.SimpleAction.new(name, None)
            act.connect("activate", handler)
            self.add_action(act)

    def do_startup(self):
        Gtk.Application.do_startup(self)
        # Show disclaimer first thing in startup
        self._show_disclaimer_if_needed()
        
        # --- NEW PASSPHRASE MANAGEMENT AT STARTUP ---
        # First, ensure that the application's data directory exists
        os.makedirs(APP_DATA_DIR, exist_ok=True)

        # Pass None as parent for early dialogs since self.win doesn't exist yet
        # These dialogs will appear as top-level windows.
        
        # Check if master passphrase is set in settings
        if not self.settings.get("master_passphrase_hash") or \
           not self.settings.get("master_passphrase_salt"):
            # First run or passphrase not set: prompt user to set it
            self.log("First launch detected or master passphrase not set. Please set a new passphrase.")
            self.set_master_passphrase()
        else:
            # Passphrase already set: prompt user to enter it
            self.log("Master passphrase detected. Please enter it to unlock server data.")
            self.verify_master_passphrase()

        # If we failed to get/verify passphrase, self.master_passphrase will be None.
        # In that case, we should not proceed with UI activation or server loading.
        if not self.master_passphrase:
            self.quit() # Exit application if passphrase cannot be set/verified
            return

        # Now that we have the master_passphrase, attempt to load the servers
        try:
            self.servers = load_servers(self.master_passphrase)
            self.log("Server data loaded successfully.")
        except ValueError as e: # Catch specific 'Incorrect passphrase' error
            self._error(f"Failed to load server data: {e}\nPlease restart the application and try again.")
            self.servers = [] # Start with empty data if loading fails due to incorrect passphrase
            self.quit() # Quit if passphrase is wrong
            return
        except Exception as e:
            self._error(f"Failed to load server data: {e}\nApplication will start with empty data.")
            self.servers = [] # Start with empty data if loading fails for other reasons

    def show_securecrt_warning_dialog(self):
        """Shows a warning about SecureCRT encryption with a 'Don't show again' checkbox."""
        parent_window = self.win if hasattr(self, 'win') and self.win else None
        
        dialog = Gtk.MessageDialog(
            transient_for=parent_window,
            modal=True,
            message_type=Gtk.MessageType.WARNING,
            buttons=Gtk.ButtonsType.OK_CANCEL,
            text="SecureCRT Import Limitations"
        )
        
        dialog.format_secondary_markup(
            "Due to SecureCRT's proprietary encryption, <b>Expect/Send Login Actions</b> "
            "and stored passwords cannot be automatically imported.\n\n"
            "You will need to enter these details manually into your server configurations after the import completes."
        )

        # Create the acknowledgment checkbox
        check_box = Gtk.CheckButton(label="I understand, do not show this message again.")
        check_box.set_margin_top(10)
        
        # Add the checkbox to the dialog's message area
        box = dialog.get_message_area()
        box.pack_start(check_box, False, False, 0)
        dialog.show_all()

        response = dialog.run()
        
        # If they clicked OK and checked the box, save it to the settings file!
        if response == Gtk.ResponseType.OK and check_box.get_active():
            self.settings["securecrt_warning_acknowledged"] = True
            save_settings(self.settings)

        dialog.destroy()
        
        # Return True if they clicked OK to proceed, False if they clicked Cancel
        return response == Gtk.ResponseType.OK

    def _show_disclaimer_if_needed(self):
        accepted = self.settings.get("disclaimer_accepted", False)
        if accepted:
            return
    
        dlg = Gtk.Dialog(
            title="Disclaimer",
            transient_for=None,
            modal=True
        )
        dlg.add_buttons(Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
                        Gtk.STOCK_OK, Gtk.ResponseType.OK)
        dlg.set_default_response(Gtk.ResponseType.OK)
    
        # Overall dialog size (width x height in px)
        dlg.set_default_size(700, 500)
    
        box = dlg.get_content_area()
        box.set_spacing(10)
        box.set_margin_top(5)
        box.set_margin_bottom(5)
        box.set_margin_start(10)
        box.set_margin_end(10)
    
        disclaimer_text = """SCARPA Connection Manager – Legal Disclaimer
    
        This software is provided "as is", without warranty of any kind, express or implied,
        including but not limited to the warranties of merchantability, fitness for a particular
        purpose, and noninfringement. In no event shall the author or contributors be held liable
        for any claim, damages, or other liability, whether in an action of contract, tort, or
        otherwise, arising from, out of, or in connection with the software or the use or other
        dealings in the software.
        
        By installing or using this application, you acknowledge that:
        
        - You are solely responsible for any actions performed using this software.
        - You understand that SSH and SFTP connections may expose systems to security risks.
        - You agree not to hold the author liable for any data loss, system compromise, or
          unintended consequences resulting from use of this application.
    
        This software is intended for educational and administrative purposes only.
        Use at your own risk.
        
        © Bo Tomas Larsson, 2025. All rights reserved."""
    
        # Wrap the label in a scrolled window to constrain height
        label = Gtk.Label(label=disclaimer_text)
        label.set_line_wrap(True)
        label.set_justify(Gtk.Justification.LEFT)
        label.set_xalign(0)  # left-align text horizontally
    
        scroller = Gtk.ScrolledWindow()
        scroller.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        scroller.set_min_content_height(180)   # visible height for text area
        scroller.set_min_content_width(460)    # width inside the dialog
        scroller.add(label)
    
        box.pack_start(scroller, True, True, 0)
    
        checkbox = Gtk.CheckButton(label="I accept the terms")
        box.pack_start(checkbox, False, False, 0)
    
        dlg.show_all()
        while True:
            resp = dlg.run()
            if resp != Gtk.ResponseType.OK:
                dlg.destroy()
                Gtk.main_quit()
                sys.exit(0)
            if not checkbox.get_active():
                self._error("You must accept the terms to use this application.")
                continue
            break
    
        dlg.destroy()
        self.settings["disclaimer_accepted"] = True
        save_settings(self.settings)

    def do_activate(self):
        # main window + header bar
        if not hasattr(self, 'win') or not self.win: # Prevent recreating window on subsequent activations
            self.win = Gtk.ApplicationWindow(application=self)
            self.win.set_default_size(700, 500)
            self.win.set_title(APP_TITLE)
            hb = Gtk.HeaderBar(show_close_button=True, title=APP_TITLE)
            self.win.set_titlebar(hb)

            # layout: menubar + paned
            vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
            self.win.add(vbox)

            self.init_ui_elements(vbox) # Call helper method for UI setup

        # Only show window if master_passphrase was successfully set/verified
        if self.master_passphrase:
            self.win.show_all()
            self.populate_tree() # Ensure tree is populated after servers are loaded
            self.tree.expand_row(Gtk.TreePath.new_from_string("0"), False)
        else:
            # If passphrase failed, quit() was called in do_startup, but destroy window if still exists
            if hasattr(self, 'win') and self.win:
                self.win.destroy()

    def init_ui_elements(self, vbox):
        # This method creates all GUI elements AFTER the main window (self.win) is available.

        # ── Menu Bar ─────────────────────────────────────────────
        menu_bar = Gtk.MenuBar()
        vbox.pack_start(menu_bar, False, False, 0)
        menus = {
            "File":    [
                ("Import…", self.on_import),
                ("Export…", self.on_export),
                ("Default Settings…", self.on_global_settings),                
                ("Change Passphrase…", self.on_change_passphrase),
                ("Quit",    self.on_quit),
            ],
            "Servers": [
                ("Add",    self.on_add_server),
                ("Edit",   self.on_edit_server),
                ("Delete", self.on_delete_selected),
                ("Copy",   self.execute_smart_copy),
                ("Paste",  self.execute_smart_paste),
            ],
            "Folders": [
                ("Add",    self.on_new_folder),
                ("Rename", self.on_rename_folder),
                ("Delete", self.on_delete_selected),
                ("Copy",   self.execute_smart_copy),  
                ("Paste",  self.execute_smart_paste), 
            ],
            "Connect": [
                ("SSH",  self.on_ssh),
                ("SFTP (CLI)", self.on_sftp),
                ("SFTP (GUI)", self.on_sftpgui),
            ],
            "Help": [
                ("About", self.on_about),
                ("User Guide", self.on_user_guide),
                ("Reset Disclaimer", self.on_reset_disclaimer),
            ],
        }
        for top, items in menus.items():
            root = Gtk.MenuItem(label=top)
            submenu = Gtk.Menu()
            root.set_submenu(submenu)
        
            if top == "Servers":
                # Store refs so we can enable/disable later
                self.servers_menu_items = {}
                for lbl, fn in items:
                    mi = Gtk.MenuItem(label=lbl)
                    mi.connect("activate", lambda w, f=fn: f(None, None))
                    submenu.append(mi)
                    self.servers_menu_items[lbl] = mi
            else:
                for lbl, fn in items:
                    if lbl == "-":
                        # If it sees a dash, it draws a clean horizontal line
                        submenu.append(Gtk.SeparatorMenuItem())
                    else:
                        mi = Gtk.MenuItem(label=lbl)
                        mi.connect("activate", lambda w, f=fn: f(None, None))
                        submenu.append(mi)        

            menu_bar.append(root)

        # ── Paned: TreeView + Log ─────────────────────────────────
        paned = Gtk.Paned(orientation=Gtk.Orientation.VERTICAL)
        vbox.pack_start(paned, True, True, 0)

        # TreeStore: icon, text, metadata
        self.store = Gtk.TreeStore(GdkPixbuf.Pixbuf, str, object)
        self.reload_folders() # This should be called *after* servers are loaded if it relies on them

        # TreeView with Pixbuf + Text
        self.tree = Gtk.TreeView(model=self.store)
        self.tree.set_headers_visible(False)

        # ── enable drag-and-drop within this TreeView ───────────────
        dnd_target = Gtk.TargetEntry.new("dnd-row", Gtk.TargetFlags.SAME_WIDGET, 0)
        self.tree.enable_model_drag_source(
            Gdk.ModifierType.BUTTON1_MASK,
            [dnd_target],
            Gdk.DragAction.MOVE,
        )
        self.tree.enable_model_drag_dest(
            [dnd_target],
            Gdk.DragAction.MOVE,
        )
        # supply the drag payload (selected row-paths)
        self.tree.connect("drag-data-get",       self.on_drag_data_get)
        self.tree.connect("drag-data-received",  self.on_tree_row_dropped)
        self.tree.connect("drag-begin",          self.on_drag_begin)
        self.tree.connect("key-press-event", self.on_tree_key_press)

        # Cell renderers & column with inline‐rename for folders
        pix_renderer = Gtk.CellRendererPixbuf()
        txt_renderer = Gtk.CellRendererText()

        txt_renderer.set_property("editable", False)
        txt_renderer.connect("edited", self._on_cell_edited)

        txt_renderer.connect("editing-canceled", self._on_editing_canceled)

        col = Gtk.TreeViewColumn()
        col.pack_start(pix_renderer, False)
        col.pack_start(txt_renderer, True)

        col.add_attribute(pix_renderer, "pixbuf", 0)
        col.add_attribute(txt_renderer, "text",   1)

        # Only folder rows (not Session root) become editable
        col.set_cell_data_func(txt_renderer, self._cell_data_func)

        self.tree.append_column(col)
        self.tree.connect("row-activated", self.on_tree_activate)
        self.tree.add_events(Gdk.EventMask.BUTTON_PRESS_MASK)
        self.tree.add_events(Gdk.EventMask.BUTTON_PRESS_MASK)
        self.tree.connect("button-press-event", self.on_tree_button_press)
        
        sel = self.tree.get_selection()
        
        # --- NEW: UNLOCK MULTI-SELECTION AND MOUSE DRAG-BOX ---
        sel.set_mode(Gtk.SelectionMode.MULTIPLE)
        self.tree.set_rubber_banding(False) 
        
        sel.connect("changed", self.on_tree_selection_changed)

        # pack TreeView
        tree_sw = Gtk.ScrolledWindow()
        tree_sw.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        tree_sw.add(self.tree)
        paned.pack1(tree_sw, resize=True, shrink=True)

        # ── Log pane (6 lines high) ───────────────────────────────
        # self.log_buffer is already initialized in __init__
        self.log_text_view = Gtk.TextView(buffer=self.log_buffer, editable=False) # Assign to self.log_text_view
        self.log_text_view.set_wrap_mode(Gtk.WrapMode.NONE)
        ctx    = self.log_text_view.get_pango_context() # Use self.log_text_view
        layout = Pango.Layout.new(ctx)
        layout.set_text("X", -1)
        _, line_h = layout.get_pixel_size()

        log_sw = Gtk.ScrolledWindow()
        log_sw.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        log_sw.set_size_request(-1, line_h * 6)
        log_sw.set_vexpand(False)
        log_sw.add(self.log_text_view) # Use self.log_text_view

        log_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2, margin=6)
        lbl = Gtk.Label(label="Log:")
        lbl.set_xalign(0)
        log_box.pack_start(lbl, False, False, 0)
        log_box.pack_start(log_sw, False, False, 0)
        paned.pack2(log_box, resize=False, shrink=False)

    def on_tree_selection_changed(self, selection):
        """Updates UI state when selection changes, fully supporting Multiple Selection"""
        model, paths = selection.get_selected_rows()
        
        # If nothing is selected, or if we have MULTIPLE items selected, 
        # we don't need to trigger the single-item rename/connect logic.
        if not paths or len(paths) > 1:
            return
            
        # If exactly ONE item is selected, we can read it safely
        try:
            tree_iter = model.get_iter(paths[0])
            row_data = model.get_value(tree_iter, 2)
            if row_data and len(row_data) >= 2:
                typ, item = row_data[0], row_data[1]
                # (If you have any toolbar buttons to enable/disable based on selection, 
                # they would be updated here!)
        except Exception as e:
            self.log(f"Selection error: {e}")

    def execute_smart_copy(self, widget=None, data=None, action="copy"):
        """Universal Copy/Cut handling multiple items"""
        selection = self.tree.get_selection()
        model, paths = selection.get_selected_rows()
        if not paths: return
        
        items_to_copy = []
        for path in paths:
            tree_iter = model.get_iter(path)
            row_data = model.get_value(tree_iter, 2)
            if not row_data or len(row_data) < 2: continue
            
            typ, item = row_data[0], row_data[1]
            actual_data = self.servers[item] if isinstance(item, int) else item
            
            items_to_copy.append({
                "type": typ,
                "data": copy.deepcopy(actual_data),
                "ref": actual_data
            })
            
        self._app_clipboard = {"action": action, "items": items_to_copy}
        self.log(f"{action.capitalize()}ed {len(items_to_copy)} item(s).")

    def execute_smart_cut(self, widget=None, data=None):
        self.execute_smart_copy(widget, data, action="cut")

    def execute_smart_paste(self, widget=None, data=None):
        """Universal Paste handling multiple items simultaneously"""
        selection = self.tree.get_selection()
        model, paths = selection.get_selected_rows()
        if not paths: return
            
        # The Paste destination is ALWAYS the first item you selected
        tree_iter = model.get_iter(paths[0])
        row_data = model.get_value(tree_iter, 2)
        if not row_data or len(row_data) < 2: return
            
        target_typ, target_item = row_data[0], row_data[1]
        is_target_folder = (target_typ == "folder")
        target_actual_data = self.servers[target_item] if isinstance(target_item, int) else target_item

        clip = getattr(self, '_app_clipboard', {})
        action = clip.get("action")
        items_to_paste = clip.get("items", [])
        
        if not action or not items_to_paste: return
            
        try: root_val = ROOT_FOLDER
        except NameError: root_val = "Session"
            
        target_base_path = str(target_actual_data) if is_target_folder else target_actual_data.get("folder", root_val)
        is_root_target = (target_base_path == root_val or target_base_path == "")
        clean_target = "" if is_root_target else target_base_path

        existing_names_in_target = {
            s.get("name") for s in self.servers if s.get("folder", root_val) == target_base_path
        }

        folders_to_add = []
        folders_to_remove = []

        # Batch process all items in the clipboard
        for clip_item in items_to_paste:
            c_type = clip_item.get("type")
            c_data = clip_item.get("data")
            c_ref = clip_item.get("ref")

            if c_type == "server":
                source_parent = c_data.get("folder", root_val)
                is_same_parent = (target_base_path == source_parent)
                
                if action == "copy":
                    new_srv = copy.deepcopy(c_data)
                    new_srv["folder"] = target_base_path if not is_root_target else root_val
                    
                    base_name = c_data.get('name', 'Server')
                    
                    # --- FIX: Strip off existing numbers so it counts cleanly ---
                    clean_base = re.sub(r'\s*\(\d+\)$', '', base_name)
                    
                    final_name = base_name
                    if final_name in existing_names_in_target:
                        counter = 1
                        final_name = f"{clean_base} ({counter})"
                        while final_name in existing_names_in_target:
                            counter += 1
                            final_name = f"{clean_base} ({counter})"
                        
                    new_srv["name"] = final_name
                    if "uuid" in new_srv:
                        new_srv["uuid"] = str(uuid.uuid4())
                        
                    self.servers.append(new_srv)
                    existing_names_in_target.add(final_name) # Ensure next item sees this new name!
                    
                elif action == "cut":
                    if is_same_parent: continue

                    base_name = c_data.get('name', 'Server')
                    
                    # --- FIX: Strip off existing numbers so it counts cleanly ---
                    clean_base = re.sub(r'\s*\(\d+\)$', '', base_name)

                    final_name = base_name
                    if final_name in existing_names_in_target:
                        counter = 1
                        final_name = f"{clean_base} ({counter})"
                        while final_name in existing_names_in_target:
                            counter += 1
                            final_name = f"{clean_base} ({counter})"

                    if c_ref in self.servers:
                        c_ref["name"] = final_name
                        c_ref["folder"] = target_base_path if not is_root_target else root_val
                        existing_names_in_target.add(final_name)

            elif c_type == "folder":
                source_path = str(c_data)
                source_name = source_path.split("/")[-1]
                source_parent = "/".join(source_path.split("/")[:-1]) if "/" in source_path else root_val
                
                if clean_target == source_path or clean_target.startswith(source_path + "/"): continue
                if action == "cut" and clean_target == source_parent: continue

                def build_full_path(fname): return fname if is_root_target else f"{clean_target}/{fname}"

                # --- FIX: Strip off existing numbers for folders too ---
                clean_base = re.sub(r'\s*\(\d+\)$', '', source_name)

                if action == "copy":
                    final_name = source_name
                    if build_full_path(final_name) in self.user_folders or build_full_path(final_name) in folders_to_add:
                        counter = 1
                        final_name = f"{clean_base} ({counter})"
                        while build_full_path(final_name) in self.user_folders or build_full_path(final_name) in folders_to_add:
                            counter += 1
                            final_name = f"{clean_base} ({counter})"
                    final_base = build_full_path(final_name)
                    
                elif action == "cut":
                    final_name = source_name
                    if (build_full_path(final_name) in self.user_folders or build_full_path(final_name) in folders_to_add) and build_full_path(final_name) != source_path:
                        counter = 1
                        final_name = f"{clean_base} ({counter})"
                        while (build_full_path(final_name) in self.user_folders or build_full_path(final_name) in folders_to_add) and build_full_path(final_name) != source_path:
                            counter += 1
                            final_name = f"{clean_base} ({counter})"
                    final_base = build_full_path(final_name)

                for uf in self.user_folders:
                    if uf.startswith(source_path + "/"):
                        remainder = uf[len(source_path):]
                        folders_to_add.append(final_base + remainder)
                        if action == "cut": folders_to_remove.append(uf)

                if action == "cut" and source_path not in folders_to_remove:
                    folders_to_remove.append(source_path)
                folders_to_add.append(final_base)

                for s in self.servers:
                    s_folder = s.get("folder", "")
                    if s_folder == source_path or s_folder.startswith(source_path + "/"):
                        remainder = s_folder[len(source_path):]
                        new_fld = final_base + remainder
                        if action == "copy":
                            ns = copy.deepcopy(s)
                            ns["folder"] = new_fld
                            if "uuid" in ns: ns["uuid"] = str(uuid.uuid4())
                            self.servers.append(ns)
                        elif action == "cut":
                            s["folder"] = new_fld

        # Apply queued folder removals/additions safely
        for f in set(folders_to_remove):
            if f in self.user_folders: self.user_folders.remove(f)
        for f in set(folders_to_add):
            if f not in self.user_folders: self.user_folders.append(f)

        if action == "cut": self._app_clipboard = {}
        self.log(f"Pasted {len(items_to_paste)} item(s) into '{target_base_path}'")
        self.save_state_and_reload()

    def save_state_and_reload(self):
        """Helper to cleanly save and refresh the UI"""
        try: root_val = ROOT_FOLDER
        except NameError: root_val = "Session"
        
        save_servers(self.servers, self.master_passphrase)
        all_f = {s.get("folder") for s in self.servers if s.get("folder") and s.get("folder") != root_val}
        self.user_folders = sorted(list(all_f | set(self.user_folders)), key=natural_key)
        self.settings["folders"] = self.user_folders
        save_settings(self.settings)
        self.reload_folders()
        self.populate_tree()
        self.tree.expand_row(Gtk.TreePath.new_from_string("0"), False)

    def on_tree_key_press(self, widget, event):
        """Clean Keyboard Handler fully supporting Multiple Selection"""
        try:
            state = event.state & Gdk.ModifierType.MODIFIER_MASK
            ctrl_pressed = bool(state & Gdk.ModifierType.CONTROL_MASK)
            keyval = event.keyval
            lower_keyval = Gdk.keyval_to_lower(keyval)

            selection = self.tree.get_selection()
            
            # --- CRITICAL FIX: Ask GTK for a LIST of rows, not just one! ---
            model, paths = selection.get_selected_rows()
            
            if not paths: return False
                
            # For actions that only make sense on one item (like Enter/Arrows), 
            # we just look at the first item in your selection.
            path = paths[0]
            tree_iter = model.get_iter(path)
            row_data = model.get_value(tree_iter, 2)
            
            if not row_data or len(row_data) < 2: return False
                
            typ, item = row_data[0], row_data[1]
            is_folder = (typ == "folder")

            # --- SMART CLIPBOARD ROUTING ---
            if ctrl_pressed:
                if lower_keyval == Gdk.KEY_c:
                    self.execute_smart_copy(action="copy")
                    return True
                elif lower_keyval == Gdk.KEY_x:
                    self.execute_smart_copy(action="cut")
                    return True
                elif lower_keyval == Gdk.KEY_v:
                    self.execute_smart_paste()
                    return True

            # --- DELETE ROUTING ---
            if keyval in (Gdk.KEY_Delete, Gdk.KEY_KP_Delete):
                self.on_delete_selected()
                return True

            # --- ENTER KEY ROUTING ---
            if keyval in (Gdk.KEY_Return, Gdk.KEY_KP_Enter):
                if is_folder:
                    if self.tree.row_expanded(path): self.tree.collapse_row(path)
                    else: self.tree.expand_row(path, False)
                    return True
                else:
                    self.on_ssh(None, None)
                    return True

            # --- ARROW KEY ROUTING ---
            if keyval == Gdk.KEY_Right:
                if is_folder:
                    if not self.tree.row_expanded(path):
                        self.tree.expand_row(path, False)
                        return True
                    else:
                        child_iter = model.iter_children(tree_iter)
                        if child_iter:
                            self.tree.set_cursor(model.get_path(child_iter), None, False)
                            return True
                return False

            elif keyval == Gdk.KEY_Left:
                if is_folder and self.tree.row_expanded(path):
                    self.tree.collapse_row(path)
                    return True
                else:
                    parent_iter = model.iter_parent(tree_iter)
                    if parent_iter:
                        self.tree.set_cursor(model.get_path(parent_iter), None, False)
                        return True
                return False

        except Exception as e:
            self.log(f"Keyboard error in on_tree_key_press: {type(e).__name__}: {e}")
            
        return False

    def set_master_passphrase(self):
        """Prompts user to set a new master passphrase for the first time."""
        while True:
            # Pass None as parent as self.win might not exist yet during initial startup
            dlg = PassphraseInputDialog(
                None, # Parent is None for initial dialogs before main window is created
                "Set Master Passphrase",
                "Please set a master passphrase for your server data:",
                confirm_text="Confirm passphrase:"
            )
            response = dlg.run()
            
            if response == Gtk.ResponseType.OK:
                passphrase, confirm_passphrase, _ = dlg.get_passphrases()
                
                if not passphrase:
                    self._error("Passphrase cannot be empty.")
                    dlg.destroy()
                    continue # Loop back to prompt again
                
                if passphrase != confirm_passphrase:
                    self._error("Passphrases do not match. Please try again.")
                    dlg.destroy()
                    continue # Loop back
                
                # Generate salt and hash the passphrase
                salt = generate_salt()
                hashed_passphrase = hash_passphrase(passphrase, salt)
                
                # Store the hash and salt in settings
                self.settings["master_passphrase_hash"] = hashed_passphrase
                self.settings["master_passphrase_salt"] = salt.hex() # Store salt as hex string
                save_settings(self.settings)
                
                self.master_passphrase = passphrase # Store passphrase for current session
                dlg.destroy()
                self._info("Master passphrase set successfully!")

                # --- FIX: Clear old encrypted server file if it exists on FIRST TIME SETUP ---
                encrypted_server_file = SERVER_FILE + ".gpg"
                if os.path.exists(encrypted_server_file):
                    try:
                        os.remove(encrypted_server_file)
                        self.log(f"Removed old encrypted server data file: {encrypted_server_file}")
                    except OSError as e:
                        self._error(f"Failed to remove old encrypted server data: {e}")
                # --- END FIX ---
                return

            else: # User cancelled
                dlg.destroy()
                self.master_passphrase = None 
                return

    def verify_master_passphrase(self):
        """Prompts user to verify their master passphrase."""
        
        # --- NEW: Check Keyring to prefill, BUT DON'T AUTO-LOGIN ---
        saved_pw = get_saved_master_passphrase()
        prefill_pw = saved_pw if saved_pw else ""
        is_remembered = bool(saved_pw)

        max_retries = 3
        for attempt in range(max_retries):
            dlg = PassphraseInputDialog(
                None, 
                "Enter Master Passphrase",
                "Please enter your master passphrase to unlock server data:",
                show_retry_message=(attempt > 0), 
                show_remember_me=True,
                prefill_passphrase=prefill_pw,      # <--- Pass the saved password
                remember_me_active=is_remembered    # <--- Tick the box if it was saved
            )
            response = dlg.run()
            
            if response == Gtk.ResponseType.OK:
                entered_passphrase, _, remember_me = dlg.get_passphrases()
                
                if not entered_passphrase:
                    self._error("Passphrase cannot be empty.")
                    dlg.destroy() 
                    # If they clear it, don't keep pre-filling it on the retry attempt
                    prefill_pw = "" 
                    continue

                stored_hash = self.settings.get("master_passphrase_hash")
                stored_salt_hex = self.settings.get("master_passphrase_salt")
                
                if not stored_hash or not stored_salt_hex:
                    self._error("Error: Passphrase hash or salt missing from settings.")
                    self.master_passphrase = None 
                    dlg.destroy()
                    return

                try:
                    stored_salt = bytes.fromhex(stored_salt_hex) 
                except ValueError:
                    self._error("Error: Invalid salt format in settings. Please delete settings file and restart.")
                    self.master_passphrase = None 
                    dlg.destroy()
                    return

                if hash_passphrase(entered_passphrase, stored_salt) == stored_hash:
                    self.master_passphrase = entered_passphrase 
                    
                    # --- NEW: Save or Clear Keyring based on checkbox ---
                    if remember_me:
                        save_master_passphrase(entered_passphrase)
                    else:
                        clear_master_passphrase() # If they unchecked it, delete it from OS!
                        
                    dlg.destroy()
                    self.log("Passphrase verified.") 
                    return
                else:
                    self._error("Incorrect passphrase. Please try again.")
                    dlg.destroy() 
                    prefill_pw = "" # Clear prefill so they can type a new one
            else: # User cancelled
                dlg.destroy()
                self.master_passphrase = None 
                return
        
        self._error("Maximum passphrase attempts reached. Application will quit.")
        self.master_passphrase = None

    # ── Simple Input Dialog ────────────────────────────────────────────────
    def _simple_input(self, title, prompt=None, default_text=""):
        # Make parent transient_for self.win only if self.win exists
        parent_window = self.win if hasattr(self, 'win') and self.win else None
        dlg = Gtk.Dialog(
            title=title,
            transient_for=parent_window,
            modal=True,
        )
        dlg.add_buttons(
            Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
            Gtk.STOCK_OK,     Gtk.ResponseType.OK,
        )
        dlg.set_default_size(300, 100)
        box = dlg.get_content_area()
        if prompt:
            lbl = Gtk.Label(label=prompt)
            lbl.set_margin_bottom(6)
            box.pack_start(lbl, False, False, 0)
        entry = Gtk.Entry()
        entry.set_text(default_text)
        entry.set_activates_default(True)
        box.pack_start(entry, False, False, 0)
        dlg.set_default_response(Gtk.ResponseType.OK)
        dlg.show_all()
        resp = dlg.run()
        text = entry.get_text().strip() if resp == Gtk.ResponseType.OK else ""
        dlg.destroy()
        return text

    def on_drag_begin(self, widget, context):
        """Restores multi-selection and sets a dynamic drag icon"""
        
        # 1. Cancel any pending inline renames so they don't pop up during a drag
        if getattr(self, 'rename_timer', None):
            GLib.source_remove(self.rename_timer)
            self.rename_timer = None
            self.deferred_path = None

        # 2. Restore the multi-selection if we backed it up during Mouse-Down
        backup = getattr(self, '_drag_paths_backup', None)
        if backup:
            selection = widget.get_selection()
            for p in backup: 
                selection.select_path(p)
            self._drag_paths_backup = None

        # 3. Calculate what we are dragging to set a cool custom cursor icon
        model, paths = widget.get_selection().get_selected_rows()
        if not paths: return
        
        num_servers, num_folders = 0, 0
        for path in paths:
            tree_iter = model.get_iter(path)
            row_data = model.get_value(tree_iter, 2)
            if row_data and len(row_data) >= 2:
                if row_data[0] == "folder": num_folders += 1
                elif row_data[0] == "server": num_servers += 1

        theme = Gtk.IconTheme.get_default()
        
        # Pick the best icon based on the selection
        if num_servers == 1 and num_folders == 0: 
            icon_name = "network-server" if theme.has_icon("network-server") else "text-x-generic"
        elif num_folders == 1 and num_servers == 0: 
            icon_name = "folder"
        elif num_servers > 1 and num_folders == 0: 
            icon_name = "network-workgroup" if theme.has_icon("network-workgroup") else "edit-copy"
        elif num_folders > 1 and num_servers == 0: 
            icon_name = "folder-saved-search" if theme.has_icon("folder-saved-search") else "folder"
        else: 
            icon_name = "folder-documents" if theme.has_icon("folder-documents") else "folder"

        Gtk.drag_set_icon_name(context, icon_name, 0, 0)

    # ── Build drag payload: serialize selected row-paths ────────────────────
    def on_drag_data_get(self, treeview, context, selection, info, time):
        """Builds GTK drag payload and saves a safe internal reference"""
        try:
            model, paths = treeview.get_selection().get_selected_rows()
            if not paths: return
            
            # 1. Send standard string data to keep GTK's pipeline happy and prevent silent aborts
            data = "\n".join(path.to_string() for path in paths)
            selection.set(selection.get_target(), 8, data.encode("utf-8"))
            
            # 2. Store the actual rich data in our safe internal pocket
            self._internal_drag_data = []
            for path in paths:
                tree_iter = model.get_iter(path)
                row_data = model.get_value(tree_iter, 2)
                if row_data and len(row_data) >= 2:
                    typ, item = row_data[0], row_data[1]
                    self._internal_drag_data.append({"type": typ, "path": item})
                    
        except Exception as e:
            self.log(f"Error starting D&D: {e}")

    # Quit application
    def on_quit(self, action, param):
        self.quit()

    # Rebuild the list of subfolders from servers + user_folders
    def reload_folders(self):
        folders = {s.get("folder", ROOT_FOLDER) for s in self.servers}
        folders |= set(self.user_folders)
        self.subfolders = sorted(folders - {ROOT_FOLDER})

    # Populate the TreeStore with folder and server icons
    def populate_tree(self):
        """
        Rebuild the TreeStore with full hierarchical folder nesting.
        """
        # --- 1) Capture dynamically which folders are currently expanded ---
        expanded_folders = set()
        
        # --- THE FIX: Inject our forced expansion target & ensure ALL parent branches open! ---
        if getattr(self, '_force_expand', None):
            parts = self._force_expand.split('/')
            cur = ""
            for p in parts:
                cur = f"{cur}/{p}" if cur else p
                expanded_folders.add(cur)
            self._force_expand = None
            
        if hasattr(self, 'tree') and self.tree:
            def capture_expanded(model, path, tree_iter):
                if self.tree.row_expanded(path):
                    row_data = model.get_value(tree_iter, 2)
                    if row_data and len(row_data) >= 2:
                        typ, val = row_data[0], row_data[1]
                        if typ == "folder":
                            expanded_folders.add(val)
            self.store.foreach(capture_expanded)

        # --- 2) Clear & Rebuild ---
        self.store.clear()
        
        try: root_val = ROOT_FOLDER
        except NameError: root_val = "Session"

        root_it = self.store.append(
            None,
            [self.folder_icon,
             root_val,
             ("folder", root_val)]
        )

        folder_iters = {root_val: root_it}

        # Recursive helper to build deep folder branches automatically
        def get_or_create_folder(full_path):
            if full_path in folder_iters:
                return folder_iters[full_path]
            
            if "/" in full_path:
                parent_path, basename = full_path.rsplit("/", 1)
                parent_it = get_or_create_folder(parent_path)
            else:
                parent_it = root_it
                basename = full_path
                
            new_it = self.store.append(parent_it, [self.folder_icon, basename, ("folder", full_path)])
            folder_iters[full_path] = new_it
            return new_it

        # 2a) Generate the folder hierarchy
        sorted_subs = sorted(self.subfolders, key=natural_key)
        for fld in sorted_subs:
            get_or_create_folder(fld)

        # 2b) Append servers accurately to their deeply nested folders
        # Sort servers alphabetically before appending to maintain natural order
        sorted_servers = sorted(enumerate(self.servers), key=lambda x: natural_key(x[1].get("name", "")))
        
        for i, s in sorted_servers:
            server_folder = s.get("folder", root_val)
            parent_it = get_or_create_folder(server_folder) if server_folder != root_val else root_it
            
            self.store.append(
                parent_it,
                [self.server_icon,
                 s.get("name", "Unknown Server"),
                 ("server", i)]
            )

        # --- 3) Restore expanded rows using dynamic pathing ---
        if hasattr(self, 'tree') and self.tree:
            def restore_expanded(model, path, tree_iter):
                row_data = model.get_value(tree_iter, 2)
                if row_data and len(row_data) >= 2:
                    typ, val = row_data[0], row_data[1]
                    if typ == "folder" and val in expanded_folders:
                        self.tree.expand_row(path, False)
            self.store.foreach(restore_expanded)

    # Drag-and-drop: reorder servers and assign them to folders
    def on_tree_row_dropped(self, widget, context, x, y, selection_data, info, time):
        """Handles dropping nested folder trees and servers securely with Smart Naming"""
        try:
            # 1. Retrieve the data from our safe internal pocket (ignoring the mangled selection_data)
            dragged_items = getattr(self, '_internal_drag_data', None)
            
            if not dragged_items: 
                Gtk.drag_finish(context, False, False, time)
                return False

            # 2. Precision targeting to lock onto the drop location
            drop_info = self.tree.get_dest_row_at_pos(x, y)
            
            try: root_val = ROOT_FOLDER
            except NameError: root_val = "Session"
            
            target_base_path = root_val
            
            if drop_info:
                path, position = drop_info
                tree_iter = self.store.get_iter(path)
                row_data = self.store.get_value(tree_iter, 2)
                
                if row_data and len(row_data) >= 2:
                    typ, item = row_data[0], row_data[1]
                    if typ == "folder":
                        target_base_path = str(item)
                    elif typ == "server":
                        actual_server = self.servers[item] if isinstance(item, int) else item
                        target_base_path = actual_server.get("folder", root_val)

            clean_target = "" if (target_base_path == root_val) else target_base_path
            
            servers_affected = False
            folders_affected = False

            # --- SMART LOCAL NAMING CHECK ---
            existing_names_in_target = {
                s.get("name") for s in self.servers if s.get("folder", root_val) == target_base_path
            }

            # 3. Process each dragged item
            for item in dragged_items:
                i_type = item.get("type")
                i_path = item.get("path")

                # --- DROPPING A SERVER ---
                if i_type == "server":
                    server_index = int(i_path)
                    if server_index < len(self.servers):
                        current_srv = self.servers[server_index]
                        old_folder = current_srv.get("folder", root_val)
                        
                        if target_base_path != old_folder:
                            base_name = current_srv.get("name", "Unknown Server")
                            final_name = base_name
                            
                            if final_name in existing_names_in_target:
                                counter = 1
                                while f"{base_name} ({counter})" in existing_names_in_target:
                                    counter += 1
                                final_name = f"{base_name} ({counter})"
                            
                            current_srv["name"] = final_name
                            current_srv["folder"] = target_base_path
                            servers_affected = True
                            
                            existing_names_in_target.add(final_name)
                            
                            if final_name == base_name:
                                self.log(f"Moved server to '{target_base_path}'")
                            else:
                                self.log(f"Moved server to '{target_base_path}' -> renamed to '{final_name}'")

                # --- DROPPING A FOLDER ---
                elif i_type == "folder":
                    source_folder = str(i_path)
                    source_name = source_folder.split("/")[-1]
                    source_parent = "/".join(source_folder.split("/")[:-1]) if "/" in source_folder else root_val

                    if clean_target == source_folder or clean_target.startswith(source_folder + "/"):
                        self.log(f"Notice: Cannot move '{source_name}' inside itself.")
                        continue
                        
                    if clean_target == source_parent or target_base_path == source_parent:
                        continue

                    def build_full_path(folder_name):
                        return folder_name if target_base_path == root_val else f"{clean_target}/{folder_name}"

                    final_name = source_name
                    counter = 1
                    while build_full_path(final_name) in self.user_folders and build_full_path(final_name) != source_folder:
                        final_name = f"{source_name} ({counter})"
                        counter += 1
                        
                    final_base = build_full_path(final_name)
                    actual_base = final_base

                    folders_to_add = []
                    folders_to_remove = []
                    
                    for uf in self.user_folders:
                        if uf == source_folder or uf.startswith(source_folder + "/"):
                            remainder = uf[len(source_folder):]
                            folders_to_add.append(actual_base + remainder)
                            folders_to_remove.append(uf)
                    
                    for f in folders_to_remove:
                        if f in self.user_folders: self.user_folders.remove(f)
                    for f in folders_to_add:
                        if f not in self.user_folders: self.user_folders.append(f)

                    for s in self.servers:
                        s_folder = s.get("folder", root_val)
                        if s_folder == source_folder or s_folder.startswith(source_folder + "/"):
                            remainder = s_folder[len(source_folder):]
                            s["folder"] = actual_base + remainder
                            servers_affected = True
                            
                    folders_affected = True
                    self.log(f"Moved folder '{source_name}' -> '{actual_base}'")

            # 4. Clean up memory and refresh UI
            self._internal_drag_data = None 
            if servers_affected or folders_affected:
                self.save_state_and_reload()
                
            # Properly finish the GTK Drag sequence
            Gtk.drag_finish(context, True, False, time)
            return True

        except Exception as e:
            self.log(f"D&D error in on_tree_row_dropped: {type(e).__name__}: {e}")
            Gtk.drag_finish(context, False, False, time)
            
        return False

    # ── File Menu: Import Servers ───────────────────────────────────────
    def on_import(self, *args):
        """Builds and displays the Graphical Import Wizard with a Dropdown Menu"""
        dialog = Gtk.Dialog(
            title="Import Server Configurations",
            transient_for=self.win if hasattr(self, 'win') and self.win else None,
            flags=0
        )
        dialog.add_buttons(
            Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
            "Import", Gtk.ResponseType.OK
        )
        # Make the "Import" button the default action
        dialog.set_default_response(Gtk.ResponseType.OK)
        
        # Setup container layout
        box = dialog.get_content_area()
        box.set_spacing(15)
        box.set_margin_top(15)
        box.set_margin_bottom(15)
        box.set_margin_start(20)
        box.set_margin_end(20)
        
        # Instruction Label
        label = Gtk.Label(label="<b>Select the source application format:</b>")
        label.set_use_markup(True)
        label.set_halign(Gtk.Align.START)
        box.pack_start(label, False, False, 0)
        
        # Dropdown Menu (ComboBoxText)
        format_combo = Gtk.ComboBoxText()
        # append(id, text) - We use the ID later to know what was selected
        format_combo.append("scarpa", "Scarpa Connection Manager")
        format_combo.append("securecrt", "SecureCRT")
        format_combo.append("putty_win", "PuTTY Windows")
        format_combo.append("putty_linux", "PuTTY Linux")
        format_combo.append("mobaxterm", "MobaXterm")
        
        # Set the default selected item to the first one (SCARPA)
        format_combo.set_active(0)
        
        # Pack the dropdown with a slight margin
        combo_box_container = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5)
        combo_box_container.set_margin_start(10)
        combo_box_container.pack_start(format_combo, False, False, 0)
        box.pack_start(combo_box_container, False, False, 0)
        
        # File chooser row
        file_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        file_entry = Gtk.Entry()
        file_entry.set_hexpand(True)
        file_entry.set_placeholder_text("Select a file or folder to import...")
        file_entry.set_editable(False) # Force the user to use the Browse button
        
        browse_button = Gtk.Button(label="Browse...")
        
        file_box.pack_start(file_entry, True, True, 0)
        file_box.pack_start(browse_button, False, False, 0)
        box.pack_start(file_box, False, False, 5)
        
        # The Browse Button Callback (Changes filter based on dropdown selection)
        def on_browse_clicked(btn):
            selected_format = format_combo.get_active_id()
            
            # --- SMART CHOOSER LOGIC ---
            # If Linux PuTTY is selected, launch a FOLDER chooser
            if selected_format == "putty_linux":
                chooser = Gtk.FileChooserDialog(
                    title="Select PuTTY Sessions Folder",
                    parent=dialog,
                    action=Gtk.FileChooserAction.SELECT_FOLDER
                )
                chooser.add_buttons(
                    Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
                    "Select Folder", Gtk.ResponseType.OK
                )
                # Auto-navigate to the hidden PuTTY directory!
                default_putty_dir = os.path.expanduser("~/.putty/sessions")
                if os.path.isdir(default_putty_dir):
                    chooser.set_current_folder(default_putty_dir)
            
            # Otherwise, launch a standard FILE chooser
            else:
                chooser = Gtk.FileChooserDialog(
                    title="Select File to Import",
                    parent=dialog,
                    action=Gtk.FileChooserAction.OPEN
                )
                chooser.add_buttons(
                    Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
                    Gtk.STOCK_OPEN, Gtk.ResponseType.OK
                )
                
                # 1. Create the strict filter based on the dropdown
                filter_custom = Gtk.FileFilter()
                if selected_format == "scarpa":
                    filter_custom.set_name("Scarpa Connection Manager (*.json, *.gpg)")
                    filter_custom.add_pattern("*.json")
                    filter_custom.add_pattern("*.gpg")
                elif selected_format == "securecrt":
                    filter_custom.set_name("SecureCRT XML (*.xml)")
                    filter_custom.add_pattern("*.xml")
                elif selected_format == "putty_win":
                    filter_custom.set_name("PuTTY Registry (*.reg)")
                    filter_custom.add_pattern("*.reg")
                elif selected_format == "mobaxterm":
                    filter_custom.set_name("MobaXterm Config (*.mobaconf, *.ini)")
                    filter_custom.add_pattern("*.mobaconf")
                    filter_custom.add_pattern("*.ini")
                    filter_custom.add_pattern("*.mxtsessions")
                
                # Add the specific filter first (makes it the default)
                chooser.add_filter(filter_custom)
                
                # 2. Create the "All Files" fallback filter
                filter_any = Gtk.FileFilter()
                filter_any.set_name("All Files (*)")
                filter_any.add_pattern("*")
                
                # Add the wildcard filter second
                chooser.add_filter(filter_any)
            
            if chooser.run() == Gtk.ResponseType.OK:
                file_entry.set_text(chooser.get_filename())
            chooser.destroy()

        browse_button.connect("clicked", on_browse_clicked)
        
        # Show all elements
        dialog.show_all()
        
        # Wait for the user to click Import or Cancel
        response = dialog.run()
        if response == Gtk.ResponseType.OK:
            path = file_entry.get_text()
            if not path:
                self.show_error_dialog("No Selection", "Please browse for a file or folder to import.")
            else:
                # Route to the correct import backend based on the dropdown ID
                selected_format = format_combo.get_active_id()
                
                if selected_format == "scarpa":
                    self.process_scarpa_import(path)
                elif selected_format == "securecrt":
                    self.process_securecrt_import(path)
                elif selected_format == "putty_win":
                    self.process_putty_import(path)
                elif selected_format == "putty_linux":
                    self.process_putty_linux_import(path)
                elif selected_format == "mobaxterm":
                    self.process_mobaxterm_import(path)
                    
        dialog.destroy()

    # ─── IMPORT BACKENDS ───────────────────────────────────────────────────
    def process_scarpa_import(self, filename):
        """Handles native SCARPA JSON/GPG files with Interactive Auto-Renaming"""
        try:
            is_encrypted = filename.lower().endswith(".gpg")
            payload = None

            if is_encrypted:
                tf = tempfile.NamedTemporaryFile("w", delete=False)
                tf.close()
                
                if IS_SNAP:
                    gpg_cmd = [
                        "gpg1", "--batch", "--yes", 
                        "--passphrase", self.master_passphrase, 
                        "--output", tf.name, "--decrypt", filename
                    ]
                else:
                    gpg_cmd = [
                        "gpg", "--batch", "--yes", 
                        "--no-tty", "--pinentry-mode", "loopback", 
                        "--passphrase", self.master_passphrase, 
                        "--output", tf.name, "--decrypt", filename
                    ]

                result = subprocess.run(gpg_cmd, check=False, capture_output=True, text=True)
                
                if result.returncode != 0:
                    if os.path.exists(tf.name): os.remove(tf.name)
                    self._error(f"GPG decryption failed during import: {result.stderr.strip()}")
                    return

                with open(tf.name, "r") as f:
                    payload = json.load(f)
                
                os.remove(tf.name)
            else:
                with open(filename, "r") as f:
                    payload = json.load(f)

            if isinstance(payload, dict):
                imported_servers = payload.get("servers", [])
                imported_folders = payload.get("folders", [])
            elif isinstance(payload, list):
                imported_servers = payload
                imported_folders = []
            else:
                self._error("Unexpected format; must be list or dict")
                return

            # Normalize 
            for srv in imported_servers:
                srv.setdefault("folder", ROOT_FOLDER)
                srv.setdefault("auto_sequence", [])
                srv.setdefault("port_forwards", [])

            # --- INTERACTIVE DEDUPLICATION LOGIC ---
            existing_sigs = {
                (s.get("name"), s.get("host"), s.get("user"), s.get("port"), s.get("folder"))
                for s in self.servers
            }
            existing_names = { s.get("name") for s in self.servers if s.get("name") }

            unique_new_servers = []
            for srv in imported_servers:
                base_name = srv.get("name")
                
                sig = (base_name, srv.get("host"), srv.get("user"), srv.get("port"), srv.get("folder"))
                if sig in existing_sigs:
                    continue  # 100% exact copy, skip silently
                    
                new_name = base_name
                if base_name in existing_names:
                    msg = (f"A connection named '{base_name}' already exists, but the imported version "
                           f"has different settings.\n\n"
                           f"Do you want to import this as a new connection and auto-rename it?")
                           
                    wants_to_import = self.ask_yes_no_dialog("Duplicate Name Detected", msg)
                    
                    if not wants_to_import:
                        continue 
                        
                    counter = 1
                    while new_name in existing_names:
                        new_name = f"{base_name}({counter})"
                        counter += 1
                        
                srv["name"] = new_name
                unique_new_servers.append(srv)
                
                new_sig = (new_name, srv.get("host"), srv.get("user"), srv.get("port"), srv.get("folder"))
                existing_sigs.add(new_sig)
                existing_names.add(new_name)

            if not unique_new_servers:
                self.show_info_dialog("No New Servers", "No new servers were imported. They were either exact duplicates or skipped by the user.")
                return

            added = len(unique_new_servers)
            self.servers.extend(unique_new_servers) 

            try:
                save_servers(self.servers, self.master_passphrase) 
            except Exception as e:
                self._error(f"Failed to save imported servers: {e}")
                return

            # Handle Folders
            folders_from_servers = {
                srv["folder"] for srv in unique_new_servers
                if srv.get("folder") != ROOT_FOLDER
            }
            all_folders = set(imported_folders) | folders_from_servers | set(self.user_folders)
            self.user_folders = sorted(all_folders, key=natural_key)
            self.settings["folders"] = self.user_folders
            save_settings(self.settings) 

            self.reload_folders()
            self.populate_tree()
            self.tree.expand_row(Gtk.TreePath.new_from_string("0"), False)

            self.log(f"Imported {added} unique servers from '{filename}'")
            self.show_info_dialog("Import Successful", f"Successfully imported {added} SCARPA servers.")

        except Exception as e:
            traceback.print_exc()
            self._error(f"Import failed:\n{e}")

    def process_securecrt_import(self, file_path):

        if not self.settings.get("securecrt_warning_acknowledged", False):
            proceed = self.show_securecrt_warning_dialog()
            if not proceed:
                self.log("SecureCRT import cancelled by user at the warning dialog.")
                return # Stop the import if they clicked Cancel

        try:
            imported_servers = parse_securecrt_xml(file_path)
            
            if not imported_servers:
                self._error("No valid servers found in the selected XML file.")
                return
               
            for srv in imported_servers:
                srv.setdefault("auto_sequence", [])
                srv.setdefault("port_forwards", [])
                srv.setdefault("folder", ROOT_FOLDER)
                
            # --- INTERACTIVE DEDUPLICATION LOGIC ---
            existing_sigs = {
                (s.get("name"), s.get("host"), s.get("user"), s.get("port"), s.get("folder"))
                for s in self.servers
            }
            existing_names = { s.get("name") for s in self.servers if s.get("name") }

            unique_new_servers = []
            for srv in imported_servers:
                base_name = srv.get("name")
                
                sig = (base_name, srv.get("host"), srv.get("user"), srv.get("port"), srv.get("folder"))
                if sig in existing_sigs:
                    continue  # 100% exact copy, skip silently
                    
                new_name = base_name
                if base_name in existing_names:
                    msg = (f"A connection named '{base_name}' already exists, but the imported version "
                           f"has different settings.\n\n"
                           f"Do you want to import this as a new connection and auto-rename it?")
                           
                    wants_to_import = self.ask_yes_no_dialog("Duplicate Name Detected", msg)
                    
                    if not wants_to_import:
                        continue 
                        
                    counter = 1
                    while new_name in existing_names:
                        new_name = f"{base_name}({counter})"
                        counter += 1
                        
                srv["name"] = new_name
                unique_new_servers.append(srv)
                
                new_sig = (new_name, srv.get("host"), srv.get("user"), srv.get("port"), srv.get("folder"))
                existing_sigs.add(new_sig)
                existing_names.add(new_name)

            if not unique_new_servers:
                self.show_info_dialog("No New Servers", "No new servers were imported. They were either exact duplicates or skipped by the user.")
                return

            added = len(unique_new_servers)
            self.servers.extend(unique_new_servers) 
            
            try:
                save_servers(self.servers, self.master_passphrase)
            except Exception as e:
                self._error(f"Failed to save XML imported servers: {e}")
                return
                
            folders_from_servers = {
                srv["folder"] for srv in unique_new_servers
                if srv.get("folder") != ROOT_FOLDER
            }
            all_folders = folders_from_servers | set(self.user_folders)
            self.user_folders = sorted(all_folders, key=natural_key)
            self.settings["folders"] = self.user_folders
            save_settings(self.settings)

            self.reload_folders()
            self.populate_tree()
            self.tree.expand_row(Gtk.TreePath.new_from_string("0"), False)
            
            self.log(f"Imported {added} unique SecureCRT servers.")
            self.show_info_dialog("Import Successful", f"Successfully imported {added} servers from XML.")
            
        except Exception as e:
            traceback.print_exc()
            self._error(f"An error occurred during XML import:\n{e}")

    def process_putty_import(self, file_path):
        """Handles native PuTTY (.reg) imports with Interactive Auto-Renaming"""
        try:
            imported_servers = parse_putty_reg(file_path)
            
            if not imported_servers:
                self._error("No valid servers found in the selected .reg file.")
                return
                
            for srv in imported_servers:
                srv.setdefault("auto_sequence", [])
                srv.setdefault("port_forwards", [])
                srv.setdefault("folder", ROOT_FOLDER)
                
            existing_sigs = {
                (s.get("name"), s.get("host"), s.get("user"), s.get("port"), s.get("folder"))
                for s in self.servers
            }
            existing_names = { s.get("name") for s in self.servers if s.get("name") }

            unique_new_servers = []
            for srv in imported_servers:
                base_name = srv.get("name")
                
                # First, check if this EXACT server is already in the list
                sig = (base_name, srv.get("host"), srv.get("user"), srv.get("port"), srv.get("folder"))
                if sig in existing_sigs:
                    continue  # It is a 100% identical copy, skip it silently.
                    
                # If the name exists but the settings are different, ASK THE USER!
                new_name = base_name
                if base_name in existing_names:
                    msg = (f"A connection named '{base_name}' already exists, but the imported version "
                           f"has different settings (IP/Port/User).\n\n"
                           f"Do you want to import this as a new connection and auto-rename it?")
                           
                    wants_to_import = self.ask_yes_no_dialog("Duplicate Name Detected", msg)
                    
                    if not wants_to_import:
                        continue # User clicked 'No', skip it!
                        
                    # User clicked 'Yes', find the next available safe name
                    counter = 1
                    while new_name in existing_names:
                        new_name = f"{base_name}({counter})"
                        counter += 1
                        
                # Apply the name (whether it's the original or the new renamed one)
                srv["name"] = new_name
                unique_new_servers.append(srv)
                
                # Update our trackers so we don't use this name again in the same import file
                new_sig = (new_name, srv.get("host"), srv.get("user"), srv.get("port"), srv.get("folder"))
                existing_sigs.add(new_sig)
                existing_names.add(new_name)

            if not unique_new_servers:
                self.show_info_dialog("No New Servers", "No new servers were imported. They were either exact duplicates or skipped by the user.")
                return

            added = len(unique_new_servers)
            self.servers.extend(unique_new_servers) 
            
            try:
                save_servers(self.servers, self.master_passphrase)
            except Exception as e:
                self._error(f"Failed to save PuTTY imported servers: {e}")
                return
                
            self.settings["folders"] = self.user_folders
            save_settings(self.settings)

            self.reload_folders()
            self.populate_tree()
            self.tree.expand_row(Gtk.TreePath.new_from_string("0"), False)
            
            self.log(f"Imported {added} unique PuTTY servers.")
            self.show_info_dialog("Import Successful", f"Successfully imported {added} servers from PuTTY.")
            
        except Exception as e:
            traceback.print_exc()
            self._error(f"An error occurred during PuTTY import:\n{e}")

    def process_putty_linux_import(self, directory_path):
        """Handles native Linux PuTTY session directory imports"""
        try:
            imported_servers = parse_putty_linux(directory_path)
            
            if not imported_servers:
                self._error("No valid servers found in the selected directory.")
                return
                
            for srv in imported_servers:
                srv.setdefault("auto_sequence", [])
                srv.setdefault("port_forwards", [])
                srv.setdefault("folder", ROOT_FOLDER) # Or whatever default folder logic you prefer
                
            existing_sigs = {
                (s.get("name"), s.get("host"), s.get("user"), s.get("port"), s.get("folder"))
                for s in self.servers
            }
            existing_names = { s.get("name") for s in self.servers if s.get("name") }

            unique_new_servers = []
            for srv in imported_servers:
                base_name = srv.get("name")
                
                # Check for exact duplicate
                sig = (base_name, srv.get("host"), srv.get("user"), srv.get("port"), srv.get("folder"))
                if sig in existing_sigs:
                    continue  
                    
                # Handle name collisions with different settings
                new_name = base_name
                if base_name in existing_names:
                    msg = (f"A connection named '{base_name}' already exists, but the imported version "
                           f"has different settings.\n\n"
                           f"Do you want to import this as a new connection and auto-rename it?")
                           
                    wants_to_import = self.ask_yes_no_dialog("Duplicate Name Detected", msg)
                    
                    if not wants_to_import:
                        continue 
                        
                    counter = 1
                    while new_name in existing_names:
                        new_name = f"{base_name}({counter})"
                        counter += 1
                        
                srv["name"] = new_name
                unique_new_servers.append(srv)
                
                new_sig = (new_name, srv.get("host"), srv.get("user"), srv.get("port"), srv.get("folder"))
                existing_sigs.add(new_sig)
                existing_names.add(new_name)

            if not unique_new_servers:
                self.show_info_dialog("No New Servers", "No new servers were imported. They were either exact duplicates or skipped.")
                return

            added = len(unique_new_servers)
            self.servers.extend(unique_new_servers) 
            
            try:
                # Assuming you have your master passphrase accessible here
                save_servers(self.servers, self.master_passphrase)
            except Exception as e:
                self._error(f"Failed to save Linux PuTTY imported servers: {e}")
                return
                
            self.settings["folders"] = self.user_folders
            save_settings(self.settings)

            self.reload_folders()
            self.populate_tree()
            self.tree.expand_row(Gtk.TreePath.new_from_string("0"), False)
            
            self.log(f"Imported {added} unique Linux PuTTY servers.")
            self.show_info_dialog("Import Successful", f"Successfully imported {added} servers from PuTTY (Linux).")
            
        except Exception as e:
            import traceback
            traceback.print_exc()
            self._error(f"An error occurred during Linux PuTTY import:\n{e}")

    def process_mobaxterm_import(self, filepath):
        """Parses MobaXterm .mobaconf or .ini files with Interactive Auto-Renaming"""
        import configparser
        import traceback
        
        config = configparser.ConfigParser(strict=False, interpolation=None)
        config.optionxform = str 
        
        try:
            # Try UTF-8 first, fallback to cp1252 if it's an older Windows export
            try:
                config.read(filepath, encoding='utf-8')
            except UnicodeDecodeError:
                config.read(filepath, encoding='cp1252')
                
            imported_servers = []
            
            # 1. Parse the MobaXterm configuration
            for section in config.sections():
                if section.startswith("Bookmarks"):
                    folder = ""
                    # Grab the folder path if it exists in this section
                    if "SubRep" in config[section]:
                        # Normalize Windows backslashes to forward slashes for the GUI
                        folder = config[section]["SubRep"].replace("\\", "/") 
                        
                    for key, val in config.items(section):
                        if key in ["SubRep", "ImgNum"]:
                            continue
                            
                        parts = val.split('%')
                        if len(parts) >= 4:
                            host = parts[1]
                            port = int(parts[2]) if parts[2].isdigit() else 22
                            user = parts[3].strip() if parts[3].strip() else ""
                            
                            # Build the raw server dict
                            srv = {
                                "name": key,
                                "host": host,
                                "port": port,
                                "user": user,
                                "type": "SSH"
                            }
                            
                            if folder:
                                srv["folder"] = folder
                                
                            imported_servers.append(srv)
                            
            if not imported_servers:
                self._error("No valid servers found in the selected MobaXterm file.")
                return

            # 2. Apply default settings (identical to PuTTY logic)
            for srv in imported_servers:
                srv.setdefault("auto_sequence", [])
                srv.setdefault("port_forwards", [])
                srv.setdefault("folder", ROOT_FOLDER)
                
            # 3. Setup Deduplication trackeres
            existing_sigs = {
                (s.get("name"), s.get("host"), s.get("user"), s.get("port"), s.get("folder"))
                for s in self.servers
            }
            existing_names = { s.get("name") for s in self.servers if s.get("name") }

            unique_new_servers = []
            
            # 4. Filter, auto-rename, and add folders
            for srv in imported_servers:
                base_name = srv.get("name")
                
                # First, check if this EXACT server is already in the list
                sig = (base_name, srv.get("host"), srv.get("user"), srv.get("port"), srv.get("folder"))
                if sig in existing_sigs:
                    continue  # It is a 100% identical copy, skip it silently.
                    
                # If the name exists but the settings are different, ASK THE USER!
                new_name = base_name
                if base_name in existing_names:
                    msg = (f"A connection named '{base_name}' already exists, but the imported version "
                           f"has different settings (IP/Port/User).\n\n"
                           f"Do you want to import this as a new connection and auto-rename it?")
                           
                    wants_to_import = self.ask_yes_no_dialog("Duplicate Name Detected", msg)
                    
                    if not wants_to_import:
                        continue # User clicked 'No', skip it!
                        
                    # User clicked 'Yes', find the next available safe name
                    counter = 1
                    while new_name in existing_names:
                        new_name = f"{base_name}({counter})"
                        counter += 1
                        
                # Apply the name (whether it's the original or the new renamed one)
                srv["name"] = new_name
                unique_new_servers.append(srv)
                
                # Check if we need to register a new custom folder from MobaXterm
                f = srv.get("folder")
                if f and f != ROOT_FOLDER and f not in self.user_folders:
                    self.user_folders.append(f)
                
                # Update our trackers so we don't use this name again in the same import file
                new_sig = (new_name, srv.get("host"), srv.get("user"), srv.get("port"), srv.get("folder"))
                existing_sigs.add(new_sig)
                existing_names.add(new_name)

            if not unique_new_servers:
                self.show_info_dialog("No New Servers", "No new servers were imported. They were either exact duplicates or skipped by the user.")
                return

            added = len(unique_new_servers)
            
            # 5. Save everything and refresh the UI (identical to PuTTY logic)
            self.servers.extend(unique_new_servers) 
            
            try:
                save_servers(self.servers, self.master_passphrase)
            except Exception as e:
                self._error(f"Failed to save MobaXterm imported servers: {e}")
                return
                
            self.settings["folders"] = self.user_folders
            save_settings(self.settings)

            self.reload_folders()
            self.populate_tree()
            self.tree.expand_row(Gtk.TreePath.new_from_string("0"), False)
            
            self.log(f"Imported {added} unique MobaXterm servers.")
            self.show_info_dialog("Import Successful", f"Successfully imported {added} servers from MobaXterm.")
            
        except Exception as e:
            traceback.print_exc()
            self._error(f"An error occurred during MobaXterm import:\n{e}")

    def on_import_putty_linux_clicked(self, widget):
        """Opens a folder chooser dialog for Linux PuTTY imports."""
        
        # 1. Create the dialog with the SELECT_FOLDER action
        dialog = Gtk.FileChooserDialog(
            title="Select PuTTY Sessions Folder",
            parent=self.win,  # Ensure this points to your main application window
            action=Gtk.FileChooserAction.SELECT_FOLDER,
        )

        # 2. Add the Cancel and Select buttons
        dialog.add_buttons(
            Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
            "Select Folder", Gtk.ResponseType.OK
        )

        # 3. Quality of Life: Auto-navigate to the hidden PuTTY directory!
        default_putty_dir = os.path.expanduser("~/.putty/sessions")
        if os.path.isdir(default_putty_dir):
            dialog.set_current_folder(default_putty_dir)

        # 4. Run the dialog and wait for the user
        response = dialog.run()
        
        if response == Gtk.ResponseType.OK:
            selected_folder = dialog.get_filename()
            self.log(f"Selected PuTTY directory: {selected_folder}")
            
            # Pass the selected folder directly to the processor we wrote earlier
            self.process_putty_linux_import(selected_folder)
        else:
            self.log("Linux PuTTY import cancelled.")

        # 5. Always destroy the dialog when finished
        dialog.destroy()

    def ask_yes_no_dialog(self, title, message):
        """Safely shows a GUI Yes/No question dialog"""
        dialog = Gtk.MessageDialog(
            transient_for=None,
            flags=0,
            message_type=Gtk.MessageType.QUESTION,
            buttons=Gtk.ButtonsType.YES_NO,
            text=title
        )
        dialog.format_secondary_text(message)
        response = dialog.run()
        dialog.destroy()
        return response == Gtk.ResponseType.YES

    # ── File Menu: Export Servers ───────────────────────────────────────
    def on_export(self, action, param):
        # Pass self.win as parent for dialogs called from UI actions
        dlg = Gtk.FileChooserDialog(
            title="Export Servers…",
            parent=self.win,
            action=Gtk.FileChooserAction.SAVE,
        )
        real_home = os.environ.get('SNAP_REAL_HOME', f"/home/{getpass.getuser()}")
        dlg.set_current_folder(real_home)
        dlg.add_buttons(
            Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
            Gtk.STOCK_SAVE,   Gtk.ResponseType.OK,
        )
        dlg.set_do_overwrite_confirmation(True)
    
        # Add filter for plaintext JSON
        filt_json = Gtk.FileFilter()
        filt_json.set_name("JSON files")
        filt_json.add_pattern("*.json")
        dlg.add_filter(filt_json)
    
        # Add filter for GPG encrypted files
        filt_gpg = Gtk.FileFilter()
        filt_gpg.set_name("GPG Encrypted Files")
        filt_gpg.add_pattern("*.gpg")
        dlg.add_filter(filt_gpg)
    
        # Set default name initially
        dlg.set_current_name("ssh_servers_export.json")

        def _on_filter_changed(dialog, pspec):
            current_filter = dialog.get_filter()
            current_name = dialog.get_current_name()
            
            if not current_filter or not current_name:
                return

            # Strip existing known extensions
            base_name = current_name
            if base_name.lower().endswith(".json"):
                base_name = base_name[:-5]
            elif base_name.lower().endswith(".gpg"):
                base_name = base_name[:-4]
            
            # Apply new extension based on selected filter
            if current_filter.get_name() == "GPG Encrypted Files":
                dialog.set_current_name(f"{base_name}.gpg")
            elif current_filter.get_name() == "JSON files":
                dialog.set_current_name(f"{base_name}.json")

        # Connect the signal "notify::filter" to our handler
        dlg.connect("notify::filter", _on_filter_changed)

        if dlg.run() == Gtk.ResponseType.OK:
            filename = dlg.get_filename()
            
            # 1. Check if the path is safe
            if not is_safe_sandbox_path(filename, dlg):
                dlg.destroy()
                return # Stop here if it's outside the home folder!
                
            # 2. If safe, close the dialog and proceed
            dlg.destroy()
            try:
                is_encrypted = filename.lower().endswith(".gpg")
                
                # Build a combined export payload
                export_data = {
                    "servers": self.servers,
                    "folders": self.user_folders
                }
    
                if is_encrypted:
                    # Write to a temporary file and encrypt it
                    tf = tempfile.NamedTemporaryFile("w", delete=False, suffix=".json")
                    json.dump(export_data, tf, indent=4)
                    tf.flush()
                    tf.close()
                    
                    # --- CHAMELEON GPG LOGIC ---
                    if IS_SNAP:
                        gpg_cmd = [
                            "gpg1", "--batch", "--yes",
                            "--symmetric", "--cipher-algo", "AES256",
                            "--passphrase", self.master_passphrase, 
                            "-o", filename, tf.name
                        ]
                    else:
                        gpg_cmd = [
                            "gpg", "--batch", "--yes",
                            "--no-tty", "--pinentry-mode", "loopback", 
                            "--symmetric", "--cipher-algo", "AES256",
                            "--passphrase", self.master_passphrase, 
                            "-o", filename, tf.name
                        ]

                    result = subprocess.run(
                        gpg_cmd,
                        check=False,
                        capture_output=True,
                        text=True
                    )
                    # ---------------------------
 
                    os.remove(tf.name) # Clean up temp file
                    
                    if result.returncode != 0:
                        raise RuntimeError(f"GPG encryption failed during export: {result.stderr.strip()}")
                else:
                    # Write to a regular JSON file
                    with open(filename, "w") as f:
                        json.dump(export_data, f, indent=4)
    
                self.log(
                    f"Exported {len(self.servers)} servers "
                    f"and {len(self.user_folders)} folders to '{filename}'"
                )
            except Exception as e:
                self._error(f"Export failed:\n{e}")
        else:
            dlg.destroy()

    def on_global_settings(self, action, param):
            """
            Opens a dialog to configure application-wide defaults for new servers.
            """
            dlg = Gtk.Dialog(title="Default Settings", transient_for=self.win, modal=True)
            dlg.add_buttons(Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL, Gtk.STOCK_OK, Gtk.ResponseType.OK)
            dlg.set_default_response(Gtk.ResponseType.OK)
            dlg.set_default_size(500, 450)
            
            content = dlg.get_content_area()
            grid = Gtk.Grid(column_spacing=12, row_spacing=12, margin=20)
            content.add(grid)
    
            # Helper to read current global setting or fall back to factory default
            def get_def(key, factory):
                return self.settings.get(key, factory)
    
            row = 0
            
            # 1. Palette
            lbl_pal = Gtk.Label(label="Default Palette:", halign=Gtk.Align.START)
            pal_cb = Gtk.ComboBoxText()
            pal_cb.set_hexpand(True)
            for p in ["None", "Tango", "Solarized Light", "Solarized Dark", "GNOME"]:
                pal_cb.append_text(p)
            current_pal = get_def("global_palette", "None")
            try: pal_cb.set_active(["None", "Tango", "Solarized Light", "Solarized Dark", "GNOME"].index(current_pal))
            except: pal_cb.set_active(0)
            
            grid.attach(lbl_pal, 0, row, 1, 1); grid.attach(pal_cb, 1, row, 1, 1); row += 1
    
            # 2. Scheme
            lbl_sch = Gtk.Label(label="Default Scheme:", halign=Gtk.Align.START)
            sch_cb = Gtk.ComboBoxText()
            for name in BUILTIN_SCHEMES.keys():
                sch_cb.append_text(name)
            current_sch = get_def("global_scheme", "Black on light yellow")
            try: sch_cb.set_active(list(BUILTIN_SCHEMES.keys()).index(current_sch))
            except: sch_cb.set_active(0)
            
            grid.attach(lbl_sch, 0, row, 1, 1); grid.attach(sch_cb, 1, row, 1, 1); row += 1
    
            # 3. Text Color
            lbl_fg = Gtk.Label(label="Default Text Color:", halign=Gtk.Align.START)
            btn_fg = Gtk.ColorButton()
            fg_color = Gdk.RGBA(); fg_color.parse(get_def("global_fg", "#000000"))
            btn_fg.set_rgba(fg_color)
            grid.attach(lbl_fg, 0, row, 1, 1); grid.attach(btn_fg, 1, row, 1, 1); row += 1
    
            # 4. Background Color
            lbl_bg = Gtk.Label(label="Default Background:", halign=Gtk.Align.START)
            btn_bg = Gtk.ColorButton()
            bg_color = Gdk.RGBA(); bg_color.parse(get_def("global_bg", "#FFFFDD"))
            btn_bg.set_rgba(bg_color)
            grid.attach(lbl_bg, 0, row, 1, 1); grid.attach(btn_bg, 1, row, 1, 1); row += 1
    
            # 5. Font
            lbl_font = Gtk.Label(label="Default Font:", halign=Gtk.Align.START)
            en_font = Gtk.Entry(text=get_def("global_font", "Ubuntu Mono 12"))
            btn_sel_font = Gtk.Button(label="Select")
            def _choose_font(_):
                fd = Gtk.FontChooserDialog(title="Select Default Font", transient_for=dlg)
                fd.set_font(en_font.get_text())
                if fd.run() == Gtk.ResponseType.OK:
                    en_font.set_text(fd.get_font())
                fd.destroy()
            btn_sel_font.connect("clicked", _choose_font)
            box_font = Gtk.Box(spacing=5)
            box_font.pack_start(en_font, True, True, 0); box_font.pack_start(btn_sel_font, False, False, 0)
            grid.attach(lbl_font, 0, row, 1, 1); grid.attach(box_font, 1, row, 1, 1); row += 1
    
            # 6. Buffer Lines
            lbl_buf = Gtk.Label(label="Default Buffer Lines:", halign=Gtk.Align.START)
            spin_buf = Gtk.SpinButton.new_with_range(100, 100000, 100)
            spin_buf.set_value(int(get_def("global_scrollback", 10000)))
            grid.attach(lbl_buf, 0, row, 1, 1); grid.attach(spin_buf, 1, row, 1, 1); row += 1
    
            # 7. Default Logging Folder (Replaces Reset Button)
            grid.attach(Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL), 0, row, 2, 1); row += 1
            
            lbl_log = Gtk.Label(label="Default Log Folder:", halign=Gtk.Align.START)
            # FileChooserButton in SELECT_FOLDER mode
            btn_log_dir = Gtk.FileChooserButton(title="Select Log Folder", action=Gtk.FileChooserAction.SELECT_FOLDER)
            current_log_dir = get_def("global_log_dir", "/tmp")
            if os.path.exists(current_log_dir):
                btn_log_dir.set_filename(current_log_dir)
            else:
                btn_log_dir.set_current_folder(os.path.expanduser("~"))
    
            grid.attach(lbl_log, 0, row, 1, 1); grid.attach(btn_log_dir, 1, row, 1, 1); row += 1
    
            # --- Handle Scheme Changes (Same as in Edit Server) ---
            def on_scheme_changed(cb):
                name = cb.get_active_text()
                if name and name in BUILTIN_SCHEMES and BUILTIN_SCHEMES[name]:
                    sch = BUILTIN_SCHEMES[name]
                    f = Gdk.RGBA(); f.parse(sch["term_fg"]); btn_fg.set_rgba(f)
                    b = Gdk.RGBA(); b.parse(sch["term_bg"]); btn_bg.set_rgba(b)
                    p = sch["term_palette"]
                    if p != "None":
                        try: pal_cb.set_active(["None", "Tango", "Solarized Light", "Solarized Dark", "GNOME"].index(p))
                        except: pass
            sch_cb.connect("changed", on_scheme_changed)
    
            dlg.show_all()
            response = dlg.run()
            
            if response == Gtk.ResponseType.OK:
                # Save to self.settings
                self.settings["global_palette"] = pal_cb.get_active_text()
                self.settings["global_scheme"] = sch_cb.get_active_text()
                self.settings["global_fg"] = btn_fg.get_rgba().to_string()
                self.settings["global_bg"] = btn_bg.get_rgba().to_string()
                self.settings["global_font"] = en_font.get_text()
                self.settings["global_scrollback"] = int(spin_buf.get_value())
                
                # Save Log Directory
                ldir = btn_log_dir.get_filename()
                if ldir:
                    self.settings["global_log_dir"] = ldir
                
                # Commit to disk
                save_settings(self.settings)
                self._info("Default Settings saved. New servers will use these defaults.")
    
            dlg.destroy()

    def on_change_passphrase(self, action, param):
        # 0) Ensure we have servers in memory and a verified session passphrase
        if not getattr(self, "master_passphrase", None):
            return self._error("No active passphrase in session. Restart the app and unlock first.")
    
        # 1) Confirm current passphrase
        dlg = PassphraseInputDialog(self.win, "Change Passphrase", "Enter current passphrase:")
        if dlg.run() != Gtk.ResponseType.OK:
            dlg.destroy(); return
        current_pass, _, _ = dlg.get_passphrases()
        dlg.destroy()
    
        stored_hash = self.settings.get("master_passphrase_hash")
        stored_salt_hex = self.settings.get("master_passphrase_salt")
        if not stored_hash or not stored_salt_hex:
            return self._error("Settings are missing passphrase hash/salt.")
    
        try:
            stored_salt = bytes.fromhex(stored_salt_hex)
        except ValueError:
            return self._error("Invalid salt format in settings. Cannot proceed.")
    
        if hash_passphrase(current_pass, stored_salt) != stored_hash:
            return self._error("Current passphrase is incorrect.")
    
        # 2) Prompt for new passphrase + confirm
        dlg2 = PassphraseInputDialog(self.win, "Change Passphrase", "Enter new passphrase:", confirm_text="Confirm new passphrase:")
        if dlg2.run() != Gtk.ResponseType.OK:
            dlg2.destroy(); return
        new_pass, new_confirm, _ = dlg2.get_passphrases()
        dlg2.destroy()
    
        if not new_pass:
            return self._error("New passphrase cannot be empty.")
        if new_pass != new_confirm:
            return self._error("New passphrases do not match.")
        if new_pass == current_pass:
            return self._error("New passphrase is identical to the current passphrase.")
    
        # 3) Re-encrypt to a temporary .gpg file using the new passphrase
        enc_path = SERVER_FILE + ".gpg"
        enc_tmp  = enc_path + ".new"
        enc_bak  = enc_path + ".bak"
    
        tf = None
        try:
            # Write current in-memory servers to a temp JSON
            tf = tempfile.NamedTemporaryFile("w", delete=False, suffix=".json")
            json.dump(self.servers, tf, indent=4)
            tf.flush(); tf.close()
    
            # --- CHAMELEON GPG LOGIC ---
            if IS_SNAP:
                gpg_cmd = [
                    "gpg1", "--batch", "--yes",
                    "--symmetric", "--cipher-algo", "AES256",
                    "--passphrase", new_pass,
                    "-o", enc_tmp, tf.name
                ]
            else:
                gpg_cmd = [
                    "gpg", "--batch", "--yes",
                    "--no-tty", "--pinentry-mode", "loopback",
                    "--symmetric", "--cipher-algo", "AES256",
                    "--passphrase", new_pass,
                    "-o", enc_tmp, tf.name
                ]

            result = subprocess.run(
                gpg_cmd,
                check=False, capture_output=True, text=True
            )
            # ---------------------------

            os.remove(tf.name); tf = None
    
            if result.returncode != 0:
                # Do not touch existing enc file or settings
                return self._error(f"GPG encryption failed:\n{result.stderr.strip()}")
    
            # 4) Atomic swap with backup
            if os.path.exists(enc_bak):
                os.remove(enc_bak)
            if os.path.exists(enc_path):
                os.rename(enc_path, enc_bak)
            os.rename(enc_tmp, enc_path)
            if os.path.exists(enc_bak):
                os.remove(enc_bak)
    
            # 5) Update settings (new salt+hash) and session passphrase
            new_salt = generate_salt()
            self.settings["master_passphrase_salt"] = new_salt.hex()
            self.settings["master_passphrase_hash"] = hash_passphrase(new_pass, new_salt)
            save_settings(self.settings)
    
            self.master_passphrase = new_pass
            self.log("Passphrase changed successfully.")
            self._info("Passphrase changed.")
    
        except Exception as e:
            # Cleanup temp/new file on error; restore from backup if needed
            try:
                if tf and os.path.exists(tf.name):
                    os.remove(tf.name)
                if os.path.exists(enc_tmp):
                    os.remove(enc_tmp)
                # If we moved the original aside but failed after, restore it
                if os.path.exists(enc_bak) and not os.path.exists(enc_path):
                    os.rename(enc_bak, enc_path)
            finally:
                self._error(f"Failed to change passphrase: {e}")
   
    # ── Folder Commands (New/Rename/Delete) ───────────────────────────────────────
    def on_new_folder(self, widget, param):
        selection = self.tree.get_selection()
        model, paths = selection.get_selected_rows()
        
        parent_path = "Session"
        try: root_val = ROOT_FOLDER
        except NameError: root_val = "Session"

        if paths:
            tree_iter = model.get_iter(paths[0])
            row_data = model.get_value(tree_iter, 2)
            if row_data and len(row_data) >= 2:
                node, val = row_data[0], row_data[1]
                if node == "folder":
                    parent_path = str(val)
                elif node == "server":
                    if isinstance(val, dict):
                        parent_path = val.get("folder", root_val)
                    elif isinstance(val, int):
                        parent_path = self.servers[val].get("folder", root_val)

        dialog = Gtk.Dialog(
            title="New Folder",
            transient_for=self.win,
            flags=Gtk.DialogFlags.MODAL,
        )
        dialog.add_button("Cancel", Gtk.ResponseType.CANCEL)
        dialog.add_button("OK", Gtk.ResponseType.OK)

        box = dialog.get_content_area()
        box.set_spacing(6)
        box.set_margin_top(10)
        box.set_margin_bottom(10)
        box.set_margin_start(10)
        box.set_margin_end(10)

        lbl = Gtk.Label(label=f"Create new folder inside: {parent_path}")
        lbl.set_xalign(0)
        box.pack_start(lbl, False, False, 0)

        entry = Gtk.Entry()
        entry.set_placeholder_text("Folder Name")
        
        # Make the Enter key trigger the OK button!
        entry.set_activates_default(True)
        dialog.set_default_response(Gtk.ResponseType.OK)
        
        box.pack_start(entry, False, False, 0)
        dialog.show_all()

        response = dialog.run()
        
        # Destroy dialog early so we can show warning popups cleanly if needed
        new_name = entry.get_text().strip().replace("/", "-")
        dialog.destroy()

        if response == Gtk.ResponseType.OK and new_name:
            new_full = new_name if parent_path == root_val else f"{parent_path}/{new_name}"
            
            # --- THE POPUP FIX ---
            if new_full in self.user_folders:
                dlg = Gtk.MessageDialog(
                    transient_for=self.win,
                    flags=0,
                    message_type=Gtk.MessageType.WARNING,
                    buttons=Gtk.ButtonsType.OK,
                    text="Folder Exists"
                )
                dlg.format_secondary_text(f"A folder named '{new_name}' already exists inside '{parent_path}'.")
                dlg.run()
                dlg.destroy()
                
                # Make them try again immediately
                return self.on_new_folder(widget, param)
                
            else:
                self.user_folders.append(new_full)
                self.log(f"Created folder: {new_full}")
                
                self._force_expand = parent_path 
                self.save_state_and_reload()

    def on_rename_folder(self, widget=None, data=None):
        """Renames a folder via the menu, showing only the short name in the dialog"""
        selection = self.tree.get_selection()
        model, paths = selection.get_selected_rows()
        if not paths: return
        
        if len(paths) > 1:
            self.show_info_dialog("Invalid", "Please select exactly ONE folder to rename.")
            return

        tree_iter = model.get_iter(paths[0])
        row_data = model.get_value(tree_iter, 2)
        if not row_data or len(row_data) < 2 or row_data[0] != "folder":
            return

        old_path = str(row_data[1])
        try: root_val = ROOT_FOLDER
        except NameError: root_val = "Session"

        if old_path == root_val:
            self.show_info_dialog("Invalid", "Cannot rename the root Session folder.")
            return

        # Extract just the short name (basename) and the parent path separately
        old_basename = old_path.split("/")[-1]
        parent_path = old_path.rsplit("/", 1)[0] if "/" in old_path else ""

        dialog = Gtk.MessageDialog(
            transient_for=self.win,
            flags=0,
            message_type=Gtk.MessageType.QUESTION,
            buttons=Gtk.ButtonsType.OK_CANCEL,
            text=f"Rename folder '{old_basename}':"
        )
        
        entry = Gtk.Entry()
        entry.set_text(old_basename) 
        entry.connect("activate", lambda e: dialog.response(Gtk.ResponseType.OK))
        
        box = dialog.get_message_area()
        box.pack_start(entry, True, True, 10)
        dialog.show_all()
        
        dialog.set_default_response(Gtk.ResponseType.OK)
        
        response = dialog.run()
        new_basename = entry.get_text().strip()
        dialog.destroy()

        if response == Gtk.ResponseType.OK and new_basename and new_basename != old_basename:
            new_basename = new_basename.replace("/", "-") 
            
            if parent_path:
                new_path = f"{parent_path}/{new_basename}"
            else:
                new_path = new_basename
                
            if new_path in self.user_folders:
                self.show_info_dialog("Exists", f"Folder '{new_path}' already exists.")
                return
                
            to_remove = []
            to_add = []
            for uf in self.user_folders:
                if uf == old_path or uf.startswith(old_path + "/"):
                    to_remove.append(uf)
                    remainder = uf[len(old_path):]
                    to_add.append(new_path + remainder)

            for uf in to_remove:
                if uf in self.user_folders:
                    self.user_folders.remove(uf)
            self.user_folders.extend(to_add)

            for s in self.servers:
                s_folder = s.get("folder", root_val)
                if s_folder == old_path or s_folder.startswith(old_path + "/"):
                    remainder = s_folder[len(old_path):]
                    s["folder"] = new_path + remainder

            self.log(f"Renamed folder: '{old_path}' -> '{new_path}'")
            self.save_state_and_reload()

    def on_delete_selected(self, widget=None, data=None):
        """Safely deletes a mixed selection of multiple servers and folders"""
        selection = self.tree.get_selection()
        model, paths = selection.get_selected_rows()
        if not paths: return

        dialog = Gtk.MessageDialog(
            transient_for=self.win, flags=0, message_type=Gtk.MessageType.WARNING,
            buttons=Gtk.ButtonsType.YES_NO,
            text=f"Are you sure you want to delete the {len(paths)} selected item(s)?"
        )
        response = dialog.run()
        dialog.destroy()

        if response == Gtk.ResponseType.YES:
            try: root_val = ROOT_FOLDER
            except NameError: root_val = "Session"
            
            folders_to_delete = []
            servers_to_delete = []
            
            # 1. Safely gather all selected items
            for path in paths:
                tree_iter = model.get_iter(path)
                row_data = model.get_value(tree_iter, 2)
                if not row_data or len(row_data) < 2: continue
                typ, item = row_data[0], row_data[1]
                
                if typ == "folder" and str(item) != root_val: 
                    folders_to_delete.append(str(item))
                elif typ == "server":
                    actual_srv = self.servers[item] if isinstance(item, int) else item
                    servers_to_delete.append(actual_srv)

            # 2. Obliterate Folders (and the servers hidden inside them)
            for fld_path in folders_to_delete:
                to_rem = [f for f in self.user_folders if f == fld_path or f.startswith(fld_path + "/")]
                for f in to_rem:
                    if f in self.user_folders: self.user_folders.remove(f)
                self.servers = [s for s in self.servers if not (s.get("folder", root_val) == fld_path or s.get("folder", "").startswith(fld_path + "/"))]
                
            # 3. Obliterate standalone selected Servers
            for srv in servers_to_delete:
                if srv in self.servers: self.servers.remove(srv)

            self.save_state_and_reload()
            self.log(f"Deleted {len(paths)} item(s).")

    def on_add_server(self, action, param):
        selection = self.tree.get_selection()
        model, paths = selection.get_selected_rows()
        
        default_folder = "Session"
        if paths:
            tree_iter = model.get_iter(paths[0])
            row_data = model.get_value(tree_iter, 2)
            if row_data and len(row_data) >= 2:
                node, val = row_data[0], row_data[1]
                if node == "folder":
                    default_folder = str(val)
                elif node == "server":
                    if isinstance(val, dict):
                        default_folder = val.get("folder", "Session")
                    elif isinstance(val, int):
                        default_folder = self.servers[val].get("folder", "Session")

        # Use your built-in dialog launcher!
        self._open_server_dialog(cfg=None, preselected_folder=default_folder)

    def on_edit_server(self, action, param):
        selection = self.tree.get_selection()
        model, paths = selection.get_selected_rows()

        if not paths:
            self.show_info_dialog("Edit Server", "Please select a server to edit.")
            return
            
        if len(paths) > 1:
            self.show_info_dialog("Edit Server", "Please select exactly ONE server to edit.")
            return

        tree_iter = model.get_iter(paths[0])
        row_data = model.get_value(tree_iter, 2)
        if not row_data or len(row_data) < 2: 
            return
            
        node, val = row_data[0], row_data[1]

        if node != "server":
            self.show_info_dialog("Edit Server", "Please select a server (not a folder).")
            return

        actual_server = self.servers[val] if isinstance(val, int) else val
        
        # Use your built-in dialog launcher!
        self._open_server_dialog(cfg=actual_server)

    # ── Connect Actions (SSH & SFTP) ─────────────────────────────────────────
    def on_ssh(self, action, param):
        selection = self.tree.get_selection()
        model, paths = selection.get_selected_rows()
        
        if not paths:
            return self._info("Select a server first.")
            
        if len(paths) > 1:
            return self._info("Please select exactly ONE server to connect to.")
            
        it = model.get_iter(paths[0])
        node, idx = model.get_value(it, 2)
        if node != "server":
            return self._info("Select a server first.")
    
        cfg = self.servers[idx]
        self.current_logging_enabled = cfg.get("logging_enabled", False)
        self.current_log_path = cfg.get("log_path", "")
        self.current_log_mode = cfg.get("log_mode", "append")

        if self.current_logging_enabled and self.current_log_mode == "overwrite" and self.current_log_path:
            try:
                os.makedirs(os.path.dirname(self.current_log_path), exist_ok=True)
                with open(self.current_log_path, 'w') as f:
                    f.write("") # Truncate file
            except Exception as e:
                print(f"Error truncating log file: {e}", file=sys.stderr)

        self.log(f"Launching SSH: {cfg['name']}")
    
        # Build forwarding flags using -L/-R/-D syntax (avoids the -o parsing issue)
        forward_opts = []
        for rule in cfg.get("port_forwards", []):
            t = rule.get("type")
            if t == "Dynamic":
                forward_opts.append(f'-D {int(rule["source_port"])}')
            elif t == "Local":
                forward_opts.append(f'-L {int(rule["source_port"])}:{rule["dest_host"]}:{int(rule["dest_port"])}')
            elif t == "Remote":
                forward_opts.append(f'-R {int(rule["source_port"])}:{rule["dest_host"]}:{int(rule["dest_port"])}')
    
        auth      = cfg.get("auth_method")
        safe_known_hosts = os.path.join(get_user_data_dir(), "known_hosts")
        cmd_parts = ["spawn", "ssh", f"-oUserKnownHostsFile={safe_known_hosts}", "-oStrictHostKeyChecking=accept-new"]
        if auth == "password":
            cmd_parts.append("-o PubkeyAuthentication=no")

        cmd_parts.append("-t")
        cmd_parts.extend(forward_opts)
        if auth == "key_file" and cfg.get("key_file"):
            cmd_parts.extend(["-i", cfg["key_file"]])
        cmd_parts.extend(["-p", str(cfg.get("port", 22))])
        cmd_parts.append(f'{cfg["user"]}@{cfg["host"]}')
    
        # First line: spawn ssh...
        lines = [" ".join(cmd_parts) + "\n", "log_user 1\n"]
    
        # Password prompt handling with timeout
        if auth == "password":
            lines.append('expect -timeout 5 "*assword:*" {\n')
            lines.append(f'    send -- "{cfg["password"]}\\r"\n')
            lines.append("    after 500\n")
            lines.append("} timeout {\n")
            lines.append("    # skip password prompt\n")
            lines.append("}\n")
    
        # Auto sequence steps with timeout and safe skip
        for step in cfg.get("auto_sequence", []):
            exp, snd = step["expect"], step["send"]
            lines.append(f'expect -timeout 1 "*{exp}*" {{\n')
            lines.append(f'    send -- "{snd}\\r"\n')
            lines.append("    after 500\n")
            lines.append("} timeout {\n")
            lines.append("    # no match, skip\n")
            lines.append("}\n")
    
        # Hand control to user
        lines.append("interact\n")
    
        self._launch_expect(lines, f"{cfg['name']} SSH", cfg)


    def on_sftp(self, action, param):
        selection = self.tree.get_selection()
        model, paths = selection.get_selected_rows()
        
        if not paths:
            return self._info("Select a server first.")
            
        if len(paths) > 1:
            return self._info("Please select exactly ONE server to connect to.")
            
        it = model.get_iter(paths[0])
        node, idx = model.get_value(it, 2)
        if node != "server":
            return self._info("Select a server first.")
    
        cfg = self.servers[idx]
        self.current_logging_enabled = cfg.get("logging_enabled", False)
        self.current_log_path = cfg.get("log_path", "")
        self.current_log_mode = cfg.get("log_mode", "append") 

        if self.current_logging_enabled and self.current_log_mode == "overwrite" and self.current_log_path:
            try:
                os.makedirs(os.path.dirname(self.current_log_path), exist_ok=True)
                with open(self.current_log_path, 'w') as f:
                    f.write("") # Truncate file
            except Exception as e:
                print(f"Error truncating log file: {e}", file=sys.stderr)

        self.log(f"Launching SFTP: {cfg['name']}")
    
        auth       = cfg.get("auth_method")
        port       = cfg.get("port", 22)
    
        key_opt    = f"-i {cfg['key_file']}" if auth == "key_file" and cfg.get("key_file") else ""
        pubkey_opt = "-o PubkeyAuthentication=no" if auth == "password" else ""
        safe_known_hosts = os.path.join(get_user_data_dir(), "known_hosts")
        
        # --- NEW: Fix SFTP transport binary for the Snap Sandbox ---
        ssh_binary = "ssh" 
        snap_path = os.environ.get("SNAP")
        if snap_path:
            ssh_binary = os.path.join(snap_path, "usr", "bin", "ssh")

        # Create the command with the new -S flag
        cmd_parts = [
            "spawn", "sftp", 
            f"-S {ssh_binary}", 
            f"-oUserKnownHostsFile={safe_known_hosts}", 
            "-oStrictHostKeyChecking=accept-new", 
            "-oBatchMode=no"
        ]
        
        if pubkey_opt:
            cmd_parts.append(pubkey_opt)

        if key_opt:
            cmd_parts.extend(key_opt.split())
            
        cmd_parts.extend(["-P", str(port), f'{cfg["user"]}@{cfg["host"]}'])

        lines = [" ".join(cmd_parts) + "\n", "log_user 1\n"]
        
        if auth == "password" and cfg.get("password"):
            lines.append('expect -timeout 5 "*assword:*" {\n')
            lines.append(f'    send -- "{cfg["password"]}\\r"\n')
            lines.append("    after 500\n")
            lines.append("} timeout {\n")
            lines.append("    # skip password prompt\n")
            lines.append("}\n")
        
        for step in cfg.get("auto_sequence", []):
            exp, snd = step["expect"], step["send"]
            lines.append(f'expect -timeout 1 "*{exp}*" {{\n')
            lines.append(f'    send -- "{snd}\\r"\n')
            lines.append("    after 500\n")
            lines.append("} timeout {\n")
            lines.append("    # no match, skip\n")
            lines.append("}\n")
        
        lines.append("interact\n")
        self._launch_expect(lines, f"{cfg['name']} SFTP", cfg)

    # Double-click on a server row → launch SSH
    def on_tree_activate(self, treeview, path, column):
        """Native GTK handler for Double-Clicks"""
        # --- FIX: Kill the rename timer instantly if they fast double-click! ---
        if getattr(self, 'rename_timer', None):
            GLib.source_remove(self.rename_timer)
            self.rename_timer = None
            self.deferred_path = None

        model = treeview.get_model()
        it = model.get_iter(path)
        typ, item = model.get_value(it, 2)
        
        if typ == "server":
            treeview.get_selection().select_path(path)
            self.on_ssh(None, None)
        elif typ == "folder":
            if treeview.row_expanded(path):
                treeview.collapse_row(path)
            else:
                treeview.expand_row(path, False)

    def on_sftpgui(self, action, param):
        # Handle if called from context menu (param has the index) or top menu (param is None)
        if param is not None and isinstance(param, int):
            idx = param
        else:
            selection = self.tree.get_selection()
            model, paths = selection.get_selected_rows()
            if not paths:
                return self._info("Select a server first.")
            if len(paths) > 1:
                return self._info("Please select exactly ONE server to connect to.")
                
            it = model.get_iter(paths[0])
            node, idx = model.get_value(it, 2)
            if node != "server":
                return self._info("Select a server first.")
    
        cfg = self.servers[idx]
        self.log(f"Launching Visual SFTP for: {cfg['name']}")
    
        host = cfg.get("host")
        port = cfg.get("port", 22)
        user = cfg.get("user")
        auth_method = cfg.get("auth_method", "password")
        password = cfg.get("password", "") if auth_method == "password" else None
        key_file = cfg.get("key_file", "") if auth_method == "key_file" else None

        try:
            sftp_window = SFTPWindow(
                parent_win=self.win, 
                host=host, 
                port=port, 
                username=user, 
                password=password, 
                private_key=key_file
            )
            sftp_window.show_all()
        except Exception as e:
            self._info(f"Failed to launch SFTP GUI: {e}")

    def _strip_ansi(self, text):
        """
        Removes ANSI escape codes and strictly normalizes line endings.
        """
        # 1. Remove ANSI OSC sequences (Window Titles, Hyperlinks)
        text = re.sub(r'\x1B\][^\x07\x1B]*(\x07|\x1B\\)', '', text)
        
        # 2. Remove ANSI CSI sequences (Colors, Cursor moves)
        text = re.sub(r'\x1B\[[0-9;?]*[a-zA-Z]', '', text)
        
        # 3. Remove other Escape sequences
        text = re.sub(r'\x1B[\(\)][0-9A-Z]', '', text)

        # 4. Normalize Line Endings (Strict Mode)
        #    Since we read with newline='', we see the raw characters.
        #    Terminal usually sends \r\n. We want just \n.
        text = text.replace('\r\n', '\n')
        
        #    Clean up any leftover raw CRs (which cause formatting glitches)
        text = text.replace('\r', '')
        
        return text             

    # ── Helper: Format Log Strings (Substitutions) ────────────────────────────
    def _format_log_data(self, template, cfg):
        if not template: return ""
        try:
            import datetime
            now = datetime.datetime.now()
            
            # Perform Substitutions
            out = template.replace("%H", str(cfg.get("host", ""))) # Host name
            out = out.replace("%S", str(cfg.get("name", ""))) # Session Name
            out = out.replace("%Y", now.strftime("%Y")) # Year        
            out = out.replace("%M", now.strftime("%m")) # Month
            out = out.replace("%D", now.strftime("%d")) # Day
            out = out.replace("%h", now.strftime("%H")) # Hours
            out = out.replace("%m", now.strftime("%M")) # Minute
            out = out.replace("%s", now.strftime("%S")) # Second    
           
            # Interpret escape sequences (like \n)
            # We wrap this in a try to prevent crash on invalid user input
            try:
                out = bytes(out, "utf-8").decode("unicode_escape")
            except:
                pass
            return out
        except Exception as e:
            print(f"Error formatting custom log data: {e}", file=sys.stderr)
            return template

    # ── Helper: Background Log Monitor ────────────────────────────────────────
    def _log_monitor(self, raw_path, final_path, stop_event, cfg):
        """
        Reads raw log data, cleans ANSI codes, handles custom log injections.
        """
        partial_buffer = ""
        incomplete_esc_re = re.compile(r'\x1B(\[[\d;?]*|\][^\x07\x1B]*)?$')
        
        # Only load custom strings if the feature is enabled
        if cfg.get("log_custom_enabled", False):
            str_conn = cfg.get("log_custom_connect", "")
            str_disc = cfg.get("log_custom_disconnect", "")
            str_line = cfg.get("log_custom_line", "")
        else:
            str_conn = ""
            str_disc = ""
            str_line = ""
        
        is_start_of_line = True

        try:
            with open(raw_path, 'r', encoding='utf-8', errors='ignore', newline='') as f_raw, \
                 open(final_path, 'a', encoding='utf-8', newline='') as f_final:
                
                # 1. Connect Header
                if str_conn:
                    msg = self._format_log_data(str_conn, cfg)
                    f_final.write(msg)
                    if not msg.endswith('\n'): f_final.write('\n')
                    f_final.flush()

                while not stop_event.is_set():
                    data = f_raw.read()
                    if not data:
                        time.sleep(0.1)
                        continue
                    
                    text = partial_buffer + data
                    partial_buffer = ""
                    
                    match = incomplete_esc_re.search(text)
                    if match:
                        span = match.span()
                        partial_buffer = text[span[0]:] 
                        text = text[:span[0]]           
                    
                    if text:
                        clean = self._strip_ansi(text)
                        
                        if str_line and clean:
                            prefix = self._format_log_data(str_line, cfg)
                            processed = prefix + clean if is_start_of_line else clean
                            processed = processed.replace('\n', '\n' + prefix)
                            
                            if clean.endswith('\n'):
                                if len(processed) >= len(prefix):
                                    processed = processed[:-len(prefix)]
                                is_start_of_line = True
                            else:
                                is_start_of_line = False
                                
                            f_final.write(processed)
                        else:
                            f_final.write(clean)
                        f_final.flush()
                
                # Final flush
                rest = f_raw.read()
                full = partial_buffer + rest
                if full:
                    clean = self._strip_ansi(full)
                    if str_line:
                        if is_start_of_line: clean = self._format_log_data(str_line, cfg) + clean
                        clean = clean.replace('\n', '\n' + self._format_log_data(str_line, cfg))
                    f_final.write(clean)
                    f_final.flush()

                # Disconnect Footer
                if str_disc:
                    if not is_start_of_line: f_final.write('\n')
                    msg = self._format_log_data(str_disc, cfg)
                    f_final.write(msg)
                    if not msg.endswith('\n'): f_final.write('\n')
                    f_final.flush()
            
        except Exception as e:
            print(f"ERROR: Log monitor thread CRASHED: {e}", file=sys.stderr)
        finally:
            if os.path.exists(raw_path):
                os.remove(raw_path)
                                
    # ── Helper: Open Settings from Terminal Window ────────────────────────────
    def _on_term_settings_clicked(self, button, data):
        # Unpack the tuple: (config, terminal_widget, window_object)
        cfg, terminal, win = data
        
        try:
            idx = self.servers.index(cfg)
            
            # This makes the Dialog a "child" of the Terminal Window.
            # When the dialog closes, focus will naturally return here.
            self._open_server_dialog(cfg, idx, target_window=win)
            
            # Apply visual changes immediately
            self.apply_appearance_to_terminal(terminal, cfg)
            
        except ValueError:
            self._error("This server configuration no longer exists.")

    # ── Generate & Launch Expect Script ───────────────────────────────────────
    def _launch_expect(self, lines, title, cfg):
        # 1. Verify Expect
        expect_path = shutil.which("expect")
        
        # --- Fallback for Snap Container ---
        if not expect_path:
            snap_dir = os.environ.get('SNAP', '')
            if snap_dir:
                snap_expect = os.path.join(snap_dir, 'usr/bin/expect')
                if os.path.exists(snap_expect):
                    expect_path = snap_expect        
        
        if not expect_path:
            return self._error("'expect' not found. Please install the 'expect' package.")

        # --- 2. Setup Real-time Logging (Temp File Strategy) ---
        raw_log_path = None
        logging_stop_event = None
        
        if getattr(self, "current_logging_enabled", False) and self.current_log_path:
            try:
                # A. Handle Overwrite Mode Manually
                log_mode = getattr(self, "current_log_mode", "append")
                if log_mode == "overwrite":
                    # Truncate the final log file now so we start fresh
                    with open(self.current_log_path, 'w') as f:
                        f.write("")
                
                # B. Create a unique TEMP file for raw output
                raw_log_path = os.path.join(tempfile.gettempdir(), f"scarpacm_raw_{uuid.uuid4().hex[:8]}.log")
                # Create it empty
                open(raw_log_path, 'w').close()
                
                # C. Start the Monitor Thread
                logging_stop_event = threading.Event()
                t = threading.Thread(
                    target=self._log_monitor,
                    # Pass 'cfg' as the last argument so we can read custom strings
                    args=(raw_log_path, self.current_log_path, logging_stop_event, cfg)
                )
                t.daemon = True 
                t.start()
                
            except Exception as e:
                print(f"Failed to setup logging: {e}", file=sys.stderr)
                # Cleanup if setup failed
                if raw_log_path and os.path.exists(raw_log_path):
                    os.remove(raw_log_path)
                raw_log_path = None

        # --- 3. Create the expect script ---
        header = [
            "#!/usr/bin/env expect\n",
            "set env(TERM) \"xterm-256color\"\n", 
            "match_max 100000\n", 
            "log_user 1\n",
        ]
        
        if raw_log_path:
            # Tcl: Open the file
            header.append(f'set log_handle [open "{raw_log_path}" w]\n')
            # Tcl: CRITICAL - Disable buffering so data is written instantly
            header.append('fconfigure $log_handle -buffering none\n')
            # Tcl: Tell Expect to use this unbuffered handle
            header.append('log_file -open $log_handle\n')
        
        header.append("set timeout -1\n")
        
        # --- Resize Trap Logic ---
        resize_trap = [
            "\n# --- Robust Window Size Syncing ---\n",
            "proc sync_term_size {} {\n",
            "    global spawn_out\n", 
            "    if {[info exists spawn_out(slave,name)]} {\n",
            "        set rows [stty rows]\n",
            "        set cols [stty columns]\n",
            "        stty rows $rows columns $cols < $spawn_out(slave,name)\n",
            "    }\n",
            "}\n",
            "trap { sync_term_size } WINCH\n",
            "sync_term_size\n\n"
        ]

        final_lines = list(lines)

        # --- Anti-idle Logic ---
        if cfg.get("anti_idle_enabled", False):
            idle_int = cfg.get("anti_idle_int", 300)
            idle_str = cfg.get("anti_idle_str", "\\r")
            new_interact = f'interact timeout {idle_int} {{ send "{idle_str}" }}\n'
            for i, line in enumerate(final_lines):
                if line.strip() == "interact":
                    final_lines[i] = new_interact
                    break
        
        spawn_index = -1
        for i, line in enumerate(final_lines):
            if line.strip().startswith("spawn"):
                spawn_index = i
                break
        
        if spawn_index != -1:
            final_lines[spawn_index+1:spawn_index+1] = resize_trap
        else:
            header.extend(resize_trap)
            
        # --- Startup Command File Logic ---
        if cfg.get("cmd_file_enabled", False):
            cpath = cfg.get("cmd_file_path", "")
            if cpath and os.path.exists(cpath):
                try:
                    with open(cpath, "r") as f:
                        file_lines = f.readlines()
                    
                    cmd_block = []
                    cmd_block.append("after 500\n") 
                    
                    for line in file_lines:
                        l = line.rstrip('\r\n')
                        l_esc = l.replace('\\', '\\\\').replace('"', '\\"').replace('[', '\\[').replace(']', '\\]').replace('$', '\\$')
                        cmd_block.append(f'send -- "{l_esc}\\r"\n')
                        cmd_block.append("after 100\n")
                    
                    idx_interact = -1
                    for i, ln in enumerate(final_lines):
                        if ln.strip().startswith("interact"):
                            idx_interact = i
                            break
                    
                    if idx_interact != -1:
                        final_lines[idx_interact:idx_interact] = cmd_block
                    else:
                        final_lines.extend(cmd_block)
                        
                except Exception as e:
                    print(f"Error reading command file: {e}", file=sys.stderr)

        if raw_log_path:
            final_lines.append('\ncatch {close $log_handle}\n')
            
        script_content = "".join(header + final_lines)

        tf = None
        try:
            tf = tempfile.NamedTemporaryFile("w", delete=False, suffix=".exp")
            tf.write(script_content)
            tf.close()
            os.chmod(tf.name, 0o700)

            # --- Create Terminal First ---
            terminal = Vte.Terminal()
            self.apply_appearance_to_terminal(terminal, cfg)
            terminal.connect("key-press-event", self._on_terminal_key_press)
            terminal.connect("button-press-event", self._on_terminal_button_press)

            # --- Create Window and HeaderBar ---
            term_window = Gtk.Window()
            term_window.set_default_size(800, 600)
            term_window.set_modal(False)
            term_window.set_destroy_with_parent(True)

            hb = Gtk.HeaderBar()
            hb.set_show_close_button(True)
            hb.set_title(title)
            term_window.set_titlebar(hb)

            # --- Create Settings Button ---
            btn_settings = Gtk.Button.new_from_icon_name("open-menu-symbolic", Gtk.IconSize.MENU)
            btn_settings.set_tooltip_text("Edit Server Settings")
            btn_settings.connect("clicked", self._on_term_settings_clicked, (cfg, terminal, term_window))
            hb.pack_end(btn_settings)

            wg = Gtk.WindowGroup()
            wg.add_window(term_window)
            term_window._wg = wg

            def on_child_exited(_terminal, _status):
                # 1. Stop logging
                if logging_stop_event:
                    logging_stop_event.set()
                
                # 2. Cleanup window and temp file
                term_window.close()
                if os.path.exists(tf.name):
                    os.remove(tf.name)
            
            terminal.connect("child-exited", on_child_exited)
            
            argv = [expect_path, "-f", tf.name]

            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                terminal.spawn_sync(
                    Vte.PtyFlags.DEFAULT,
                    os.environ.get('HOME', '/tmp'), # Made this safer just in case
                    argv,
                    GLib.get_environ(),             # <--- THE MAGIC FIX!
                    GLib.SpawnFlags.SEARCH_PATH, 
                    None,
                    None,
                )

            scrolled_window = Gtk.ScrolledWindow()
            scrolled_window.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
            scrolled_window.add(terminal)
            
            term_window.add(scrolled_window)
            term_window.show_all()
            
        except Exception as e:
            self._error(f"Failed to launch terminal: {e}")
            if tf and os.path.exists(tf.name):
                os.remove(tf.name)
            if logging_stop_event:
                logging_stop_event.set()
            if raw_log_path and os.path.exists(raw_log_path):
                os.remove(raw_log_path)

    # ── Logging to GUI Only ──────────────────────────────────────────────
    def log(self, msg):
        # Always try to write to log_buffer if it exists
        if hasattr(self, 'log_buffer') and self.log_buffer is not None:
            end = self.log_buffer.get_end_iter()
            self.log_buffer.insert(end, msg + "\n")
            # Scroll to bottom
            if self.log_text_view and self.log_text_view.get_parent():
                 self.log_text_view.scroll_to_mark(self.log_buffer.get_mark("insert"), 0.0, True, 0.0, 1.0)
        else:
            # Fallback for very early messages
            print(f"LOG (early): {msg}", file=sys.stderr)
            
    # ── Info / Error / Confirm Dialogs ───────────────────────────────────
    def _info(self, text):
        # Make parent transient_for self.win only if self.win exists
        parent_window = self.win if hasattr(self, 'win') and self.win else None
        dlg = Gtk.MessageDialog(
            transient_for=parent_window, # Can be None
            flags=0,
            message_type=Gtk.MessageType.INFO,
            buttons=Gtk.ButtonsType.OK,
            text=text
        )
        dlg.set_default_response(Gtk.ResponseType.OK) # Set OK as default button
        dlg.run()
        dlg.destroy()

    def _error(self, text):
        # Make parent transient_for self.win only if self.win exists
        parent_window = self.win if hasattr(self, 'win') and self.win else None
        dlg = Gtk.MessageDialog(
            transient_for=parent_window, # Can be None
            flags=0,
            message_type=Gtk.MessageType.ERROR,
            buttons=Gtk.ButtonsType.CLOSE,
            text=text
        )
        dlg.run()
        dlg.destroy()
        print(f"ERROR: {text}", file=sys.stderr) # Also print to console for debugging

    def _confirm(self, title, text, parent_window=None): # Added parent_window argument
        # Use provided parent_window or default to self.win if available, else None
        parent_to_use = parent_window if parent_window else (self.win if hasattr(self, 'win') and self.win else None)
        
        dlg = Gtk.MessageDialog(
            transient_for=parent_to_use, # Can be None
            flags=0,
            message_type=Gtk.MessageType.QUESTION,
            buttons=Gtk.ButtonsType.YES_NO,
            text=text
        )
        dlg.set_title(title)
        res = dlg.run()
        dlg.destroy()
        return res == Gtk.ResponseType.YES

    # ── Help: About Dialog ─────────────────────────────────────────────
    def on_about(self, action, param):
        # Make parent transient_for self.win only if self.win exists
        parent_window = self.win if hasattr(self, 'win') and self.win else None
        about = Gtk.AboutDialog(
            transient_for=parent_window, # Can be None
            modal=True,
            program_name=APP_TITLE,
            version="1.2.22",
            authors=["Copilot, Gemini, Tomas Larsson"],
            artists=["Tomas Larsson"],
            comments="A GTK-based SSH/SFTP session manager.\nRiposa in pace, Aquila di Filottrano. Sarai sempre con noi!"
        )
        about.run()
        about.destroy()
    def on_reset_disclaimer(self, action, param):
        self.settings["disclaimer_accepted"] = False
        save_settings(self.settings)
        self._info("Disclaimer will be shown again on next launch.")

    def on_tree_button_press(self, tree, event):
        state = event.state & Gdk.ModifierType.MODIFIER_MASK
        has_modifiers = bool(state & (Gdk.ModifierType.CONTROL_MASK | Gdk.ModifierType.SHIFT_MASK))

        # 1. Handle Right Click
        if event.button == Gdk.BUTTON_SECONDARY:
            x, y = int(event.x), int(event.y)
            path_info = tree.get_path_at_pos(x, y)
            
            if path_info:
                path, col, cx, cy = path_info
                selection = tree.get_selection()
                model, paths = selection.get_selected_rows()
                
                if path not in paths:
                    tree.set_cursor(path, col, False)
                    model, paths = selection.get_selected_rows()
                
                tree_iter = model.get_iter(path)
                row_data = model.get_value(tree_iter, 2)
                
                if row_data and len(row_data) >= 2:
                    node, val = row_data[0], row_data[1]
                    menu = self._create_context_menu(node, val)
                    menu.popup_at_pointer(event)
                return True
            else:
                # --- Right-Click in Empty Space ---
                tree.get_selection().unselect_all()
                menu = Gtk.Menu()
                
                mi_folder = Gtk.MenuItem(label="Add Folder")
                mi_folder.connect("activate", lambda w: self.on_new_folder(None, None))
                menu.append(mi_folder)
                
                mi_server = Gtk.MenuItem(label="Add Server")
                mi_server.connect("activate", lambda w: self.on_add_server(None, None))
                menu.append(mi_server)
                
                menu.show_all()
                menu.popup_at_pointer(event)
                return True

        # 2. Handle Left Click (Smart Rename & D&D Backup Logic)
        if event.button == Gdk.BUTTON_PRIMARY:
            # Clear existing timer on ANY left click event (Press, Release, or Double)
            if getattr(self, 'rename_timer', None):
                GLib.source_remove(self.rename_timer)
                self.rename_timer = None
                self.deferred_path = None

            # --- THE FIX ---
            # Ignore anything that isn't a standard, single Mouse Down event.
            # (Previously, the Mouse UP event after a double-click was starting a NEW timer!)
            if event.type != Gdk.EventType.BUTTON_PRESS:
                return False 

            path_info = tree.get_path_at_pos(int(event.x), int(event.y))
            
            # --- Left-Click in Empty Space ---
            if not path_info:
                tree.get_selection().unselect_all()
                return False
                
            path, col, cx, cy = path_info

            selection = tree.get_selection()
            model, rows = selection.get_selected_rows()
            is_selected = any(r == path for r in rows)

            # --- THE MULTI-DRAG BACKUP ---
            if is_selected and len(rows) > 1:
                self._drag_paths_backup = rows
            else:
                self._drag_paths_backup = None

            if has_modifiers:
                return False

            if is_selected and len(rows) > 1:
                return False
                
            # If it's a single item and already selected, trigger inline rename
            if is_selected:
                self.deferred_path = path
                # Increased slightly to 600ms so fast clicks don't trip it accidentally
                self.rename_timer = GLib.timeout_add(600, self._trigger_rename)
                return False
        
        return False

   # build a context menu based on whether it's a folder, server or root
    def _create_context_menu(self, node, val):
            menu = Gtk.Menu()
    
            # ─── FOLDER CONTEXT MENU ─────────────────────────────
            if node == "folder":
                # 1. Add Server (Available on all folders)
                mi = Gtk.MenuItem(label="Add Server")
                mi.connect("activate", lambda w: self.on_add_server(None, None)) 
                menu.append(mi)
    
                # 2. Add Folder (Available on all folders)
                mi = Gtk.MenuItem(label="Add Folder")
                mi.connect("activate", lambda w: self.on_new_folder(None, None))
                menu.append(mi)
    
                # 3. Paste Server (NEW: Point to Smart Paste)
                if getattr(self, '_app_clipboard', {}).get("items"):
                    mi = Gtk.MenuItem(label="Paste")
                    mi.connect("activate", lambda w: self.execute_smart_paste())
                    menu.append(mi)
    
                # Separator before destructive actions
                menu.append(Gtk.SeparatorMenuItem())
    
                # 4. Rename/Delete (Only for user-defined folders, not Root)
                if val != ROOT_FOLDER:
                    mi = Gtk.MenuItem(label="Rename Folder")
                    mi.connect("activate", lambda w: self.on_rename_folder(None, None))
                    menu.append(mi)
    
                    mi = Gtk.MenuItem(label="Delete Folder")
                    mi.connect("activate", lambda w: self.on_delete_selected(None, None))
                    menu.append(mi)
    
            # ─── SERVER CONTEXT MENU ─────────────────────────────
            elif node == "server":
                # 1. Connect SSH
                mi = Gtk.MenuItem(label="Connect SSH")
                mi.connect("activate", self.on_ssh, val) 
                menu.append(mi)
                
                # 1b. Connect SFTP (CLI)
                mi_sftp_cli = Gtk.MenuItem(label="Connect SFTP (CLI)")
                mi_sftp_cli.connect("activate", self.on_sftp, val) 
                menu.append(mi_sftp_cli)

                # 1c. Connect SFTP (GUI)
                mi_sftp_gui = Gtk.MenuItem(label="Connect SFTP (GUI)")
                # --- FIX IS ON THIS LINE BELOW (Changed to on_sftpgui) ---
                mi_sftp_gui.connect("activate", self.on_sftpgui, val) 
                menu.append(mi_sftp_gui)

                # Add a separator line to make it look clean
                menu.append(Gtk.SeparatorMenuItem())
                
                # 2. Edit / Copy / Delete ...
                for lbl, fn in (
                    ("Edit Server", self.on_edit_server),
                    ("Copy Server", self.execute_smart_copy),
                    ("Delete Server", self.on_delete_selected),
                ): 
                    mi = Gtk.MenuItem(label=lbl)
                    mi.connect("activate", lambda w, f=fn: f(None, None))
                    menu.append(mi)
    
            menu.show_all()
            return menu

    # ── In-line Renaming Logic (Click-Wait-Click) ─────────────────────────────
    def _cell_data_func(self, column, cell, model, tree_iter, data):
        """Determines which rows can be inline edited"""
        row_data = model.get_value(tree_iter, 2)
        if not row_data or len(row_data) < 2:
            cell.set_property("editable", False)
            return

        typ, item = row_data[0], row_data[1]
        
        try: root_val = ROOT_FOLDER
        except NameError: root_val = "Session"

        if typ == "folder" and str(item) == root_val:
            cell.set_property("editable", False)
        else:
            # --- FIX: Only allow editing if our slow-timer explicitly unlocks this specific path! ---
            path = model.get_path(tree_iter)
            is_active = (getattr(self, "_active_edit_path", None) == path)
            cell.set_property("editable", is_active)

    def _trigger_rename(self):
        """Called by the timer to enable editing."""
        self.rename_timer = None
        if not getattr(self, 'deferred_path', None): return False
        
        self.rename_path = self.deferred_path
        self.deferred_path = None
        
        # --- FIX: Temporarily unlock this specific row for editing ---
        self._active_edit_path = self.rename_path
        
        col = self.tree.get_column(0)
        self.tree.set_cursor(self.rename_path, col, True) 
        return False

    def _on_editing_canceled(self, renderer):
        """Reset state if user presses Escape."""
        self.rename_path = None
        self._active_edit_path = None # Relock the row!

    def _on_cell_edited(self, widget, path, text):
        """Handles inline renaming of folders AND servers safely without crashing GTK"""
        self.rename_path = None
        self._active_edit_path = None # Relock the row!
        
        new_name = text.strip()
        if not new_name: return

        try:
            tree_iter = self.store.get_iter(path)
            row_data = self.store.get_value(tree_iter, 2)
            if not row_data or len(row_data) < 2:
                return

            typ, item = row_data[0], row_data[1]
            
            try: root_val = ROOT_FOLDER
            except NameError: root_val = "Session"

            # --- RENAME SERVER ---
            if typ == "server":
                actual_server = self.servers[item] if isinstance(item, int) else item
                old_name = actual_server.get("name", "")
                
                if new_name == old_name: return
                
                target_folder = actual_server.get("folder", root_val)
                
                # Smart local collision check
                existing_names = {
                    s.get("name") for s in self.servers 
                    if s.get("folder", root_val) == target_folder and s != actual_server
                }
                
                final_name = new_name
                counter = 1
                while final_name in existing_names:
                    final_name = f"{new_name} ({counter})"
                    counter += 1
                    
                actual_server["name"] = final_name
                self.log(f"Renamed server: '{old_name}' -> '{final_name}'")
                
                # Safely rebuild UI
                GLib.idle_add(self.save_state_and_reload)
                return

            # --- RENAME FOLDER ---
            elif typ == "folder":
                new_name = new_name.replace("/", "-") 
                old_path = str(item)

                if old_path == root_val: return

                if "/" in old_path:
                    parent_path = old_path.rsplit("/", 1)[0]
                    new_path = f"{parent_path}/{new_name}"
                else:
                    new_path = new_name

                if new_path == old_path: return

                if new_path in self.user_folders:
                    self.log(f"Notice: Folder '{new_path}' already exists.")
                    return

                to_remove = []
                to_add = []
                for uf in self.user_folders:
                    if uf == old_path or uf.startswith(old_path + "/"):
                        to_remove.append(uf)
                        remainder = uf[len(old_path):]
                        to_add.append(new_path + remainder)

                for uf in to_remove:
                    if uf in self.user_folders:
                        self.user_folders.remove(uf)
                self.user_folders.extend(to_add)

                for s in self.servers:
                    s_folder = s.get("folder", root_val)
                    if s_folder == old_path or s_folder.startswith(old_path + "/"):
                        remainder = s_folder[len(old_path):]
                        s["folder"] = new_path + remainder

                self.log(f"Renamed folder: '{old_path}' -> '{new_path}'")
                
                # Safely rebuild UI
                GLib.idle_add(self.save_state_and_reload)

        except Exception as e:
            self.log(f"Rename error: {type(e).__name__}: {e}")

    def _start_help_server(self):
        """
        Starts a simple, temporary HTTP server in a background thread to serve
        the help file, bypassing any browser sandboxing issues.
        Returns the URL to the help file and the server object.
        """
        try:
            # The directory where user_guide.html is located
            serve_directory = os.path.dirname(HELP_FILE_PATH)
            # The filename of the guide
            file_name = os.path.basename(HELP_FILE_PATH)

            # A special handler that serves files from our specific directory
            class HelpRequestHandler(http.server.SimpleHTTPRequestHandler):
                def __init__(self, *args, **kwargs):
                    super().__init__(*args, directory=serve_directory, **kwargs)
                
                # Optional: Mute the terminal logging so it doesn't spam your console
                def log_message(self, format, *args):
                    pass

            # Find a free port to run the server on
            httpd = socketserver.TCPServer(("127.0.0.1", 0), HelpRequestHandler)
            port = httpd.server_address[1]
            
            # Run the server in a daemon thread. This means the thread will
            # automatically shut down when the main application exits.
            server_thread = threading.Thread(target=httpd.serve_forever)
            server_thread.daemon = True
            server_thread.start()

            url = f"http://127.0.0.1:{port}/{file_name}"
            self.log(f"Help server started at {url}")
            return url, httpd
            
        except Exception as e:
            self.log(f"Failed to start local help server: {e}")
            return None, None

    def on_user_guide(self, action, param):
            """
            Opens the user guide by starting a local web server and pointing
            the default browser to it.
            """
            self.log(f"Attempting to launch help guide via local web server.")
            
            # We need to keep a reference to the server, otherwise it might
            # get garbage collected in some Python versions.
            if not hasattr(self, "_help_server"):
                self._help_server = None
    
            # Start the server (or reuse if already running, though this simple
            # version starts a new one each time for simplicity).
            url, self._help_server = self._start_help_server()
    
            if url and self._help_server:
                try:
                    webbrowser.open_new(url)
                except Exception as e:
                    self._error(f"Failed to open the web browser.\n\nError: {e}")
                    self.log(f"webbrowser.open_new failed: {e}")
            else:
                self._error("Could not start the local help server to display the user guide.")

    def _open_server_dialog(self, cfg=None, idx=None, target_window=None, preselected_folder=None):
        is_edit = cfg is not None
    
        if target_window:
            parent_window = target_window
        else:
            parent_window = self.win if hasattr(self, 'win') and self.win else None
            
        dlg = Gtk.Dialog(
            title="Edit Server" if is_edit else "Add Server",
            transient_for=None,
            modal=True
        )

        dlg.add_buttons(Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
                        Gtk.STOCK_OK,     Gtk.ResponseType.OK)
        dlg.set_default_response(Gtk.ResponseType.OK)
        
        dlg.set_size_request(700, 600) 
        dlg.set_resizable(False) 
    
        content = dlg.get_content_area()
        nb = Gtk.Notebook()
        nb.set_hexpand(True)
        nb.set_vexpand(True)
        content.pack_start(nb, True, True, 0)
    
        # ── General tab ──────────────────────
        grid = Gtk.Grid(column_spacing=6, row_spacing=6, margin=10)
        nb.append_page(grid, Gtk.Label(label="General"))
    
        def add_row(label, widget, row):
            lbl = Gtk.Label(label=label)
            lbl.set_halign(Gtk.Align.START)
            grid.attach(lbl, 0, row, 1, 1)
            grid.attach(widget, 1, row, 1, 1)
    
        en_name = Gtk.Entry();   en_name.set_size_request(300, -1); en_name.set_activates_default(True)
        en_host = Gtk.Entry();   en_host.set_size_request(300, -1); en_host.set_activates_default(True)
        en_port = Gtk.Entry();   en_port.set_size_request(300, -1); en_port.set_activates_default(True)
        en_user = Gtk.Entry();   en_user.set_size_request(300, -1); en_user.set_activates_default(True)
        folder_cb = Gtk.ComboBoxText(); folder_cb.set_size_request(300, -1)
        
        en_port.set_text(str(cfg.get("port", 22)) if cfg else "22")
        if cfg:
            en_name.set_text(cfg["name"])
            en_host.set_text(cfg["host"])
            en_user.set_text(cfg.get("user", ""))
   
        folder_cb.append_text(ROOT_FOLDER)
        for f in self.subfolders:
            folder_cb.append_text(f)
            
        # --- SMART FOLDER SELECTION ---
        idx_f = 0
        target_fld = cfg.get("folder") if cfg else preselected_folder
        
        try: root_val = ROOT_FOLDER
        except NameError: root_val = "Session"
        
        if target_fld and target_fld != root_val and target_fld in self.subfolders:
            idx_f = self.subfolders.index(target_fld) + 1
            
        folder_cb.set_active(idx_f)
    
        add_row("Name:",   en_name,   0)
        add_row("Host:",   en_host,   1)
        add_row("Port:",   en_port,   2)
        add_row("User:",   en_user,   3)
        add_row("Folder:", folder_cb, 4)


        # ── Auth tab ──────────────────────
        auth_page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6, margin=10)
        nb.append_page(auth_page, Gtk.Label(label="Auth"))
    
        auth_pw  = Gtk.RadioButton.new_with_label(None, "Password")
        auth_key = Gtk.RadioButton.new_with_label_from_widget(auth_pw, "Key File")
    
        pw_entry = Gtk.Entry()
        pw_entry.set_size_request(300, -1)
        pw_entry.set_visibility(False)
        pw_entry.set_placeholder_text("Enter password")
        pw_entry.set_activates_default(True)
    
        key_entry = Gtk.Entry(); key_entry.set_size_request(300, -1)
        key_btn   = Gtk.Button(label="Browse")
        key_btn.connect("clicked", lambda w: browse_key(dlg, key_entry))
        key_box   = Gtk.Box(spacing=6)
        key_box.pack_start(key_entry, True, True, 0)
        key_box.pack_start(key_btn,   False, False, 0)
    
        for w in (auth_pw, pw_entry, auth_key, key_box):
            auth_page.pack_start(w, False, False, 0)
    
        def _toggle_pw(rb, entry, sensitive):
            if rb.get_active():
                entry.set_sensitive(sensitive)
        auth_pw.connect("toggled", _toggle_pw, pw_entry, True)
        auth_key.connect("toggled", _toggle_pw, pw_entry, False)
    
        if cfg:
            mode = cfg.get("auth_method", "password")
            auth_pw.set_active(mode == "password")
            auth_key.set_active(mode == "key_file")
            pw_entry.set_text(cfg.get("password", ""))
            key_entry.set_text(cfg.get("key_file", ""))
    
        pw_entry.set_sensitive(auth_pw.get_active())
    
        # ── Terminal Tab ──────────────────────────────────────────────────────────
        term_page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, margin=12)
        nb.append_page(term_page, Gtk.Label(label="Terminal"))
    
        # --- Section 1: Session Logging ---
        lbl_log_head = Gtk.Label(label="<b>Session Logging</b>", use_markup=True, xalign=0)
        term_page.pack_start(lbl_log_head, False, False, 0)
    
        log_grid = Gtk.Grid(column_spacing=12, row_spacing=6)
        log_grid.set_margin_start(12) 
        term_page.pack_start(log_grid, False, False, 0)
    
        # Main Logging Controls
        log_enable = Gtk.CheckButton(label="Enable Logging")
        log_grid.attach(log_enable, 0, 0, 2, 1)
    
        log_entry = Gtk.Entry(); log_entry.set_size_request(280, -1)
        log_btn   = Gtk.Button(label="Browse")
        
        # Sandbox check directly inside the logging browse button
        def _browse_log_inline(w):
            d = Gtk.FileChooserDialog("Select Log File", dlg, Gtk.FileChooserAction.SAVE)
            real_home = os.environ.get('SNAP_REAL_HOME', os.path.expanduser('~'))
            d.set_current_folder(real_home)
            d.add_buttons(Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL, Gtk.STOCK_SAVE, Gtk.ResponseType.OK)
            
            if d.run() == Gtk.ResponseType.OK:
                filename = d.get_filename()
                is_safe = os.path.abspath(filename).startswith(os.path.abspath(real_home))
                
                if not is_safe:
                    warn_dlg = Gtk.MessageDialog(
                        transient_for=dlg, modal=True,
                        message_type=Gtk.MessageType.INFO, buttons=Gtk.ButtonsType.OK,
                        text="Sandbox Restriction"
                    )
                    warn_dlg.format_secondary_markup(
                         "You are running the Snap version of Scarpa Connection Manager.\n\n"
                        "Due to strict security sandboxing, local file access is restricted "
                        f"to your home directory:\n<b>{real_home}</b>\n\n"
                        "If you need full local file-system access, we recommend installing the PPA version:\n\n"
                        "<tt>sudo add-apt-repository ppa:larre-b-larsson/scarpa-connection-manager\n"
                        "sudo apt update\n"
                        "sudo apt install scarpa-connection-manager</tt>"
                    ) 
                    warn_dlg.run()
                    warn_dlg.destroy()
                    d.destroy()
                    return

                log_entry.set_text(filename)
            d.destroy()

        log_btn.connect("clicked", _browse_log_inline)
        log_grid.attach(log_entry, 0, 1, 1, 1)
        log_grid.attach(log_btn,   1, 1, 1, 1)
    
        hbox_mode = Gtk.Box(spacing=12)
        hbox_mode.pack_start(Gtk.Label(label="Mode:"), False, False, 0)
        rb_append = Gtk.RadioButton.new_with_label(None, "Append to file")
        rb_overwr = Gtk.RadioButton.new_with_label_from_widget(rb_append, "Overwrite file")
        hbox_mode.pack_start(rb_append, False, False, 0)
        hbox_mode.pack_start(rb_overwr, False, False, 0)
        log_grid.attach(hbox_mode, 0, 2, 2, 1)
    
        # --- Subsection: Append Data to Log ---
        vbox_append = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        vbox_append.set_margin_top(8)
        vbox_append.set_margin_start(12)
        term_page.pack_start(vbox_append, False, False, 0)
    
        chk_log_custom = Gtk.CheckButton(label="Append Data to Log")
        vbox_append.pack_start(chk_log_custom, False, False, 0)
    
        # We create a specific group for the labels + the anti-idle checkbox below.
        # This aligns the start of the input boxes perfectly.
        sg_labels = Gtk.SizeGroup(mode=Gtk.SizeGroupMode.HORIZONTAL)
    
        # Row: At connect
        hbox_conn = Gtk.Box(spacing=12)
        lbl_conn = Gtk.Label(label="At connect:", xalign=0)
        ent_log_conn = Gtk.Entry()
        ent_log_conn.set_width_chars(30)  # <--- FORCE WIDTH HERE
        sg_labels.add_widget(lbl_conn)
        hbox_conn.pack_start(lbl_conn, False, False, 0)
        hbox_conn.pack_start(ent_log_conn, False, False, 0)
        vbox_append.pack_start(hbox_conn, False, False, 0)
    
        # Row: At disconnect
        hbox_disc = Gtk.Box(spacing=12)
        lbl_disc = Gtk.Label(label="At disconnect:", xalign=0)
        ent_log_disc = Gtk.Entry()
        ent_log_disc.set_width_chars(30)  # <--- FORCE WIDTH HERE
        sg_labels.add_widget(lbl_disc)
        hbox_disc.pack_start(lbl_disc, False, False, 0)
        hbox_disc.pack_start(ent_log_disc, False, False, 0)
        vbox_append.pack_start(hbox_disc, False, False, 0)
    
        # Row: On each line
        hbox_line = Gtk.Box(spacing=12)
        lbl_line = Gtk.Label(label="On each line:", xalign=0)
        ent_log_line = Gtk.Entry()
        ent_log_line.set_width_chars(30)  # <--- FORCE WIDTH HERE
        sg_labels.add_widget(lbl_line)
        hbox_line.pack_start(lbl_line, False, False, 0)
        hbox_line.pack_start(ent_log_line, False, False, 0)
        vbox_append.pack_start(hbox_line, False, False, 0)
    
        # Help Label
        help_txt = ("<small><b>Substitutions:</b> %H=Hostname, %S=Session Name, "
                    "%Y=Year, %M=Month, %D=Day, %h=Hour, %m=Min, %s=Sec.\nUse \\n for newline.</small>")
        lbl_help = Gtk.Label(label=help_txt, use_markup=True, xalign=0)
        vbox_append.pack_start(lbl_help, False, False, 0)
    
        # --- Logic: Handle Enable/Disable Dependencies ---
        def _update_log_states(widget=None):
            main_active = log_enable.get_active()
            custom_active = chk_log_custom.get_active()
    
            log_entry.set_sensitive(main_active)
            log_btn.set_sensitive(main_active)
            hbox_mode.set_sensitive(main_active)
            chk_log_custom.set_sensitive(main_active)
            
            fields_active = main_active and custom_active
            ent_log_conn.set_sensitive(fields_active)
            ent_log_disc.set_sensitive(fields_active)
            ent_log_line.set_sensitive(fields_active)
            lbl_help.set_sensitive(fields_active)
            lbl_conn.set_sensitive(fields_active)
            lbl_disc.set_sensitive(fields_active)
            lbl_line.set_sensitive(fields_active)
    
        log_enable.connect("toggled", _update_log_states)
        chk_log_custom.connect("toggled", _update_log_states)
    
        # --- Section 2: Anti-Idle ---
        term_page.pack_start(Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL), False, False, 0)
        lbl_idle_head = Gtk.Label(label="<b>Anti-idle</b>", use_markup=True, xalign=0)
        term_page.pack_start(lbl_idle_head, False, False, 0)
        
        box_idle = Gtk.Box(spacing=12); box_idle.set_margin_start(12)
        chk_idle = Gtk.CheckButton(label="Send string:")
        
        # This aligns the "At connect" inputs with the "\r" input below
        sg_labels.add_widget(chk_idle)
    
        ent_idle_str = Gtk.Entry(); ent_idle_str.set_width_chars(6)
        lbl_every = Gtk.Label(label="every")
        spin_idle = Gtk.SpinButton.new_with_range(1, 9999, 1)
        lbl_sec = Gtk.Label(label="seconds")
        box_idle.pack_start(chk_idle, False, False, 0); box_idle.pack_start(ent_idle_str, False, False, 0)
        box_idle.pack_start(lbl_every, False, False, 0); box_idle.pack_start(spin_idle, False, False, 0)
        box_idle.pack_start(lbl_sec, False, False, 0)
        term_page.pack_start(box_idle, False, False, 0)
        
        def _toggle_idle(chk):
            sen = chk.get_active()
            ent_idle_str.set_sensitive(sen); spin_idle.set_sensitive(sen)
            lbl_every.set_sensitive(sen); lbl_sec.set_sensitive(sen)
        chk_idle.connect("toggled", _toggle_idle)
    
        # --- Section 3: Buffer ---
        term_page.pack_start(Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL), False, False, 0)
        lbl_buf_head = Gtk.Label(label="<b>Scrollback Buffer</b>", use_markup=True, xalign=0)
        term_page.pack_start(lbl_buf_head, False, False, 0)
        
        box_buf = Gtk.Box(spacing=12); box_buf.set_margin_start(12)
        spin_buf = Gtk.SpinButton.new_with_range(100, 100000, 100)
        box_buf.pack_start(Gtk.Label(label="Lines:"), False, False, 0)
        box_buf.pack_start(spin_buf, False, False, 0)
        term_page.pack_start(box_buf, False, False, 0)
    
        # --- Section 4: Startup Command File ---
        term_page.pack_start(Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL), False, False, 0)
        lbl_cmd_head = Gtk.Label(label="<b>Startup Command File</b>", use_markup=True, xalign=0)
        term_page.pack_start(lbl_cmd_head, False, False, 0)
        
        cmd_grid = Gtk.Grid(column_spacing=12, row_spacing=6); cmd_grid.set_margin_start(12)
        term_page.pack_start(cmd_grid, False, False, 0)
        chk_cmd = Gtk.CheckButton(label="Send file content at login")
        ent_cmd = Gtk.Entry(); ent_cmd.set_size_request(280, -1)
        btn_cmd = Gtk.Button(label="Browse")

        # Sandbox check directly inside the command browse button
        def _browse_cmd(w):
            d = Gtk.FileChooserDialog("Select Command File", dlg, Gtk.FileChooserAction.OPEN)
            real_home = os.environ.get('SNAP_REAL_HOME', os.path.expanduser('~'))
            d.set_current_folder(real_home)
            d.add_buttons(Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL, Gtk.STOCK_OPEN, Gtk.ResponseType.OK)
            
            if d.run() == Gtk.ResponseType.OK:
                filename = d.get_filename()
                is_safe = os.path.abspath(filename).startswith(os.path.abspath(real_home))
                
                if not is_safe:
                    warn_dlg = Gtk.MessageDialog(
                        transient_for=dlg, modal=True,
                        message_type=Gtk.MessageType.INFO, buttons=Gtk.ButtonsType.OK,
                        text="Sandbox Restriction"
                    )
                    warn_dlg.format_secondary_markup(
                        "You are running the Snap version of Scarpa Connection Manager.\n\n"
                        "Due to strict security sandboxing, local file access is restricted "
                        f"to your home directory:\n<b>{real_home}</b>\n\n"
                        "If you need full local file-system access, we recommend installing the PPA version:\n\n"
                        "<tt>sudo add-apt-repository ppa:larre-b-larsson/scarpa-connection-manager\n"
                        "sudo apt update\n"
                        "sudo apt install scarpa-connection-manager</tt>"
                    )
                    warn_dlg.run()
                    warn_dlg.destroy()
                    d.destroy()
                    return

                ent_cmd.set_text(filename)
                
            d.destroy()

        btn_cmd.connect("clicked", _browse_cmd)
        cmd_grid.attach(chk_cmd, 0, 0, 2, 1) 
        cmd_grid.attach(ent_cmd, 0, 1, 1, 1) 
        cmd_grid.attach(btn_cmd, 1, 1, 1, 1)

        def _toggle_cmd(chk):
            sen = chk.get_active()
            ent_cmd.set_sensitive(sen); btn_cmd.set_sensitive(sen)
        chk_cmd.connect("toggled", _toggle_cmd)
    
        # --- Load Values ---
        if cfg:
            log_enable.set_active(cfg.get("logging_enabled", False))
            log_entry.set_text(cfg.get("log_path", "/tmp/scarpacm_log.txt"))
            if cfg.get("log_mode", "append") == "overwrite": rb_overwr.set_active(True)
            else: rb_append.set_active(True)
            
            # Load Custom Log Data
            chk_log_custom.set_active(cfg.get("log_custom_enabled", False))
            ent_log_conn.set_text(cfg.get("log_custom_connect", ""))
            ent_log_disc.set_text(cfg.get("log_custom_disconnect", ""))
            ent_log_line.set_text(cfg.get("log_custom_line", ""))
    
            chk_idle.set_active(cfg.get("anti_idle_enabled", False))
            ent_idle_str.set_text(cfg.get("anti_idle_str", "\\r"))
            spin_idle.set_value(cfg.get("anti_idle_int", 300))
            spin_buf.set_value(int(cfg.get("term_scrollback", getattr(self, "DEFAULT_TERM_SCROLLBACK", 10000))))
            chk_cmd.set_active(cfg.get("cmd_file_enabled", False))
            ent_cmd.set_text(cfg.get("cmd_file_path", ""))
            
            _update_log_states()
            _toggle_idle(chk_idle)
            _toggle_cmd(chk_cmd)
        else:
            # Defaults
            def_log_dir = self.settings.get("global_log_dir", "/tmp")
            log_entry.set_text(os.path.join(def_log_dir, "scarpacm_log.txt"))
            rb_append.set_active(True)
            ent_idle_str.set_text("\\r")
            spin_idle.set_value(300)
            spin_buf.set_value(int(self.settings.get("global_scrollback", getattr(self, "DEFAULT_TERM_SCROLLBACK", 10000))))
            _update_log_states()
            _toggle_idle(chk_idle)
            _toggle_cmd(chk_cmd)

        # ──  Login Actions Tab ──────────────────────
        seq_page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6, margin=10)
        nb.append_page(seq_page, Gtk.Label(label="Login Actions"))
    
        seq_store = Gtk.ListStore(str, str, bool)  # expect, send, hide
        seq_view = Gtk.TreeView(model=seq_store)
        seq_view.set_grid_lines(Gtk.TreeViewGridLines.BOTH)
    
        sw = Gtk.ScrolledWindow()
        sw.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        sw.set_hexpand(True); sw.set_vexpand(True)
        sw.add(seq_view)
        seq_page.pack_start(sw, True, True, 0)
    
        def _exp_cell(col, renderer, model, it, data):
            renderer.set_property("text", model.get_value(it, 0))
    
        def _snd_cell(col, renderer, model, it, data):
            txt  = model.get_value(it, 1)
            hide = model.get_value(it, 2)
            renderer.set_property("text", "*" * len(txt) if hide else txt)
    
        for title, func in (("Expect", _exp_cell), ("Send", _snd_cell)):
            rnd = Gtk.CellRendererText()
            col = Gtk.TreeViewColumn(title, rnd)
            col.set_cell_data_func(rnd, func)
            col.set_sizing(Gtk.TreeViewColumnSizing.FIXED)
            col.set_fixed_width(165)
            seq_view.append_column(col)
    
        btn_box = Gtk.Box(spacing=6)
        btn_add  = Gtk.Button(label="Add")
        btn_edit = Gtk.Button(label="Edit")
        btn_del  = Gtk.Button(label="Delete")
        up_btn   = Gtk.Button(); up_btn.add(Gtk.Arrow(arrow_type=Gtk.ArrowType.UP, shadow_type=Gtk.ShadowType.NONE))
        dn_btn   = Gtk.Button(); dn_btn.add(Gtk.Arrow(arrow_type=Gtk.ArrowType.DOWN, shadow_type=Gtk.ShadowType.NONE))
    
        btn_add.connect("clicked", lambda w: self._open_seq_editor(dlg, seq_store, None))
        btn_edit.connect("clicked", lambda w: self._edit_seq_selected(seq_view, seq_store, dlg))
        btn_del.connect("clicked", lambda w: self._delete_seq_selected(seq_view, seq_store))
        up_btn.connect("clicked", lambda w: self._move_seq_up(seq_view, seq_store))
        dn_btn.connect("clicked", lambda w: self._move_seq_down(seq_view, seq_store))
    
        for b in (btn_add, btn_edit, btn_del, up_btn, dn_btn):
            btn_box.pack_start(b, False, False, 0)
        seq_page.pack_start(btn_box, False, False, 0)
    
        if cfg:
            for step in cfg.get("auto_sequence", []):
                seq_store.append([step["expect"], step["send"], step.get("hide", True)])
 

        # ── Port Forwarding Tab ──────────────────────
        fwd_page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6, margin=10)
        nb.append_page(fwd_page, Gtk.Label(label="Port Forwarding"))
    
        fwd_store = Gtk.ListStore(str, int, str, int, object)
        fwd_view = Gtk.TreeView(model=fwd_store)
        fwd_view.set_grid_lines(Gtk.TreeViewGridLines.BOTH)
    
        sw_fwd = Gtk.ScrolledWindow()
        sw_fwd.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        sw_fwd.set_hexpand(True); sw_fwd.set_vexpand(True)
        sw_fwd.add(fwd_view)
        fwd_page.pack_start(sw_fwd, True, True, 0)
    
        for i, title in enumerate(["Type", "Source Port", "Destination Host", "Destination Port"]):
            renderer = Gtk.CellRendererText()
            col = Gtk.TreeViewColumn(title, renderer, text=i)
            fwd_view.append_column(col)
    
        fwd_btn_box = Gtk.Box(spacing=6)
        btn_add_fwd  = Gtk.Button(label="Add")
        btn_edit_fwd = Gtk.Button(label="Edit")
        btn_del_fwd  = Gtk.Button(label="Delete")
        fwd_btn_box.pack_start(btn_add_fwd,  False, False, 0)
        fwd_btn_box.pack_start(btn_edit_fwd, False, False, 0)
        fwd_btn_box.pack_start(btn_del_fwd,  False, False, 0)
        fwd_page.pack_start(fwd_btn_box, False, False, 0)
    
        btn_add_fwd.connect("clicked", lambda w: self._add_edit_forward_rule(dlg, fwd_store))
        btn_edit_fwd.connect("clicked", lambda w: self._add_edit_forward_rule(dlg, fwd_store, fwd_view))
        btn_del_fwd.connect("clicked", lambda w: self._delete_selected_from_view(fwd_view, fwd_store))
    
        if cfg:
            for rule in cfg.get("port_forwards", []):
                fwd_store.append([
                    rule["type"],
                    int(rule["source_port"]),
                    rule.get("dest_host", ""),
                    int(rule.get("dest_port", 0)),
                    rule
                ])

        # ── Appearance Tab (Grid layout for alignment) ───────────────────────────────
        app_page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, margin=12)
        nb.append_page(app_page, Gtk.Label(label="Appearance"))
        
        grid = Gtk.Grid(column_spacing=12, row_spacing=8)
        app_page.pack_start(grid, False, False, 0)
        
        row = 0
        
        # Palette
        lbl_palette = Gtk.Label(); lbl_palette.set_markup("<b>Palette:</b>")
        lbl_palette.set_halign(Gtk.Align.START)
        pal_cb = Gtk.ComboBoxText(); pal_cb.set_size_request(240, -1)
        for p in ["None", "Tango", "Solarized Light", "Solarized Dark", "GNOME"]:
            pal_cb.append_text(p)
        grid.attach(lbl_palette, 0, row, 1, 1)
        grid.attach(pal_cb,     1, row, 1, 1)
        row += 1
        
        # Color scheme
        lbl_scheme = Gtk.Label(); lbl_scheme.set_markup("<b>Color scheme:</b>")
        lbl_scheme.set_halign(Gtk.Align.START)
        scheme_cb = Gtk.ComboBoxText(); scheme_cb.set_size_request(240, -1)
        for name in BUILTIN_SCHEMES.keys():
            scheme_cb.append_text(name)
        grid.attach(lbl_scheme, 0, row, 1, 1)
        grid.attach(scheme_cb,  1, row, 1, 1)
        row += 1
        
        # Text color
        lbl_fg = Gtk.Label(label="Text color:"); lbl_fg.set_halign(Gtk.Align.START)
        btn_fg = Gtk.ColorButton()
        grid.attach(lbl_fg, 0, row, 1, 1)
        grid.attach(btn_fg, 1, row, 1, 1)
        row += 1
        
        # Background
        lbl_bg = Gtk.Label(label="Background:"); lbl_bg.set_halign(Gtk.Align.START)
        btn_bg = Gtk.ColorButton()
        grid.attach(lbl_bg, 0, row, 1, 1)
        grid.attach(btn_bg, 1, row, 1, 1)
        row += 1
        
        # Font
        lbl_font = Gtk.Label(); lbl_font.set_markup("<b>Font:</b>")
        lbl_font.set_halign(Gtk.Align.START)
        en_font = Gtk.Entry(); en_font.set_size_request(240, -1)
        btn_font = Gtk.Button(label="Select")
        
        def on_choose_font(_btn):
            parent_window = dlg if dlg else (self.win if hasattr(self, 'win') and self.win else None)
            fd = Gtk.FontChooserDialog(title="Select Font", transient_for=parent_window)
            current = en_font.get_text().strip()
            if current:
                try: fd.set_font(current)
                except Exception: pass
            if fd.run() == Gtk.ResponseType.OK:
                en_font.set_text(fd.get_font())
            fd.destroy()
        
        btn_font.connect("clicked", on_choose_font)
        font_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        font_box.pack_start(en_font, False, False, 0)
        font_box.pack_start(btn_font, False, False, 0)
        grid.attach(lbl_font, 0, row, 1, 1)
        grid.attach(font_box, 1, row, 1, 1)
        row += 1
        
        # Defaults
        lbl_defaults = Gtk.Label(); lbl_defaults.set_markup("<b>Defaults:</b>")
        lbl_defaults.set_halign(Gtk.Align.START)
        btn_reset = Gtk.Button(label="Reset to Defaults")
        
        def on_reset_defaults(_):
            # Load from Default Settings (or fall back to factory defaults)
            def_font = self.settings.get("global_font", "Ubuntu Mono 12")
            def_fg   = self.settings.get("global_fg", "#000000")
            def_bg   = self.settings.get("global_bg", "#FFFFDD")
            def_pal  = self.settings.get("global_palette", "None")
            def_buf  = self.settings.get("global_scrollback", 10000)
            def_sch  = self.settings.get("global_scheme", "Black on light yellow")

            en_font.set_text(def_font)
            fg = Gdk.RGBA(); fg.parse(def_fg); btn_fg.set_rgba(fg)
            bg = Gdk.RGBA(); bg.parse(def_bg); btn_bg.set_rgba(bg)
            	
            try:
                pal_cb.set_active(["None", "Tango", "Solarized Light", "Solarized Dark", "GNOME"].index(def_pal))
            except ValueError:
                pal_cb.set_active(0)
            
            spin_buf.set_value(def_buf)
            
            try:
                # Find the scheme in the list
                idx_scheme = 0
                for i, name in enumerate(BUILTIN_SCHEMES.keys()):
                    if name == def_sch:
                        idx_scheme = i
                        break
                scheme_cb.set_active(idx_scheme)
            except Exception:
                scheme_cb.set_active(0)

        btn_reset.connect("clicked", on_reset_defaults)
        grid.attach(lbl_defaults, 0, row, 1, 1)
        grid.attach(btn_reset,   1, row, 1, 1)
        row += 1
        
        # --- Pre-fill when editing ---
        if cfg:
            en_font.set_text(cfg.get("term_font", getattr(self, "DEFAULT_TERM_FONT", "Ubuntu Mono 12")))
            fg = Gdk.RGBA(); fg.parse(cfg.get("term_fg", getattr(self, "DEFAULT_TERM_FG", "#000000"))); btn_fg.set_rgba(fg)
            bg = Gdk.RGBA(); bg.parse(cfg.get("term_bg", getattr(self, "DEFAULT_TERM_BG", "#FFFFDD"))); btn_bg.set_rgba(bg)
            pal = cfg.get("term_palette", getattr(self, "DEFAULT_TERM_PALETTE", "None"))
            try:
                pal_cb.set_active(["None", "Tango", "Solarized Light", "Solarized Dark", "GNOME"].index(pal))
            except ValueError:
                pal_cb.set_active(0)
            scheme_name = cfg.get("term_scheme")
            if scheme_name and scheme_name in BUILTIN_SCHEMES:
                scheme_cb.set_active(list(BUILTIN_SCHEMES.keys()).index(scheme_name))
            else:
                scheme_cb.set_active(list(BUILTIN_SCHEMES.keys()).index("Custom"))

        if not cfg:
            # Load Global Defaults
            def_font = self.settings.get("global_font", "Ubuntu Mono 12")
            def_fg   = self.settings.get("global_fg", "#000000")
            def_bg   = self.settings.get("global_bg", "#FFFFDD")
            def_pal  = self.settings.get("global_palette", "None")
            def_buf  = self.settings.get("global_scrollback", 10000)
            def_sch  = self.settings.get("global_scheme", "Black on light yellow")
            
            # Font
            en_font.set_text(def_font)
        
            # Colors
            fg = Gdk.RGBA(); fg.parse(def_fg); btn_fg.set_rgba(fg)
            bg = Gdk.RGBA(); bg.parse(def_bg); btn_bg.set_rgba(bg)
        
            # Palette
            try:
                pal_cb.set_active(["None", "Tango", "Solarized Light", "Solarized Dark", "GNOME"].index(def_pal))
            except ValueError:
                pal_cb.set_active(0)
        
            # Buffer
            spin_buf.set_value(def_buf)
        
            # Scheme
            try:
                idx_scheme = 0
                for i, name in enumerate(BUILTIN_SCHEMES.keys()):
                    if name == def_sch:
                        idx_scheme = i
                        break
                scheme_cb.set_active(idx_scheme)
            except Exception:
                scheme_cb.set_active(0)
                
            # --- ALSO SET DEFAULT LOG PATH ---
            def_log_dir = self.settings.get("global_log_dir", "/tmp")
            log_entry.set_text(os.path.join(def_log_dir, "scarpacm_log.txt"))
       
        # --- Scheme change handler ---
        def on_scheme_changed(cb):
            idx = cb.get_active()
            if idx is None or idx < 0: return
            name = list(BUILTIN_SCHEMES.keys())[idx]
            scheme = BUILTIN_SCHEMES.get(name)
            if scheme:
                fg = Gdk.RGBA(); fg.parse(scheme.get("term_fg", btn_fg.get_rgba().to_string())); btn_fg.set_rgba(fg)
                bg = Gdk.RGBA(); bg.parse(scheme.get("term_bg", btn_bg.get_rgba().to_string())); btn_bg.set_rgba(bg)
                pal = scheme.get("term_palette")
                if pal and pal != "None":
                    try:
                        pal_idx = ["None", "Tango", "Solarized Light", "Solarized Dark", "GNOME"].index(pal)
                    except ValueError:
                        pal_idx = 0
                    pal_cb.set_active(pal_idx)
        
        scheme_cb.connect("changed", on_scheme_changed)
        
        dlg.show_all()

        # Validation loop
        result = None

        while True:
            resp = dlg.run()
            if resp != Gtk.ResponseType.OK:
                break
    
            name = en_name.get_text().strip()
            if not name:
                self.show_info_dialog("Error", "Server Name is required.")
                continue
                
            target_folder = folder_cb.get_active_text() or "Session"

            # --- START COLLISION CHECK ---
            is_duplicate = False
            for i, existing_server in enumerate(self.servers):
                # If editing, we skip checking the current server against itself!
                if is_edit:
                    if idx is not None and i == idx:
                        continue
                    elif cfg is not None and existing_server == cfg:
                        continue
                
                existing_name = existing_server.get("name", "")
                existing_folder = existing_server.get("folder", "Session")
                
                # Treat missing/blank folder as "Session" root
                if not existing_folder: existing_folder = "Session"
                check_folder = target_folder if target_folder else "Session"
                
                if existing_name == name and existing_folder == check_folder:
                    is_duplicate = True
                    break
                    
            if is_duplicate:
                self.show_info_dialog("Name Collision", f"A server named '{name}' already exists in the '{target_folder}' folder.\n\nPlease choose a different name or folder.")
                continue
            # --- END COLLISION CHECK ---
    
            result = {
                "name":         name,
                "host":         en_host.get_text().strip(),
                "port":         int(en_port.get_text().strip()),
                "user":         en_user.get_text().strip(),
                "folder":       folder_cb.get_active_text(),
                "auth_method":  "password" if auth_pw.get_active() else "key_file",
                "password":     pw_entry.get_text().strip(),
                "key_file":     key_entry.get_text().strip(),
                "logging_enabled": log_enable.get_active(),
                "log_path":        log_entry.get_text().strip(),
                "log_mode": "overwrite" if rb_overwr.get_active() else "append",
                "log_custom_enabled": chk_log_custom.get_active(),
                "log_custom_connect": ent_log_conn.get_text(),
                "log_custom_disconnect": ent_log_disc.get_text(),
                "log_custom_line": ent_log_line.get_text(),
                "cmd_file_enabled": chk_cmd.get_active(),
                "cmd_file_path":    ent_cmd.get_text().strip(),
                "anti_idle_enabled": chk_idle.get_active(),
                "anti_idle_str":     ent_idle_str.get_text(),
                "anti_idle_int":     int(spin_idle.get_value()),
                "auto_sequence": [
                    {"expect": seq_store[i][0], "send": seq_store[i][1], "hide": seq_store[i][2]}
                    for i in range(len(seq_store))
                ],
                "port_forwards": []
            }
    
            # Read final appearance values directly from widgets
            result["term_font"] = en_font.get_text().strip()
            result["term_fg"]   = btn_fg.get_rgba().to_string()
            result["term_bg"]   = btn_bg.get_rgba().to_string()
            result["term_palette"]    = pal_cb.get_active_text() or "None"
            result["term_scrollback"] = spin_buf.get_value_as_int()
            result["term_scheme"] = scheme_cb.get_active_text() or "Custom"
    
            for i in range(len(fwd_store)):
                rule = fwd_store[i][4]
                if rule["type"] == "Dynamic":
                    result["port_forwards"].append({
                        "type": "Dynamic",
                        "source_port": int(rule["source_port"])
                    })
                else:
                    result["port_forwards"].append({
                        "type": rule["type"],
                        "source_port": int(rule["source_port"]),
                        "dest_host": rule.get("dest_host", "localhost"),
                        "dest_port": int(rule.get("dest_port", 0)),
                    })
    
            break
    
        dlg.destroy()
    
        if result:
            if result["logging_enabled"]:
                os.makedirs(os.path.dirname(result["log_path"]), exist_ok=True)
                if not os.path.exists(result["log_path"]):
                    open(result["log_path"], "w").close()
    
            if is_edit:
                # Fallback to automatically find idx if missing
                actual_idx = idx
                if actual_idx is None and cfg in self.servers:
                    actual_idx = self.servers.index(cfg)
                    
                if actual_idx is not None:
                    self.servers[actual_idx].clear()
                    self.servers[actual_idx].update(result)
                    self.log(f"Edited '{result['name']}'")
                else:
                    # Failsafe append
                    self.servers.append(result)
                    self.log(f"Added as new (edit failed to find original): '{result['name']}'")
            else:
                self.servers.append(result)
                self.log(f"Added '{result['name']}'")
                
                # --- FIX: Tell the UI to force expand the folder so we see the new server ---
                try: root_val = ROOT_FOLDER
                except NameError: root_val = "Session"
                self._force_expand = result.get("folder", root_val)
   
            try:
                save_servers(self.servers, self.master_passphrase)
            except Exception as e:
                self._error(f"Failed to save servers after add/edit: {e}")
    
            self.reload_folders()
            self.populate_tree()
            self.tree.expand_row(Gtk.TreePath.new_from_string("0"), False)

    def _add_edit_forward_rule(self, parent, store, view=None):
        """Add a new port forward rule, or edit the selected one."""
        rule_to_edit = None
        tree_iter = None
        if view:
            model, paths = view.get_selection().get_selected_rows()
            if not paths:
                return
            tree_iter = store.get_iter(paths[0])
            rule_to_edit = store.get_value(tree_iter, 4)
    
        # --- FIX: Added use_header_bar=0 to prevent GTK layout crashes ---
        dlg = Gtk.Dialog(
            title="Edit Forwarding Rule" if rule_to_edit else "Add Forwarding Rule",
            transient_for=parent,
            modal=True,
            use_header_bar=0
        )
        dlg.add_buttons(Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
                        Gtk.STOCK_OK,     Gtk.ResponseType.OK)
                        
        # Set default response so Enter works
        dlg.set_default_response(Gtk.ResponseType.OK)
    
        grid = Gtk.Grid(column_spacing=6, row_spacing=6, margin=10)
        dlg.get_content_area().add(grid)
    
        # Type
        grid.attach(Gtk.Label(label="Type:", halign=Gtk.Align.START), 0, 0, 1, 1)
        type_cb = Gtk.ComboBoxText()
        for t in ("Local", "Remote", "Dynamic"):
            type_cb.append_text(t)
        type_cb.set_active(0)
        grid.attach(type_cb, 1, 0, 1, 1)
    
        # Source Port
        grid.attach(Gtk.Label(label="Source Port:", halign=Gtk.Align.START), 0, 1, 1, 1)
        src_port_spin = Gtk.SpinButton.new_with_range(1, 65535, 1)
        src_port_spin.set_activates_default(True)  # <-- Enter triggers OK
        grid.attach(src_port_spin, 1, 1, 1, 1)
    
        # Destination Host
        grid.attach(Gtk.Label(label="Destination Host:", halign=Gtk.Align.START), 0, 2, 1, 1)
        dest_host_entry = Gtk.Entry(text="localhost")
        dest_host_entry.set_activates_default(True)  # <-- Enter triggers OK
        grid.attach(dest_host_entry, 1, 2, 1, 1)
    
        # Destination Port
        grid.attach(Gtk.Label(label="Destination Port:", halign=Gtk.Align.START), 0, 3, 1, 1)
        dest_port_spin = Gtk.SpinButton.new_with_range(1, 65535, 1)
        dest_port_spin.set_activates_default(True)  # <-- Enter triggers OK
        grid.attach(dest_port_spin, 1, 3, 1, 1)
    
        # Disable dest fields if Dynamic selected
        def update_dest_visibility(*_):
            is_dynamic = (type_cb.get_active_text() == "Dynamic")
            dest_host_entry.set_sensitive(not is_dynamic)
            dest_port_spin.set_sensitive(not is_dynamic)
        type_cb.connect("changed", update_dest_visibility)
        update_dest_visibility()
    
        if rule_to_edit:
            type_cb.set_active({"Local": 0, "Remote": 1, "Dynamic": 2}[rule_to_edit.get("type", "Local")])
            src_port_spin.set_value(rule_to_edit.get("source_port", 1080))
            dest_host_entry.set_text(rule_to_edit.get("dest_host", "localhost"))
            dest_port_spin.set_value(rule_to_edit.get("dest_port", 80))
            update_dest_visibility()
    
        dlg.show_all()
        if dlg.run() == Gtk.ResponseType.OK:
            t = type_cb.get_active_text()
            rule = {"type": t, "source_port": int(src_port_spin.get_value())}
            
            if t != "Dynamic":
                rule["dest_host"] = dest_host_entry.get_text().strip() or "localhost"
                rule["dest_port"] = int(dest_port_spin.get_value())
    
            row = [rule["type"], rule["source_port"], rule.get("dest_host",""), rule.get("dest_port",0), rule]
            if tree_iter:
                store.set(tree_iter, [0,1,2,3,4], row)
            else:
                store.append(row)
        dlg.destroy()    
    
    def _delete_selected_from_view(self, view, store):
        """Delete the currently selected rows from a Gtk.TreeView/ListStore."""
        model, paths = view.get_selection().get_selected_rows()
        for p in sorted(paths, reverse=True):
            it = store.get_iter(p)
            store.remove(it)

    def _edit_seq_selected(self, view, store, parent):
        model, paths = view.get_selection().get_selected_rows()
        if paths:
            it = store.get_iter(paths[0])
            self._open_seq_editor(parent, store, it)

    def _delete_seq_selected(self, view, store):
        model, paths = view.get_selection().get_selected_rows()
        for p in sorted(paths, reverse=True):
            it = store.get_iter(p)
            store.remove(it)

    def _move_seq_up(self, view, store):
        model, paths = view.get_selection().get_selected_rows()
        if not paths: return
        row = paths[0][0]
        if row <= 0: return
        it = store.get_iter(paths[0])
        e, s, h = store.get_value(it, 0), store.get_value(it, 1), store.get_value(it, 2)
        store.remove(it)
        new_it = store.insert(row-1, [e, s, h])
        view.get_selection().select_iter(new_it)

    def _move_seq_down(self, view, store):
        model, paths = view.get_selection().get_selected_rows()
        if not paths: return
        row = paths[0][0]
        if row >= len(store)-1: return
        it = store.get_iter(paths[0])
        e, s, h = store.get_value(it, 0), store.get_value(it, 1), store.get_value(it, 2)
        store.remove(it)
        new_it = store.insert(row+1, [e, s, h])
        view.get_selection().select_iter(new_it)

    def _open_seq_editor(self, parent, seq_store, tree_iter):
        """
        Add/Edit a single Login-Action step.
        seq_store: Gtk.ListStore(str expect, str send, bool hide)
        tree_iter: iter to edit, or None to append new.
        """
        # --- FIX: Attach to the actual 'parent' dialog to avoid GTK structural crashes ---
        dlg = Gtk.Dialog(
            title="Edit Step" if tree_iter else "Add Step",
            transient_for=parent,
            modal=True,
            use_header_bar=0  # Forces GTK to build a traditional, crash-free button box
        )
        dlg.add_buttons(
            Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
            Gtk.STOCK_OK,     Gtk.ResponseType.OK
        )
        dlg.set_default_size(360, 160)
        dlg.set_resizable(False)
        
        # Set default response so Enter works smoothly
        dlg.set_default_response(Gtk.ResponseType.OK)
    
        box = dlg.get_content_area()
        box.set_margin_top(10)
        box.set_margin_bottom(10)
        box.set_margin_start(10)
        box.set_margin_end(10)
    
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        ent_exp = Gtk.Entry(); ent_exp.set_size_request(165, -1)
        ent_snd = Gtk.Entry(); ent_snd.set_size_request(165, -1)
        
        # Trigger OK when pressing Enter in these boxes
        ent_exp.set_activates_default(True)
        ent_snd.set_activates_default(True)
        
        row.pack_start(ent_exp, False, False, 0)
        row.pack_start(Gtk.Separator(orientation=Gtk.Orientation.VERTICAL), False, False, 0)
        row.pack_start(ent_snd, False, False, 0)
        box.pack_start(row, False, False, 0)
    
        mask_chk = Gtk.CheckButton(label="Hide Send Input")
        mask_chk.set_tooltip_text("When unselected, show and clear Send text")
        mask_chk.set_active(False)
        box.pack_start(mask_chk, False, False, 6)
    
        if tree_iter:
            e0 = seq_store.get_value(tree_iter, 0)
            s0 = seq_store.get_value(tree_iter, 1)
            h0 = seq_store.get_value(tree_iter, 2)
            ent_exp.set_text(e0)
            ent_snd.set_text(s0)
            mask_chk.set_active(h0)
    
        ent_snd.set_visibility(not mask_chk.get_active())
    
        def _on_mask_toggled(cb):
            ent_snd.set_visibility(not cb.get_active())
            if not cb.get_active():
                ent_snd.set_text("")
        mask_chk.connect("toggled", _on_mask_toggled)
    
        dlg.show_all()
        resp = dlg.run()
    
        if resp == Gtk.ResponseType.OK:
            exp_txt = ent_exp.get_text().strip()
            snd_txt = ent_snd.get_text()
            hide_fl = mask_chk.get_active()
            if tree_iter:
                seq_store.set(tree_iter, [0,1,2], [exp_txt, snd_txt, hide_fl])
            else:
                seq_store.append([exp_txt, snd_txt, hide_fl])
    
        dlg.destroy()

    def apply_appearance_to_terminal(self, terminal, cfg):
        """Apply font, colors, palette and scrollback to a Vte.Terminal."""
    
        # --- Font ---
        fontname = cfg.get("term_font", DEFAULT_TERM_FONT)
        if fontname:
            try:
                desc = Pango.FontDescription(fontname)
                terminal.set_font(desc)
            except Exception as e:
                self.log(f"Could not set font '{fontname}': {e}")
    
        # --- Foreground / Background ---
        fg = Gdk.RGBA(); fg.parse(cfg.get("term_fg", DEFAULT_TERM_FG))
        bg = Gdk.RGBA(); bg.parse(cfg.get("term_bg", DEFAULT_TERM_BG))
          
        # --- Palette selection ---
        pal_name = cfg.get("term_palette", DEFAULT_TERM_PALETTE)
        palette = []
    
        if pal_name == "Tango":
            # Tango 16‑color palette
            tango_hex = [
                "#2e3436", "#cc0000", "#4e9a06", "#c4a000",
                "#3465a4", "#75507b", "#06989a", "#d3d7cf",
                "#555753", "#ef2929", "#8ae234", "#fce94f",
                "#729fcf", "#ad7fa8", "#34e2e2", "#eeeeec",
            ]
            palette = [Gdk.RGBA() for _ in tango_hex]
            for i, h in enumerate(tango_hex):
                palette[i].parse(h)
    
        elif pal_name == "Solarized Light":
            solarized_light_hex = [
                "#073642", "#dc322f", "#859900", "#b58900",
                "#268bd2", "#d33682", "#2aa198", "#eee8d5",
                "#002b36", "#cb4b16", "#586e75", "#657b83",
                "#839496", "#6c71c4", "#93a1a1", "#fdf6e3",
            ]
            palette = [Gdk.RGBA() for _ in solarized_light_hex]
            for i, h in enumerate(solarized_light_hex):
                palette[i].parse(h)
    
        elif pal_name == "Solarized Dark":
            solarized_dark_hex = [
                "#073642", "#dc322f", "#859900", "#b58900",
                "#268bd2", "#d33682", "#2aa198", "#eee8d5",
                "#002b36", "#cb4b16", "#586e75", "#657b83",
                "#839496", "#6c71c4", "#93a1a1", "#fdf6e3",
            ]
            palette = [Gdk.RGBA() for _ in solarized_dark_hex]
            for i, h in enumerate(solarized_dark_hex):
                palette[i].parse(h)
    
        # "None" or unknown → leave palette empty to use VTE defaults
    
        # --- Apply colors ---
        try:
            terminal.set_colors(fg, bg, palette)
        except Exception as e:
            self.log(f"Could not set colors: {e}")
    
        # --- Scrollback ---
        terminal.set_scrollback_lines(cfg.get("term_scrollback", DEFAULT_TERM_SCROLLBACK))

    def _on_terminal_key_press(self, terminal, event):
            """
            Handles Ctrl+C (Smart Copy) and Ctrl+V (Paste) in the terminal.
            """
            # Check if Control key is held down
            if event.state & Gdk.ModifierType.CONTROL_MASK:
                
                # --- Handle Ctrl+C ---
                if event.keyval == Gdk.KEY_c:
                    # Smart Copy: Only copy if there is an active selection.
                    # If no selection, return False to let the default SIGINT (Interrupt) happen.
                    if terminal.get_has_selection():
                        terminal.copy_clipboard_format(Vte.Format.TEXT)
                        return True # Return True to consume the event (block SIGINT)
                
                # --- Handle Ctrl+V ---
                elif event.keyval == Gdk.KEY_v:
                    terminal.paste_clipboard()
                    return True # Return True to consume the event (block literal insert)
    
            # For all other keys, return False to let VTE handle them normally
            return False

    def _on_terminal_button_press(self, terminal, event):
            """
            Handles mouse clicks to show a context menu on right-click.
            """            
            # Check for Right Click (Button 3)
            if event.type == Gdk.EventType.BUTTON_PRESS and event.button == 3:
                menu = Gtk.Menu()
    
                # ── Copy Item ──
                # Only enable "Copy" if there is text selected
                copy_item = Gtk.MenuItem(label="Copy")
                if terminal.get_has_selection():
                    copy_item.set_sensitive(True)
                    copy_item.connect("activate", lambda w: terminal.copy_clipboard_format(Vte.Format.TEXT))
                else:
                    copy_item.set_sensitive(False)
                menu.append(copy_item)
    
                # ── Paste Item ──
                paste_item = Gtk.MenuItem(label="Paste")
                paste_item.connect("activate", lambda w: terminal.paste_clipboard())
                menu.append(paste_item)
    
                # ── Show Menu ──
                menu.show_all()
                # Use popup_at_pointer for modern GTK (3.22+)
                menu.popup_at_pointer(event)
                
                return True # Return True to stop other handlers from processing the click
            
            return False

    # ─── DIALOG HELPERS ────────────────────────────────────────────────────
    def ask_for_password(self, message):
        """Safely pops up a password entry dialog"""
        dialog = Gtk.MessageDialog(
            transient_for=None,
            flags=0,
            message_type=Gtk.MessageType.QUESTION,
            buttons=Gtk.ButtonsType.OK_CANCEL,
            text=message
        )
        
        # Create a hidden password entry field
        entry = Gtk.Entry()
        entry.set_visibility(False)  # Hides text as dots
        
        # --- FIX: Trigger OK when pressing Enter ---
        entry.set_activates_default(True)
        dialog.set_default_response(Gtk.ResponseType.OK)
        
        box = dialog.get_message_area()
        box.pack_start(entry, True, True, 10)
        dialog.show_all()
        
        response = dialog.run()
        password = entry.get_text() if response == Gtk.ResponseType.OK else None
        dialog.destroy()
        return password

    def show_info_dialog(self, title, message):
        """Safely shows a GUI info message"""
        dialog = Gtk.MessageDialog(
            transient_for=None,
            flags=0,
            message_type=Gtk.MessageType.INFO,
            buttons=Gtk.ButtonsType.OK,
            text=title
        )
        dialog.format_secondary_text(message)
        dialog.run()
        dialog.destroy()

# ── main() ─────────────────────────────────────────────────────────────────────────────

def main():
    app = ScarpaConnectionManager()
    sys.exit(app.run(sys.argv))


if __name__ == "__main__":
    main()
