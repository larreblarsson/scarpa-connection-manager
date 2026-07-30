#!/usr/bin/env python3
import sys
import os
import json
import time
import subprocess
import gi

gi.require_version('Gtk', '3.0')
from gi.repository import Gtk, Gdk, GLib, Pango

# ---------------------------------------------------------
# Configuration Paths
# ---------------------------------------------------------
CONFIG_DIR = os.path.expanduser("~/.local/share/scarpa_connection_manager")
CONFIG_FILE = os.path.join(CONFIG_DIR, "mirror_settings.json")

# ---------------------------------------------------------
# Unified GTK CSS Theme
# ---------------------------------------------------------
GTK_CSS = b"""
window {
    background-color: #f2f2f2;
    color: #2b2b2b;
}
list {
    background-color: #ffffff;
    border: 1px solid #b5b5b5;
    border-radius: 6px;
    padding: 4px;
}
row {
    background-color: #ffffff;
    border: 1px solid #dcdcdc;
    border-radius: 5px;
    margin-bottom: 4px;
    padding: 8px;
}
row:selected {
    background-color: #e5eaf0;
    color: #000000;
    border: 1px solid #adadad;
}
button:not(.titlebutton) {
    background-color: #fcfcfc;
    border: 1px solid #adadad;
    border-radius: 4px;
    padding: 5px 14px;
    color: #2b2b2b;
}
button:not(.titlebutton):hover {
    background-color: #e8e8e8;
    border: 1px solid #7a7a7a;
}
button:not(.titlebutton):active {
    background-color: #d4d4d4;
}
button:not(.titlebutton):disabled {
    background-color: #ebebeb;
    color: #a0a0a0;
    border: 1px solid #d0d0d0;
}

/* 1. Style standard text entries */
entry {
    background-color: #ffffff;
    border: 1px solid #adadad;
    border-radius: 4px;
    padding: 5px 8px;
    min-height: 26px;
    box-shadow: none; /* This removes the sneaky inner shadow! */
}

/* 2. Strip the double-border from the outer combobox container */
combobox {
    background: transparent;
    border: none;
    padding: 0;
}

/* 3. Style the internal dropdown button to match the text entries exactly */
combobox button {
    background-color: #ffffff;
    border: 1px solid #adadad;
    border-radius: 4px;
    padding: 5px 8px;
    min-height: 26px;
}
"""

def apply_css():
    css_provider = Gtk.CssProvider()
    css_provider.load_from_data(GTK_CSS)
    Gtk.StyleContext.add_provider_for_screen(
        Gdk.Screen.get_default(),
        css_provider,
        Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
    )

# ---------------------------------------------------------
# UI Components
# ---------------------------------------------------------
class DeviceSettingsDialog(Gtk.Dialog):
    def __init__(self, hardware_serial, current_config, active_adb_id, parent=None):
        super().__init__(title="Device Settings", transient_for=parent, flags=0)
        self.set_default_size(420, 370)
        self.set_modal(True)
        # Enable HeaderBar for the dialog
        self.set_type_hint(Gdk.WindowTypeHint.DIALOG)
        
        self.hardware_serial = hardware_serial
        self.config = current_config.copy()
        self.active_adb_id = active_adb_id
        
        # Capture the cancel button so we can shift focus to it later
        self.btn_cancel = self.add_button("Cancel", Gtk.ResponseType.CANCEL)
        self.add_button("Save", Gtk.ResponseType.ACCEPT)
        
        self.initUI()

    def initUI(self):
        box = self.get_content_area()
        box.set_spacing(10)
        box.set_margin_top(15)
        box.set_margin_bottom(15)
        box.set_margin_start(15)
        box.set_margin_end(15)

        grid = Gtk.Grid(row_spacing=10, column_spacing=10)
        box.pack_start(grid, False, False, 0)

        # Name Entry - Removed "/ Alias" from the label
        lbl_name = Gtk.Label(label="Device Name:", xalign=0)
        self.name_entry = Gtk.Entry()
        self.name_entry.set_text(self.config.get('name', ''))
        self.name_entry.set_placeholder_text(self.hardware_serial)
        self.name_entry.set_hexpand(True)
        grid.attach(lbl_name, 0, 0, 1, 1)
        grid.attach(self.name_entry, 1, 0, 1, 1)

        # Bitrate ComboBox
        lbl_bitrate = Gtk.Label(label="Video Bitrate:", xalign=0)
        self.bitrate_cb = Gtk.ComboBoxText()
        for br in ["Default", "16M", "8M", "4M", "2M"]:
            self.bitrate_cb.append_text(br)
        self.bitrate_cb.set_active_id(self.config.get('bitrate', 'Default'))
        if self.bitrate_cb.get_active() == -1:
            self.bitrate_cb.set_active(0)
        grid.attach(lbl_bitrate, 0, 1, 1, 1)
        grid.attach(self.bitrate_cb, 1, 1, 1, 1)

        # Resolution ComboBox
        lbl_res = Gtk.Label(label="Max Resolution:", xalign=0)
        self.res_cb = Gtk.ComboBoxText()
        for res in ["Default", "1920", "1080", "720", "480"]:
            self.res_cb.append_text(res)
        self.res_cb.set_active_id(self.config.get('resolution', 'Default'))
        if self.res_cb.get_active() == -1:
            self.res_cb.set_active(0)
        grid.attach(lbl_res, 0, 2, 1, 1)
        grid.attach(self.res_cb, 1, 2, 1, 1)

        # Checkboxes
        self.screen_off_chk = Gtk.CheckButton(label="Turn device screen off while mirroring")
        self.screen_off_chk.set_active(self.config.get('screen_off', False))
        grid.attach(self.screen_off_chk, 1, 3, 1, 1)

        self.audio_chk = Gtk.CheckButton(label="Enable Audio Relay")
        self.audio_chk.set_active(self.config.get('audio', True))
        grid.attach(self.audio_chk, 1, 4, 1, 1)
        
        # Wireless Setup Button
        self.wifi_btn = Gtk.Button(label="Setup Wireless Connection")
        self.wifi_btn.set_tooltip_text("Click while connected via USB to establish a wireless bridge.")
        if not self.active_adb_id or ":" in self.active_adb_id:
            self.wifi_btn.set_sensitive(False)
            self.wifi_btn.set_label("Wireless Setup (Connect via USB first)")
        else:
            self.wifi_btn.connect("clicked", self.setup_wireless)
        box.pack_start(self.wifi_btn, False, False, 10)
        
        # Forget Device Button
        self.forget_btn = Gtk.Button(label="Forget Device")
        self.forget_btn.set_tooltip_text("Remove this device from the saved list permanently.")
        self.forget_btn.connect("clicked", self.forget_device)
        box.pack_start(self.forget_btn, False, False, 0)
        
        self.show_all()
        
        # Defer the focus shift until AFTER the dialog fully opens and runs
        # We also move the cursor to the end of the text just to be safe!
        self.name_entry.set_position(-1)
        GLib.idle_add(self.btn_cancel.grab_focus)

    def update_config_from_ui(self):
        self.config['name'] = self.name_entry.get_text().strip()
        self.config['bitrate'] = self.bitrate_cb.get_active_text()
        self.config['resolution'] = self.res_cb.get_active_text()
        self.config['screen_off'] = self.screen_off_chk.get_active()
        self.config['audio'] = self.audio_chk.get_active()

    def forget_device(self, btn):
        dialog = Gtk.MessageDialog(
            transient_for=self,
            flags=0,
            message_type=Gtk.MessageType.QUESTION,
            buttons=Gtk.ButtonsType.YES_NO,
            text="Forget Device"
        )
        dialog.format_secondary_text("Are you sure you want to remove this device from your saved list?")
        response = dialog.run()
        dialog.destroy()
        
        if response == Gtk.ResponseType.YES:
            self.config['_delete_flag'] = True
            self.response(Gtk.ResponseType.ACCEPT)

    def setup_wireless(self, btn):
        dialog = Gtk.MessageDialog(
            transient_for=self,
            flags=0,
            message_type=Gtk.MessageType.QUESTION,
            buttons=Gtk.ButtonsType.YES_NO,
            text="Wireless Setup"
        )
        dialog.format_secondary_text("Ensure the device is connected to the same Wi-Fi network as this PC.\n\nThis will read the device IP and bridge the connection over Wi-Fi. Proceed?")
        response = dialog.run()
        dialog.destroy()
        
        if response == Gtk.ResponseType.YES:
            try:
                subprocess.run(['adb', '-s', self.active_adb_id, 'tcpip', '5555'], check=True)
                time.sleep(1.5)
                
                ip_result = subprocess.run(['adb', '-s', self.active_adb_id, 'shell', 'ip', 'route'], 
                                           capture_output=True, text=True, check=True)
                
                ip_address = None
                for line in ip_result.stdout.split('\n'):
                    if 'src ' in line and ('wlan' in line):
                        parts = line.split()
                        try:
                            src_index = parts.index('src')
                            ip_address = parts[src_index + 1]
                            break
                        except (ValueError, IndexError):
                            pass
                
                if ip_address:
                    subprocess.run(['adb', 'connect', f'{ip_address}:5555'], check=True)
                    info_dialog = Gtk.MessageDialog(transient_for=self, message_type=Gtk.MessageType.INFO, buttons=Gtk.ButtonsType.OK, text="Success")
                    info_dialog.format_secondary_text(f"Bridged to {ip_address}:5555.\n\nYou can now safely unplug your USB cable. The list will update automatically!")
                    info_dialog.run()
                    info_dialog.destroy()
                    self.response(Gtk.ResponseType.ACCEPT)
                else:
                    warn_dialog = Gtk.MessageDialog(transient_for=self, message_type=Gtk.MessageType.WARNING, buttons=Gtk.ButtonsType.OK, text="Warning")
                    warn_dialog.format_secondary_text("Enabled TCP/IP, but could not read the phone's Wi-Fi IP address. Make sure the phone is connected to Wi-Fi.")
                    warn_dialog.run()
                    warn_dialog.destroy()
                    
            except Exception as e:
                err_dialog = Gtk.MessageDialog(transient_for=self, message_type=Gtk.MessageType.ERROR, buttons=Gtk.ButtonsType.OK, text="Error")
                err_dialog.format_secondary_text(f"Failed to setup wireless mode:\n{e}")
                err_dialog.run()
                err_dialog.destroy()

class ScarpaMirrorApp(Gtk.Window):
    def __init__(self):
        super().__init__(title="Scarpa Android Mirror")
        self.set_default_size(680, 480)
        
        # Setup HeaderBar
        self.header = Gtk.HeaderBar()
        self.header.set_show_close_button(True)
        self.header.set_title("Saved & Connected Devices")
        self.set_titlebar(self.header)
        
        self.refresh_btn = Gtk.Button(label="Manual Refresh")
        self.refresh_btn.connect("clicked", lambda x: self.refresh_devices(force=True))
        self.header.pack_end(self.refresh_btn)

        self.device_configs = {}
        self.last_active_map = None  
        
        self.load_settings()
        self.initUI()
        
        self.refresh_devices(force=True)

        # Replaces QTimer
        GLib.timeout_add(2000, self.refresh_devices)

    def load_settings(self):
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, 'r') as f:
                    self.device_configs = json.load(f)
            except Exception as e:
                print(f"Error loading config: {e}")

    def save_settings(self):
        os.makedirs(CONFIG_DIR, exist_ok=True)
        try:
            with open(CONFIG_FILE, 'w') as f:
                json.dump(self.device_configs, f, indent=4)
        except Exception as e:
            print(f"Error saving config: {e}")

    def initUI(self):
        # Set spacing to 0 and removed margins so the list sits flush against the window edges
        vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self.add(vbox)

        # Replaces QListWidget with Gtk.ListBox
        self.device_list = Gtk.ListBox()
        self.device_list.set_selection_mode(Gtk.SelectionMode.NONE)
        
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scrolled.add(self.device_list)
        vbox.pack_start(scrolled, True, True, 0)

    def _get_hardware_serial(self, adb_id):
        try:
            res = subprocess.run(['adb', '-s', adb_id, 'shell', 'getprop', 'ro.serialno'],
                                 capture_output=True, text=True, timeout=5)
            if res.returncode == 0 and res.stdout.strip():
                return res.stdout.strip()
        except:
            pass
        return adb_id 

    def refresh_devices(self, force=False):
        active_map = {} 

        try:
            result = subprocess.run(['adb', 'devices'], capture_output=True, text=True, check=True)
            for line in result.stdout.strip().split('\n')[1:]:
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 2 and parts[1] == 'device':
                        adb_id = parts[0]
                        hw_serial = self._get_hardware_serial(adb_id)
                        
                        if hw_serial not in active_map:
                            active_map[hw_serial] = {'usb': None, 'wifi': None}
                            
                        if ":" in adb_id:
                            active_map[hw_serial]['wifi'] = adb_id
                        else:
                            active_map[hw_serial]['usb'] = adb_id

            if not force and active_map == self.last_active_map:
                return True # Keep the timer running
                
            self.last_active_map = active_map

            for hw_serial in active_map:
                if hw_serial not in self.device_configs:
                    self.device_configs[hw_serial] = {
                        'name': '',
                        'bitrate': 'Default',
                        'resolution': 'Default',
                        'screen_off': False,
                        'audio': True
                    }
            if force:
                self.save_settings()

            # Clear the list
            for child in self.device_list.get_children():
                self.device_list.remove(child)

            sorted_serials = sorted(self.device_configs.keys(), 
                                    key=lambda s: 0 if s in active_map else 1)

            for serial in sorted_serials:
                conf = self.device_configs[serial]
                active_info = active_map.get(serial)
                self.add_device_row(serial, conf, active_info)

            if not self.device_configs:
                lbl = Gtk.Label(label="  No devices found or saved yet. Connect via USB to begin.", xalign=0)
                lbl.set_margin_top(15)
                lbl.set_margin_bottom(15)
                self.device_list.add(lbl)

            self.device_list.show_all()

        except Exception as e:
            if force:
                err_dialog = Gtk.MessageDialog(transient_for=self, message_type=Gtk.MessageType.ERROR, buttons=Gtk.ButtonsType.OK, text="Error")
                err_dialog.format_secondary_text(f"Failed to run 'adb devices':\n{e}")
                err_dialog.run()
                err_dialog.destroy()
                
        return True # Keep the timer running

    def add_device_row(self, hardware_serial, config, active_info):
        row = Gtk.ListBoxRow()
        hbox = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=15)
        hbox.set_margin_top(8)
        hbox.set_margin_bottom(8)
        hbox.set_margin_start(10)
        hbox.set_margin_end(10)
        row.add(hbox)

        # Mobile Device Icon
        icon = Gtk.Image.new_from_icon_name("smartphone", Gtk.IconSize.DND)
        hbox.pack_start(icon, False, False, 0)

        # Stacked Layout for text
        vbox_text = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        
        display_name = config.get('name') or hardware_serial
        title_label = Gtk.Label(label=f"<b>{display_name}</b>", use_markup=True, xalign=0)
        vbox_text.pack_start(title_label, False, False, 0)

        connect_id = None
        if active_info:
            connect_id = active_info.get('usb') or active_info.get('wifi')
            if active_info.get('usb') and active_info.get('wifi'):
                # The & must be escaped as &amp; for GTK's Pango markup
                status_text = "USB &amp; Wi-Fi"
            elif active_info.get('usb'):
                status_text = "USB"
            else:
                status_text = "Wi-Fi"
            status_color = "#2e8b57"
        else:
            status_text = "❌ Offline"
            status_color = "#888888"

        status_label = Gtk.Label(label=f"<span foreground='{status_color}'>{status_text}</span>", use_markup=True, xalign=0)
        vbox_text.pack_start(status_label, False, False, 0)
        
        hbox.pack_start(vbox_text, True, True, 0)

        # Buttons
        connect_btn = Gtk.Button(label="Connect")
        connect_btn.set_sensitive(connect_id is not None)
        connect_btn.connect("clicked", lambda x: self.launch_mirror(hardware_serial, connect_id))
        hbox.pack_start(connect_btn, False, False, 0)

        edit_btn = Gtk.Button(label="Edit")
        edit_btn.connect("clicked", lambda x: self.open_device_settings(hardware_serial, connect_id))
        hbox.pack_start(edit_btn, False, False, 0)

        self.device_list.add(row)

    def launch_mirror(self, hardware_serial, connect_id):
        config = self.device_configs.get(hardware_serial, {})
        
        cmd = ['scrcpy', '-s', connect_id]
        
        if config.get('bitrate', 'Default') != 'Default':
            cmd.extend(['--video-bit-rate', config['bitrate']])
        if config.get('resolution', 'Default') != 'Default':
            cmd.extend(['--max-size', config['resolution']])
        if config.get('screen_off'):
            cmd.append('--turn-screen-off')
        if not config.get('audio', True):
            cmd.append('--no-audio')

        try:
            subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except FileNotFoundError:
            err = Gtk.MessageDialog(transient_for=self, message_type=Gtk.MessageType.ERROR, buttons=Gtk.ButtonsType.OK, text="Error")
            err.format_secondary_text("scrcpy command not found. Is it installed?")
            err.run()
            err.destroy()
        except Exception as e:
            err = Gtk.MessageDialog(transient_for=self, message_type=Gtk.MessageType.ERROR, buttons=Gtk.ButtonsType.OK, text="Error")
            err.format_secondary_text(f"Could not start scrcpy:\n{e}")
            err.run()
            err.destroy()

    def open_device_settings(self, hardware_serial, active_adb_id):
        current_config = self.device_configs.get(hardware_serial, {})
        
        dialog = DeviceSettingsDialog(hardware_serial, current_config, active_adb_id, self)
        response = dialog.run()
        
        if response == Gtk.ResponseType.ACCEPT:
            dialog.update_config_from_ui()
            if dialog.config.get('_delete_flag'):
                if hardware_serial in self.device_configs:
                    del self.device_configs[hardware_serial]
            else:
                self.device_configs[hardware_serial] = dialog.config
            
            self.save_settings()
            self.refresh_devices(force=True)
            
        dialog.destroy()

if __name__ == '__main__':
    apply_css()
    app = ScarpaMirrorApp()
    app.connect("destroy", Gtk.main_quit)
    app.show_all()
    Gtk.main()
