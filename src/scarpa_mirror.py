#!/usr/bin/env python3
import sys
import subprocess
from PyQt5.QtWidgets import (QApplication, QWidget, QVBoxLayout,
                             QHBoxLayout, QComboBox, QPushButton, QLabel, QMessageBox)

class MirrorManagerApp(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.refresh_devices()

    def initUI(self):
        self.setWindowTitle('Android Mirror Manager')
        # Made the window slightly taller to fit the new button
        self.setFixedSize(350, 180)

        layout = QVBoxLayout()

        # Device Selection Area
        self.label = QLabel("Select Android Device:")
        layout.addWidget(self.label)

        h_layout = QHBoxLayout()
        self.device_combo = QComboBox()
        h_layout.addWidget(self.device_combo)

        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self.refresh_devices)
        h_layout.addWidget(self.refresh_btn)

        layout.addLayout(h_layout)

        # Standard USB Connect
        self.connect_btn = QPushButton("Connect (USB / Active Wi-Fi)")
        self.connect_btn.clicked.connect(self.connect_device)
        layout.addWidget(self.connect_btn)

        # New Wireless Setup Button
        self.wifi_btn = QPushButton("Setup Wireless Connection")
        self.wifi_btn.setToolTip("Connect via USB first, click this, then you can unplug.")
        self.wifi_btn.clicked.connect(self.setup_wireless)
        layout.addWidget(self.wifi_btn)

        self.setLayout(layout)

    def refresh_devices(self):
        """Runs 'adb devices' and populates the dropdown."""
        self.device_combo.clear()
        try:
            result = subprocess.run(['adb', 'devices'], capture_output=True, text=True, check=True)
            lines = result.stdout.strip().split('\n')
            
            devices_found = False
            
            for line in lines[1:]:
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 2 and parts[1] == 'device':
                        device_id = parts[0]
                        self.device_combo.addItem(device_id)
                        devices_found = True
            
            if not devices_found:
                self.device_combo.addItem("No devices found")
                self.connect_btn.setEnabled(False)
                self.wifi_btn.setEnabled(False)
            else:
                self.connect_btn.setEnabled(True)
                self.wifi_btn.setEnabled(True)
                
        except Exception as e:
            self.device_combo.addItem(f"Error: ADB not found or failed")
            self.connect_btn.setEnabled(False)
            self.wifi_btn.setEnabled(False)

    def connect_device(self):
        """Launches scrcpy targeting the selected device ID."""
        selected_device = self.device_combo.currentText()
        if selected_device and "Error" not in selected_device and "found" not in selected_device:
            try:
                subprocess.Popen(['scrcpy', '-s', selected_device])
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Could not start scrcpy:\n{e}")

    def setup_wireless(self):
        """Uses scrcpy's built-in --tcpip flag to automate wireless setup."""
        selected_device = self.device_combo.currentText()
        if selected_device and "Error" not in selected_device and "found" not in selected_device:
            
            # Show a helpful reminder dialog
            reply = QMessageBox.question(self, 'Wireless Setup', 
                                         "Ensure your phone is plugged in via USB right now.\n\n"
                                         "Once the stream starts, you can unplug the USB cable.\n\n"
                                         "Proceed?", 
                                         QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes)
            
            if reply == QMessageBox.Yes:
                try:
                    # Launch scrcpy with the tcpip flag targeted at the USB device
                    subprocess.Popen(['scrcpy', '-s', selected_device, '--tcpip'])
                except Exception as e:
                    QMessageBox.critical(self, "Error", f"Could not start wireless setup:\n{e}")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    manager = MirrorManagerApp()
    manager.show()
    sys.exit(app.exec_())
