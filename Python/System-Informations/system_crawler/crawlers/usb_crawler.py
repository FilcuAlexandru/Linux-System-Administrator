#!/usr/bin/env python3.6
# -*- coding: utf-8 -*-

#########################################################################################################################
# A Python 3.6 script that verifies USB device informations on a Linux server.                                          #
# The script verifies the following: USB devices, USB hubs, device manufacturers, USB versions, and USB device details. #
# Version: 0.0.1                                                                                                        #
# Author: Alexandru Filcu                                                                                               #
#########################################################################################################################

######################
# Import handy tools #
######################

import subprocess
import sys
import json
from collections import OrderedDict


class USBCrawler:
    """Class for collecting USB device information"""
    
    def __init__(self):
        self.info = OrderedDict()
    
    def run_command(self, command, shell=False):
        """Execute a shell command and return the output"""
        try:
            result = subprocess.Popen(
                command,
                shell=shell,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            stdout, stderr = result.communicate()
            
            if result.returncode != 0:
                return None
            
            return stdout.strip() if stdout else "N/A"
        
        except Exception as e:
            return None
    
    def get_usb_devices_lsusb(self):
        """Get USB devices from lsusb"""
        usb_devices = OrderedDict()
        
        # Check if lsusb is available
        lsusb_check = self.run_command("which lsusb", shell=True)
        
        if lsusb_check:
            # Get all USB devices
            usb_list = self.run_command("lsusb", shell=True)
            usb_devices['usb_devices_list'] = usb_list if usb_list else "N/A"
            
            # Get detailed USB device information
            usb_detailed = self.run_command("lsusb -v", shell=True)
            usb_devices['usb_devices_verbose'] = usb_detailed if usb_detailed else "N/A"
            
            # Get USB tree view
            usb_tree = self.run_command("lsusb -t", shell=True)
            usb_devices['usb_devices_tree'] = usb_tree if usb_tree else "N/A"
        else:
            usb_devices['usb_devices_list'] = "lsusb not available"
            usb_devices['usb_devices_verbose'] = "lsusb not available"
            usb_devices['usb_devices_tree'] = "lsusb not available"
        
        self.info['lsusb_info'] = usb_devices
    
    def get_usb_devices_lspci(self):
        """Get USB controllers from lspci"""
        usb_pci = OrderedDict()
        
        # Get USB devices from lspci
        usb_controllers = self.run_command("lspci | grep -i usb", shell=True)
        usb_pci['usb_controllers'] = usb_controllers if usb_controllers else "N/A"
        
        # Get detailed USB controller info
        usb_detailed = self.run_command("lspci -k | grep -A 2 -i usb", shell=True)
        usb_pci['usb_controllers_detailed'] = usb_detailed if usb_detailed else "N/A"
        
        self.info['usb_pci_info'] = usb_pci
    
    def get_usb_kernel_modules(self):
        """Get loaded USB kernel modules"""
        usb_modules = OrderedDict()
        
        # Check for USB host controller drivers
        uhci_driver = self.run_command("lsmod | grep -i uhci", shell=True)
        usb_modules['uhci_hcd'] = uhci_driver if uhci_driver else "Not loaded"
        
        # Check for EHCI driver
        ehci_driver = self.run_command("lsmod | grep -i ehci", shell=True)
        usb_modules['ehci_hcd'] = ehci_driver if ehci_driver else "Not loaded"
        
        # Check for XHCI driver
        xhci_driver = self.run_command("lsmod | grep -i xhci", shell=True)
        usb_modules['xhci_hcd'] = xhci_driver if xhci_driver else "Not loaded"
        
        # Check for USB core
        usb_core = self.run_command("lsmod | grep -i '^usb'", shell=True)
        usb_modules['usb_core'] = usb_core if usb_core else "Not loaded"
        
        # Check for USB storage
        usb_storage = self.run_command("lsmod | grep -i usb_storage", shell=True)
        usb_modules['usb_storage'] = usb_storage if usb_storage else "Not loaded"
        
        # Check for USB HID
        usb_hid = self.run_command("lsmod | grep -i usbhid", shell=True)
        usb_modules['usbhid'] = usb_hid if usb_hid else "Not loaded"
        
        self.info['usb_kernel_modules'] = usb_modules
    
    def get_usb_sysfs_info(self):
        """Get USB information from sysfs"""
        usb_sysfs = OrderedDict()
        
        # Get USB device list from sysfs
        usb_device_list = self.run_command("ls -la /sys/bus/usb/devices/", shell=True)
        usb_sysfs['usb_devices_sysfs'] = usb_device_list if usb_device_list else "N/A"
        
        # Get USB host info
        usb_hosts = self.run_command("ls -la /sys/bus/usb/devices/ | grep usb", shell=True)
        usb_sysfs['usb_hosts'] = usb_hosts if usb_hosts else "N/A"
        
        self.info['usb_sysfs_info'] = usb_sysfs
    
    def get_usb_device_count(self):
        """Get total USB device count"""
        usb_count = self.run_command("lsusb 2>/dev/null | wc -l", shell=True)
        self.info['total_usb_devices'] = usb_count if usb_count else "N/A"
    
    def get_usb_hubs_count(self):
        """Get total USB hubs count"""
        hub_count = self.run_command("lsusb | grep -i hub | wc -l", shell=True)
        self.info['total_usb_hubs'] = hub_count if hub_count else "N/A"
    
    def get_usb_storage_devices(self):
        """Get USB storage devices"""
        storage_devices = OrderedDict()
        
        # Get USB block devices
        usb_block = self.run_command("lsblk -S", shell=True)
        storage_devices['usb_block_devices'] = usb_block if usb_block else "N/A"
        
        # Get mounted USB devices
        usb_mounts = self.run_command("mount | grep -i 'usb\\|removable'", shell=True)
        storage_devices['usb_mounted'] = usb_mounts if usb_mounts else "N/A"
        
        # Get /proc/partitions
        partitions = self.run_command("cat /proc/partitions | grep -E 'sd[a-z]'", shell=True)
        storage_devices['partitions'] = partitions if partitions else "N/A"
        
        self.info['usb_storage_devices'] = storage_devices
    
    def get_usb_tty_devices(self):
        """Get USB TTY/Serial devices"""
        usb_tty = self.run_command("ls -la /dev/ttyUSB* 2>/dev/null || echo 'No USB TTY devices found'", shell=True)
        self.info['usb_tty_devices'] = usb_tty if usb_tty else "N/A"
    
    def get_dmesg_usb_info(self):
        """Get USB information from dmesg"""
        dmesg_usb = self.run_command("dmesg | grep -i 'usb' | tail -30", shell=True)
        self.info['dmesg_usb_info'] = dmesg_usb if dmesg_usb else "N/A"
    
    def get_usb_speed_info(self):
        """Get USB speed information"""
        speed_info = OrderedDict()
        
        # Get USB version info from lsusb
        usb_version = self.run_command("lsusb -v 2>/dev/null | grep -i 'bcdUSB\\|USB Version' | head -10", shell=True)
        speed_info['usb_versions'] = usb_version if usb_version else "N/A"
        
        self.info['usb_speed_info'] = speed_info
    
    def get_usb_bus_info(self):
        """Get USB bus information"""
        bus_info = OrderedDict()
        
        # Get USB bus structure
        usb_bus = self.run_command("cat /proc/bus/usb/devices", shell=True)
        bus_info['usb_bus_devices'] = usb_bus if usb_bus else "N/A"
        
        self.info['usb_bus_info'] = bus_info
    
    def gather_all_info(self):
        """Collect all USB device information"""
        print("[*] Gathering USB device information...")
        
        self.get_usb_device_count()
        print("    [+] Total USB devices count - OK")
        
        self.get_usb_hubs_count()
        print("    [+] USB hubs count - OK")
        
        self.get_usb_devices_lsusb()
        print("    [+] lsusb info - OK")
        
        self.get_usb_devices_lspci()
        print("    [+] USB PCI info - OK")
        
        self.get_usb_kernel_modules()
        print("    [+] USB kernel modules - OK")
        
        self.get_usb_sysfs_info()
        print("    [+] USB sysfs info - OK")
        
        self.get_usb_storage_devices()
        print("    [+] USB storage devices - OK")
        
        self.get_usb_tty_devices()
        print("    [+] USB TTY devices - OK")
        
        self.get_usb_speed_info()
        print("    [+] USB speed info - OK")
        
        self.get_usb_bus_info()
        print("    [+] USB bus info - OK")
        
        self.get_dmesg_usb_info()
        print("    [+] dmesg USB info - OK")
        
        print("[*] Information gathering completed!\n")
    
    def get_info(self, key=None):
        """Return information"""
        if key is None:
            return self.info
        return self.info.get(key, "N/A")
    
    def display_info(self, verbose=True):
        """Display collected information"""
        print("╔" + "═" * 78 + "╗")
        print("║" + " USB INFORMATIONS REPORT ".center(78) + "║")
        print("╚" + "═" * 78 + "╝")
        
        for key, value in self.info.items():
            print("\n[{}]".format(key.upper().replace('_', ' ')))
            print("-" * 80)
            
            if isinstance(value, dict):
                # Display nested dictionary
                for sub_key, sub_value in value.items():
                    print("\n  {}:".format(sub_key.upper().replace('_', ' ')))
                    if verbose:
                        print("  {}".format(sub_value.replace('\n', '\n  ') if isinstance(sub_value, str) else str(sub_value)))
                    else:
                        if isinstance(sub_value, str):
                            first_line = sub_value.split('\n')[0] if sub_value else "N/A"
                        else:
                            first_line = str(sub_value)
                        print("  {}".format(first_line))
            else:
                if verbose:
                    print(value)
                else:
                    # Display only first line for compact mode
                    first_line = value.split('\n')[0] if isinstance(value, str) else str(value)
                    print(first_line)
    
    def export_to_dict(self):
        """Export information to a dictionary"""
        return dict(self.info)
    
    def export_to_json(self, pretty=True, output_file=None):
        """Export information to JSON format"""
        # Flatten nested OrderedDict/dict to ensure JSON serialization
        data = self._flatten_for_json(self.info)
        
        if pretty:
            json_output = json.dumps(data, indent=2)
        else:
            json_output = json.dumps(data)
        
        if output_file:
            try:
                with open(output_file, 'w') as f:
                    f.write(json_output)
                print("[+] JSON output written to: {}".format(output_file))
                return None
            except Exception as e:
                print("[-] Error writing to file: {}".format(str(e)))
                return json_output
        else:
            return json_output
    
    def _flatten_for_json(self, obj):
        """Convert OrderedDict and nested structures to regular dicts for JSON"""
        if isinstance(obj, OrderedDict):
            return {k: self._flatten_for_json(v) for k, v in obj.items()}
        elif isinstance(obj, dict):
            return {k: self._flatten_for_json(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._flatten_for_json(item) for item in obj]
        else:
            return obj


def main():
    """Main function"""
    crawler = USBCrawler()
    crawler.gather_all_info()
    crawler.display_info(verbose=True)
    
    return crawler


if __name__ == "__main__":
    main()