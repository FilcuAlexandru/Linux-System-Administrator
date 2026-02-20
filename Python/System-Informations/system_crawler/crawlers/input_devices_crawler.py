#!/usr/bin/env python3.6
# -*- coding: utf-8 -*-

######################################################################################################
# A PYTHON 3.6 SCRIPT THAT CRAWLS INPUT DEVICE INFORMATION ON LINUX SYSTEMS.                         #
# THE SCRIPT CRAWLS KEYBOARDS, MICE, TOUCHPADS, INPUT DEVICES, HID DEVICES, AND INPUT CONFIGURATION. #
# THE SCRIPT DISPLAYS THE COLLECTED INFORMATION AS JSON OUTPUT.                                      #
# VERSION: 0.0.1                                                                                     #
# AUTHOR: ALEXANDRU FILCU                                                                            #
######################################################################################################

######################
# Import handy tools #
######################

import subprocess
import sys
import json
from collections import OrderedDict


class InputDevicesCrawler:
    """Class for collecting Input device information"""
    
    def __init__(self):
        self.info = OrderedDict()
        self.is_vmware = self._detect_vmware()
    
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
    
    def _detect_vmware(self):
        """Detect if running on VMware"""
        systemd_virt = self.run_command("systemd-detect-virt", shell=True)
        return systemd_virt == "vmware" if systemd_virt else False
    
    def get_input_devices_pci(self):
        """Get input devices from PCI"""
        input_pci = OrderedDict()
        
        # Get keyboard devices from lspci
        keyboard_devices = self.run_command("lspci | grep -i 'keyboard'", shell=True)
        input_pci['keyboard_devices'] = keyboard_devices if keyboard_devices else "N/A"
        
        # Get mouse devices from lspci
        mouse_devices = self.run_command("lspci | grep -i 'mouse'", shell=True)
        input_pci['mouse_devices'] = mouse_devices if mouse_devices else "N/A"
        
        # Get input controller devices
        input_controllers = self.run_command("lspci | grep -i 'input'", shell=True)
        input_pci['input_controllers'] = input_controllers if input_controllers else "N/A"
        
        self.info['input_devices_pci'] = input_pci
    
    def get_input_devices_usb(self):
        """Get USB input devices"""
        usb_input = OrderedDict()
        
        # Get USB input devices from lsusb
        usb_devices = self.run_command("lsusb | grep -i 'keyboard\\|mouse\\|hid\\|input'", shell=True)
        usb_input['usb_input_devices'] = usb_devices if usb_devices else "N/A"
        
        # Get detailed USB input info
        usb_detailed = self.run_command("lsusb -v 2>/dev/null | grep -A 5 -i 'keyboard\\|mouse\\|hid' | head -30", shell=True)
        usb_input['usb_input_devices_detailed'] = usb_detailed if usb_detailed else "N/A"
        
        self.info['usb_input_devices'] = usb_input
    
    def get_input_devices_dev(self):
        """Get input devices from /dev"""
        dev_input = OrderedDict()
        
        # Get input devices list
        input_list = self.run_command("ls -la /dev/input/", shell=True)
        dev_input['input_devices_dev'] = input_list if input_list else "N/A"
        
        # Get keyboard devices
        keyboard_dev = self.run_command("ls -la /dev/input/ | grep -i 'event'", shell=True)
        dev_input['event_devices'] = keyboard_dev if keyboard_dev else "N/A"
        
        # Get mouse devices
        mouse_dev = self.run_command("ls -la /dev/input/mouse*", shell=True)
        dev_input['mouse_devices'] = mouse_dev if mouse_dev else "N/A"
        
        self.info['input_devices_dev'] = dev_input
    
    def get_input_devices_sysfs(self):
        """Get input devices from sysfs"""
        sysfs_input = OrderedDict()
        
        # Get input devices from sysfs
        sysfs_list = self.run_command("ls /sys/class/input/", shell=True)
        sysfs_input['input_devices_sysfs'] = sysfs_list if sysfs_list else "N/A"
        
        # Get detailed device info
        detailed_info = self.run_command("for device in /sys/class/input/input*; do echo \"Device: $(basename $device) - Name: $(cat $device/name 2>/dev/null || echo 'N/A')\"; done", shell=True)
        sysfs_input['input_devices_detailed'] = detailed_info if detailed_info else "N/A"
        
        self.info['input_devices_sysfs'] = sysfs_input
    
    def get_keyboard_info(self):
        """Get keyboard information"""
        keyboard_info = OrderedDict()
        
        # Get keyboard layouts
        keyboard_layouts = self.run_command("localectl status 2>/dev/null | grep -i 'keymap\\|layout'", shell=True)
        keyboard_info['keyboard_layout'] = keyboard_layouts if keyboard_layouts else "N/A"
        
        # Get keyboard repeat settings
        keyboard_repeat = self.run_command("xset q 2>/dev/null | grep -A 3 'auto repeat'", shell=True)
        keyboard_info['keyboard_repeat'] = keyboard_repeat if keyboard_repeat else "N/A"
        
        # Get keyboard models
        keyboard_models = self.run_command("grep -r 'keyboard' /etc/X11/xorg.conf.d/ 2>/dev/null | head -10", shell=True)
        keyboard_info['keyboard_models'] = keyboard_models if keyboard_models else "N/A"
        
        self.info['keyboard_info'] = keyboard_info
    
    def get_mouse_info(self):
        """Get mouse information"""
        mouse_info = OrderedDict()
        
        # Get mouse speed
        mouse_speed = self.run_command("xset q 2>/dev/null | grep -A 2 'pointer'", shell=True)
        mouse_info['mouse_speed'] = mouse_speed if mouse_speed else "N/A"
        
        # Get mouse acceleration
        mouse_accel = self.run_command("xset q 2>/dev/null | grep -i 'accel'", shell=True)
        mouse_info['mouse_acceleration'] = mouse_accel if mouse_accel else "N/A"
        
        # Get mouse button count
        mouse_buttons = self.run_command("cat /proc/bus/input/devices 2>/dev/null | grep -A 2 'mouse'", shell=True)
        mouse_info['mouse_buttons'] = mouse_buttons if mouse_buttons else "N/A"
        
        self.info['mouse_info'] = mouse_info
    
    def get_touchpad_info(self):
        """Get touchpad information"""
        touchpad_info = OrderedDict()
        
        # Get touchpad devices
        touchpad_devices = self.run_command("lsusb | grep -i 'touchpad\\|trackpad'", shell=True)
        touchpad_info['usb_touchpad'] = touchpad_devices if touchpad_devices else "N/A"
        
        # Get Synaptics touchpad info
        synaptics = self.run_command("synclient -l 2>/dev/null | head -20", shell=True)
        touchpad_info['synaptics_touchpad'] = synaptics if synaptics else "Not found"
        
        # Get libinput touchpad info
        libinput = self.run_command("libinput list-devices 2>/dev/null | grep -A 5 'touchpad\\|pointer'", shell=True)
        touchpad_info['libinput_devices'] = libinput if libinput else "Not available"
        
        self.info['touchpad_info'] = touchpad_info
    
    def get_hid_devices(self):
        """Get HID (Human Interface Device) information"""
        hid_info = OrderedDict()
        
        # Get HID devices from lsusb
        hid_devices = self.run_command("lsusb | grep -i 'hid'", shell=True)
        hid_info['hid_devices'] = hid_devices if hid_devices else "N/A"
        
        # Get HID bus devices
        hid_bus = self.run_command("ls /sys/bus/hid/devices/ 2>/dev/null", shell=True)
        hid_info['hid_bus_devices'] = hid_bus if hid_bus else "N/A"
        
        # Get detailed HID info
        hid_detailed = self.run_command("for device in /sys/bus/hid/devices/*/; do echo \"Device: $(basename $device) - Name: $(cat $device/uevent 2>/dev/null | grep HID_NAME | cut -d= -f2)\"; done", shell=True)
        hid_info['hid_devices_detailed'] = hid_detailed if hid_detailed else "N/A"
        
        self.info['hid_devices'] = hid_info
    
    def get_input_kernel_modules(self):
        """Get loaded input kernel modules"""
        kernel_modules = OrderedDict()
        
        # Get HID modules
        hid_modules = self.run_command("lsmod | grep -i 'hid'", shell=True)
        kernel_modules['hid_modules'] = hid_modules if hid_modules else "Not loaded"
        
        # Get input core module
        input_core = self.run_command("lsmod | grep '^input '", shell=True)
        kernel_modules['input_core'] = input_core if input_core else "Not loaded"
        
        # Get USB HID module
        usb_hid = self.run_command("lsmod | grep -i 'usbhid'", shell=True)
        kernel_modules['usbhid_module'] = usb_hid if usb_hid else "Not loaded"
        
        # Get keyboard modules
        keyboard_modules = self.run_command("lsmod | grep -i 'keyboard\\|atkbd'", shell=True)
        kernel_modules['keyboard_modules'] = keyboard_modules if keyboard_modules else "Not loaded"
        
        # Get mouse modules
        mouse_modules = self.run_command("lsmod | grep -i 'mouse\\|psmouse'", shell=True)
        kernel_modules['mouse_modules'] = mouse_modules if mouse_modules else "Not loaded"
        
        self.info['input_kernel_modules'] = kernel_modules
    
    def get_vmware_input_devices(self):
        """Get VMware-specific input device information"""
        vmware_input = OrderedDict()
        
        if self.is_vmware:
            vmware_input['virtualization_type'] = "VMware"
            
            # Check for VMware mouse driver
            vmware_mouse = self.run_command("lsusb | grep -i 'vmware.*mouse\\|vmware.*input'", shell=True)
            vmware_input['vmware_mouse'] = vmware_mouse if vmware_mouse else "Not found"
            
            # Check for VMware pointing device
            vmware_pointing = self.run_command("lspci -k | grep -A 2 -i 'input\\|mouse'", shell=True)
            vmware_input['vmware_pointing_device'] = vmware_pointing if vmware_pointing else "N/A"
            
            # Check input device from dmesg
            dmesg_input = self.run_command("dmesg | grep -i 'input\\|mouse\\|keyboard' | tail -10", shell=True)
            vmware_input['vmware_input_boot_info'] = dmesg_input if dmesg_input else "N/A"
            
            # Check for absolute positioning (needed for VMware)
            absolute_pos = self.run_command("cat /proc/bus/input/devices 2>/dev/null | grep -i 'abs'", shell=True)
            vmware_input['absolute_positioning'] = absolute_pos if absolute_pos else "Not found"
        else:
            vmware_input['virtualization_type'] = "Physical Server or Non-VMware VM"
            vmware_input['vmware_mouse'] = "N/A"
            vmware_input['vmware_pointing_device'] = "N/A"
            vmware_input['vmware_input_boot_info'] = "N/A"
        
        self.info['vmware_input_devices'] = vmware_input
    
    def get_input_devices_proc(self):
        """Get input devices from /proc"""
        proc_input = OrderedDict()
        
        # Get all input devices from /proc/bus/input/devices
        all_devices = self.run_command("cat /proc/bus/input/devices", shell=True)
        proc_input['all_input_devices'] = all_devices if all_devices else "N/A"
        
        self.info['proc_input_devices'] = proc_input
    
    def get_input_event_handlers(self):
        """Get input event handlers"""
        handlers = OrderedDict()
        
        # Get event handlers
        event_handlers = self.run_command("cat /proc/bus/input/handlers", shell=True)
        handlers['event_handlers'] = event_handlers if event_handlers else "N/A"
        
        self.info['input_event_handlers'] = handlers
    
    def get_input_x11_configuration(self):
        """Get X11 input configuration"""
        x11_config = OrderedDict()
        
        # Check X11 input devices
        x11_devices = self.run_command("xinput list 2>/dev/null", shell=True)
        x11_config['x11_input_devices'] = x11_devices if x11_devices else "X11 not available"
        
        # Get X11 keyboard layout
        x11_layout = self.run_command("setxkbmap -query 2>/dev/null", shell=True)
        x11_config['x11_keyboard_layout'] = x11_layout if x11_layout else "N/A"
        
        self.info['x11_input_configuration'] = x11_config
    
    def get_dmesg_input_info(self):
        """Get input device information from dmesg"""
        dmesg_input = self.run_command("dmesg | grep -i 'input\\|hid\\|keyboard\\|mouse' | tail -20", shell=True)
        self.info['dmesg_input_info'] = dmesg_input if dmesg_input else "N/A"
    
    def gather_all_info(self):
        """Collect all input device information"""
        print("[*] Gathering input device information...")
        
        self.get_vmware_input_devices()
        print("    [+] VMware/Virtualization input detection - OK")
        
        self.get_input_devices_pci()
        print("    [+] Input devices (PCI) - OK")
        
        self.get_input_devices_usb()
        print("    [+] USB input devices - OK")
        
        self.get_input_devices_dev()
        print("    [+] Input devices (/dev) - OK")
        
        self.get_input_devices_sysfs()
        print("    [+] Input devices (sysfs) - OK")
        
        self.get_input_devices_proc()
        print("    [+] Input devices (/proc) - OK")
        
        self.get_keyboard_info()
        print("    [+] Keyboard info - OK")
        
        self.get_mouse_info()
        print("    [+] Mouse info - OK")
        
        self.get_touchpad_info()
        print("    [+] Touchpad info - OK")
        
        self.get_hid_devices()
        print("    [+] HID devices - OK")
        
        self.get_input_kernel_modules()
        print("    [+] Input kernel modules - OK")
        
        self.get_input_event_handlers()
        print("    [+] Input event handlers - OK")
        
        self.get_input_x11_configuration()
        print("    [+] X11 input configuration - OK")
        
        self.get_dmesg_input_info()
        print("    [+] dmesg input info - OK")
        
        print("[*] Information gathering completed!\n")
    
    def get_info(self, key=None):
        """Return information"""
        if key is None:
            return self.info
        return self.info.get(key, "N/A")
    
    def display_info(self, verbose=True):
        """Display collected information"""
        print("╔" + "═" * 78 + "╗")
        print("║" + " INPUT DEVICES INFORMATIONS REPORT ".center(78) + "║")
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
    crawler = InputDevicesCrawler()
    crawler.gather_all_info()
    crawler.display_info(verbose=True)
    
    return crawler


if __name__ == "__main__":
    main()