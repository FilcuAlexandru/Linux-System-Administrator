#!/usr/bin/env python3.6
# -*- coding: utf-8 -*-

#########################################################################################################
# A PYTHON 3.6 SCRIPT THAT CRAWLS MOTHERBOARD AND BIOS INFORMATION ON LINUX SYSTEMS.                    #
# THE SCRIPT CRAWLS MOTHERBOARD MANUFACTURER, MODEL, BIOS INFO, SERIAL NUMBERS, AND SYSTEM INFORMATION. #
# THE SCRIPT DISPLAYS THE COLLECTED INFORMATION AS JSON OUTPUT.                                         #
# VERSION: 0.0.1                                                                                        #
# AUTHOR: ALEXANDRU FILCU                                                                               #
#########################################################################################################

######################
# Import handy tools #
######################

import subprocess
import sys
import json
from collections import OrderedDict


class MotherboardCrawler:
    """Class for collecting Motherboard and BIOS information"""
    
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
    
    def get_system_info_dmidecode(self):
        """Get system information from dmidecode"""
        system_info = OrderedDict()
        
        # Check if dmidecode is available
        dmidecode_check = self.run_command("which dmidecode", shell=True)
        
        if dmidecode_check:
            # Get System Information
            system_data = self.run_command("sudo dmidecode -t system 2>/dev/null || dmidecode -t system 2>/dev/null", shell=True)
            system_info['system_info'] = system_data if system_data else "N/A"
            
            # Get Baseboard Information (Motherboard)
            baseboard_data = self.run_command("sudo dmidecode -t baseboard 2>/dev/null || dmidecode -t baseboard 2>/dev/null", shell=True)
            system_info['baseboard_info'] = baseboard_data if baseboard_data else "N/A"
            
            # Get BIOS Information
            bios_data = self.run_command("sudo dmidecode -t bios 2>/dev/null || dmidecode -t bios 2>/dev/null", shell=True)
            system_info['bios_info'] = bios_data if bios_data else "N/A"
            
            # Get Chassis Information
            chassis_data = self.run_command("sudo dmidecode -t chassis 2>/dev/null || dmidecode -t chassis 2>/dev/null", shell=True)
            system_info['chassis_info'] = chassis_data if chassis_data else "N/A"
        else:
            system_info['system_info'] = "dmidecode not available"
            system_info['baseboard_info'] = "dmidecode not available"
            system_info['bios_info'] = "dmidecode not available"
            system_info['chassis_info'] = "dmidecode not available"
        
        self.info['dmidecode_info'] = system_info
    
    def get_bios_info_hostnamectl(self):
        """Get BIOS info from hostnamectl"""
        hostnamectl_output = self.run_command("hostnamectl", shell=True)
        
        if hostnamectl_output:
            # Parse hardware vendor and model
            bios_info = OrderedDict()
            lines = hostnamectl_output.split('\n')
            for line in lines:
                if 'Hardware Vendor' in line or 'Hardware Model' in line or 'Chassis' in line:
                    bios_info[line.split(':')[0].strip()] = line.split(':')[1].strip() if ':' in line else "N/A"
            
            self.info['hostnamectl_hardware'] = bios_info if bios_info else "N/A"
        else:
            self.info['hostnamectl_hardware'] = "N/A"
    
    def get_motherboard_model(self):
        """Get motherboard model"""
        motherboard_model = self.run_command("sudo dmidecode -s baseboard-product-name 2>/dev/null || dmidecode -s baseboard-product-name 2>/dev/null", shell=True)
        self.info['motherboard_model'] = motherboard_model if motherboard_model else "N/A"
    
    def get_motherboard_manufacturer(self):
        """Get motherboard manufacturer"""
        manufacturer = self.run_command("sudo dmidecode -s baseboard-manufacturer 2>/dev/null || dmidecode -s baseboard-manufacturer 2>/dev/null", shell=True)
        self.info['motherboard_manufacturer'] = manufacturer if manufacturer else "N/A"
    
    def get_bios_vendor(self):
        """Get BIOS vendor"""
        bios_vendor = self.run_command("sudo dmidecode -s bios-vendor 2>/dev/null || dmidecode -s bios-vendor 2>/dev/null", shell=True)
        self.info['bios_vendor'] = bios_vendor if bios_vendor else "N/A"
    
    def get_bios_version(self):
        """Get BIOS version"""
        bios_version = self.run_command("sudo dmidecode -s bios-version 2>/dev/null || dmidecode -s bios-version 2>/dev/null", shell=True)
        self.info['bios_version'] = bios_version if bios_version else "N/A"
    
    def get_bios_release_date(self):
        """Get BIOS release date"""
        bios_date = self.run_command("sudo dmidecode -s bios-release-date 2>/dev/null || dmidecode -s bios-release-date 2>/dev/null", shell=True)
        self.info['bios_release_date'] = bios_date if bios_date else "N/A"
    
    def get_system_manufacturer(self):
        """Get system manufacturer"""
        sys_manufacturer = self.run_command("sudo dmidecode -s system-manufacturer 2>/dev/null || dmidecode -s system-manufacturer 2>/dev/null", shell=True)
        self.info['system_manufacturer'] = sys_manufacturer if sys_manufacturer else "N/A"
    
    def get_system_product_name(self):
        """Get system product name"""
        sys_product = self.run_command("sudo dmidecode -s system-product-name 2>/dev/null || dmidecode -s system-product-name 2>/dev/null", shell=True)
        self.info['system_product_name'] = sys_product if sys_product else "N/A"
    
    def get_system_serial_number(self):
        """Get system serial number"""
        sys_serial = self.run_command("sudo dmidecode -s system-serial-number 2>/dev/null || dmidecode -s system-serial-number 2>/dev/null", shell=True)
        self.info['system_serial_number'] = sys_serial if sys_serial else "N/A"
    
    def get_system_uuid(self):
        """Get system UUID"""
        sys_uuid = self.run_command("sudo dmidecode -s system-uuid 2>/dev/null || dmidecode -s system-uuid 2>/dev/null", shell=True)
        self.info['system_uuid'] = sys_uuid if sys_uuid else "N/A"
    
    def get_chassis_type(self):
        """Get chassis type"""
        chassis_type = self.run_command("sudo dmidecode -s chassis-type 2>/dev/null || dmidecode -s chassis-type 2>/dev/null", shell=True)
        self.info['chassis_type'] = chassis_type if chassis_type else "N/A"
    
    def get_chassis_manufacturer(self):
        """Get chassis manufacturer"""
        chassis_mfg = self.run_command("sudo dmidecode -s chassis-manufacturer 2>/dev/null || dmidecode -s chassis-manufacturer 2>/dev/null", shell=True)
        self.info['chassis_manufacturer'] = chassis_mfg if chassis_mfg else "N/A"
    
    def get_chassis_serial_number(self):
        """Get chassis serial number"""
        chassis_serial = self.run_command("sudo dmidecode -s chassis-serial-number 2>/dev/null || dmidecode -s chassis-serial-number 2>/dev/null", shell=True)
        self.info['chassis_serial_number'] = chassis_serial if chassis_serial else "N/A"
    
    def get_board_serial_number(self):
        """Get baseboard serial number"""
        board_serial = self.run_command("sudo dmidecode -s baseboard-serial-number 2>/dev/null || dmidecode -s baseboard-serial-number 2>/dev/null", shell=True)
        self.info['baseboard_serial_number'] = board_serial if board_serial else "N/A"
    
    def get_pci_devices_info(self):
        """Get PCI devices information"""
        pci_info = OrderedDict()
        
        # Get all PCI devices
        pci_devices = self.run_command("lspci", shell=True)
        pci_info['all_pci_devices'] = pci_devices if pci_devices else "N/A"
        
        # Get detailed PCI information
        pci_detailed = self.run_command("lspci -v", shell=True)
        pci_info['pci_devices_verbose'] = pci_detailed if pci_detailed else "N/A"
        
        self.info['pci_devices'] = pci_info
    
    def get_dmesg_boot_info(self):
        """Get boot information from dmesg"""
        dmesg_boot = self.run_command("dmesg | head -50", shell=True)
        self.info['dmesg_boot_info'] = dmesg_boot if dmesg_boot else "N/A"
    
    def get_proc_cmdline(self):
        """Get kernel command line"""
        cmdline = self.run_command("cat /proc/cmdline", shell=True)
        self.info['kernel_cmdline'] = cmdline if cmdline else "N/A"
    
    def gather_all_info(self):
        """Collect all motherboard and BIOS information"""
        print("[*] Gathering motherboard and BIOS information...")
        
        self.get_system_manufacturer()
        print("    [+] System manufacturer - OK")
        
        self.get_system_product_name()
        print("    [+] System product name - OK")
        
        self.get_system_serial_number()
        print("    [+] System serial number - OK")
        
        self.get_system_uuid()
        print("    [+] System UUID - OK")
        
        self.get_motherboard_manufacturer()
        print("    [+] Motherboard manufacturer - OK")
        
        self.get_motherboard_model()
        print("    [+] Motherboard model - OK")
        
        self.get_board_serial_number()
        print("    [+] Baseboard serial number - OK")
        
        self.get_bios_vendor()
        print("    [+] BIOS vendor - OK")
        
        self.get_bios_version()
        print("    [+] BIOS version - OK")
        
        self.get_bios_release_date()
        print("    [+] BIOS release date - OK")
        
        self.get_chassis_type()
        print("    [+] Chassis type - OK")
        
        self.get_chassis_manufacturer()
        print("    [+] Chassis manufacturer - OK")
        
        self.get_chassis_serial_number()
        print("    [+] Chassis serial number - OK")
        
        self.get_bios_info_hostnamectl()
        print("    [+] Hardware info from hostnamectl - OK")
        
        self.get_system_info_dmidecode()
        print("    [+] dmidecode info - OK")
        
        self.get_pci_devices_info()
        print("    [+] PCI devices info - OK")
        
        self.get_dmesg_boot_info()
        print("    [+] dmesg boot info - OK")
        
        self.get_proc_cmdline()
        print("    [+] Kernel command line - OK")
        
        print("[*] Information gathering completed!\n")
    
    def get_info(self, key=None):
        """Return information"""
        if key is None:
            return self.info
        return self.info.get(key, "N/A")
    
    def display_info(self, verbose=True):
        """Display collected information"""
        print("╔" + "═" * 78 + "╗")
        print("║" + " MOTHERBOARD INFORMATIONS REPORT ".center(78) + "║")
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
    crawler = MotherboardCrawler()
    crawler.gather_all_info()
    crawler.display_info(verbose=True)
    
    return crawler


if __name__ == "__main__":
    main()