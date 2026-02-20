#!/usr/bin/env python3.6
# -*- coding: utf-8 -*-

########################################################################################
# A PYTHON 3.6 SCRIPT THAT CRAWLS PCI DEVICE INFORMATION ON LINUX SYSTEMS.             #
# THE SCRIPT CRAWLS PCI DEVICES, DEVICE CLASSES, DRIVERS, VENDORS, AND DEVICE DETAILS. #
# THE SCRIPT DISPLAYS THE COLLECTED INFORMATION AS JSON OUTPUT.                        #
# VERSION: 0.0.1                                                                       #
# AUTHOR: ALEXANDRU FILCU                                                              #
########################################################################################

######################
# Import handy tools #
######################

import subprocess
import sys
import json
from collections import OrderedDict


class PCICrawler:
    """Class for collecting PCI device information"""
    
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
    
    def get_pci_devices_list(self):
        """Get all PCI devices"""
        pci_devices = self.run_command("lspci", shell=True)
        self.info['pci_devices_list'] = pci_devices if pci_devices else "N/A"
    
    def get_pci_devices_verbose(self):
        """Get detailed PCI device information"""
        pci_verbose = self.run_command("lspci -v", shell=True)
        self.info['pci_devices_verbose'] = pci_verbose if pci_verbose else "N/A"
    
    def get_pci_devices_very_verbose(self):
        """Get very detailed PCI device information"""
        pci_vv = self.run_command("lspci -vv", shell=True)
        self.info['pci_devices_very_verbose'] = pci_vv if pci_vv else "N/A"
    
    def get_pci_devices_with_kernel_drivers(self):
        """Get PCI devices with kernel driver information"""
        pci_kernel = self.run_command("lspci -k", shell=True)
        self.info['pci_devices_kernel_drivers'] = pci_kernel if pci_kernel else "N/A"
    
    def get_pci_device_count(self):
        """Get total PCI device count"""
        pci_count = self.run_command("lspci | wc -l", shell=True)
        self.info['total_pci_devices'] = pci_count if pci_count else "N/A"
    
    def get_pci_devices_by_class(self):
        """Get PCI devices organized by class"""
        class_info = OrderedDict()
        
        # Network devices
        network = self.run_command("lspci | grep -i 'network\\|ethernet'", shell=True)
        class_info['network_devices'] = network if network else "N/A"
        
        # Storage devices
        storage = self.run_command("lspci | grep -i 'storage\\|sata\\|nvme\\|scsi'", shell=True)
        class_info['storage_devices'] = storage if storage else "N/A"
        
        # VGA/Graphics devices
        graphics = self.run_command("lspci | grep -i 'vga\\|3d\\|display'", shell=True)
        class_info['graphics_devices'] = graphics if graphics else "N/A"
        
        # USB Controllers
        usb = self.run_command("lspci | grep -i 'usb'", shell=True)
        class_info['usb_controllers'] = usb if usb else "N/A"
        
        # Audio devices
        audio = self.run_command("lspci | grep -i 'audio\\|sound'", shell=True)
        class_info['audio_devices'] = audio if audio else "N/A"
        
        # Bridge devices
        bridge = self.run_command("lspci | grep -i 'bridge'", shell=True)
        class_info['bridge_devices'] = bridge if bridge else "N/A"
        
        # Communication devices
        communication = self.run_command("lspci | grep -i 'communication'", shell=True)
        class_info['communication_devices'] = communication if communication else "N/A"
        
        # Serial Bus controllers
        serial = self.run_command("lspci | grep -i 'serial bus'", shell=True)
        class_info['serial_bus_controllers'] = serial if serial else "N/A"
        
        # Wireless controllers
        wireless = self.run_command("lspci | grep -i 'wireless\\|wifi'", shell=True)
        class_info['wireless_controllers'] = wireless if wireless else "N/A"
        
        self.info['pci_devices_by_class'] = class_info
    
    def get_pci_vendor_device_info(self):
        """Get PCI vendor and device information"""
        vendor_info = OrderedDict()
        
        # Get list of vendors
        vendors = self.run_command("lspci | awk -F':' '{print $2}' | sort -u | head -20", shell=True)
        vendor_info['top_vendors'] = vendors if vendors else "N/A"
        
        # Get device list with IDs
        device_ids = self.run_command("lspci -n", shell=True)
        vendor_info['device_ids'] = device_ids if device_ids else "N/A"
        
        self.info['pci_vendor_info'] = vendor_info
    
    def get_pci_slot_info(self):
        """Get PCI slot information"""
        slot_info = self.run_command("lspci -t", shell=True)
        self.info['pci_slot_info'] = slot_info if slot_info else "N/A"
    
    def get_pci_bridge_info(self):
        """Get PCI bridge information"""
        bridge_info = OrderedDict()
        
        # Get PCI Express bridges
        pcie_bridge = self.run_command("lspci -k | grep -A 2 'PCI Express'", shell=True)
        bridge_info['pcie_bridges'] = pcie_bridge if pcie_bridge else "N/A"
        
        # Get all bridges
        all_bridges = self.run_command("lspci | grep -i bridge", shell=True)
        bridge_info['all_bridges'] = all_bridges if all_bridges else "N/A"
        
        self.info['pci_bridge_info'] = bridge_info
    
    def get_pci_rom_bios_info(self):
        """Get PCI ROM/BIOS information"""
        rom_info = self.run_command("lspci -v | grep -i 'rom\\|bios'", shell=True)
        self.info['pci_rom_bios_info'] = rom_info if rom_info else "N/A"
    
    def get_pci_drivers_loaded(self):
        """Get loaded PCI drivers from kernel"""
        drivers = OrderedDict()
        
        # Get all loaded drivers
        loaded_drivers = self.run_command("lsmod | head -30", shell=True)
        drivers['loaded_kernel_modules'] = loaded_drivers if loaded_drivers else "N/A"
        
        # Get PCI driver modules
        pci_modules = self.run_command("ls /sys/bus/pci/drivers/", shell=True)
        drivers['pci_driver_modules'] = pci_modules if pci_modules else "N/A"
        
        self.info['pci_drivers_info'] = drivers
    
    def get_pci_device_capabilities(self):
        """Get PCI device capabilities"""
        capabilities = OrderedDict()
        
        # Get MSI (Message Signaled Interrupts) capable devices
        msi_devices = self.run_command("lspci -v | grep -i msi", shell=True)
        capabilities['msi_capable_devices'] = msi_devices if msi_devices else "N/A"
        
        # Get power management capable devices
        power_mgmt = self.run_command("lspci -v | grep -i 'power management'", shell=True)
        capabilities['power_management_devices'] = power_mgmt if power_mgmt else "N/A"
        
        self.info['pci_device_capabilities'] = capabilities
    
    def get_pci_error_info(self):
        """Get PCI error information from dmesg"""
        error_info = self.run_command("dmesg | grep -i 'pci\\|aer\\|error' | tail -20", shell=True)
        self.info['pci_error_info'] = error_info if error_info else "N/A"
    
    def get_iommu_info(self):
        """Get IOMMU (Input/Output Memory Management Unit) information"""
        iommu_info = OrderedDict()
        
        # Check for Intel VT-d
        vtd_check = self.run_command("dmesg | grep -i 'vt-d'", shell=True)
        iommu_info['vt_d_status'] = vtd_check if vtd_check else "Not available"
        
        # Check for AMD-Vi
        amdvi_check = self.run_command("dmesg | grep -i 'amd-vi'", shell=True)
        iommu_info['amd_vi_status'] = amdvi_check if amdvi_check else "Not available"
        
        # Check IOMMU groups
        iommu_groups = self.run_command("ls /sys/kernel/iommu_groups/ 2>/dev/null | wc -l", shell=True)
        iommu_info['iommu_groups_count'] = iommu_groups if iommu_groups else "N/A"
        
        self.info['iommu_info'] = iommu_info
    
    def get_pcie_version_info(self):
        """Get PCIe version information"""
        pcie_info = OrderedDict()
        
        # Get PCIe gen info
        pcie_gen = self.run_command("lspci -v | grep -i 'gen [0-9]'", shell=True)
        pcie_info['pcie_generation'] = pcie_gen if pcie_gen else "N/A"
        
        # Get PCIe speed
        pcie_speed = self.run_command("lspci -v | grep -i 'speed'", shell=True)
        pcie_info['pcie_speed'] = pcie_speed if pcie_speed else "N/A"
        
        # Get PCIe width
        pcie_width = self.run_command("lspci -v | grep -i 'width'", shell=True)
        pcie_info['pcie_width'] = pcie_width if pcie_width else "N/A"
        
        self.info['pcie_version_info'] = pcie_info
    
    def get_pci_hotplug_info(self):
        """Get PCI hotplug information"""
        hotplug_info = self.run_command("ls /sys/bus/pci_express/devices/ 2>/dev/null || echo 'N/A'", shell=True)
        self.info['pci_hotplug_info'] = hotplug_info if hotplug_info else "N/A"
    
    def get_acpi_pci_info(self):
        """Get ACPI PCI information"""
        acpi_pci = OrderedDict()
        
        # Check ACPI status
        acpi_status = self.run_command("dmesg | grep -i 'acpi' | head -10", shell=True)
        acpi_pci['acpi_status'] = acpi_status if acpi_status else "N/A"
        
        # Get PCI routing table
        pci_routing = self.run_command("cat /proc/acpi/pci_root 2>/dev/null || echo 'N/A'", shell=True)
        acpi_pci['pci_routing'] = pci_routing if pci_routing else "N/A"
        
        self.info['acpi_pci_info'] = acpi_pci
    
    def gather_all_info(self):
        """Collect all PCI device information"""
        print("[*] Gathering PCI device information...")
        
        self.get_pci_device_count()
        print("    [+] Total PCI devices count - OK")
        
        self.get_pci_devices_list()
        print("    [+] PCI devices list - OK")
        
        self.get_pci_devices_by_class()
        print("    [+] PCI devices by class - OK")
        
        self.get_pci_vendor_device_info()
        print("    [+] PCI vendor and device info - OK")
        
        self.get_pci_devices_with_kernel_drivers()
        print("    [+] PCI devices with kernel drivers - OK")
        
        self.get_pci_devices_verbose()
        print("    [+] PCI devices verbose - OK")
        
        self.get_pci_devices_very_verbose()
        print("    [+] PCI devices very verbose - OK")
        
        self.get_pci_slot_info()
        print("    [+] PCI slot info - OK")
        
        self.get_pci_bridge_info()
        print("    [+] PCI bridge info - OK")
        
        self.get_pcie_version_info()
        print("    [+] PCIe version info - OK")
        
        self.get_pci_rom_bios_info()
        print("    [+] PCI ROM/BIOS info - OK")
        
        self.get_pci_drivers_loaded()
        print("    [+] PCI drivers info - OK")
        
        self.get_pci_device_capabilities()
        print("    [+] PCI device capabilities - OK")
        
        self.get_iommu_info()
        print("    [+] IOMMU info - OK")
        
        self.get_pci_hotplug_info()
        print("    [+] PCI hotplug info - OK")
        
        self.get_acpi_pci_info()
        print("    [+] ACPI PCI info - OK")
        
        self.get_pci_error_info()
        print("    [+] PCI error info - OK")
        
        print("[*] Information gathering completed!\n")
    
    def get_info(self, key=None):
        """Return information"""
        if key is None:
            return self.info
        return self.info.get(key, "N/A")
    
    def display_info(self, verbose=True):
        """Display collected information"""
        print("╔" + "═" * 78 + "╗")
        print("║" + " PCI DEVICES INFORMATIONS REPORT ".center(78) + "║")
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
    crawler = PCICrawler()
    crawler.gather_all_info()
    crawler.display_info(verbose=True)
    
    return crawler


if __name__ == "__main__":
    main()