#!/usr/bin/env python3.6
# -*- coding: utf-8 -*-

######################################################################################################################
# A Python 3.6 script that verifies BIOS and Firmware informations on a Linux server.                                #
# The script verifies the following: BIOS version, UEFI info, firmware settings, boot order, and boot configuration. #
# Version: 0.0.1                                                                                                     #
# Author: Alexandru Filcu                                                                                            #
######################################################################################################################

######################
# Import handy tools #
######################

import subprocess
import sys
import json
from collections import OrderedDict


class BIOSCrawler:
    """Class for collecting BIOS and Firmware information"""
    
    def __init__(self):
        self.info = OrderedDict()
        self.is_vmware = self._detect_vmware()
        self.is_suse = self._detect_suse()
        self.is_uefi = self._detect_uefi()
    
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
    
    def _detect_suse(self):
        """Detect if running on SUSE Linux"""
        suse_check = self.run_command("grep -i 'suse\\|opensuse' /etc/os-release", shell=True)
        return bool(suse_check)
    
    def _detect_uefi(self):
        """Detect if system is UEFI"""
        uefi_check = self.run_command("test -d /sys/firmware/efi && echo 'UEFI' || echo 'BIOS'", shell=True)
        return uefi_check == "UEFI" if uefi_check else False
    
    def get_bios_info(self):
        """Get BIOS information"""
        bios_info = OrderedDict()
        
        # Get BIOS vendor
        bios_vendor = self.run_command("sudo dmidecode -s bios-vendor 2>/dev/null || dmidecode -s bios-vendor 2>/dev/null", shell=True)
        bios_info['bios_vendor'] = bios_vendor if bios_vendor else "N/A"
        
        # Get BIOS version
        bios_version = self.run_command("sudo dmidecode -s bios-version 2>/dev/null || dmidecode -s bios-version 2>/dev/null", shell=True)
        bios_info['bios_version'] = bios_version if bios_version else "N/A"
        
        # Get BIOS release date
        bios_date = self.run_command("sudo dmidecode -s bios-release-date 2>/dev/null || dmidecode -s bios-release-date 2>/dev/null", shell=True)
        bios_info['bios_release_date'] = bios_date if bios_date else "N/A"
        
        # Get full BIOS info from dmidecode
        bios_full = self.run_command("sudo dmidecode -t bios 2>/dev/null || dmidecode -t bios 2>/dev/null", shell=True)
        bios_info['bios_full_info'] = bios_full if bios_full else "N/A"
        
        self.info['bios_info'] = bios_info
    
    def get_firmware_type(self):
        """Get firmware type (UEFI/BIOS)"""
        firmware_info = OrderedDict()
        
        if self.is_uefi:
            firmware_info['firmware_type'] = "UEFI"
            
            # Get EFI version
            efi_version = self.run_command("cat /sys/firmware/efi/fw_platform_size 2>/dev/null", shell=True)
            firmware_info['efi_version'] = efi_version if efi_version else "N/A"
            
            # Get EFI variables
            efi_vars = self.run_command("ls /sys/firmware/efi/efivars/ 2>/dev/null | wc -l", shell=True)
            firmware_info['efi_variables_count'] = efi_vars if efi_vars else "N/A"
            
            # Check Secure Boot status
            secure_boot = self.run_command("cat /sys/firmware/efi/fw_platform_size 2>/dev/null || cat /proc/cmdline | grep -o 'secure_boot=.*' || echo 'N/A'", shell=True)
            firmware_info['secure_boot_status'] = secure_boot if secure_boot else "N/A"
        else:
            firmware_info['firmware_type'] = "BIOS (Legacy)"
            firmware_info['efi_version'] = "N/A"
            firmware_info['secure_boot_status'] = "N/A (Legacy BIOS)"
        
        self.info['firmware_type'] = firmware_info
    
    def get_uefi_boot_info(self):
        """Get UEFI boot information"""
        uefi_info = OrderedDict()
        
        if self.is_uefi:
            # Get EFI boot entries
            boot_entries = self.run_command("efibootmgr 2>/dev/null | head -20", shell=True)
            uefi_info['efi_boot_entries'] = boot_entries if boot_entries else "efibootmgr not available"
            
            # Get EFI partition info
            efi_part = self.run_command("lsblk -f | grep -i 'EFI\\|vfat'", shell=True)
            uefi_info['efi_partition'] = efi_part if efi_part else "N/A"
            
            # Get ESP (EFI System Partition) info
            esp_mount = self.run_command("mount | grep -i 'efi\\|esp'", shell=True)
            uefi_info['esp_mount_point'] = esp_mount if esp_mount else "N/A"
            
            # Get GRUB UEFI info
            grub_uefi = self.run_command("grub-mkconfig -o /dev/null 2>&1 | grep -i 'UEFI\\|EFI' | head -5", shell=True)
            uefi_info['grub_uefi_config'] = grub_uefi if grub_uefi else "N/A"
        else:
            uefi_info['efi_boot_entries'] = "Not applicable (Legacy BIOS)"
            uefi_info['efi_partition'] = "N/A"
            uefi_info['esp_mount_point'] = "N/A"
            uefi_info['grub_uefi_config'] = "N/A"
        
        self.info['uefi_boot_info'] = uefi_info
    
    def get_boot_order(self):
        """Get boot order"""
        boot_info = OrderedDict()
        
        # Get boot order from efibootmgr
        boot_order = self.run_command("efibootmgr 2>/dev/null | grep '^Boot' | head -10", shell=True)
        boot_info['boot_order'] = boot_order if boot_order else "N/A or Legacy BIOS"
        
        # Get current boot device
        current_boot = self.run_command("cat /proc/cmdline | tr ' ' '\\n' | grep -i 'boot\\|root' | head -5", shell=True)
        boot_info['current_boot_device'] = current_boot if current_boot else "N/A"
        
        self.info['boot_order'] = boot_info
    
    def get_bootloader_info(self):
        """Get bootloader information"""
        bootloader_info = OrderedDict()
        
        # Check for GRUB
        grub_check = self.run_command("which grub-mkconfig 2>/dev/null || which grub2-mkconfig 2>/dev/null", shell=True)
        if grub_check:
            bootloader_info['bootloader'] = "GRUB"
            
            # Get GRUB version
            grub_version = self.run_command("grub-mkconfig --version 2>/dev/null || grub2-mkconfig --version 2>/dev/null", shell=True)
            bootloader_info['grub_version'] = grub_version if grub_version else "N/A"
            
            # Get GRUB config
            grub_config = self.run_command("cat /boot/grub*/grub.cfg 2>/dev/null | head -30", shell=True)
            bootloader_info['grub_config'] = grub_config if grub_config else "N/A"
        else:
            bootloader_info['bootloader'] = "Unknown"
            bootloader_info['grub_version'] = "N/A"
            bootloader_info['grub_config'] = "N/A"
        
        # Check for LILO
        lilo_check = self.run_command("which lilo 2>/dev/null", shell=True)
        if lilo_check:
            bootloader_info['lilo_installed'] = "Yes"
        else:
            bootloader_info['lilo_installed'] = "No"
        
        # Check for SYSLINUX
        syslinux_check = self.run_command("which syslinux 2>/dev/null", shell=True)
        if syslinux_check:
            bootloader_info['syslinux_installed'] = "Yes"
        else:
            bootloader_info['syslinux_installed'] = "No"
        
        self.info['bootloader_info'] = bootloader_info
    
    def get_kernel_boot_params(self):
        """Get kernel boot parameters"""
        kernel_params = OrderedDict()
        
        # Get /proc/cmdline
        cmdline = self.run_command("cat /proc/cmdline", shell=True)
        kernel_params['kernel_cmdline'] = cmdline if cmdline else "N/A"
        
        # Parse important parameters
        if cmdline:
            # Check for IOMMU
            iommu = self.run_command("cat /proc/cmdline | grep -o 'intel_iommu=.*\\|amd_iommu=.*' | head -1", shell=True)
            kernel_params['iommu_enabled'] = iommu if iommu else "Disabled or N/A"
            
            # Check for GRUB_CMDLINE_LINUX
            grub_cmdline = self.run_command("grep '^GRUB_CMDLINE_LINUX' /etc/default/grub 2>/dev/null || grep '^GRUB_CMDLINE_LINUX' /etc/sysconfig/grub 2>/dev/null", shell=True)
            kernel_params['grub_cmdline'] = grub_cmdline if grub_cmdline else "N/A"
        
        self.info['kernel_boot_params'] = kernel_params
    
    def get_secureboot_info(self):
        """Get Secure Boot information"""
        secureboot_info = OrderedDict()
        
        # Check Secure Boot status
        sb_status = self.run_command("mokutil --sb-state 2>/dev/null || echo 'mokutil not available'", shell=True)
        secureboot_info['secureboot_status'] = sb_status if sb_status else "N/A"
        
        # Check UEFI Secure Boot variable
        sb_var = self.run_command("cat /sys/firmware/efi/efivars/SecureBoot-* 2>/dev/null || echo 'N/A'", shell=True)
        secureboot_info['secureboot_variable'] = sb_var if sb_var else "N/A"
        
        # Get MOK (Machine Owner Key) info
        mok_info = self.run_command("mokutil --list-enrolled 2>/dev/null | head -10", shell=True)
        secureboot_info['mok_keys'] = mok_info if mok_info else "N/A"
        
        self.info['secureboot_info'] = secureboot_info
    
    def get_tpm_info(self):
        """Get TPM (Trusted Platform Module) information"""
        tpm_info = OrderedDict()
        
        # Check TPM presence
        tpm_check = self.run_command("ls /dev/tpm* 2>/dev/null | wc -l", shell=True)
        if tpm_check and tpm_check != "0":
            tpm_info['tpm_present'] = "Yes"
            
            # Get TPM version
            tpm_version = self.run_command("cat /sys/class/tpm/tpm0/tpm_version_major 2>/dev/null || cat /proc/device-tree/ibm,vtpm/compatible 2>/dev/null", shell=True)
            tpm_info['tpm_version'] = tpm_version if tpm_version else "N/A"
            
            # Check tpm2 tools
            tpm2_tools = self.run_command("which tpm2_getcap 2>/dev/null && echo 'Installed' || echo 'Not installed'", shell=True)
            tpm_info['tpm2_tools'] = tpm2_tools if tpm2_tools else "N/A"
        else:
            tpm_info['tpm_present'] = "No"
            tpm_info['tpm_version'] = "N/A"
            tpm_info['tpm2_tools'] = "N/A"
        
        self.info['tpm_info'] = tpm_info
    
    def get_acpi_info(self):
        """Get ACPI information"""
        acpi_info = OrderedDict()
        
        # Check ACPI support
        acpi_status = self.run_command("cat /proc/acpi/info 2>/dev/null | head -5", shell=True)
        acpi_info['acpi_info'] = acpi_status if acpi_status else "N/A"
        
        # Get ACPI tables
        acpi_tables = self.run_command("ls /sys/firmware/acpi/tables/ 2>/dev/null | head -20", shell=True)
        acpi_info['acpi_tables'] = acpi_tables if acpi_tables else "N/A"
        
        # Check ACPI daemon
        acpi_daemon = self.run_command("systemctl status acpid 2>/dev/null | grep -i 'active\\|inactive'", shell=True)
        acpi_info['acpid_status'] = acpi_daemon if acpi_daemon else "N/A"
        
        self.info['acpi_info'] = acpi_info
    
    def get_vmware_firmware_info(self):
        """Get VMware-specific firmware information"""
        vmware_fw = OrderedDict()
        
        if self.is_vmware:
            vmware_fw['virtualization_type'] = "VMware"
            
            # Check VMware firmware signature
            vmware_sig = self.run_command("dmesg | grep -i 'vmware\\|bios.*vmware' | head -5", shell=True)
            vmware_fw['vmware_bios_signature'] = vmware_sig if vmware_sig else "N/A"
            
            # Check for virtual BIOS
            virtual_bios = self.run_command("sudo dmidecode -t system 2>/dev/null | grep -i 'vmware\\|virtual'", shell=True)
            vmware_fw['virtual_bios_info'] = virtual_bios if virtual_bios else "N/A"
            
            # Check boot firmware
            boot_fw = self.run_command("cat /proc/cmdline | grep -o 'boot_fw=.*' || echo 'N/A'", shell=True)
            vmware_fw['boot_firmware'] = boot_fw if boot_fw else "N/A"
        else:
            vmware_fw['virtualization_type'] = "Physical Server or Non-VMware VM"
            vmware_fw['vmware_bios_signature'] = "N/A"
            vmware_fw['virtual_bios_info'] = "N/A"
        
        self.info['vmware_firmware_info'] = vmware_fw
    
    def get_suse_firmware_info(self):
        """Get SUSE-specific firmware information"""
        suse_fw = OrderedDict()
        
        if self.is_suse:
            suse_fw['os_type'] = "SUSE Linux"
            
            # Check SUSE YaST2 bootloader config
            yast_bootloader = self.run_command("cat /etc/sysconfig/bootloader 2>/dev/null | head -10", shell=True)
            suse_fw['yast_bootloader_config'] = yast_bootloader if yast_bootloader else "N/A"
            
            # Check SUSE BIOS/UEFI configuration
            suse_fw_config = self.run_command("cat /etc/sysconfig/boot 2>/dev/null | head -10", shell=True)
            suse_fw['suse_boot_config'] = suse_fw_config if suse_fw_config else "N/A"
            
            # Check SUSE specific bootloader files
            suse_boot_files = self.run_command("ls -la /boot/grub*/ 2>/dev/null | head -20", shell=True)
            suse_fw['suse_boot_files'] = suse_boot_files if suse_boot_files else "N/A"
        else:
            suse_fw['os_type'] = "Not SUSE Linux"
            suse_fw['yast_bootloader_config'] = "N/A"
            suse_fw['suse_boot_config'] = "N/A"
        
        self.info['suse_firmware_info'] = suse_fw
    
    def get_firmware_updates(self):
        """Get firmware update information"""
        updates_info = OrderedDict()
        
        # Check for LVFS (Linux Vendor Firmware Service)
        lvfs_check = self.run_command("fwupdmgr get-devices 2>/dev/null | head -10", shell=True)
        updates_info['lvfs_devices'] = lvfs_check if lvfs_check else "fwupdmgr not available"
        
        # Check firmware update status
        fw_updates = self.run_command("fwupdmgr get-updates 2>/dev/null", shell=True)
        updates_info['firmware_updates_available'] = fw_updates if fw_updates else "N/A"
        
        self.info['firmware_updates'] = updates_info
    
    def get_dmesg_firmware_info(self):
        """Get firmware information from dmesg"""
        dmesg_fw = self.run_command("dmesg | grep -i 'firmware\\|bios\\|uefi\\|efi\\|boot' | tail -20", shell=True)
        self.info['dmesg_firmware_info'] = dmesg_fw if dmesg_fw else "N/A"
    
    def gather_all_info(self):
        """Collect all BIOS and firmware information"""
        print("[*] Gathering BIOS and firmware information...")
        
        self.get_bios_info()
        print("    [+] BIOS info - OK")
        
        self.get_firmware_type()
        print("    [+] Firmware type (UEFI/BIOS) - OK")
        
        self.get_uefi_boot_info()
        print("    [+] UEFI boot info - OK")
        
        self.get_boot_order()
        print("    [+] Boot order - OK")
        
        self.get_bootloader_info()
        print("    [+] Bootloader info - OK")
        
        self.get_kernel_boot_params()
        print("    [+] Kernel boot parameters - OK")
        
        self.get_secureboot_info()
        print("    [+] Secure Boot info - OK")
        
        self.get_tpm_info()
        print("    [+] TPM info - OK")
        
        self.get_acpi_info()
        print("    [+] ACPI info - OK")
        
        self.get_vmware_firmware_info()
        print("    [+] VMware firmware info - OK")
        
        self.get_suse_firmware_info()
        print("    [+] SUSE firmware info - OK")
        
        self.get_firmware_updates()
        print("    [+] Firmware updates - OK")
        
        self.get_dmesg_firmware_info()
        print("    [+] dmesg firmware info - OK")
        
        print("[*] Information gathering completed!\n")
    
    def get_info(self, key=None):
        """Return information"""
        if key is None:
            return self.info
        return self.info.get(key, "N/A")
    
    def display_info(self, verbose=True):
        """Display collected information"""
        print("╔" + "═" * 78 + "╗")
        print("║" + " BIOS/FIRMWARE INFORMATIONS REPORT ".center(78) + "║")
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
    crawler = BIOSCrawler()
    crawler.gather_all_info()
    crawler.display_info(verbose=True)
    
    return crawler


if __name__ == "__main__":
    main()