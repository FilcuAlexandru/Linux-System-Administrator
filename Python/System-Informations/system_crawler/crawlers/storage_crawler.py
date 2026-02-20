#!/usr/bin/env python3.6
# -*- coding: utf-8 -*-

######################################################################################################
# A PYTHON 3.6 SCRIPT THAT CRAWLS STORAGE AND DISK INFORMATION ON LINUX SYSTEMS.                     #
# THE SCRIPT CRAWLS DISK CAPACITY, USAGE, PARTITIONS, MOUNT POINTS, DISK SPEED, AND STORAGE DEVICES. #
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


class StorageCrawler:
    """Class for collecting Storage and Disk information"""
    
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
    
    def get_disk_usage(self):
        """Get disk usage information"""
        disk_usage = self.run_command("df -h", shell=True)
        self.info['disk_usage'] = disk_usage if disk_usage else "N/A"
    
    def get_disk_usage_inodes(self):
        """Get disk inodes usage"""
        inode_usage = self.run_command("df -i", shell=True)
        self.info['inode_usage'] = inode_usage if inode_usage else "N/A"
    
    def get_partition_info(self):
        """Get partition information"""
        partition_info = self.run_command("lsblk", shell=True)
        self.info['partition_info'] = partition_info if partition_info else "N/A"
    
    def get_partition_info_detailed(self):
        """Get detailed partition information"""
        partition_detailed = self.run_command("lsblk -f", shell=True)
        self.info['partition_info_detailed'] = partition_detailed if partition_detailed else "N/A"
    
    def get_disk_list(self):
        """Get disk list from lsblk"""
        disk_list = self.run_command("lsblk -d", shell=True)
        self.info['disk_list'] = disk_list if disk_list else "N/A"
    
    def get_mount_points(self):
        """Get mount points"""
        mount_points = self.run_command("mount | grep -v 'type tmpfs'", shell=True)
        self.info['mount_points'] = mount_points if mount_points else "N/A"
    
    def get_fstab(self):
        """Get /etc/fstab content"""
        fstab = self.run_command("cat /etc/fstab", shell=True)
        self.info['fstab'] = fstab if fstab else "N/A"
    
    def get_disk_devices(self):
        """Get disk devices from /proc/partitions"""
        partitions = self.run_command("cat /proc/partitions", shell=True)
        self.info['proc_partitions'] = partitions if partitions else "N/A"
    
    def get_disk_device_info(self):
        """Get disk device information using fdisk"""
        disk_info = OrderedDict()
        
        # Get list of disk devices
        disks = self.run_command("lsblk -d -n -o NAME", shell=True)
        
        if disks:
            disk_list = disks.split('\n')
            for disk in disk_list:
                if disk.strip():
                    fdisk_output = self.run_command("fdisk -l /dev/{} 2>/dev/null | head -20".format(disk.strip()), shell=True)
                    disk_info['/dev/{}'.format(disk.strip())] = fdisk_output if fdisk_output else "N/A"
        
        self.info['fdisk_info'] = disk_info if disk_info else "N/A"
    
    def get_disk_model_info(self):
        """Get disk model information"""
        disk_model = OrderedDict()
        
        # Get disk model from lsblk
        disk_models = self.run_command("lsblk -d -o NAME,MODEL", shell=True)
        disk_model['disk_models'] = disk_models if disk_models else "N/A"
        
        # Get disk size from lsblk
        disk_sizes = self.run_command("lsblk -d -o NAME,SIZE", shell=True)
        disk_model['disk_sizes'] = disk_sizes if disk_sizes else "N/A"
        
        # Get disk type from lsblk
        disk_types = self.run_command("lsblk -d -o NAME,TYPE", shell=True)
        disk_model['disk_types'] = disk_types if disk_types else "N/A"
        
        self.info['disk_model_info'] = disk_model
    
    def get_disk_smart_info(self):
        """Get SMART information from disks"""
        smart_info = OrderedDict()
        
        # Check if smartctl is available
        smartctl_check = self.run_command("which smartctl", shell=True)
        
        if smartctl_check:
            # Get list of SMART capable disks
            smart_disks = self.run_command("lsblk -d -n -o NAME", shell=True)
            
            if smart_disks:
                disk_list = smart_disks.split('\n')
                for disk in disk_list:
                    if disk.strip():
                        smart_output = self.run_command("smartctl -i /dev/{} 2>/dev/null || echo 'No SMART info available'".format(disk.strip()), shell=True)
                        smart_info['/dev/{}'.format(disk.strip())] = smart_output if smart_output else "N/A"
        else:
            smart_info['status'] = "smartctl not available"
        
        self.info['smart_info'] = smart_info
    
    def get_disk_io_stats(self):
        """Get disk I/O statistics"""
        io_stats = OrderedDict()
        
        # Get iostat if available
        iostat_check = self.run_command("which iostat", shell=True)
        
        if iostat_check:
            iostat_output = self.run_command("iostat -d", shell=True)
            io_stats['iostat'] = iostat_output if iostat_output else "N/A"
        else:
            io_stats['iostat'] = "iostat not available"
        
        # Get disk stats from /proc/diskstats
        diskstats = self.run_command("cat /proc/diskstats", shell=True)
        io_stats['diskstats'] = diskstats if diskstats else "N/A"
        
        self.info['disk_io_stats'] = io_stats
    
    def get_filesystem_types(self):
        """Get filesystem types in use"""
        fs_types = self.run_command("df -T | grep -v '^Filesystem'", shell=True)
        self.info['filesystem_types'] = fs_types if fs_types else "N/A"
    
    def get_disk_space_summary(self):
        """Get disk space summary"""
        space_summary = OrderedDict()
        
        # Total used space
        total_used = self.run_command("df -h / | tail -1 | awk '{print $3}'", shell=True)
        space_summary['total_used'] = total_used if total_used else "N/A"
        
        # Total available space
        total_available = self.run_command("df -h / | tail -1 | awk '{print $4}'", shell=True)
        space_summary['total_available'] = total_available if total_available else "N/A"
        
        # Total capacity
        total_capacity = self.run_command("df -h / | tail -1 | awk '{print $2}'", shell=True)
        space_summary['total_capacity'] = total_capacity if total_capacity else "N/A"
        
        # Usage percentage
        usage_percent = self.run_command("df -h / | tail -1 | awk '{print $5}'", shell=True)
        space_summary['usage_percentage'] = usage_percent if usage_percent else "N/A"
        
        self.info['disk_space_summary'] = space_summary
    
    def get_lvm_info(self):
        """Get LVM (Logical Volume Manager) information"""
        lvm_info = OrderedDict()
        
        # Check for physical volumes
        pv_info = self.run_command("pvdisplay 2>/dev/null || echo 'No LVM physical volumes found'", shell=True)
        lvm_info['physical_volumes'] = pv_info if pv_info else "N/A"
        
        # Check for volume groups
        vg_info = self.run_command("vgdisplay 2>/dev/null || echo 'No LVM volume groups found'", shell=True)
        lvm_info['volume_groups'] = vg_info if vg_info else "N/A"
        
        # Check for logical volumes
        lv_info = self.run_command("lvdisplay 2>/dev/null || echo 'No LVM logical volumes found'", shell=True)
        lvm_info['logical_volumes'] = lv_info if lv_info else "N/A"
        
        self.info['lvm_info'] = lvm_info
    
    def get_raid_info(self):
        """Get RAID information"""
        raid_info = OrderedDict()
        
        # Check for RAID status
        mdstat = self.run_command("cat /proc/mdstat 2>/dev/null || echo 'No RAID devices found'", shell=True)
        raid_info['mdstat'] = mdstat if mdstat else "N/A"
        
        # Check for RAID devices
        raid_devices = self.run_command("ls -la /dev/md* 2>/dev/null || echo 'No RAID devices found'", shell=True)
        raid_info['raid_devices'] = raid_devices if raid_devices else "N/A"
        
        self.info['raid_info'] = raid_info
    
    def get_dmesg_storage_info(self):
        """Get storage information from dmesg"""
        dmesg_storage = self.run_command("dmesg | grep -i 'disk\\|storage\\|sata\\|nvme\\|ata' | tail -20", shell=True)
        self.info['dmesg_storage_info'] = dmesg_storage if dmesg_storage else "N/A"
    
    def gather_all_info(self):
        """Collect all storage and disk information"""
        print("[*] Gathering storage and disk information...")
        
        self.get_disk_space_summary()
        print("    [+] Disk space summary - OK")
        
        self.get_disk_usage()
        print("    [+] Disk usage (df -h) - OK")
        
        self.get_disk_usage_inodes()
        print("    [+] Inode usage - OK")
        
        self.get_partition_info()
        print("    [+] Partition info - OK")
        
        self.get_partition_info_detailed()
        print("    [+] Partition info detailed - OK")
        
        self.get_disk_list()
        print("    [+] Disk list - OK")
        
        self.get_mount_points()
        print("    [+] Mount points - OK")
        
        self.get_fstab()
        print("    [+] /etc/fstab - OK")
        
        self.get_disk_devices()
        print("    [+] /proc/partitions - OK")
        
        self.get_disk_model_info()
        print("    [+] Disk model info - OK")
        
        self.get_disk_device_info()
        print("    [+] Disk device info (fdisk) - OK")
        
        self.get_filesystem_types()
        print("    [+] Filesystem types - OK")
        
        self.get_disk_io_stats()
        print("    [+] Disk I/O statistics - OK")
        
        self.get_disk_smart_info()
        print("    [+] SMART info - OK")
        
        self.get_lvm_info()
        print("    [+] LVM info - OK")
        
        self.get_raid_info()
        print("    [+] RAID info - OK")
        
        self.get_dmesg_storage_info()
        print("    [+] dmesg storage info - OK")
        
        print("[*] Information gathering completed!\n")
    
    def get_info(self, key=None):
        """Return information"""
        if key is None:
            return self.info
        return self.info.get(key, "N/A")
    
    def display_info(self, verbose=True):
        """Display collected information"""
        print("╔" + "═" * 78 + "╗")
        print("║" + " STORAGE INFORMATIONS REPORT ".center(78) + "║")
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
    crawler = StorageCrawler()
    crawler.gather_all_info()
    crawler.display_info(verbose=True)
    
    return crawler


if __name__ == "__main__":
    main()