#!/usr/bin/env python3
# -*- coding: utf-8 -*-

######################################################################
#                  HARDWARE CRAWLER v0.0.1                           #
#           Hardware Detection for Linux Servers                     #
#                                                                    #
# Comprehensive hardware information gathering on any Linux          #
# distribution. Combines kernel interfaces (/proc, /sys) with        #
# system commands for maximum compatibility and detail.              #
#                                                                    #
# CLEAR VERBOSITY PROGRESSION:                                       #
#  • --v   (Level 1): Essential hardware information only            #
#  • --vv  (Level 2): Extended specifications and details            #
#  • --vvv (Level 3): Complete deep analysis of all hardware         #
#                                                                    #
# Each component shows DIFFERENT output at each level:               #
#  • CPU: Model → Model + Stepping → All flags + microcode           #
#  • RAM: Total → Total + Cache info → All DMI + statistics          #
#  • Storage: Devices → Devices + partitions → Devices + SMART       #
#  • Motherboard: Basic → Basic + BIOS → Full with serials           #
#                                                                    #
# STRICT HARDWARE DETECTION ONLY:                                    #
#  • OS Detection: Distribution, kernel, architecture                #
#  • CPU detection: cores, model, frequency, flags, virtualization   #
#  • RAM analysis: capacity, modules, speed, ECC, timings            #
#  • Motherboard info: BIOS version, chassis type, serial numbers    #
#  • Storage hardware: HDDs/SSDs detection, SMART status             #
#  • GPU enumeration: VGA and 3D graphics controllers                #
#  • PCI device listing: Complete hardware inventory                 #
#  • USB devices: All USB controllers and devices                    #
#                                                                    #
# Author: Alexandru Filcu                                            #
# License: MIT                                                       #
# Version: 0.0.1                                                     #
######################################################################

######################
# IMPORT HANDY TOOLS #
######################

import sys
import os
import subprocess
import json
import csv
import re
from collections import OrderedDict
from datetime import datetime

# -- Verify Python -- #
if sys.version_info < (3, 6):
    print("Error: Python 3.6 or later is required", file=sys.stderr)
    sys.exit(1)


class Colors:
    """ANSI color codes"""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'


class CommandExecutor:
    """Safe command execution with error handling"""
    
    def __init__(self, debug=False):
        self.debug = debug
    
    def debug_log(self, msg):
        if self.debug:
            print("[DEBUG] {}".format(msg), file=sys.stderr)
    
    @staticmethod
    def run_command(cmd, timeout=10):
        try:
            result = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL,
                                           universal_newlines=True, timeout=timeout)
            return result.strip()
        except:
            return None
    
    def run_debug(self, cmd, timeout=10):
        self.debug_log("CMD: {}".format(cmd))
        result = self.run_command(cmd, timeout)
        if result:
            self.debug_log("RESULT: {}".format(result[:80]))
        return result
    
    @staticmethod
    def command_exists(cmd):
        try:
            return subprocess.call("command -v {} >/dev/null 2>&1".format(cmd), shell=True) == 0
        except:
            return False
    
    @staticmethod
    def read_file(path):
        try:
            with open(path, 'r') as f:
                return f.read().strip()
        except:
            return None
    
    def read_debug(self, path):
        self.debug_log("READ: {}".format(path))
        result = self.read_file(path)
        if result:
            self.debug_log("CONTENT: {}".format(result[:80]))
        return result
    
    def get_value(self, cmd=None, fallback=None):
        if cmd:
            result = self.run_debug(cmd)
            if result:
                return result
        if fallback:
            result = self.read_debug(fallback)
            if result:
                return result
        return 'N/A'


class HardwareCrawler:
    """Hardware detection with clear verbosity levels"""
    
    def __init__(self, verbosity=1, dry_run=False, export_format=None, 
                 export_directory='.', debug=False, quiet=False):
        self.verbosity = min(max(verbosity, 1), 3)
        self.dry_run = dry_run
        self.export_format = export_format
        self.export_dir = export_directory
        self.debug = debug
        self.quiet = quiet
        self.executor = CommandExecutor(debug=debug)
        self.hardware_data = OrderedDict()
        self.root_available = os.geteuid() == 0 if hasattr(os, 'geteuid') else False
    
    def debug_log(self, msg):
        if self.debug and not self.quiet:
            print("[DEBUG] {}".format(msg), file=sys.stderr)
    
    def info_log(self, msg):
        if not self.quiet and msg:
            print("[INFO] {}".format(msg), file=sys.stderr)
    
    @staticmethod
    def color_text(text, color):
        return color + str(text) + Colors.ENDC

    @staticmethod
    def strip_ansi(text):
        return re.sub(r'\033\[[0-9;]*m', '', str(text))

    def center_text(self, text, width):
        text = str(text)
        if len(text) >= width:
            return text[:width]
        padding = width - len(text)
        return (" " * (padding // 2)) + text + (" " * (padding - padding // 2))

    def print_dry_run_table(self, data):
        headers = ["CHECK", "STATUS", "--v", "--vv", "--vvv"]
        col_widths = [25, 10, 6, 6, 6]
        border = "+" + "+".join(["-" * (w + 2) for w in col_widths]) + "+"
        
        print(border)
        header_row = "|"
        for i, h in enumerate(headers):
            header_row += " " + self.center_text(h, col_widths[i]) + " |"
        print(header_row)
        print(border)
        
        for row in data:
            row_str = "|"
            for i, cell in enumerate(row):
                row_str += " " + self.center_text(str(cell), col_widths[i]) + " |"
            print(row_str)
            print(border)

    def print_header(self, title):
        border = '#' * 80
        padding = (80 - len(title) - 8) // 2
        centered = '### ' + (' ' * padding) + title + (' ' * padding) + ' ###'
        print(self.color_text(border, Colors.HEADER))
        print(self.color_text(centered, Colors.HEADER))
        print(self.color_text(border + '\n', Colors.HEADER))

    def print_table(self, data):
        if not data:
            print(self.color_text("  No data available\n", Colors.WARNING))
            return

        col1_width = 30
        col2_width = 46
        
        top_border = '+' + '=' * col1_width + '+' + '=' * col2_width + '+'
        print(self.color_text(top_border, Colors.OKBLUE))

        for idx, row in enumerate(data):
            if len(row) >= 2:
                col1_text = str(row[0])
                col2_text = str(row[1])
                col1_clean = self.strip_ansi(col1_text)
                col2_clean = self.strip_ansi(col2_text)
                
                if len(col1_clean) > col1_width - 3:
                    col1_clean = col1_clean[:col1_width - 6] + '...'
                if len(col2_clean) > col2_width - 3:
                    col2_clean = col2_clean[:col2_width - 6] + '...'
                
                print('| ' + col1_clean.ljust(col1_width - 2) + ' | ' + col2_clean.ljust(col2_width - 2) + ' |')
                
                if idx < len(data) - 1:
                    separator = '+' + '-' * col1_width + '+' + '-' * col2_width + '+'
                    print(self.color_text(separator, Colors.OKBLUE))

        bottom_border = '+' + '=' * col1_width + '+' + '=' * col2_width + '+'
        print(self.color_text(bottom_border + '\n', Colors.OKBLUE))

    def perform_dry_run(self):
        self.info_log("The script has been executed and started in --dry-run=true mode.")
        self.info_log("The script will return the result for each hardware check and validate it according to the verbosity level.")
        self.info_log("The script will now begin verification to see if all necessary dependencies and requirements are met.")
        self.info_log("Starting the verification of dependencies and requirements.")
        print()

        # -- Format: (name, /proc_check, /sys_check, command, command_for, needs_root, available_at_v, available_at_vv, available_at_vvv) -- #
        checks = [
            ("OS Informations", "/proc/version", "/sys/kernel/", "uname", "uname", False, True, True, True),
            ("CPU Informations", "/proc/cpuinfo", "/sys/devices/system/cpu/", "lscpu", "lscpu", False, True, True, True),
            ("Memory Informations", "/proc/meminfo", "/sys/module/memory/", "free", "free", False, True, True, True),
            ("Block Devices Informations", "/proc/partitions", "/sys/block/", "lsblk", "lsblk", False, True, True, True),
            ("PCI Devices Informations", "/proc/bus/pci/", "/sys/bus/pci/", "lspci", "lspci", False, False, True, True),
            ("USB Devices Informations", "/proc/bus/usb/", "/sys/bus/usb/", "lsusb", "lsusb", False, False, False, True),
            ("DMI Informations", "/sys/devices/virtual/dmi/id/", "/sys/class/dmi/", "dmidecode", "dmidecode", True, False, True, True),
            ("GPU Informations", "/proc/bus/pci/", "/sys/class/drm/", "lspci", "lspci (GPU filtering)", False, False, True, True),
            ("SMART Status Informations", "/proc/scsi/", "/sys/block/", "smartctl", "smartctl", False, False, False, True),
        ]

        results = []
        passed = 0
        failed = 0

        for name, proc_path, sys_path, cmd, cmd_desc, needs_root, avail_v, avail_vv, avail_vvv in checks:
            try:
                self.info_log("Now checking dependencies and requirements for gathering the {} ...".format(name))
                
                # -- Check /proc -- #
                proc_available = os.path.exists(proc_path)
                proc_status = "✓" if proc_available else "✗"
                
                # -- Check /sys -- #
                sys_available = os.path.exists(sys_path)
                sys_status = "✓" if sys_available else "✗"
                
                # -- Check command -- #
                cmd_available = self.executor.command_exists(cmd)
                cmd_status = "✓" if cmd_available else "✗"
                
                # -- Build requirements string -- #
                reqs = []
                if proc_available:
                    reqs.append("{} {}".format(proc_status, proc_path))
                else:
                    reqs.append("{} {} (not found)".format(proc_status, proc_path))
                    
                if sys_available:
                    reqs.append("{} {}".format(sys_status, sys_path))
                else:
                    reqs.append("{} {} (not found)".format(sys_status, sys_path))
                    
                if cmd_available:
                    reqs.append("{} {}".format(cmd_status, cmd_desc))
                else:
                    reqs.append("{} {} (not found)".format(cmd_status, cmd_desc))
                
                self.info_log("Verifying the following dependencies and requirements:")
                for req in reqs:
                    self.info_log("  └─ {}".format(req))
                
                self.info_log("Finalizing the validation of dependencies and requirements.")
                
                # -- Determine overall availability -- #
                available = (proc_available or sys_available) and (cmd_available or not needs_root)
                
                if available:
                    if needs_root and not self.root_available:
                        result_str = "⚠"
                        print("[WARNING]: The script can gather {} but requires root privileges.".format(name))
                        print("[WARNING]: Please run the script with sudo to obtain all {} .".format(name))
                    else:
                        result_str = "✓"
                        passed += 1
                        self.info_log("The scripts can successfully gather the necessary {} .".format(name))
                else:
                    result_str = "✗"
                    failed += 1
                    print("[WARNING]: The script cannot successfully gather all necessary {} .".format(name))
                    missing = []
                    if not proc_available:
                        missing.append(proc_path)
                    if not sys_available:
                        missing.append(sys_path)
                    if not cmd_available:
                        missing.append(cmd)
                    print("[WARNING]: The script failed to gather all necessary {} because: {} not found.".format(name, ", ".join(missing)))
                    print("[WARNING]: Please verify and fix the mentioned problems to be able to fully run the script.")
                
                print()
                
                v_status = "✓" if (avail_v and available and not (needs_root and not self.root_available)) else "✗"
                vv_status = "✓" if (avail_vv and available and not (needs_root and not self.root_available)) else "✗"
                vvv_status = "✓" if (avail_vvv and available and not (needs_root and not self.root_available)) else "✗"
                
                # -- Table display names -- #
                table_names = {
                    "OS Informations": "OS Informations",
                    "CPU Informations": "CPU Informations",
                    "Memory Informations": "Memory Informations",
                    "Block Devices Informations": "Block Devices",
                    "PCI Devices Informations": "PCI Devices",
                    "USB Devices Informations": "USB Devices",
                    "DMI Informations": "DMI Information",
                    "GPU Informations": "GPU Detection",
                    "SMART Status Informations": "SMART Status",
                }
                
                results.append([table_names.get(name, name), result_str, v_status, vv_status, vvv_status])
            except Exception as e:
                self.info_log("ERROR checking {}: {}".format(name, str(e)))
                results.append([name, "ERR", "✗", "✗", "✗"])
                failed += 1

        self.info_log("The summary of the verification is available in the following overview:")
        print()
        self.print_dry_run_table(results)
        
        print()
        return failed == 0

    ###################
    # OS Informations #
    ###################

    def get_os_info(self):
        data = OrderedDict()
        try:
            # -- Level 1 -- #
            data['Kernel Release'] = self.executor.get_value("uname -r")
            data['Architecture'] = self.executor.get_value("uname -m")
            
            os_release = self.executor.read_file('/etc/os-release')
            if os_release:
                for line in os_release.split('\n'):
                    if line.startswith('NAME='):
                        data['Distribution'] = line.split('=')[1].strip('"')
                    elif line.startswith('VERSION='):
                        data['Version'] = line.split('=')[1].strip('"')
            
            # -- Level 2 -- #
            if self.verbosity >= 2:
                data['Kernel Version'] = self.executor.get_value("uname -v")
                data['Hardware Platform'] = self.executor.get_value("uname -i")
            
            # -- Level 3 -- #
            if self.verbosity >= 3:
                data['Pretty Name'] = self.executor.get_value("grep PRETTY_NAME /etc/os-release | cut -d= -f2 | xargs")
                data['Build ID'] = self.executor.get_value("grep BUILD_ID /etc/os-release | cut -d= -f2 | xargs")
        except Exception as e:
            self.debug_log("OS error: {}".format(str(e)))
        return data

    ####################
    # CPU Informations #
    ####################

    def get_cpu_components(self):
        data = OrderedDict()
        try:
            # -- Level 1 -- #
            data['Physical Count'] = self.executor.get_value("grep -c '^processor' /proc/cpuinfo")
            data['CPU Model'] = self.executor.get_value("grep -m 1 'model name' /proc/cpuinfo | cut -d: -f2 | xargs")
            data['Total Cores'] = self.executor.get_value("nproc")
            data['CPU Vendor'] = self.executor.get_value("grep -m 1 'vendor_id' /proc/cpuinfo | cut -d: -f2 | xargs")
            
            # -- Level 2 -- #
            if self.verbosity >= 2:
                data['CPU Stepping'] = self.executor.get_value("grep -m 1 'stepping' /proc/cpuinfo | cut -d: -f2 | xargs")
                data['CPU Family'] = self.executor.get_value("grep -m 1 'cpu family' /proc/cpuinfo | cut -d: -f2 | xargs")
                data['L3 Cache'] = self.executor.get_value("grep -m 1 'cache size' /proc/cpuinfo | cut -d: -f2 | xargs")
                data['Cores Per Socket'] = self.executor.get_value("grep -m 1 'cpu cores' /proc/cpuinfo | cut -d: -f2 | xargs")
                data['Frequency (MHz)'] = self.executor.get_value("grep -m 1 'cpu MHz' /proc/cpuinfo | cut -d: -f2 | xargs")
                
                flags = self.executor.get_value("grep -m 1 'flags' /proc/cpuinfo | cut -d: -f2 | xargs") or ""
                data['VMX (Intel)'] = 'Yes' if 'vmx' in flags else 'No'
                data['SVM (AMD)'] = 'Yes' if 'svm' in flags else 'No'
            
            # -- Level 3 -- #
            if self.verbosity >= 3:
                flags = self.executor.get_value("grep -m 1 'flags' /proc/cpuinfo | cut -d: -f2 | xargs") or ""
                if flags:
                    flags_list = flags.split()
                    data['Total Extensions'] = str(len(flags_list))
                    important = ['vmx', 'svm', 'avx', 'avx2', 'aes', 'rdrand']
                    found = [f for f in important if f in flags_list]
                    data['Important Extensions'] = ', '.join(found) if found else 'None'
                
                data['Microcode'] = self.executor.get_value("grep -m 1 'microcode' /proc/cpuinfo | cut -d: -f2 | xargs")
                data['Bogomips'] = self.executor.get_value("grep -m 1 'bogomips' /proc/cpuinfo | cut -d: -f2 | xargs")
                data['FPU'] = self.executor.get_value("grep -m 1 '^fpu[[:space:]]' /proc/cpuinfo | cut -d: -f2 | xargs")
        except Exception as e:
            self.debug_log("CPU error: {}".format(str(e)))
        return data

    ####################
    # RAM Informations #
    ####################

    def get_ram_components(self):
        data = OrderedDict()
        try:
            meminfo = self.executor.read_file('/proc/meminfo') or ""
            
            # -- Level 1 -- #
            total_ram = 0
            mem_free = 0
            for line in meminfo.split('\n'):
                if line.startswith('MemTotal:'):
                    kb = int(line.split()[1])
                    total_ram = kb
                    data['Total RAM'] = '{:.2f} GB'.format(kb / (1024 * 1024))
                elif line.startswith('MemFree:'):
                    kb = int(line.split()[1])
                    mem_free = kb
                elif line.startswith('SwapTotal:'):
                    kb = int(line.split()[1])
                    data['Total Swap'] = '{:.2f} GB'.format(kb / (1024 * 1024))
            
            # -- Calculate RAM Used at level 1 -- #
            if total_ram > 0 and mem_free > 0:
                ram_used = total_ram - mem_free
                data['RAM Used'] = '{:.2f} GB'.format(ram_used / (1024 * 1024))
            
            # -- Level 2 -- #
            if self.verbosity >= 2:
                for line in meminfo.split('\n'):
                    if line.startswith('MemAvailable:'):
                        kb = int(line.split()[1])
                        data['Available RAM'] = '{:.2f} GB'.format(kb / (1024 * 1024))
                    elif line.startswith('MemFree:'):
                        kb = int(line.split()[1])
                        data['Free RAM'] = '{:.2f} GB'.format(kb / (1024 * 1024))
                    elif line.startswith('Cached:'):
                        kb = int(line.split()[1])
                        data['Cached Memory'] = '{:.2f} MB'.format(kb / 1024)
                    elif line.startswith('Buffers:'):
                        kb = int(line.split()[1])
                        data['Buffered Memory'] = '{:.2f} MB'.format(kb / 1024)
                
                # -- Add DMI info at level 2 -- #
                if self.executor.command_exists('dmidecode'):
                    try:
                        data['RAM Modules'] = self.executor.run_debug("dmidecode -t memory 2>/dev/null | grep -c 'Memory Device'")
                        data['RAM Speed'] = self.executor.get_value("dmidecode -t memory 2>/dev/null | grep -m 1 'Speed' | cut -d: -f2 | xargs")
                        data['RAM Type'] = self.executor.get_value("dmidecode -t memory 2>/dev/null | grep -m 1 'Type:' | cut -d: -f2 | xargs")
                        data['Form Factor'] = self.executor.get_value("dmidecode -t memory 2>/dev/null | grep -m 1 'Form Factor' | cut -d: -f2 | xargs")
                    except:
                        pass
            
            # -- Level 3 -- #
            if self.verbosity >= 3:
                for line in meminfo.split('\n'):
                    if line.startswith('Active:'):
                        kb = int(line.split()[1])
                        data['Active Memory'] = '{:.2f} GB'.format(kb / (1024 * 1024))
                    elif line.startswith('Inactive:'):
                        kb = int(line.split()[1])
                        data['Inactive Memory'] = '{:.2f} GB'.format(kb / (1024 * 1024))
                    elif line.startswith('Dirty:'):
                        kb = int(line.split()[1])
                        data['Dirty Pages'] = '{:.2f} MB'.format(kb / 1024)
                    elif line.startswith('HugePages_Total:'):
                        data['Huge Pages Total'] = line.split()[1]
                    elif line.startswith('HugePages_Free:'):
                        data['Huge Pages Free'] = line.split()[1]
                
                # -- Deep DMI at level 3 -- #
                if self.executor.command_exists('dmidecode'):
                    try:
                        data['RAM Voltage'] = self.executor.get_value("dmidecode -t memory 2>/dev/null | grep -m 1 'Voltage' | cut -d: -f2 | xargs")
                        data['Error Correction'] = self.executor.get_value("dmidecode -t memory 2>/dev/null | grep -m 1 'Error Correction' | cut -d: -f2 | xargs")
                        data['Manufacturer'] = self.executor.get_value("dmidecode -t memory 2>/dev/null | grep -m 1 'Manufacturer' | cut -d: -f2 | xargs")
                        data['Part Number'] = self.executor.get_value("dmidecode -t memory 2>/dev/null | grep -m 1 'Part Number' | cut -d: -f2 | xargs")
                        data['Serial Number'] = self.executor.get_value("dmidecode -t memory 2>/dev/null | grep -m 1 'Serial Number' | cut -d: -f2 | xargs")
                        data['Bank Locator'] = self.executor.get_value("dmidecode -t memory 2>/dev/null | grep -m 1 'Bank Locator' | cut -d: -f2 | xargs")
                    except:
                        pass
        except Exception as e:
            self.debug_log("RAM error: {}".format(str(e)))
        return data

    ############################
    # MOTHERBOARD Informations #
    ############################

    def get_motherboard_info(self):
        data = OrderedDict()
        try:
            # -- Level 1 -- #
            if self.executor.command_exists('dmidecode'):
                data['System Manufacturer'] = self.executor.get_value("dmidecode -t system 2>/dev/null | grep Manufacturer | head -1 | cut -d: -f2 | xargs")
                data['Product Name'] = self.executor.get_value("dmidecode -t system 2>/dev/null | grep 'Product Name' | head -1 | cut -d: -f2 | xargs")
            else:
                dmi_path = '/sys/devices/virtual/dmi/id/'
                if os.path.exists(dmi_path):
                    data['System Manufacturer'] = self.executor.read_file(dmi_path + 'sys_vendor') or 'N/A'
                    data['Product Name'] = self.executor.read_file(dmi_path + 'product_name') or 'N/A'
            
            # -- Level 2 -- #
            if self.verbosity >= 2 and self.executor.command_exists('dmidecode'):
                data['BIOS Vendor'] = self.executor.get_value("dmidecode -t bios 2>/dev/null | grep Vendor | head -1 | cut -d: -f2 | xargs")
                data['BIOS Version'] = self.executor.get_value("dmidecode -t bios 2>/dev/null | grep Version | head -1 | cut -d: -f2 | xargs")
                data['BIOS Date'] = self.executor.get_value("dmidecode -t bios 2>/dev/null | grep 'Release Date' | cut -d: -f2 | xargs")
                data['Chassis Type'] = self.executor.get_value("dmidecode -t chassis 2>/dev/null | grep Type | head -1 | cut -d: -f2 | xargs")
            
            # -- Level 3 -- #
            if self.verbosity >= 3 and self.executor.command_exists('dmidecode'):
                data['System Serial'] = self.executor.get_value("dmidecode -t system 2>/dev/null | grep 'Serial Number' | head -1 | cut -d: -f2 | xargs")
                data['System UUID'] = self.executor.get_value("dmidecode -t system 2>/dev/null | grep UUID | cut -d: -f2 | xargs")
                data['System SKU'] = self.executor.get_value("dmidecode -t system 2>/dev/null | grep SKU | cut -d: -f2 | xargs")
        except Exception as e:
            self.debug_log("Motherboard error: {}".format(str(e)))
        return data

    ########################
    # STORAGE Informations #
    ########################

    def get_storage_components(self):
        data = []
        try:
            # -- Level 1 -- #
            block = self.executor.get_value("lsblk -d -o NAME,SIZE,TYPE,ROTA,MODEL 2>/dev/null")
            if block and block != 'N/A':
                for i, line in enumerate(block.split('\n')):
                    if i > 0 and line.strip():
                        try:
                            parts = line.split(None, 4)
                            if len(parts) >= 2:
                                name = parts[0]
                                size = parts[1]
                                rota = parts[3] if len(parts) > 3 else 'N/A'
                                model = parts[4] if len(parts) > 4 else 'Virtual'
                                dtype = 'SSD' if rota == '0' else 'HDD' if rota == '1' else 'UNKNOWN'
                                data.append(['/dev/' + name, '{} [{}] {}'.format(size, dtype, model)])
                        except:
                            pass
            
            # -- Level 3 -- #
            if self.verbosity >= 3 and self.executor.command_exists('smartctl'):
                disks = self.executor.get_value("lsblk -d -o NAME 2>/dev/null | grep -v NAME | head -2")
                if disks and disks != 'N/A':
                    for disk in disks.split('\n'):
                        if disk.strip():
                            health = self.executor.run_debug("smartctl -H /dev/{} 2>/dev/null | grep 'SMART overall'".format(disk.strip()))
                            if health and health != 'N/A':
                                status = health.split()[-1] if health else 'N/A'
                                data.append(['   └─ {} [SMART]'.format(disk.strip()), 'Status: {}'.format(status)])
        except Exception as e:
            self.debug_log("Storage error: {}".format(str(e)))
        return data

    ####################
    # GPU Informations #
    ####################

    def get_gpu_info(self):
        data = []
        try:
            gpu = self.executor.get_value("lspci 2>/dev/null | grep -i 'vga\\|3d\\|display\\|graphics'")
            if gpu and gpu != 'N/A':
                for line in gpu.split('\n'):
                    if line.strip():
                        match = re.match(r'^([0-9a-f:.]+)\s+(.*)', line)
                        if match:
                            data.append([match.group(1), match.group(2)])
        except Exception as e:
            self.debug_log("GPU error: {}".format(str(e)))
        return data

    ####################
    # PCI Informations #
    ####################

    def get_pci_devices(self):
        data = []
        try:
            pci = self.executor.get_value("lspci 2>/dev/null")
            if pci and pci != 'N/A':
                for line in pci.split('\n')[:30]:
                    if line.strip():
                        match = re.match(r'^([0-9a-f:.]+)\s+(.*)', line)
                        if match:
                            data.append([match.group(1), match.group(2)])
        except Exception as e:
            self.debug_log("PCI error: {}".format(str(e)))
        return data

    ####################
    # USB Informations #
    ####################

    def get_usb_devices(self):
        data = []
        try:
            if self.executor.command_exists('lsusb'):
                usb = self.executor.get_value("lsusb 2>/dev/null")
                if usb and usb != 'N/A':
                    for line in usb.split('\n'):
                        if line.strip():
                            data.append(['USB Device', line.strip()])
        except Exception as e:
            self.debug_log("USB error: {}".format(str(e)))
        return data

    ##########
    # EXPORT #
    ##########

    def export_to_json(self, filepath):
        try:
            if self.dry_run:
                if not self.quiet:
                    print(self.color_text('[DRY-RUN] Would export JSON to: {}'.format(filepath), Colors.OKBLUE))
                return True
            os.makedirs(os.path.dirname(filepath) or '.', exist_ok=True)
            with open(filepath, 'w') as f:
                json.dump(self.hardware_data, f, indent=2)
            print(self.color_text('[+] Exported: {}'.format(filepath), Colors.OKGREEN))
            return True
        except Exception as e:
            print(self.color_text('[-] Export error: {}'.format(str(e)), Colors.FAIL))
            return False

    def export_to_csv(self, filepath):
        try:
            if self.dry_run:
                if not self.quiet:
                    print(self.color_text('[DRY-RUN] Would export CSV to: {}'.format(filepath), Colors.OKBLUE))
                return True
            os.makedirs(os.path.dirname(filepath) or '.', exist_ok=True)
            with open(filepath, 'w', newline='') as f:
                writer = csv.writer(f)
                for section, items in self.hardware_data.items():
                    writer.writerow([section])
                    if isinstance(items, dict):
                        for k, v in items.items():
                            writer.writerow([k, v])
                    elif isinstance(items, list):
                        for row in items:
                            writer.writerow(row)
                    writer.writerow([])
            print(self.color_text('[+] Exported: {}'.format(filepath), Colors.OKGREEN))
            return True
        except Exception as e:
            print(self.color_text('[-] Export error: {}'.format(str(e)), Colors.FAIL))
            return False

    def export_to_log(self, filepath):
        try:
            if self.dry_run:
                if not self.quiet:
                    print(self.color_text('[DRY-RUN] Would export LOG to: {}'.format(filepath), Colors.OKBLUE))
                return True
            os.makedirs(os.path.dirname(filepath) or '.', exist_ok=True)
            with open(filepath, 'w') as f:
                f.write('HARDWARE REPORT\n')
                f.write('Generated: {}\n'.format(datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
                f.write('=' * 80 + '\n\n')
                
                for section, items in self.hardware_data.items():
                    f.write('\n' + '=' * 80 + '\n')
                    f.write(section + '\n')
                    f.write('=' * 80 + '\n\n')
                    
                    if isinstance(items, dict):
                        for k, v in items.items():
                            f.write('{}: {}\n'.format(k, v))
                    elif isinstance(items, list):
                        for row in items:
                            f.write(' | '.join(str(x) for x in row) + '\n')
                    f.write('\n')
            
            print(self.color_text('[+] Exported: {}'.format(filepath), Colors.OKGREEN))
            return True
        except Exception as e:
            print(self.color_text('[-] Export error: {}'.format(str(e)), Colors.FAIL))
            return False

    #####################
    # COLLECT & DISPLAY #
    #####################

    def collect_all_data(self):
        self.hardware_data['Operating System'] = self.get_os_info()
        self.hardware_data['CPU Components'] = self.get_cpu_components()
        self.hardware_data['RAM Components'] = self.get_ram_components()
        self.hardware_data['Motherboard'] = self.get_motherboard_info()
        self.hardware_data['Storage Hardware'] = self.get_storage_components()
        self.hardware_data['GPU Devices'] = self.get_gpu_info()
        
        if self.verbosity >= 2:
            self.hardware_data['PCI Devices'] = self.get_pci_devices()
        
        if self.verbosity >= 3:
            self.hardware_data['USB Devices'] = self.get_usb_devices()

    def display_all_data(self):
        for section, items in self.hardware_data.items():
            self.print_header(section)
            if isinstance(items, dict):
                self.print_table([[k, v] for k, v in items.items()])
            elif isinstance(items, list):
                if items:
                    self.print_table(items)
                else:
                    print(self.color_text("  No data available\n", Colors.WARNING))

    def export(self, fmt):
        if not self.hardware_data:
            print(self.color_text('No data to export', Colors.WARNING))
            return False
        
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        if fmt == 'json':
            return self.export_to_json(os.path.join(self.export_dir, f'hardware_{ts}.json'))
        elif fmt == 'csv':
            return self.export_to_csv(os.path.join(self.export_dir, f'hardware_{ts}.csv'))
        elif fmt == 'log':
            return self.export_to_log(os.path.join(self.export_dir, f'hardware_{ts}.log'))
        
        return False

    def run(self):
        try:
            if self.dry_run:
                return self.perform_dry_run()
            
            self.collect_all_data()
            
            if not self.export_format:
                self.display_all_data()
                return True
            else:
                return self.export(self.export_format)
        except Exception as e:
            self.debug_log("Run error: {}".format(str(e)))
            return False


def parse_args(args):
    config = {
        'verbosity': 1,
        'dry_run': True,
        'export_format': None,
        'export_directory': '.',
        'debug': False,
        'quiet': False
    }
    
    for arg in args:
        if arg == '--help':
            print_help()
            sys.exit(0)
        elif arg == '--version':
            print("hardware_crawler version 0.0.1")
            sys.exit(0)
        elif arg == '--debug':
            config['debug'] = True
        elif arg == '--quiet':
            config['quiet'] = True
        elif arg == '--v':
            config['verbosity'] = 1
        elif arg == '--vv':
            config['verbosity'] = 2
        elif arg == '--vvv':
            config['verbosity'] = 3
        elif arg.startswith('--dry-run='):
            config['dry_run'] = arg.split('=')[1].lower() in ('true', '1', 'yes')
        elif arg.startswith('--export='):
            config['export_format'] = arg.split('=')[1].lower()
        elif arg.startswith('--export-directory='):
            config['export_directory'] = arg.split('=', 1)[1]
    
    return config


def print_help():
    print("""
HARDWARE CRAWLER v0.0.1 - Linux Server Hardware Detection

DESCRIPTION:
  Hardware Crawler is a comprehensive hardware information gathering tool for Linux servers. 
  It reports hardware details like CPU, RAM, motherboard, storage, and GPU using /proc, /sys, and system commands.

USAGE:
   python3 hardware_crawler.sh [OPTIONS]
   ./hardware_crawler.sh [OPTIONS]

OPTIONS:
  --help                     Show this help message
  --version                  Show version information
  --debug                    Enable debug logging to stderr
  --quiet                    Suppress console output (except exports)
  
  EXECUTION MODE:
  --dry-run=true             Validate dependencies without collecting (default)
  --dry-run=false            Perform full hardware collection and analysis
  
  VERBOSITY LEVELS:
  --v                        Basic information (default)
  --vv                       Extended information with detailed specs
  --vvv                      Deep hardware enumeration (all details)
  
  EXPORT OPTIONS:
  --export=json              Export to JSON format
  --export=csv               Export to CSV format
  --export=log               Export to LOG format
  --export-directory=/path   Save exports to specific directory

############
# EXAMPLES #
############

1. VALIDATE SYSTEM CONFIGURATION (DRY-RUN MODE):
   
   Command:
     python3 hardware_crawler.sh --dry-run=true
     ./hardware_crawler.sh --dry-run=true
   
   What it does:
     • Checks if all dependencies (/proc, /sys, commands) are available
     • Verifies which hardware detection methods can be used
     • Shows compatibility table with support for --v, --vv, --vvv levels
     • Does NOT collect actual hardware information
     • Perfect for pre-flight checks before running full collection
   
   Output:
     Shows detailed validation for each check:
     - OS Informations: /proc/version, /sys/kernel/, uname command
     - CPU Informations: /proc/cpuinfo, /sys/devices/system/cpu/, lscpu
     - Memory Informations: /proc/meminfo, /sys/module/memory/, free
     - And more for Block Devices, PCI, USB, DMI, GPU, SMART
   
   Use case:
     Before running the full script, verify your system has all required dependencies. 
     Useful for troubleshooting missing hardware detection.


2. COLLECT BASIC HARDWARE INFORMATION:
   
   Command:
     python3 hardware_crawler.sh --dry-run=false --v
     ./hardware_crawler.sh --dry-run=false --v
   
   What it does:
     • Collects essential hardware information only
     • Minimalist output with core specifications
     • Fast execution
     • Shows: OS kernel/arch/distribution, CPU model/cores, RAM total/swap,
       Motherboard manufacturer, Storage devices, GPU detection
   
   Output:
     Organized sections with key information:
     ├─ Operating System: Kernel Release, Architecture, Distribution, Version
     ├─ CPU Components: Physical Count, Model, Total Cores, Vendor
     ├─ RAM Components: Total RAM, Total Swap, RAM Used
     ├─ Motherboard: Manufacturer, Product Name
     ├─ Storage Hardware: Device list with size/type
     └─ GPU Devices: Detected graphics controllers
   
   Use case:
     Quick hardware overview for documentation or basic system assessment.
     Ideal for automated checks that don't need detailed specifications.


3. COLLECT EXTENDED HARDWARE DETAILS:
   
   Command:
     python3 hardware_crawler.sh --dry-run=false --vv
     ./hardware_crawler.sh --dry-run=false --vv
   
   What it does:
     • Collects detailed hardware specifications
     • Includes stepping, family, cache, frequency, virtualization support
     • RAM speed, type, form factor, ECC information
     • BIOS version, release date, chassis type
     • PCI device listing
   
   Output:
     Extended sections with comprehensive data:
     ├─ OS: Kernel version, hardware platform, build ID
     ├─ CPU: Stepping, Family, Cache, Frequency, Virtualization (VMX/SVM)
     ├─ RAM: Available, Free, Cached, Buffered (+ DMI specs)
     ├─ Motherboard: BIOS Vendor, Version, Date, Chassis Type
     ├─ Storage: Device details with model information
     ├─ PCI Devices: Complete hardware inventory
     └─ GPU: Detailed graphics controller detection
   
   Use case:
     Detailed hardware audit for system administration, capacity planning,
     or hardware compatibility assessment.


4. COLLECT COMPLETE HARDWARE ENUMERATION:
   
   Command:
     python3 hardware_crawler.sh --dry-run=false --vvv
     ./hardware_crawler.sh --dry-run=false --vvv 
          
   What it does:
     • Collects EVERYTHING about hardware
     • CPU flags, microcode, extensions, FPU information
     • Complete memory statistics (active, inactive, dirty, huge pages)
     • Memory manufacturer, part number, serial, bank locators
     • System UUID, serial numbers, SKU
     • SMART status for storage devices
     • USB device enumeration
   
   Output:
     Complete detailed sections:
     ├─ OS: All kernel info, build ID, version codename
     ├─ CPU: All flags, microcode, FPU, APIC ID, bogomips
     ├─ RAM: 15+ fields including advanced memory statistics
     ├─ Motherboard: All identifiers, serials, UUID, SKU
     ├─ Storage: Full specs + SMART health status
     ├─ PCI Devices: Complete inventory
     ├─ GPU: All graphics controllers
     └─ USB Devices: All USB devices and controllers
   
   Use case:
     Maximum detail for hardware documentation, compliance audits,
     detailed problem diagnostics, or long-term capacity tracking.


5. EXPORT HARDWARE DATA TO JSON:
   
   Command:
     python3 hardware_crawler.sh --dry-run=false --vv --export=json --export-directory=/tmp
     ./hardware_crawler.sh --dry-run=false --vv --export=json --export-directory=/tmp
   
   What it does:
     • Collects extended hardware information (level --vv)
     • Exports data to JSON format
     • Saves to /tmp directory with timestamp filename
     • JSON format allows programmatic processing
   
   Output:
     Creates file: /tmp/hardware_yyyymmdd_hhmmss.json
     Contains: Structured JSON data ready for parsing by other tools
   
   Use case:
     Integration with other tools, API consumption, long-term monitoring
     databases, or automated hardware tracking systems.


6. EXPORT HARDWARE DATA TO CSV:
   
   Command:
     python3 hardware_crawler.sh --dry-run=false --vvv --export=csv --export-directory=/tmp
     ./hardware_crawler.sh --dry-run=false --vvv --export=csv --export-directory=/tmp
   
   What it does:
     • Collects complete hardware information (level --vvv)
     • Exports data to CSV format
     • Compatible with Excel and spreadsheet applications
   
   Output:
     Creates file: /tmp/hardware_yyyymmdd_hhmmss.csv
     Contains: Comma-separated values organized by sections
   
   Use case:
     Spreadsheet analysis, data comparison across multiple systems,
     presentation-ready hardware reports.


7. EXPORT HARDWARE DATA TO LOG:
   
   Command:
     python3 hardware_crawler.sh --dry-run=false --vv --export=log --export-directory=/tmp
     ./hardware_crawler.sh --dry-run=false --vv --export=log --export-directory=/tmp
   
   What it does:
     • Collects extended hardware information
     • Exports to human-readable LOG format
     • Includes timestamp and formatted sections
   
   Output:
     Creates file: /tmp/hardware_yyyymmdd_hhmmss.log
     Contains: Pretty-printed hardware information
   
   Use case:
     Documentation, archival records, system baselines,
     easy-to-read reports for non-technical users.


8. DEBUG MODE WITH FULL ENUMERATION:
   
   Command:
     python3 hardware_crawler.sh --debug --dry-run=false --vvv
     ./hardware_crawler.sh --debug --dry-run=false --vvv
   
   What it does:
     • Enables debug logging to stderr
     • Shows every command executed and its results
     • Collects complete hardware information (level --vvv)
     • Useful for troubleshooting and understanding script behavior
   
   Output:
     Standard output: Hardware sections as usual
     Debug output (stderr): [DEBUG] messages showing:
       - Executed commands
       - File read operations
       - Command results
   
   Use case:
     Troubleshooting hardware detection issues, understanding why
     certain data is not available, script development and debugging.


9. QUIET MODE WITH EXPORT:
   
   Command:
     python3 hardware_crawler.sh --quiet --dry-run=false --vvv --export=json
     ./hardware_crawler.sh --quiet --dry-run=false --vvv --export=json
   
   What it does:
     • Suppresses all console output except export messages
     • Collects complete hardware information
     • Exports to JSON format
     • Clean, non-verbose execution
   
   Output:
     Only: [+] Data exported to: /tmp/hardware_yyyymmdd_hhmmss.json
     All hardware info sent to file, nothing to console
   
   Use case:
     Automated scripts, cron jobs, background tasks where
     console output is not needed.


10. COMPLETE DOCUMENTATION RUN:
    
    Command:
      python3 hardware_crawler.sh --dry-run=false --vvv --export=log --export-directory=/tmp
      ./hardware_crawler.sh --dry-run=false --vvv --export=log --export-directory=/tmp
    
    What it does:
      • Collects ALL hardware information (level --vvv)
      • Exports to readable LOG format
      • Saves to ./reports directory
      • Creates timestamped filename
    
    Output:
      Creates: ./reports/hardware_yyyymmdd_hhmmss.log
      Contains: Complete, formatted, human-readable hardware documentation
    
    Use case:
      System documentation, hardware inventory, compliance records,
      baseline creation for future comparisons.

##############################
# VERBOSITY LEVEL COMPARISON #
##############################

  --v (BASIC):
    ✓ Essential info only (4-7 fields per component)
    ✓ Fastest execution
    ✓ Minimal output size
    ✓ Best for: Quick checks, automated systems, minimal logging
    
  --vv (EXTENDED):
    ✓ Detailed specs (9-15 fields per component)
    ✓ Moderate execution time
    ✓ Comprehensive data
    ✓ Best for: System audits, capacity planning, hardware assessment
    
  --vvv (DEEP):
    ✓ Complete enumeration (15+ fields per component)
    ✓ Slower execution (but still < 5 seconds)
    ✓ Maximum detail level
    ✓ Best for: Full documentation, compliance, problem diagnostics

#############################
# DRY-RUN vs FULL EXECUTION #
#############################

  DRY-RUN (--dry-run=true):
    • Does NOT collect hardware information
    • Validates all dependencies exist
    • Shows compatibility matrix
    • Use: Before running full script to check system readiness
    • Time: < 1 second
    
  FULL EXECUTION (--dry-run=false):
    • Collects actual hardware information
    • Displays or exports results
    • Uses detected dependencies
    • Use: Actual hardware data collection
    • Time: 1-5 seconds depending on verbosity

################
# REQUIREMENTS #
################

  Minimum:
    • Python 3.6 or later
    • Linux kernel with /proc/cpuinfo
    • Basic utilities: uname, cat, grep
    
  Optional (for enhanced detection):
    • lsblk, lspci, lsusb, dmidecode, smartctl
    
  Note:
    Script works with or without optional tools - it gracefully falls back to /proc and /sys when commands unavailable.
    """)


def main():
    try:
        config = parse_args(sys.argv[1:])
        
        crawler = HardwareCrawler(
            verbosity=config['verbosity'],
            dry_run=config['dry_run'],
            export_format=config['export_format'],
            export_directory=config['export_directory'],
            debug=config['debug'],
            quiet=config['quiet']
        )
        
        success = crawler.run()
        sys.exit(0 if success else 1)
    
    except KeyboardInterrupt:
        print(Colors.FAIL + '\n[-] Interrupted' + Colors.ENDC)
        sys.exit(1)
    except Exception as e:
        print(Colors.FAIL + '\n[-] Error: ' + str(e) + Colors.ENDC)
        sys.exit(1)


if __name__ == '__main__':
    main()
