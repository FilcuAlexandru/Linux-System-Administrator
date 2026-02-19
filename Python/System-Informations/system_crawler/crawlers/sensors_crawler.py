#!/usr/bin/env python3.6
# -*- coding: utf-8 -*-

##################################################################################################
# A Python 3.6 script that verifies Sensor information on a Linux server.                        #
# The script verifies the following: temperature, voltage, fan speed, and other sensor readings. #
# Version: 0.0.1                                                                                 #
# Author: Alexandru Filcu                                                                        #
##################################################################################################

######################
# Import handy tools #
######################

import subprocess
import sys
import json
from collections import OrderedDict


class SensorsCrawler:
    """Class for collecting Sensor information"""
    
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
    
    def get_sensors_info(self):
        """Get sensor information using sensors command"""
        sensors_info = OrderedDict()
        
        # Check if lm_sensors is available
        sensors_check = self.run_command("which sensors", shell=True)
        
        if sensors_check:
            # Get all sensor data
            all_sensors = self.run_command("sensors", shell=True)
            sensors_info['all_sensors'] = all_sensors if all_sensors else "N/A"
            
            # Get sensor data with JSON output if available
            sensors_json = self.run_command("sensors -A -u", shell=True)
            sensors_info['sensors_detailed'] = sensors_json if sensors_json else "N/A"
        else:
            sensors_info['all_sensors'] = "lm_sensors not installed"
            sensors_info['sensors_detailed'] = "lm_sensors not installed"
        
        self.info['lm_sensors'] = sensors_info
    
    def get_thermal_zone_info(self):
        """Get thermal zone information from /sys/class/thermal/"""
        thermal_info = OrderedDict()
        
        # Get list of thermal zones
        thermal_zones = self.run_command("ls /sys/class/thermal/thermal_zone* 2>/dev/null | wc -l", shell=True)
        thermal_info['thermal_zones_count'] = thermal_zones if thermal_zones else "0"
        
        # Get temperature from thermal zones
        thermal_temp = self.run_command("for zone in /sys/class/thermal/thermal_zone*; do echo \"$zone: $(cat $zone/temp 2>/dev/null || echo 'N/A') mC\"; done", shell=True)
        thermal_info['thermal_zones_temperature'] = thermal_temp if thermal_temp else "N/A"
        
        # Get thermal zone types
        thermal_types = self.run_command("for zone in /sys/class/thermal/thermal_zone*; do echo \"$(basename $zone): $(cat $zone/type 2>/dev/null || echo 'N/A')\"; done", shell=True)
        thermal_info['thermal_zones_types'] = thermal_types if thermal_types else "N/A"
        
        self.info['thermal_zones'] = thermal_info
    
    def get_acpi_thermal_info(self):
        """Get ACPI thermal information"""
        acpi_thermal = OrderedDict()
        
        # Check for thermal module
        acpi_temp = self.run_command("cat /proc/acpi/thermal_zone/*/temperature 2>/dev/null || echo 'No ACPI thermal zones found'", shell=True)
        acpi_thermal['acpi_thermal_temperature'] = acpi_temp if acpi_temp else "N/A"
        
        # Get ACPI trip points
        acpi_trips = self.run_command("cat /proc/acpi/thermal_zone/*/trip_points 2>/dev/null || echo 'No trip points found'", shell=True)
        acpi_thermal['acpi_trip_points'] = acpi_trips if acpi_trips else "N/A"
        
        self.info['acpi_thermal'] = acpi_thermal
    
    def get_cpu_temperature(self):
        """Get CPU temperature from various sources"""
        cpu_temp = OrderedDict()
        
        # Try cpufreq-info
        cpufreq_check = self.run_command("which cpufreq-info", shell=True)
        if cpufreq_check:
            cpufreq_temp = self.run_command("cpufreq-info -i 2>/dev/null | grep -i temperature", shell=True)
            cpu_temp['cpufreq_temperature'] = cpufreq_temp if cpufreq_temp else "N/A"
        else:
            cpu_temp['cpufreq_temperature'] = "cpufreq-info not available"
        
        # Try from /proc/cpuinfo (some systems report it)
        cpuinfo_temp = self.run_command("grep -i 'temperature' /proc/cpuinfo", shell=True)
        cpu_temp['cpuinfo_temperature'] = cpuinfo_temp if cpuinfo_temp else "N/A"
        
        # Try from dmesg
        dmesg_temp = self.run_command("dmesg | grep -i 'temperature\\|thermal' | tail -5", shell=True)
        cpu_temp['dmesg_temperature'] = dmesg_temp if dmesg_temp else "N/A"
        
        self.info['cpu_temperature'] = cpu_temp
    
    def get_fan_information(self):
        """Get fan speed information"""
        fan_info = OrderedDict()
        
        # Get fan speeds from thermal_zone
        fan_speeds = self.run_command("ls /sys/devices/platform/coretemp.0/hwmon/*/fan*_input 2>/dev/null | while read f; do echo \"$f: $(cat $f 2>/dev/null || echo 'N/A') RPM\"; done", shell=True)
        fan_info['fan_speeds'] = fan_speeds if fan_speeds else "N/A"
        
        # Try to get PWM fan control
        pwm_fans = self.run_command("ls /sys/devices/platform/*/pwm 2>/dev/null | while read f; do echo \"$f: $(cat $f 2>/dev/null || echo 'N/A')\"; done", shell=True)
        fan_info['pwm_fans'] = pwm_fans if pwm_fans else "N/A"
        
        # Get fan info from sensors command
        sensors_fans = self.run_command("sensors 2>/dev/null | grep -i 'fan'", shell=True)
        fan_info['sensors_fans'] = sensors_fans if sensors_fans else "N/A"
        
        self.info['fan_information'] = fan_info
    
    def get_voltage_information(self):
        """Get voltage information"""
        voltage_info = OrderedDict()
        
        # Get voltage from sensors
        sensors_voltage = self.run_command("sensors 2>/dev/null | grep -E 'in[0-9]|Vcore|V\\+|V-'", shell=True)
        voltage_info['sensors_voltage'] = sensors_voltage if sensors_voltage else "N/A"
        
        # Get from /sys/class/hwmon
        hwmon_voltage = self.run_command("for f in /sys/class/hwmon/*/in*_input; do echo \"$f: $(cat $f 2>/dev/null || echo 'N/A') mV\"; done", shell=True)
        voltage_info['hwmon_voltage'] = hwmon_voltage if hwmon_voltage else "N/A"
        
        self.info['voltage_information'] = voltage_info
    
    def get_hwmon_devices(self):
        """Get hwmon (hardware monitoring) devices"""
        hwmon_info = OrderedDict()
        
        # List all hwmon devices
        hwmon_list = self.run_command("ls /sys/class/hwmon/", shell=True)
        hwmon_info['hwmon_devices'] = hwmon_list if hwmon_list else "N/A"
        
        # Get detailed hwmon info
        hwmon_detailed = self.run_command("for device in /sys/class/hwmon/hwmon*; do echo \"Device: $device\"; cat $device/name 2>/dev/null; done", shell=True)
        hwmon_info['hwmon_devices_detailed'] = hwmon_detailed if hwmon_detailed else "N/A"
        
        self.info['hwmon_devices'] = hwmon_info
    
    def get_vmware_specific_sensors(self):
        """Get VMware-specific sensor information"""
        vmware_sensors = OrderedDict()
        
        if self.is_vmware:
            vmware_sensors['virtualization_type'] = "VMware"
            
            # Get VMware tools info if available
            vmtools_check = self.run_command("which vmtoolsd", shell=True)
            if vmtools_check:
                vmware_sensors['vmware_tools'] = "Installed"
                
                # Try to get VM info from VMware tools
                vm_info = self.run_command("vmtoolsd --cmd 'info-get guestinfo.detailed.data' 2>/dev/null || echo 'N/A'", shell=True)
                vmware_sensors['vmware_vm_info'] = vm_info if vm_info else "N/A"
            else:
                vmware_sensors['vmware_tools'] = "Not installed"
                vmware_sensors['vmware_vm_info'] = "N/A"
            
            # Get hardware info from dmesg
            vmware_hw = self.run_command("dmesg | grep -i 'vmware\\|svga\\|vmxnet' | head -10", shell=True)
            vmware_sensors['vmware_hardware_info'] = vmware_hw if vmware_hw else "N/A"
            
            # Virtual CPUs
            vcpu_count = self.run_command("nproc", shell=True)
            vmware_sensors['virtual_cpu_count'] = vcpu_count if vcpu_count else "N/A"
            
            # Virtual memory
            vmem = self.run_command("free -h | head -2", shell=True)
            vmware_sensors['virtual_memory'] = vmem if vmem else "N/A"
        else:
            vmware_sensors['virtualization_type'] = "Physical Server or Non-VMware VM"
            vmware_sensors['vmware_tools'] = "N/A"
            vmware_sensors['vmware_vm_info'] = "N/A"
            vmware_sensors['vmware_hardware_info'] = "N/A"
        
        self.info['vmware_specific_sensors'] = vmware_sensors
    
    def get_pcie_slot_power(self):
        """Get PCIe slot power information if available"""
        pcie_power = OrderedDict()
        
        # Check for PCI devices power consumption
        pcie_power_info = self.run_command("cat /sys/devices/pci*/*/power_state 2>/dev/null | head -10", shell=True)
        pcie_power['pcie_power_state'] = pcie_power_info if pcie_power_info else "N/A"
        
        self.info['pcie_power_info'] = pcie_power
    
    def get_dmesg_sensor_info(self):
        """Get sensor information from dmesg"""
        dmesg_sensors = self.run_command("dmesg | grep -i 'sensor\\|thermal\\|temperature' | tail -20", shell=True)
        self.info['dmesg_sensor_info'] = dmesg_sensors if dmesg_sensors else "N/A"
    
    def get_sensor_alerts_limits(self):
        """Get sensor alert limits and thresholds"""
        alerts = OrderedDict()
        
        # Get high temperature alert
        high_temp = self.run_command("cat /sys/class/thermal/*/trip_point_*/temp 2>/dev/null | head -10", shell=True)
        alerts['thermal_trip_points'] = high_temp if high_temp else "N/A"
        
        # Get critical temperature from sensors
        critical_temp = self.run_command("sensors -A 2>/dev/null | grep -i 'critical\\|alarm\\|max'", shell=True)
        alerts['sensor_critical_limits'] = critical_temp if critical_temp else "N/A"
        
        self.info['sensor_alerts_limits'] = alerts
    
    def get_kernel_modules_sensors(self):
        """Get loaded kernel modules related to sensors"""
        kernel_modules = OrderedDict()
        
        # Check for coretemp module (Intel)
        coretemp = self.run_command("lsmod | grep coretemp", shell=True)
        kernel_modules['coretemp_module'] = coretemp if coretemp else "Not loaded"
        
        # Check for k10temp module (AMD)
        k10temp = self.run_command("lsmod | grep k10temp", shell=True)
        kernel_modules['k10temp_module'] = k10temp if k10temp else "Not loaded"
        
        # Check for other sensor modules
        other_modules = self.run_command("lsmod | grep -E 'hwmon|thermal|sensor'", shell=True)
        kernel_modules['other_sensor_modules'] = other_modules if other_modules else "Not loaded"
        
        self.info['kernel_modules_sensors'] = kernel_modules
    
    def gather_all_info(self):
        """Collect all sensor information"""
        print("[*] Gathering sensor information...")
        
        self.get_vmware_specific_sensors()
        print("    [+] VMware/Virtualization detection - OK")
        
        self.get_lm_sensors_info()
        print("    [+] lm_sensors info - OK")
        
        self.get_thermal_zone_info()
        print("    [+] Thermal zones - OK")
        
        self.get_acpi_thermal_info()
        print("    [+] ACPI thermal info - OK")
        
        self.get_cpu_temperature()
        print("    [+] CPU temperature - OK")
        
        self.get_fan_information()
        print("    [+] Fan information - OK")
        
        self.get_voltage_information()
        print("    [+] Voltage information - OK")
        
        self.get_hwmon_devices()
        print("    [+] hwmon devices - OK")
        
        self.get_kernel_modules_sensors()
        print("    [+] Kernel modules (sensors) - OK")
        
        self.get_sensor_alerts_limits()
        print("    [+] Sensor alerts and limits - OK")
        
        self.get_pcie_slot_power()
        print("    [+] PCIe slot power - OK")
        
        self.get_dmesg_sensor_info()
        print("    [+] dmesg sensor info - OK")
        
        print("[*] Information gathering completed!\n")
    
    def get_lm_sensors_info(self):
        """Wrapper method for get_sensors_info"""
        self.get_sensors_info()
    
    def get_info(self, key=None):
        """Return information"""
        if key is None:
            return self.info
        return self.info.get(key, "N/A")
    
    def display_info(self, verbose=True):
        """Display collected information"""
        print("╔" + "═" * 78 + "╗")
        print("║" + " SENSORS INFORMATIONS REPORT ".center(78) + "║")
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
    crawler = SensorsCrawler()
    crawler.gather_all_info()
    crawler.display_info(verbose=True)
    
    return crawler


if __name__ == "__main__":
    main()