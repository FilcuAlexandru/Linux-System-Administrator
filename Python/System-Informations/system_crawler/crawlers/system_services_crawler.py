#!/usr/bin/env python3.6
# -*- coding: utf-8 -*-

###############################################################################################################
# A Python 3.6 script that verifies System Services information on a Linux server.                            #
# The script verifies the following: systemd services, daemons, service status, timers, sockets, and targets. #
# Version: 0.0.1                                                                                              #
# Author: Alexandru Filcu                                                                                     #
###############################################################################################################

######################
# Import handy tools #
######################

import subprocess
import sys
import json
from collections import OrderedDict


class SystemServicesCrawler:
    """Class for collecting System Services information"""
    
    def __init__(self):
        self.info = OrderedDict()
        self.is_vmware = self._detect_vmware()
        self.is_suse = self._detect_suse()
    
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
    
    def get_systemd_version(self):
        """Get systemd version"""
        systemd_version = self.run_command("systemctl --version | head -1", shell=True)
        self.info['systemd_version'] = systemd_version if systemd_version else "N/A"
    
    def get_all_services(self):
        """Get all systemd services"""
        services_info = OrderedDict()
        
        # Get all services (including disabled and inactive)
        all_services = self.run_command("systemctl list-units --all --type=service --no-pager | tail -n +2", shell=True)
        services_info['all_services'] = all_services if all_services else "N/A"
        
        # Count services by state
        active_count = self.run_command("systemctl list-units --type=service | grep -c 'active'", shell=True)
        services_info['active_services_count'] = active_count if active_count else "0"
        
        inactive_count = self.run_command("systemctl list-units --all --type=service | grep -c 'inactive'", shell=True)
        services_info['inactive_services_count'] = inactive_count if inactive_count else "0"
        
        failed_count = self.run_command("systemctl list-units --all --type=service | grep -c 'failed'", shell=True)
        services_info['failed_services_count'] = failed_count if failed_count else "0"
        
        self.info['all_services'] = services_info
    
    def get_active_services(self):
        """Get active running services"""
        active_services = self.run_command("systemctl list-units --type=service --state=running --no-pager | tail -n +2", shell=True)
        self.info['active_running_services'] = active_services if active_services else "N/A"
    
    def get_enabled_services(self):
        """Get enabled services"""
        enabled_services = self.run_command("systemctl list-unit-files --type=service | grep 'enabled' | head -30", shell=True)
        self.info['enabled_services'] = enabled_services if enabled_services else "N/A"
    
    def get_failed_services(self):
        """Get failed services"""
        failed_services = OrderedDict()
        
        # Get failed services
        failed_list = self.run_command("systemctl list-units --all --type=service --state=failed --no-pager | tail -n +2", shell=True)
        failed_services['failed_services_list'] = failed_list if failed_list else "No failed services"
        
        # Get failed status details
        failed_details = self.run_command("systemctl list-units --failed", shell=True)
        failed_services['failed_details'] = failed_details if failed_details else "N/A"
        
        self.info['failed_services'] = failed_services
    
    def get_systemd_targets(self):
        """Get systemd targets"""
        targets_info = OrderedDict()
        
        # Get all targets
        all_targets = self.run_command("systemctl list-units --type=target --no-pager | tail -n +2", shell=True)
        targets_info['all_targets'] = all_targets if all_targets else "N/A"
        
        # Get default target
        default_target = self.run_command("systemctl get-default", shell=True)
        targets_info['default_target'] = default_target if default_target else "N/A"
        
        # Get current target
        current_target = self.run_command("systemctl list-units --type=target --state=active --no-pager | grep active | head -1", shell=True)
        targets_info['current_target'] = current_target if current_target else "N/A"
        
        self.info['systemd_targets'] = targets_info
    
    def get_systemd_timers(self):
        """Get systemd timers"""
        timers_info = OrderedDict()
        
        # Get all timers
        all_timers = self.run_command("systemctl list-timers --all --no-pager", shell=True)
        timers_info['all_timers'] = all_timers if all_timers else "No timers found"
        
        # Count active timers
        active_timers = self.run_command("systemctl list-timers --no-pager | grep -c 'active'", shell=True)
        timers_info['active_timers_count'] = active_timers if active_timers else "0"
        
        self.info['systemd_timers'] = timers_info
    
    def get_systemd_sockets(self):
        """Get systemd sockets"""
        sockets_info = OrderedDict()
        
        # Get all sockets
        all_sockets = self.run_command("systemctl list-units --type=socket --all --no-pager | tail -n +2", shell=True)
        sockets_info['all_sockets'] = all_sockets if all_sockets else "N/A"
        
        # Count active sockets
        active_sockets = self.run_command("systemctl list-units --type=socket --state=active --no-pager | grep -c 'active'", shell=True)
        sockets_info['active_sockets_count'] = active_sockets if active_sockets else "0"
        
        self.info['systemd_sockets'] = sockets_info
    
    def get_systemd_mount_points(self):
        """Get systemd mount points"""
        mount_info = OrderedDict()
        
        # Get all mount units
        all_mounts = self.run_command("systemctl list-units --type=mount --all --no-pager | tail -n +2", shell=True)
        mount_info['all_mount_units'] = all_mounts if all_mounts else "N/A"
        
        # Get active mounts
        active_mounts = self.run_command("systemctl list-units --type=mount --state=active --no-pager | tail -n +2", shell=True)
        mount_info['active_mounts'] = active_mounts if active_mounts else "N/A"
        
        self.info['systemd_mount_points'] = mount_info
    
    def get_running_daemons(self):
        """Get running daemon processes"""
        daemons_info = OrderedDict()
        
        # Get running daemons (services ending with 'd')
        running_daemons = self.run_command("ps aux | grep -E '\\s[a-z]+d\\s' | grep -v grep | awk '{print $1, $11}' | head -30", shell=True)
        daemons_info['running_daemons'] = running_daemons if running_daemons else "N/A"
        
        # Get daemon count
        daemon_count = self.run_command("ps aux | grep -E '\\s[a-z]+d\\s' | grep -v grep | wc -l", shell=True)
        daemons_info['daemon_count'] = daemon_count if daemon_count else "0"
        
        self.info['running_daemons'] = daemons_info
    
    def get_service_dependencies(self):
        """Get service dependencies"""
        deps_info = OrderedDict()
        
        # Get services with dependencies
        with_deps = self.run_command("systemctl show-environment | head -5", shell=True)
        deps_info['environment'] = with_deps if with_deps else "N/A"
        
        # Get wants relationships
        wants = self.run_command("systemctl list-dependencies --all 2>/dev/null | head -30", shell=True)
        deps_info['dependencies_tree'] = wants if wants else "N/A"
        
        self.info['service_dependencies'] = deps_info
    
    def get_service_resource_usage(self):
        """Get service resource usage"""
        resource_info = OrderedDict()
        
        # Get memory usage by services
        memory_usage = self.run_command("systemctl status --all 2>/dev/null | grep -i 'memory' | head -10", shell=True)
        resource_info['memory_usage'] = memory_usage if memory_usage else "N/A"
        
        # Get CPU usage (simplified)
        cpu_info = self.run_command("ps aux --sort=-%cpu | head -10 | awk '{print $1, $3, $11}'", shell=True)
        resource_info['top_cpu_processes'] = cpu_info if cpu_info else "N/A"
        
        self.info['service_resource_usage'] = resource_info
    
    def get_service_logs(self):
        """Get service logs information"""
        logs_info = OrderedDict()
        
        # Get journalctl status
        journal_status = self.run_command("journalctl --disk-usage", shell=True)
        logs_info['journalctl_disk_usage'] = journal_status if journal_status else "N/A"
        
        # Get recent errors from journal
        recent_errors = self.run_command("journalctl -p err..alert -n 20 --no-pager", shell=True)
        logs_info['recent_errors'] = recent_errors if recent_errors else "N/A"
        
        # Get recent warnings
        recent_warnings = self.run_command("journalctl -p warning -n 10 --no-pager", shell=True)
        logs_info['recent_warnings'] = recent_warnings if recent_warnings else "N/A"
        
        self.info['service_logs'] = logs_info
    
    def get_service_unit_files(self):
        """Get systemd unit files location and count"""
        unit_files_info = OrderedDict()
        
        # Get systemd unit file paths
        unit_paths = self.run_command("systemctl -p UnitPath --no-pager show-environment 2>/dev/null || echo '/etc/systemd/system /lib/systemd/system'", shell=True)
        unit_files_info['unit_file_paths'] = unit_paths if unit_paths else "N/A"
        
        # Count unit files
        unit_count = self.run_command("find /etc/systemd/system* /lib/systemd/system* -name '*.service' 2>/dev/null | wc -l", shell=True)
        unit_files_info['total_unit_files'] = unit_count if unit_count else "0"
        
        # Get custom unit files
        custom_units = self.run_command("ls -la /etc/systemd/system/ | grep -E '\\.service|\\.target|\\.timer' | head -20", shell=True)
        unit_files_info['custom_unit_files'] = custom_units if custom_units else "N/A"
        
        self.info['service_unit_files'] = unit_files_info
    
    def get_boot_services(self):
        """Get services that run at boot"""
        boot_services = self.run_command("systemctl list-unit-files --type=service | grep 'enabled' | awk '{print $1}' | head -30", shell=True)
        self.info['boot_enabled_services'] = boot_services if boot_services else "N/A"
    
    def get_vmware_services(self):
        """Get VMware-specific services"""
        vmware_services = OrderedDict()
        
        if self.is_vmware:
            vmware_services['virtualization_type'] = "VMware"
            
            # Check VMware Tools service
            vmware_tools = self.run_command("systemctl status vmtoolsd 2>/dev/null | grep -i 'active\\|inactive'", shell=True)
            vmware_services['vmware_tools_service'] = vmware_tools if vmware_tools else "Not found"
            
            # Check VMware specific services
            vmware_specific = self.run_command("systemctl list-units --type=service | grep -i 'vmware\\|vm' | head -10", shell=True)
            vmware_services['vmware_specific_services'] = vmware_specific if vmware_specific else "N/A"
            
            # Check open-vm-tools
            open_vm_tools = self.run_command("systemctl status open-vm-tools 2>/dev/null | grep -i 'active\\|inactive'", shell=True)
            vmware_services['open_vm_tools_service'] = open_vm_tools if open_vm_tools else "Not installed"
        else:
            vmware_services['virtualization_type'] = "Physical Server or Non-VMware VM"
            vmware_services['vmware_tools_service'] = "N/A"
        
        self.info['vmware_services'] = vmware_services
    
    def get_suse_services(self):
        """Get SUSE-specific services"""
        suse_services = OrderedDict()
        
        if self.is_suse:
            suse_services['os_type'] = "SUSE Linux"
            
            # Check YaST2 services
            yast_services = self.run_command("systemctl list-units --type=service | grep -i 'yast\\|yastd' | head -10", shell=True)
            suse_services['yast_services'] = yast_services if yast_services else "N/A"
            
            # Check SuSEfirewall2
            suse_firewall = self.run_command("systemctl status SuSEfirewall2 2>/dev/null | grep -i 'active\\|inactive'", shell=True)
            suse_services['susefirewall2_status'] = suse_firewall if suse_firewall else "Not found"
            
            # Check SUSE specific services
            suse_specific = self.run_command("systemctl list-units --type=service | grep -i 'suse\\|novell' | head -10", shell=True)
            suse_services['suse_specific_services'] = suse_specific if suse_specific else "N/A"
            
            # Check system update service
            update_service = self.run_command("systemctl status packagekit 2>/dev/null | grep -i 'active\\|inactive'", shell=True)
            suse_services['packagekit_status'] = update_service if update_service else "N/A"
        else:
            suse_services['os_type'] = "Not SUSE Linux"
            suse_services['yast_services'] = "N/A"
        
        self.info['suse_services'] = suse_services
    
    def get_essential_services_status(self):
        """Get status of essential system services"""
        essential_info = OrderedDict()
        
        essential_services = [
            'systemd-journald',
            'systemd-logind',
            'dbus',
            'sshd',
            'crond',
            'rsyslog',
            'network',
            'networking',
            'systemd-resolved',
            'auditd'
        ]
        
        for service in essential_services:
            status = self.run_command("systemctl is-active {} 2>/dev/null || echo 'not-found'".format(service), shell=True)
            if status and status != 'not-found':
                essential_info[service] = status
        
        self.info['essential_services_status'] = essential_info
    
    def get_user_services(self):
        """Get user-specific services (systemd --user)"""
        user_services = OrderedDict()
        
        # Get user services
        user_service_list = self.run_command("systemctl --user list-units --type=service 2>/dev/null | tail -n +2", shell=True)
        user_services['user_services'] = user_service_list if user_service_list else "No user services"
        
        # Count user services
        user_count = self.run_command("systemctl --user list-units --type=service 2>/dev/null | grep -c 'service'", shell=True)
        user_services['user_services_count'] = user_count if user_count else "0"
        
        self.info['user_services'] = user_services
    
    def get_dmesg_services_info(self):
        """Get service information from dmesg"""
        dmesg_services = self.run_command("dmesg | grep -i 'service\\|daemon\\|systemd' | tail -20", shell=True)
        self.info['dmesg_services_info'] = dmesg_services if dmesg_services else "N/A"
    
    def gather_all_info(self):
        """Collect all system services information"""
        print("[*] Gathering system services information...")
        
        self.get_systemd_version()
        print("    [+] Systemd version - OK")
        
        self.get_vmware_services()
        print("    [+] VMware services - OK")
        
        self.get_suse_services()
        print("    [+] SUSE services - OK")
        
        self.get_all_services()
        print("    [+] All services - OK")
        
        self.get_active_services()
        print("    [+] Active running services - OK")
        
        self.get_enabled_services()
        print("    [+] Enabled services - OK")
        
        self.get_failed_services()
        print("    [+] Failed services - OK")
        
        self.get_essential_services_status()
        print("    [+] Essential services status - OK")
        
        self.get_boot_services()
        print("    [+] Boot enabled services - OK")
        
        self.get_systemd_targets()
        print("    [+] Systemd targets - OK")
        
        self.get_systemd_timers()
        print("    [+] Systemd timers - OK")
        
        self.get_systemd_sockets()
        print("    [+] Systemd sockets - OK")
        
        self.get_systemd_mount_points()
        print("    [+] Systemd mount points - OK")
        
        self.get_running_daemons()
        print("    [+] Running daemons - OK")
        
        self.get_service_unit_files()
        print("    [+] Service unit files - OK")
        
        self.get_service_dependencies()
        print("    [+] Service dependencies - OK")
        
        self.get_service_resource_usage()
        print("    [+] Service resource usage - OK")
        
        self.get_user_services()
        print("    [+] User services - OK")
        
        self.get_service_logs()
        print("    [+] Service logs - OK")
        
        self.get_dmesg_services_info()
        print("    [+] dmesg services info - OK")
        
        print("[*] Information gathering completed!\n")
    
    def get_info(self, key=None):
        """Return information"""
        if key is None:
            return self.info
        return self.info.get(key, "N/A")
    
    def display_info(self, verbose=True):
        """Display collected information"""
        print("╔" + "═" * 78 + "╗")
        print("║" + " SYSTEM SERVICES INFORMATIONS REPORT ".center(78) + "║")
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
    crawler = SystemServicesCrawler()
    crawler.gather_all_info()
    crawler.display_info(verbose=True)
    
    return crawler


if __name__ == "__main__":
    main()