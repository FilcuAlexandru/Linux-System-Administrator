#!/usr/bin/env python3.6
# -*- coding: utf-8 -*-

#############################################################################################################################################################
# A Python 3.6 script that verifies OS information on a Linux server.                                                                                       #
# The script verifies the following: os-release, hostname, kernel, lsb_release, /proc/version, virtualization, uptime, locale, and time/date configuration. #
# Version: 0.0.1                                                                                                                                            #
# Author: Alexandru Filcu                                                                                                                                   #
#############################################################################################################################################################

######################
# Import handy tools #
######################

import subprocess
import sys
import json
import os
from collections import OrderedDict


class OSCrawler:
    """Class for collecting OS information"""
    
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
    
    def get_os_release(self):
        """Read information from /etc/os-release"""
        self.info['os_release'] = self.run_command("cat /etc/os-release", shell=True) or "N/A"
    
    def get_hostname(self):
        """Get hostname information"""
        self.info['hostname'] = self.run_command("hostnamectl", shell=True) or "N/A"
    
    def get_kernel_info(self):
        """Get kernel information"""
        self.info['kernel_info'] = self.run_command("uname -a", shell=True) or "N/A"
    
    def get_lsb_release(self):
        """Get LSB Release information"""
        self.info['lsb_release'] = self.run_command("lsb_release -a", shell=True) or "N/A"
    
    def get_proc_version(self):
        """Read version from /proc/version"""
        self.info['proc_version'] = self.run_command("cat /proc/version", shell=True) or "N/A"
    
    def get_virtualization(self):
        """Detect virtualization type"""
        self.info['virtualization'] = self.run_command(
            "systemd-detect-virt", 
            shell=True
        ) or "N/A"
    
    def get_uptime(self):
        """Get server uptime"""
        self.info['uptime'] = self.run_command("uptime", shell=True) or "N/A"
    
    def get_locale(self):
        """Get locale configuration"""
        self.info['locale'] = self.run_command("locale", shell=True) or "N/A"
    
    def get_timedatectl(self):
        """Get time and date configuration"""
        self.info['timedatectl'] = self.run_command("timedatectl", shell=True) or "N/A"
    

    def gather_all_info(self):
        """Collect all OS information"""
        print("[*] Gathering OS information...")
        
        self.get_os_release()
        print("    [+] /etc/os-release - OK")
        
        self.get_hostname()
        print("    [+] hostnamectl - OK")
        
        self.get_kernel_info()
        print("    [+] uname -a - OK")
        
        self.get_lsb_release()
        print("    [+] lsb_release -a - OK")
        
        self.get_proc_version()
        print("    [+] /proc/version - OK")
        
        self.get_virtualization()
        print("    [+] systemd-detect-virt - OK")
        
        self.get_uptime()
        print("    [+] uptime - OK")
        
        self.get_locale()
        print("    [+] locale - OK")
        
        self.get_timedatectl()
        print("    [+] timedatectl - OK")
        
        print("[*] Information gathering completed!\n")
    
    def get_info(self, key=None):
        """Return information"""
        if key is None:
            return self.info
        return self.info.get(key, "N/A")
    
    def display_info(self, verbose=True):
        """Display collected information"""
        print("╔" + "═" * 78 + "╗")
        print("║" + " OS INFORMATIONS REPORT ".center(78) + "║")
        print("╚" + "═" * 78 + "╝")
        
        for key, value in self.info.items():
            print("\n[{}]".format(key.upper().replace('_', ' ')))
            print("-" * 80)
            
            if isinstance(value, dict):
                # Display nested dictionary
                for sub_key, sub_value in value.items():
                    print("\n  {}:".format(sub_key.upper().replace('_', ' ')))
                    if verbose:
                        print("  {}".format(sub_value.replace('\n', '\n  ') if sub_value else "N/A"))
                    else:
                        first_line = sub_value.split('\n')[0] if sub_value else "N/A"
                        print("  {}".format(first_line))
            else:
                if verbose:
                    print(value)
                else:
                    # Display only first line for compact mode
                    first_line = value.split('\n')[0] if value else "N/A"
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
    crawler = OSCrawler()
    crawler.gather_all_info()
    crawler.display_info(verbose=True)
    
    return crawler


if __name__ == "__main__":
    main()