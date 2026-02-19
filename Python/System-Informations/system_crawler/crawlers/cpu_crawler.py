#!/usr/bin/env python3.6
# -*- coding: utf-8 -*-

######################################################################################################################
# A Python 3.6 script that verifies CPU informations on a Linux server.                                              #
# The script verifies the following: CPU model, cores, threads, frequency, cache, flags, and virtualization support. #
# Version: 0.0.1                                                                                                     #
# Author: Alexandru Filcu                                                                                            #
######################################################################################################################

######################
# Import handy tools #
######################

import subprocess
import sys
import json
import re
from collections import OrderedDict


class CPUCrawler:
    """Class for collecting CPU information"""
    
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
    
    def get_cpu_model(self):
        """Get CPU model name"""
        cpu_model = self.run_command("grep -m1 'model name' /proc/cpuinfo | cut -d':' -f2", shell=True)
        self.info['cpu_model'] = cpu_model.strip() if cpu_model else "N/A"
    
    def get_cpu_count(self):
        """Get total number of CPUs"""
        cpu_count = self.run_command("grep -c '^processor' /proc/cpuinfo", shell=True)
        self.info['cpu_count'] = cpu_count if cpu_count else "N/A"
    
    def get_cpu_cores(self):
        """Get number of cores per CPU"""
        cores = self.run_command("grep 'cpu cores' /proc/cpuinfo | head -1 | cut -d':' -f2", shell=True)
        self.info['cpu_cores'] = cores.strip() if cores else "N/A"
    
    def get_cpu_threads(self):
        """Get number of threads per core"""
        threads = self.run_command("grep 'siblings' /proc/cpuinfo | head -1 | cut -d':' -f2", shell=True)
        self.info['cpu_threads'] = threads.strip() if threads else "N/A"
    
    def get_cpu_frequency(self):
        """Get CPU frequency"""
        frequency = self.run_command("grep 'cpu MHz' /proc/cpuinfo | head -1 | cut -d':' -f2", shell=True)
        self.info['cpu_frequency'] = frequency.strip() if frequency else "N/A"
    
    def get_cpu_cache(self):
        """Get CPU cache information"""
        cache_info = self.run_command("grep 'cache size' /proc/cpuinfo | head -1 | cut -d':' -f2", shell=True)
        self.info['cpu_cache'] = cache_info.strip() if cache_info else "N/A"
    
    def get_cpu_flags(self):
        """Get CPU flags/features"""
        flags = self.run_command("grep -m1 '^flags' /proc/cpuinfo | cut -d':' -f2", shell=True)
        self.info['cpu_flags'] = flags.strip() if flags else "N/A"
    
    def get_cpu_stepping(self):
        """Get CPU stepping"""
        stepping = self.run_command("grep -m1 'stepping' /proc/cpuinfo | cut -d':' -f2", shell=True)
        self.info['cpu_stepping'] = stepping.strip() if stepping else "N/A"
    
    def get_cpu_family(self):
        """Get CPU family"""
        family = self.run_command("grep -m1 'cpu family' /proc/cpuinfo | cut -d':' -f2", shell=True)
        self.info['cpu_family'] = family.strip() if family else "N/A"
    
    def get_lscpu_info(self):
        """Get comprehensive CPU info from lscpu command"""
        lscpu_output = self.run_command("lscpu", shell=True)
        self.info['lscpu'] = lscpu_output if lscpu_output else "N/A"
    
    def get_cpuinfo_full(self):
        """Get full /proc/cpuinfo content"""
        cpuinfo = self.run_command("cat /proc/cpuinfo", shell=True)
        self.info['cpuinfo_full'] = cpuinfo if cpuinfo else "N/A"
    
    def gather_all_info(self):
        """Collect all CPU information"""
        print("[*] Gathering CPU information...")
        
        self.get_cpu_model()
        print("    [+] CPU model - OK")
        
        self.get_cpu_count()
        print("    [+] CPU count - OK")
        
        self.get_cpu_cores()
        print("    [+] CPU cores - OK")
        
        self.get_cpu_threads()
        print("    [+] CPU threads - OK")
        
        self.get_cpu_frequency()
        print("    [+] CPU frequency - OK")
        
        self.get_cpu_cache()
        print("    [+] CPU cache - OK")
        
        self.get_cpu_stepping()
        print("    [+] CPU stepping - OK")
        
        self.get_cpu_family()
        print("    [+] CPU family - OK")
        
        self.get_cpu_flags()
        print("    [+] CPU flags - OK")
        
        self.get_lscpu_info()
        print("    [+] lscpu - OK")
        
        self.get_cpuinfo_full()
        print("    [+] /proc/cpuinfo - OK")
        
        print("[*] Information gathering completed!\n")
    
    def get_info(self, key=None):
        """Return information"""
        if key is None:
            return self.info
        return self.info.get(key, "N/A")
    
    def display_info(self, verbose=True):
        """Display collected information"""
        print("╔" + "═" * 78 + "╗")
        print("║" + " CPU INFORMATIONS REPORT ".center(78) + "║")
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
    crawler = CPUCrawler()
    crawler.gather_all_info()
    crawler.display_info(verbose=True)
    
    return crawler


if __name__ == "__main__":
    main()