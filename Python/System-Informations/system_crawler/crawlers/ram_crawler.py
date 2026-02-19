#!/usr/bin/env python3.6
# -*- coding: utf-8 -*-

###############################################################################################################################
# A Python 3.6 script that verifies RAM informations on a Linux server.                                                       #
# The script verifies the following: total memory, free memory, used memory, buffers, cache, and detailed memory information. #
# Version: 0.0.1                                                                                                              #
# Author: Alexandru Filcu                                                                                                     #
###############################################################################################################################

######################
# Import handy tools #
######################

import subprocess
import sys
import json
from collections import OrderedDict


class RAMCrawler:
    """Class for collecting RAM/Memory information"""
    
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
    
    def _parse_meminfo(self, key):
        """Parse a specific value from /proc/meminfo"""
        value = self.run_command("grep '^{}' /proc/meminfo | awk '{{print $2}}'".format(key), shell=True)
        return value if value else "N/A"
    
    def get_total_memory(self):
        """Get total memory in KB"""
        total = self._parse_meminfo("MemTotal")
        self.info['total_memory'] = "{} KB".format(total) if total != "N/A" else "N/A"
    
    def get_free_memory(self):
        """Get free memory in KB"""
        free = self._parse_meminfo("MemFree")
        self.info['free_memory'] = "{} KB".format(free) if free != "N/A" else "N/A"
    
    def get_available_memory(self):
        """Get available memory in KB"""
        available = self._parse_meminfo("MemAvailable")
        self.info['available_memory'] = "{} KB".format(available) if available != "N/A" else "N/A"
    
    def get_used_memory(self):
        """Calculate used memory"""
        total = self.run_command("grep '^MemTotal' /proc/meminfo | awk '{print $2}'", shell=True)
        free = self.run_command("grep '^MemFree' /proc/meminfo | awk '{print $2}'", shell=True)
        
        if total != "N/A" and free != "N/A":
            try:
                used = int(total) - int(free)
                self.info['used_memory'] = "{} KB".format(used)
            except:
                self.info['used_memory'] = "N/A"
        else:
            self.info['used_memory'] = "N/A"
    
    def get_buffers(self):
        """Get buffers memory in KB"""
        buffers = self._parse_meminfo("Buffers")
        self.info['buffers'] = "{} KB".format(buffers) if buffers != "N/A" else "N/A"
    
    def get_cached(self):
        """Get cached memory in KB"""
        cached = self._parse_meminfo("Cached")
        self.info['cached'] = "{} KB".format(cached) if cached != "N/A" else "N/A"
    
    def get_swap_total(self):
        """Get total swap memory in KB"""
        swap_total = self._parse_meminfo("SwapTotal")
        self.info['swap_total'] = "{} KB".format(swap_total) if swap_total != "N/A" else "N/A"
    
    def get_swap_free(self):
        """Get free swap memory in KB"""
        swap_free = self._parse_meminfo("SwapFree")
        self.info['swap_free'] = "{} KB".format(swap_free) if swap_free != "N/A" else "N/A"
    
    def get_swap_used(self):
        """Calculate used swap memory"""
        swap_total = self.run_command("grep '^SwapTotal' /proc/meminfo | awk '{print $2}'", shell=True)
        swap_free = self.run_command("grep '^SwapFree' /proc/meminfo | awk '{print $2}'", shell=True)
        
        if swap_total != "N/A" and swap_free != "N/A":
            try:
                swap_used = int(swap_total) - int(swap_free)
                self.info['swap_used'] = "{} KB".format(swap_used)
            except:
                self.info['swap_used'] = "N/A"
        else:
            self.info['swap_used'] = "N/A"
    
    def get_slab(self):
        """Get slab memory in KB"""
        slab = self._parse_meminfo("Slab")
        self.info['slab'] = "{} KB".format(slab) if slab != "N/A" else "N/A"
    
    def get_page_tables(self):
        """Get page tables memory in KB"""
        page_tables = self._parse_meminfo("PageTables")
        self.info['page_tables'] = "{} KB".format(page_tables) if page_tables != "N/A" else "N/A"
    
    def get_meminfo_full(self):
        """Get full /proc/meminfo content"""
        meminfo = self.run_command("cat /proc/meminfo", shell=True)
        self.info['meminfo_full'] = meminfo if meminfo else "N/A"
    
    def get_memory_usage_percentage(self):
        """Calculate memory usage percentage"""
        total = self.run_command("grep '^MemTotal' /proc/meminfo | awk '{print $2}'", shell=True)
        available = self.run_command("grep '^MemAvailable' /proc/meminfo | awk '{print $2}'", shell=True)
        
        if total != "N/A" and available != "N/A":
            try:
                percentage = (100.0 * (int(total) - int(available))) / int(total)
                self.info['memory_usage_percentage'] = "{:.2f}%".format(percentage)
            except:
                self.info['memory_usage_percentage'] = "N/A"
        else:
            self.info['memory_usage_percentage'] = "N/A"
    
    def gather_all_info(self):
        """Collect all RAM/Memory information"""
        print("[*] Gathering RAM information...")
        
        self.get_total_memory()
        print("    [+] Total memory - OK")
        
        self.get_free_memory()
        print("    [+] Free memory - OK")
        
        self.get_available_memory()
        print("    [+] Available memory - OK")
        
        self.get_used_memory()
        print("    [+] Used memory - OK")
        
        self.get_memory_usage_percentage()
        print("    [+] Memory usage percentage - OK")
        
        self.get_buffers()
        print("    [+] Buffers - OK")
        
        self.get_cached()
        print("    [+] Cached - OK")
        
        self.get_swap_total()
        print("    [+] Swap total - OK")
        
        self.get_swap_free()
        print("    [+] Swap free - OK")
        
        self.get_swap_used()
        print("    [+] Swap used - OK")
        
        self.get_slab()
        print("    [+] Slab - OK")
        
        self.get_page_tables()
        print("    [+] Page tables - OK")
        
        self.get_meminfo_full()
        print("    [+] /proc/meminfo - OK")
        
        print("[*] Information gathering completed!\n")
    
    def get_info(self, key=None):
        """Return information"""
        if key is None:
            return self.info
        return self.info.get(key, "N/A")
    
    def display_info(self, verbose=True):
        """Display collected information"""
        print("╔" + "═" * 78 + "╗")
        print("║" + " RAM INFORMATIONS REPORT ".center(78) + "║")
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
    crawler = RAMCrawler()
    crawler.gather_all_info()
    crawler.display_info(verbose=True)
    
    return crawler


if __name__ == "__main__":
    main()