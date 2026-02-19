#!/usr/bin/env python3.6
# -*- coding: utf-8 -*-

###############################################################################################
# A Python 3.6 script that verifies GPU informations on a Linux server.                       #
# The script verifies the following: GPU model, memory, driver, temperature, and utilization. #
# Version: 0.0.1                                                                              #
# Author: Alexandru Filcu                                                                     #
###############################################################################################

######################
# Import handy tools #
######################

import subprocess
import sys
import json
from collections import OrderedDict


class GPUCrawler:
    """Class for collecting GPU information"""
    
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
    
    def get_nvidia_gpu_info(self):
        """Get NVIDIA GPU information"""
        nvidia_info = OrderedDict()
        
        # Check if nvidia-smi is available
        nvidia_smi_check = self.run_command("which nvidia-smi", shell=True)
        
        if nvidia_smi_check:
            # Get GPU count
            gpu_count = self.run_command("nvidia-smi --query-gpu=count --format=csv,noheader,nounits | head -1", shell=True)
            nvidia_info['gpu_count'] = gpu_count if gpu_count else "N/A"
            
            # Get GPU name
            gpu_name = self.run_command("nvidia-smi --query-gpu=name --format=csv,noheader | head -1", shell=True)
            nvidia_info['gpu_name'] = gpu_name if gpu_name else "N/A"
            
            # Get GPU driver version
            driver_version = self.run_command("nvidia-smi --query-gpu=driver_version --format=csv,noheader | head -1", shell=True)
            nvidia_info['driver_version'] = driver_version if driver_version else "N/A"
            
            # Get CUDA Compute Capability
            compute_cap = self.run_command("nvidia-smi --query-gpu=compute_cap --format=csv,noheader | head -1", shell=True)
            nvidia_info['compute_capability'] = compute_cap if compute_cap else "N/A"
            
            # Get GPU Memory
            gpu_memory = self.run_command("nvidia-smi --query-gpu=memory.total --format=csv,noheader,nounits | head -1", shell=True)
            nvidia_info['gpu_memory_total'] = "{} MB".format(gpu_memory) if gpu_memory else "N/A"
            
            # Get GPU Memory Free
            gpu_memory_free = self.run_command("nvidia-smi --query-gpu=memory.free --format=csv,noheader,nounits | head -1", shell=True)
            nvidia_info['gpu_memory_free'] = "{} MB".format(gpu_memory_free) if gpu_memory_free else "N/A"
            
            # Get GPU Memory Used
            gpu_memory_used = self.run_command("nvidia-smi --query-gpu=memory.used --format=csv,noheader,nounits | head -1", shell=True)
            nvidia_info['gpu_memory_used'] = "{} MB".format(gpu_memory_used) if gpu_memory_used else "N/A"
            
            # Get GPU Temperature
            gpu_temp = self.run_command("nvidia-smi --query-gpu=temperature.gpu --format=csv,noheader,nounits | head -1", shell=True)
            nvidia_info['gpu_temperature'] = "{}°C".format(gpu_temp) if gpu_temp else "N/A"
            
            # Get GPU Utilization
            gpu_util = self.run_command("nvidia-smi --query-gpu=utilization.gpu --format=csv,noheader,nounits | head -1", shell=True)
            nvidia_info['gpu_utilization'] = "{}%".format(gpu_util) if gpu_util else "N/A"
            
            # Get GPU Power Draw
            gpu_power = self.run_command("nvidia-smi --query-gpu=power.draw --format=csv,noheader,nounits | head -1", shell=True)
            nvidia_info['gpu_power_draw'] = "{} W".format(gpu_power) if gpu_power else "N/A"
            
            # Get full nvidia-smi output
            nvidia_full = self.run_command("nvidia-smi", shell=True)
            nvidia_info['nvidia_smi_full'] = nvidia_full if nvidia_full else "N/A"
            
            self.info['nvidia_gpu'] = nvidia_info
        else:
            self.info['nvidia_gpu'] = "NVIDIA GPU tools not found"
    
    def get_amd_gpu_info(self):
        """Get AMD GPU information"""
        amd_info = OrderedDict()
        
        # Check if rocm-smi is available
        rocm_smi_check = self.run_command("which rocm-smi", shell=True)
        
        if rocm_smi_check:
            # Get GPU count
            gpu_count = self.run_command("rocm-smi --showproductname | grep -c 'GPU'", shell=True)
            amd_info['gpu_count'] = gpu_count if gpu_count else "N/A"
            
            # Get GPU name
            gpu_name = self.run_command("rocm-smi --showproductname | grep 'GPU' | head -1", shell=True)
            amd_info['gpu_name'] = gpu_name if gpu_name else "N/A"
            
            # Get GPU memory
            gpu_memory = self.run_command("rocm-smi --showmeminfo all | head -5", shell=True)
            amd_info['gpu_memory'] = gpu_memory if gpu_memory else "N/A"
            
            # Get GPU Temperature
            gpu_temp = self.run_command("rocm-smi --showtemp | grep 'GPU' | head -1", shell=True)
            amd_info['gpu_temperature'] = gpu_temp if gpu_temp else "N/A"
            
            # Get full rocm-smi output
            rocm_full = self.run_command("rocm-smi", shell=True)
            amd_info['rocm_smi_full'] = rocm_full if rocm_full else "N/A"
            
            self.info['amd_gpu'] = amd_info
        else:
            self.info['amd_gpu'] = "AMD ROCm tools not found"
    
    def get_intel_gpu_info(self):
        """Get Intel GPU information"""
        intel_info = OrderedDict()
        
        # Check if intel_gpu_top is available
        intel_gpu_check = self.run_command("which intel_gpu_top", shell=True)
        
        if intel_gpu_check:
            # Get GPU info from lspci
            gpu_info = self.run_command("lspci | grep -i 'vga\\|3d\\|display' | grep -i intel", shell=True)
            intel_info['gpu_info_pci'] = gpu_info if gpu_info else "N/A"
            
            self.info['intel_gpu'] = intel_info
        else:
            self.info['intel_gpu'] = "Intel GPU tools not found"
    
    def get_vmware_gpu_info(self):
        """Get VMware SVGA GPU information"""
        vmware_info = OrderedDict()
        
        # Check if VMware SVGA is present
        vmware_gpu = self.run_command("lspci | grep -i 'vmware.*svga'", shell=True)
        
        if vmware_gpu:
            vmware_info['gpu_device'] = vmware_gpu if vmware_gpu else "N/A"
            
            # Get detailed VMware SVGA info
            vmware_detailed = self.run_command("lspci -k | grep -A 3 -i 'vmware.*svga'", shell=True)
            vmware_info['gpu_device_detailed'] = vmware_detailed if vmware_detailed else "N/A"
            
            # Check vmwgfx kernel module
            vmwgfx_module = self.run_command("lsmod | grep vmwgfx", shell=True)
            vmware_info['vmwgfx_kernel_module'] = vmwgfx_module if vmwgfx_module else "Not loaded"
            
            # Get vmwgfx driver info
            vmwgfx_version = self.run_command("modinfo vmwgfx 2>/dev/null | grep version | head -1", shell=True)
            vmware_info['vmwgfx_driver_version'] = vmwgfx_version if vmwgfx_version else "N/A"
            
            # Check for memory allocation
            vmware_memory = self.run_command("cat /proc/cmdline | grep -o 'vmwgfx[^[:space:]]*'", shell=True)
            vmware_info['vmware_cmdline_params'] = vmware_memory if vmware_memory else "N/A"
            
            # Get video memory info from dmesg
            vmware_vram = self.run_command("dmesg | grep -i 'svga\\|vram\\|vmwgfx' | head -5", shell=True)
            vmware_info['vmware_boot_info'] = vmware_vram if vmware_vram else "N/A"
            
            self.info['vmware_gpu'] = vmware_info
        else:
            self.info['vmware_gpu'] = "VMware SVGA GPU not found"
    
    def get_vmware_gpu_info(self):
        """Get VMware SVGA GPU information"""
        vmware_info = OrderedDict()
        
        # Check if VMware SVGA is present
        vmware_gpu = self.run_command("lspci | grep -i 'vmware.*svga'", shell=True)
        
        if vmware_gpu:
            vmware_info['gpu_device'] = vmware_gpu if vmware_gpu else "N/A"
            
            # Get detailed VMware SVGA info
            vmware_detailed = self.run_command("lspci -k | grep -A 3 -i 'vmware.*svga'", shell=True)
            vmware_info['gpu_device_detailed'] = vmware_detailed if vmware_detailed else "N/A"
            
            # Check vmwgfx kernel module
            vmwgfx_module = self.run_command("lsmod | grep vmwgfx", shell=True)
            vmware_info['vmwgfx_kernel_module'] = vmwgfx_module if vmwgfx_module else "Not loaded"
            
            # Get vmwgfx driver info
            vmwgfx_version = self.run_command("modinfo vmwgfx 2>/dev/null | grep version | head -1", shell=True)
            vmware_info['vmwgfx_driver_version'] = vmwgfx_version if vmwgfx_version else "N/A"
            
            # Check for memory allocation
            vmware_memory = self.run_command("cat /proc/cmdline | grep -o 'vmwgfx[^[:space:]]*'", shell=True)
            vmware_info['vmware_cmdline_params'] = vmware_memory if vmware_memory else "N/A"
            
            # Get video memory info from dmesg
            vmware_vram = self.run_command("dmesg | grep -i 'svga\\|vram\\|vmwgfx' | head -5", shell=True)
            vmware_info['vmware_boot_info'] = vmware_vram if vmware_vram else "N/A"
            
            self.info['vmware_gpu'] = vmware_info
        else:
            self.info['vmware_gpu'] = "VMware SVGA GPU not found"
    

    def get_gpu_from_lspci(self):
        """Get GPU information from lspci"""
        gpu_pci_info = OrderedDict()
        
        # Get all VGA/3D controllers from lspci
        gpu_devices = self.run_command("lspci | grep -i 'vga\\|3d\\|display'", shell=True)
        gpu_pci_info['vga_devices'] = gpu_devices if gpu_devices else "N/A"
        
        # Get detailed info with driver info
        gpu_detailed = self.run_command("lspci -k | grep -A 2 -i 'vga\\|3d\\|display'", shell=True)
        gpu_pci_info['vga_devices_detailed'] = gpu_detailed if gpu_detailed else "N/A"
        
        self.info['gpu_pci_info'] = gpu_pci_info
    
    def get_gpu_from_lsmod(self):
        """Get loaded GPU drivers"""
        gpu_drivers = OrderedDict()
        
        # Check for NVIDIA drivers
        nvidia_driver = self.run_command("lsmod | grep -i nvidia", shell=True)
        gpu_drivers['nvidia_kernel_module'] = nvidia_driver if nvidia_driver else "Not loaded"
        
        # Check for AMD drivers
        amd_driver = self.run_command("lsmod | grep -i amdgpu", shell=True)
        gpu_drivers['amd_kernel_module'] = amd_driver if amd_driver else "Not loaded"
        
        # Check for Intel drivers
        intel_driver = self.run_command("lsmod | grep -i 'i915\\|xe'", shell=True)
        gpu_drivers['intel_kernel_module'] = intel_driver if intel_driver else "Not loaded"
        
        # Check for VMware drivers
        vmware_driver = self.run_command("lsmod | grep -i vmwgfx", shell=True)
        gpu_drivers['vmware_kernel_module'] = vmware_driver if vmware_driver else "Not loaded"
        
        # Check for nouveau (open-source NVIDIA)
        nouveau_driver = self.run_command("lsmod | grep -i nouveau", shell=True)
        gpu_drivers['nouveau_kernel_module'] = nouveau_driver if nouveau_driver else "Not loaded"
        
        self.info['gpu_kernel_modules'] = gpu_drivers
    
    def gather_all_info(self):
        """Collect all GPU information"""
        print("[*] Gathering GPU information...")
        
        self.get_nvidia_gpu_info()
        print("    [+] NVIDIA GPU info - OK")
        
        self.get_amd_gpu_info()
        print("    [+] AMD GPU info - OK")
        
        self.get_intel_gpu_info()
        print("    [+] Intel GPU info - OK")
        
        self.get_vmware_gpu_info()
        print("    [+] VMware GPU info - OK")
        
        self.get_gpu_from_lspci()
        print("    [+] GPU PCI info - OK")
        
        self.get_gpu_from_lsmod()
        print("    [+] GPU kernel modules - OK")
        
        print("[*] Information gathering completed!\n")
    
    def get_info(self, key=None):
        """Return information"""
        if key is None:
            return self.info
        return self.info.get(key, "N/A")
    
    def display_info(self, verbose=True):
        """Display collected information"""
        print("╔" + "═" * 78 + "╗")
        print("║" + " GPU INFORMATIONS REPORT ".center(78) + "║")
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
    crawler = GPUCrawler()
    crawler.gather_all_info()
    crawler.display_info(verbose=True)
    
    return crawler


if __name__ == "__main__":
    main()