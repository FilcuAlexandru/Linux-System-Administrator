#!/usr/bin/env python3.6
# -*- coding: utf-8 -*-

#############################################################################################################################################################
# Main System Crawler - Aggregator Script                                                                                                              #
# This script calls all individual system crawlers and consolidates their data.                                                                         #
#                                                                                                                                                       #
# Usage:                                                                                                                                                #
#   python3.6 system_crawler.py                              # Default: dry-run=true, crawler=all                                                     #
#   python3.6 system_crawler.py --dry-run=false              # Run all crawlers                                                                        #
#   python3.6 system_crawler.py --crawler=os,cpu,ram         # Select specific crawlers (dry-run=true by default)                                     #
#   python3.6 system_crawler.py --dry-run=false --crawler=os # Run only OS crawler                                                                     #
#   python3.6 system_crawler.py --crawler=all --dry-run=false # Run all crawlers                                                                       #
#                                                                                                                                                       #
# Directory Structure:                                                                                                                                  #
# system_crawler/                                                                                                                                      #
#   ├── system_crawler.py (this file)                                                                                                                  #
#   └── crawlers/                                                                                                                                      #
#       ├── os_crawler.py, cpu_crawler.py, ram_crawler.py, gpu_crawler.py, motherboard_crawler.py                                                    #
#       ├── usb_crawler.py, storage_crawler.py, network_crawler.py, pci_crawler.py, sensors_crawler.py                                              #
#       ├── audio_crawler.py, input_devices_crawler.py, security_crawler.py, system_services_crawler.py, bios_crawler.py                            #
#                                                                                                                                                       #
# Version: 2.0.0                                                                                                                                       #
# Author: Alexandru Filcu                                                                                                                              #
#############################################################################################################################################################

import sys
import os
import json
import argparse
from collections import OrderedDict
from datetime import datetime

# Add crawlers directory to path
crawlers_dir = os.path.join(os.path.dirname(__file__), 'crawlers')
sys.path.insert(0, crawlers_dir)

# Import all crawlers
try:
    from os_crawler import OSCrawler
    from cpu_crawler import CPUCrawler
    from ram_crawler import RAMCrawler
    from gpu_crawler import GPUCrawler
    from motherboard_crawler import MotherboardCrawler
    from usb_crawler import USBCrawler
    from storage_crawler import StorageCrawler
    from network_crawler import NetworkCrawler
    from pci_crawler import PCICrawler
    from sensors_crawler import SensorsCrawler
    from audio_crawler import AudioCrawler
    from input_devices_crawler import InputDevicesCrawler
    from security_crawler import SecurityCrawler
    from system_services_crawler import SystemServicesCrawler
    from bios_crawler import BIOSCrawler
    
    print("[OK] All crawlers imported successfully!\n")
except ImportError as e:
    print("[ERROR] Error importing crawlers: {}".format(str(e)))
    sys.exit(1)


class SystemCrawlerAggregator:
    """Main aggregator that runs all system crawlers"""
    
    def __init__(self, dry_run=True, selected_crawlers=None):
        self.all_data = OrderedDict()
        self.available_crawlers = OrderedDict()
        self.selected_crawlers = OrderedDict()
        self.execution_time = None
        self.start_time = None
        self.dry_run = dry_run
        self.selected_crawler_names = selected_crawlers or ['all']
        
        # Initialize available crawlers mapping
        self._init_available_crawlers()
        
        # Select crawlers based on input
        self._select_crawlers()
    
    def _init_available_crawlers(self):
        """Initialize available crawlers mapping"""
        self.available_crawlers['os'] = OSCrawler
        self.available_crawlers['cpu'] = CPUCrawler
        self.available_crawlers['ram'] = RAMCrawler
        self.available_crawlers['gpu'] = GPUCrawler
        self.available_crawlers['motherboard'] = MotherboardCrawler
        self.available_crawlers['usb'] = USBCrawler
        self.available_crawlers['storage'] = StorageCrawler
        self.available_crawlers['network'] = NetworkCrawler
        self.available_crawlers['pci'] = PCICrawler
        self.available_crawlers['sensors'] = SensorsCrawler
        self.available_crawlers['audio'] = AudioCrawler
        self.available_crawlers['input_devices'] = InputDevicesCrawler
        self.available_crawlers['security'] = SecurityCrawler
        self.available_crawlers['system_services'] = SystemServicesCrawler
        self.available_crawlers['bios'] = BIOSCrawler
    
    def _select_crawlers(self):
        """Select crawlers based on input"""
        if 'all' in self.selected_crawler_names:
            # Select all crawlers
            self.selected_crawlers = self.available_crawlers.copy()
        else:
            # Select specific crawlers
            for crawler_name in self.selected_crawler_names:
                crawler_name = crawler_name.strip()
                if crawler_name in self.available_crawlers:
                    self.selected_crawlers[crawler_name] = self.available_crawlers[crawler_name]
                else:
                    print("[WARNING] Unknown crawler: {}".format(crawler_name))
        
        if not self.selected_crawlers:
            print("[ERROR] No valid crawlers selected!")
            sys.exit(1)
    
    def print_dry_run_summary(self):
        """Print dry-run summary"""
        print("\n╔" + "═" * 78 + "╗")
        print("║" + " DRY-RUN MODE SUMMARY ".center(78) + "║")
        print("╠" + "═" * 78 + "╣")
        print("║ This is a simulation. No actual checks will be performed.".ljust(79) + "║")
        print("║ Selected crawlers: {}".format(len(self.selected_crawlers)).ljust(79) + "║")
        print("║".ljust(79) + "║")
        print("║ Crawlers to be executed:".ljust(79) + "║")
        
        for crawler_name in self.selected_crawlers.keys():
            print("║   - {}".format(crawler_name.upper()).ljust(79) + "║")
        
        print("║".ljust(79) + "║")
        print("║ To run the actual checks, use: --dry-run=false".ljust(79) + "║")
        print("╚" + "═" * 78 + "╝\n")
    
    def initialize_crawlers(self):
        """Initialize selected crawlers"""
        if self.dry_run:
            print("[*] DRY-RUN MODE - Simulating crawler initialization...\n")
        else:
            print("[*] Initializing selected crawlers...\n")
        
        for crawler_name, crawler_class in self.selected_crawlers.items():
            crawler_instance = crawler_class()
            self.selected_crawlers[crawler_name] = crawler_instance
        
        if self.dry_run:
            print("[OK] All {} crawlers initialized (simulation)!\n".format(len(self.selected_crawlers)))
        else:
            print("[OK] All {} crawlers initialized!\n".format(len(self.selected_crawlers)))
    
    def run_all_crawlers(self):
        """Run all selected crawlers and collect data"""
        if self.dry_run:
            print("╔" + "═" * 78 + "╗")
            print("║" + " DRY-RUN: SIMULATING CRAWLER EXECUTION ".center(78) + "║")
            print("╚" + "═" * 78 + "╝\n")
        else:
            print("╔" + "═" * 78 + "╗")
            print("║" + " RUNNING ALL SELECTED CRAWLERS ".center(78) + "║")
            print("╚" + "═" * 78 + "╝\n")
        
        self.start_time = datetime.now()
        
        for crawler_name, crawler in self.selected_crawlers.items():
            if self.dry_run:
                print("[*] Simulating {} crawler...".format(crawler_name.upper()))
                print("[+] {} crawler would be executed\n".format(crawler_name.upper()))
            else:
                print("[*] Running {} crawler...".format(crawler_name.upper()))
                try:
                    crawler.gather_all_info()
                    self.all_data[crawler_name] = crawler.export_to_dict()
                    print("[+] {} crawler completed!\n".format(crawler_name.upper()))
                except Exception as e:
                    print("[-] Error in {} crawler: {}\n".format(crawler_name.upper(), str(e)))
        
        self.execution_time = (datetime.now() - self.start_time).total_seconds()
        
        print("\n╔" + "═" * 78 + "╗")
        print("║" + " EXECUTION SUMMARY ".center(78) + "║")
        print("╠" + "═" * 78 + "╣")
        
        if self.dry_run:
            print("║ Dry-run simulation completed!".ljust(79) + "║")
            print("║ Crawlers simulated: {}".format(len(self.selected_crawlers)).ljust(79) + "║")
        else:
            print("║ All crawlers executed successfully!".ljust(79) + "║")
            print("║ Total crawlers run: {}".format(len(self.selected_crawlers)).ljust(79) + "║")
        
        print("║ Execution time: {:.2f} seconds".format(self.execution_time).ljust(79) + "║")
        print("╚" + "═" * 78 + "╝\n")
    
    def display_summary(self):
        """Display summary of collected data"""
        if self.dry_run:
            return
        
        print("╔" + "═" * 78 + "╗")
        print("║" + " SYSTEM INFORMATION SUMMARY ".center(78) + "║")
        print("╚" + "═" * 78 + "╝\n")
        
        for crawler_name, data in self.all_data.items():
            print("\n[{}]".format(crawler_name.upper()))
            print("-" * 80)
            
            # Display first 3 entries from each crawler as preview
            count = 0
            for key, value in data.items():
                if count >= 3:
                    print("  ... and {} more items".format(len(data) - 3))
                    break
                
                if isinstance(value, str):
                    first_line = value.split('\n')[0] if value else "N/A"
                    if len(first_line) > 70:
                        first_line = first_line[:67] + "..."
                    print("  {}: {}".format(key, first_line))
                else:
                    print("  {}: {}".format(key, str(value)[:70]))
                
                count += 1
    
    def export_to_json(self, pretty=True, output_file=None):
        """Export all data to JSON"""
        if self.dry_run:
            print("[WARNING] No data to export in dry-run mode\n")
            return None
        
        data = self._flatten_for_json(self.all_data)
        
        # Add metadata
        metadata = OrderedDict()
        metadata['timestamp'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        metadata['total_crawlers'] = len(self.selected_crawlers)
        metadata['execution_time_seconds'] = self.execution_time
        
        final_data = OrderedDict()
        final_data['metadata'] = metadata
        final_data['system_data'] = data
        
        if pretty:
            json_output = json.dumps(final_data, indent=2)
        else:
            json_output = json.dumps(final_data)
        
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
    
    def export_to_text_report(self, output_file=None):
        """Export all data to text report"""
        if self.dry_run:
            print("[WARNING] No report generated in dry-run mode\n")
            return None
        
        report_lines = []
        
        report_lines.append("╔" + "═" * 78 + "╗")
        report_lines.append("║" + " COMPLETE SYSTEM INFORMATION REPORT ".center(78) + "║")
        report_lines.append("╚" + "═" * 78 + "╝\n")
        
        report_lines.append("Generated: {}\n".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        report_lines.append("Total Crawlers: {}".format(len(self.selected_crawlers)))
        report_lines.append("Execution Time: {:.2f} seconds\n".format(self.execution_time))
        report_lines.append("=" * 80 + "\n")
        
        for crawler_name in self.selected_crawlers.keys():
            if crawler_name in self.all_data:
                report_lines.append("\n[{}]".format(crawler_name.upper()))
                report_lines.append("-" * 80)
                
                for key, value in self.all_data[crawler_name].items():
                    report_lines.append("\n  {}:".format(key.upper().replace('_', ' ')))
                    
                    if isinstance(value, str):
                        report_lines.append("  {}".format(value.replace('\n', '\n  ')))
                    else:
                        report_lines.append("  {}".format(str(value)))
        
        report_text = "\n".join(report_lines)
        
        if output_file:
            try:
                with open(output_file, 'w') as f:
                    f.write(report_text)
                print("[+] Text report written to: {}".format(output_file))
                print("[NOTE] Report size: {:.2f} KB".format(len(report_text) / 1024))
                return None
            except Exception as e:
                print("[-] Error writing to file: {}".format(str(e)))
                return report_text
        else:
            return report_text
    
    def get_crawler_data(self, crawler_name):
        """Get data from specific crawler"""
        return self.all_data.get(crawler_name, {})
    
    def get_all_data(self):
        """Get all collected data"""
        return self.all_data
    
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


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='System Crawler - Aggregate system information from multiple crawlers',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python3.6 system_crawler.py                                    # Dry-run with all crawlers
  python3.6 system_crawler.py --dry-run=true                     # Dry-run with all crawlers
  python3.6 system_crawler.py --crawler=os --dry-run=false       # Run only OS crawler
  python3.6 system_crawler.py --crawler=cpu,ram --dry-run=false  # Run CPU and RAM crawlers
  python3.6 system_crawler.py --dry-run=false --force            # Run ALL crawlers (requires --force)

Available crawlers:
  os, cpu, ram, gpu, motherboard, usb, storage, network, pci, sensors,
  audio, input_devices, security, system_services, bios

IMPORTANT: Running all 15 crawlers with --crawler=all requires --force flag
           This is intentional to prevent accidental heavy resource consumption.
        '''
    )
    
    parser.add_argument(
        '--dry-run',
        type=str,
        default='true',
        choices=['true', 'false'],
        help='Run in simulation mode (default: true)'
    )
    
    parser.add_argument(
        '--crawler',
        type=str,
        default='all',
        help='Crawlers to run (comma-separated). Default: all'
    )
    
    parser.add_argument(
        '--force',
        action='store_true',
        help='Force execution of all crawlers (required when using --crawler=all with --dry-run=false)'
    )
    
    args = parser.parse_args()
    
    # Convert dry-run string to boolean
    dry_run = args.dry_run.lower() == 'true'
    
    # Parse crawler list
    if args.crawler.lower() == 'all':
        selected_crawlers = ['all']
    else:
        selected_crawlers = [c.strip() for c in args.crawler.split(',')]
    
    return dry_run, selected_crawlers, args.force


def validate_execution(dry_run, force_flag, selected_crawlers):
    """Validate if execution should proceed"""
    # If running in dry-run mode, always allow
    if dry_run:
        return True
    
    # If running all crawlers in actual mode, require --force flag
    if selected_crawlers == ['all'] and not force_flag:
        print("\n" + "!" * 80)
        print("ERROR: Running all crawlers requires --force flag")
        print("!" * 80)
        print("\nThis is intentional to prevent accidental execution of heavy resource consumption.")
        print("\nUsage to run all crawlers:")
        print("  python3.6 system_crawler.py --dry-run=false --force")
        print("\nOr run specific crawlers without --force:")
        print("  python3.6 system_crawler.py --crawler=os,cpu,ram --dry-run=false")
        print("")
        return False
    
    # If running specific crawlers in actual mode, allow without --force
    return True


def main():
    """Main function"""
    
    # Parse command line arguments
    dry_run, selected_crawlers, force_flag = parse_arguments()
    
    print("\n╔" + "═" * 78 + "╗")
    print("║" + " SYSTEM CRAWLER AGGREGATOR ".center(78) + "║")
    print("╚" + "═" * 78 + "╝\n")
    
    print("Configuration:")
    print("  Dry-run mode: {}".format("ON (Safe)" if dry_run else "OFF (Heavy resources)"))
    print("  Selected crawlers: {}\n".format(", ".join(selected_crawlers)))
    
    # Create aggregator to check crawler count
    temp_aggregator = SystemCrawlerAggregator(dry_run=True, selected_crawlers=selected_crawlers)
    crawler_count = len(temp_aggregator.selected_crawlers)
    
    print("  Crawlers to execute: {}\n".format(crawler_count))
    
    # Validate execution
    if not validate_execution(dry_run, force_flag, selected_crawlers):
        sys.exit(1)
    
    # Create aggregator for actual execution
    aggregator = SystemCrawlerAggregator(dry_run=dry_run, selected_crawlers=selected_crawlers)
    
    if dry_run:
        # Print dry-run summary
        aggregator.print_dry_run_summary()
    
    # Initialize crawlers
    aggregator.initialize_crawlers()
    
    # Run crawlers
    aggregator.run_all_crawlers()
    
    # Display summary (only in actual run mode)
    aggregator.display_summary()
    
    # Export reports (only in actual run mode)
    if not dry_run:
        aggregator.export_to_json(pretty=True, output_file="system_report.json")
        aggregator.export_to_text_report(output_file="system_report.txt")
        
        # Print final summary
        print("\n╔" + "═" * 78 + "╗")
        print("║" + " REPORT GENERATION COMPLETED ".center(78) + "║")
        print("╠" + "═" * 78 + "╣")
        print("║ JSON report: system_report.json".ljust(79) + "║")
        print("║ Text report: system_report.txt".ljust(79) + "║")
        print("║ Execution time: {:.2f} seconds".format(aggregator.execution_time).ljust(79) + "║")
        print("╚" + "═" * 78 + "╝\n")
    
    return aggregator


if __name__ == "__main__":
    aggregator = main()