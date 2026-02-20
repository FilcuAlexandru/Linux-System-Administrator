#!/usr/bin/env python3.6
# -*- coding: utf-8 -*-

#############################################################################################################################################
# SYSTEM CRAWLER AGGREGATOR - COMPREHENSIVE SYSTEM INFORMATION GATHERING TOOL.                                                              #
# THE MAIN SCRIPT THAT CALLS ALL CRAWLERS TO COLLECT AND AGGREGATE SYSTEM DATA.                                                             #
# ORCHESTRATES EXECUTION OF ALL CRAWLERS AND MANAGES DATA EXPORT TO MULTIPLE FORMATS (JSON, CSV, LOG, HTML) USING MODULAR EXPORTER CLASSES. #
# VERSION: 0.0.1                                                                                                                            #
# AUTHOR: ALEXANDRU FILCU                                                                                                                   #
#############################################################################################################################################

import sys
import os
import json
import argparse
import time
from collections import OrderedDict
from datetime import datetime

# Add crawlers and exporters directories to path
crawlers_dir = os.path.join(os.path.dirname(__file__), 'crawlers')
exporters_dir = os.path.join(os.path.dirname(__file__), 'exporters')
sys.path.insert(0, crawlers_dir)
sys.path.insert(0, exporters_dir)

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
    
    # Import exporters
    from json_exporter import JSONExporter
    from csv_exporter import CSVExporter
    from log_exporter import LOGExporter
    from html_exporter import HTMLExporter
    
    print("[OK] All crawlers imported successfully!\n")
except ImportError as e:
    print("[ERROR] Error importing crawlers: {}".format(str(e)))
    sys.exit(1)


class SystemCrawlerAggregator:
    """ Main aggregator class that orchestrates execution of all system crawlers """
    
    def __init__(self, dry_run=True, selected_crawlers=None):
        """ Initialize the aggregator with configuration """
        self.all_data = OrderedDict()
        self.available_crawlers = OrderedDict()
        self.selected_crawlers = OrderedDict()
        self.execution_time = None
        self.start_time = None
        self.dry_run = dry_run
        self.selected_crawler_names = selected_crawlers or ['all']
        
        self._init_available_crawlers()
        self._select_crawlers()
    
    def _init_available_crawlers(self):
        """ Initialize mapping of all available crawlers """
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
        """ Select crawlers based on user input """
        if 'all' in self.selected_crawler_names:
            self.selected_crawlers = self.available_crawlers.copy()
        else:
            for crawler_name in self.selected_crawler_names:
                crawler_name = crawler_name.strip()
                if crawler_name in self.available_crawlers:
                    self.selected_crawlers[crawler_name] = self.available_crawlers[crawler_name]
                else:
                    print("[WARNING] Unknown crawler: {}".format(crawler_name))
        
        if not self.selected_crawlers:
            print("[ERROR] No valid crawlers selected!")
            sys.exit(1)
    
    def initialize_crawlers(self):
        """ Initialize all selected crawlers by instantiating their classes """
        for crawler_name, crawler_item in list(self.selected_crawlers.items()):
            if isinstance(crawler_item, type):
                self.selected_crawlers[crawler_name] = crawler_item()
    
    def run_all_crawlers(self):
        """ Execute all selected crawlers and collect system information """
        print("╔" + "═" * 78 + "╗")
        print("║" + " EXECUTING SYSTEM CRAWLERS ".center(78) + "║")
        print("╚" + "═" * 78 + "╝\n")
        
        self.start_time = datetime.now()
        
        for crawler_name, crawler in self.selected_crawlers.items():
            crawler_display = crawler_name.upper()
            
            try:
                print("[*] Running {} crawler...".format(crawler_display))
                crawler.gather_all_info()
                self.all_data[crawler_name] = crawler.export_to_dict()
                print("[+] {} crawler completed!\n".format(crawler_display))
                
            except Exception as e:
                print("[-] Error in {} crawler: {}\n".format(crawler_display, str(e)))
        
        self.execution_time = (datetime.now() - self.start_time).total_seconds()
        
        print("╔" + "═" * 78 + "╗")
        print("║" + " EXECUTION SUMMARY ".center(78) + "║")
        print("╠" + "═" * 78 + "╣")
        print("║ All crawlers executed successfully!".ljust(79) + "║")
        print("║ Total crawlers run: {}".format(len(self.selected_crawlers)).ljust(79) + "║")
        print("║ Execution time: {:.2f} seconds".format(self.execution_time).ljust(79) + "║")
        print("╚" + "═" * 78 + "╝\n")
    
    def get_crawler_data(self, crawler_name):
        """ Retrieve collected data from a specific crawler """
        return self.all_data.get(crawler_name, {})
    
    def get_all_data(self):
        """ Retrieve all collected data from all crawlers """
        return self.all_data


def parse_arguments():
    """ Parse and validate command line arguments """
    parser = argparse.ArgumentParser(
        description='System Crawler - Comprehensive system information gathering tool',
        prog='system_crawler.py'
    )
    
    parser.add_argument(
        '--dry-run',
        type=str,
        default='true',
        choices=['true', 'false'],
        help='Run in simulation mode (default: true)'
    )
    
    parser.add_argument(
        '--crawlers',
        type=str,
        default='all',
        help='Comma-separated list of crawlers to run (e.g., os,cpu,ram) or "all" for all crawlers'
    )
    
    parser.add_argument(
        '--force',
        action='store_true',
        help='Force execution (required when running more than 5 crawlers with --dry-run=false)'
    )
    
    args = parser.parse_args()
    
    dry_run = args.dry_run.lower() == 'true'
    
    if args.crawlers.lower() == 'all':
        selected_crawlers = ['all']
    else:
        selected_crawlers = [c.strip() for c in args.crawlers.split(',')]
    
    return dry_run, selected_crawlers, args.force


def validate_execution(dry_run, force_flag, selected_crawlers, crawler_count):
    """ Validate that execution can proceed based on user input """
    if dry_run:
        return True
    
    # If more than 5 crawlers selected, require --force flag
    if crawler_count > 5:
        if not force_flag:
            print("\n" + "!" * 80)
            print("ERROR: Running {} crawlers requires --force flag (max 5 without --force)".format(crawler_count))
            print("!" * 80)
            print("\nThis prevents accidental execution of heavy resource consumption.")
            print("\nExamples:")
            print("  python3.6 system_crawler.py --crawlers=os,cpu,ram --dry-run=false")
            print("  python3.6 system_crawler.py --crawlers=all --dry-run=false --force")
            print("")
            return False
    
    return True


def main():
    """ Main entry point for the System Crawler application """
    
    dry_run, selected_crawlers, force_flag = parse_arguments()
    
    # Create temp aggregator to get crawler count
    temp_aggregator = SystemCrawlerAggregator(dry_run=True, selected_crawlers=selected_crawlers)
    crawler_count = len(temp_aggregator.selected_crawlers)
    
    # Validate execution can proceed
    if not validate_execution(dry_run, force_flag, selected_crawlers, crawler_count):
        sys.exit(1)
    
    # Create and run aggregator
    aggregator = SystemCrawlerAggregator(dry_run=dry_run, selected_crawlers=selected_crawlers)
    aggregator.initialize_crawlers()
    aggregator.run_all_crawlers()
    
    # Generate reports using exporters
    if not dry_run:
        print("[*] Generating reports...\n")
        
        # JSON export
        json_exporter = JSONExporter(aggregator)
        json_exporter.export(pretty=True, output_file="system_report.json")
        print("[+] JSON report generated")
        
        # LOG export
        log_exporter = LOGExporter(aggregator)
        log_exporter.export(output_file="system_report.log")
        print("[+] Log report generated")
        
        # CSV export
        csv_exporter = CSVExporter(aggregator)
        csv_exporter.export(output_file="system_report.csv")
        print("[+] CSV report generated")
        
        # HTML export
        html_exporter = HTMLExporter(aggregator)
        html_exporter.export(output_file="system_report.html")
        print("[+] HTML report generated\n")
        
        print("╔" + "═" * 78 + "╗")
        print("║" + " REPORT GENERATION COMPLETED ".center(78) + "║")
        print("╠" + "═" * 78 + "╣")
        print("║ JSON report: system_report.json".ljust(79) + "║")
        print("║ Log report:  system_report.log".ljust(79) + "║")
        print("║ CSV report:  system_report.csv".ljust(79) + "║")
        print("║ HTML report: system_report.html".ljust(79) + "║")
        print("║ Execution time: {:.2f} seconds".format(aggregator.execution_time).ljust(79) + "║")
        print("╚" + "═" * 78 + "╝\n")
    
    return aggregator


if __name__ == "__main__":
    aggregator = main()