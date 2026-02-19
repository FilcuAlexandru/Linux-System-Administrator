#!/usr/bin/env python3.6
# -*- coding: utf-8 -*-

################################################################################
# System Crawler Aggregator - Comprehensive System Information Gathering Tool. #
# The main script that calls all the crawlers to extract the information.      #
# Version: 0.0.1                                                               #
# Author: Alexandru Filcu                                                      #
################################################################################

######################
# Import handy tools #
######################

import sys
import os
import json
import argparse
import time
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
    
    def export_to_json(self, pretty=True, output_file=None):
        """ Export collected data to JSON format """
        data = self._flatten_for_json(self.all_data)
        
        metadata = OrderedDict()
        metadata['timestamp'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        metadata['total_crawlers'] = len(self.selected_crawlers)
        metadata['execution_time_seconds'] = self.execution_time
        
        final_data = OrderedDict()
        final_data['metadata'] = metadata
        final_data['system_data'] = data
        
        if pretty:
            json_output = json.dumps(final_data, indent=2, ensure_ascii=False)
        else:
            json_output = json.dumps(final_data, ensure_ascii=False)
        
        if output_file:
            try:
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(json_output)
                return True
            except Exception as e:
                return False
        else:
            return json_output
    
    def export_to_text_report(self, output_file=None):
        """ Export collected data to plain text log format """
        report_lines = []
        
        report_lines.append("=" * 80)
        report_lines.append("COMPLETE SYSTEM INFORMATION REPORT")
        report_lines.append("=" * 80 + "\n")
        
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
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(report_text)
                return True
            except Exception as e:
                return False
        else:
            return report_text
    
    def export_to_csv(self, output_file=None):
        """ Export collected data to CSV format """
        csv_lines = []
        csv_lines.append("Crawler,Key,Value")
        
        for crawler_name, data in self.all_data.items():
            for key, value in data.items():
                if isinstance(value, str):
                    value_str = value.replace(',', ';').replace('\n', ' ')[:100]
                else:
                    value_str = str(value)[:100]
                
                csv_lines.append("{},{},{}".format(crawler_name, key, value_str))
        
        csv_text = "\n".join(csv_lines)
        
        if output_file:
            try:
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(csv_text)
                return True
            except Exception as e:
                return False
        else:
            return csv_text
    
    def export_to_html(self, output_file=None):
        """ Export collected data to HTML format for web viewing """
        html_lines = []
        
        html_lines.append("<!DOCTYPE html>")
        html_lines.append("<html>")
        html_lines.append("<head>")
        html_lines.append("<title>System Information Report</title>")
        html_lines.append("<meta charset='utf-8'>")
        html_lines.append("<style>")
        html_lines.append("body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }")
        html_lines.append("h1 { color: #333; border-bottom: 2px solid #007bff; padding-bottom: 10px; }")
        html_lines.append("h2 { color: #555; margin-top: 30px; }")
        html_lines.append("table { width: 100%; border-collapse: collapse; background: white; margin-top: 10px; }")
        html_lines.append("th, td { padding: 12px; text-align: left; border: 1px solid #ddd; }")
        html_lines.append("th { background: #007bff; color: white; }")
        html_lines.append("tr:nth-child(even) { background: #f9f9f9; }")
        html_lines.append(".metadata { background: #e7f3ff; padding: 15px; border-radius: 5px; margin-bottom: 20px; }")
        html_lines.append("</style>")
        html_lines.append("</head>")
        html_lines.append("<body>")
        html_lines.append("<h1>System Information Report</h1>")
        
        html_lines.append("<div class='metadata'>")
        html_lines.append("<strong>Generated:</strong> {}<br>".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        html_lines.append("<strong>Total Crawlers:</strong> {}<br>".format(len(self.selected_crawlers)))
        html_lines.append("<strong>Execution Time:</strong> {:.2f} seconds".format(self.execution_time))
        html_lines.append("</div>")
        
        for crawler_name, data in self.all_data.items():
            html_lines.append("<h2>{}</h2>".format(crawler_name.upper()))
            html_lines.append("<table>")
            html_lines.append("<tr><th>Key</th><th>Value</th></tr>")
            
            for key, value in data.items():
                value_str = str(value)[:200] if not isinstance(value, str) else value[:200]
                html_lines.append("<tr><td>{}</td><td><pre>{}</pre></td></tr>".format(
                    key.replace('_', ' ').title(), 
                    value_str.replace('<', '&lt;').replace('>', '&gt;')
                ))
            
            html_lines.append("</table>")
        
        html_lines.append("</body>")
        html_lines.append("</html>")
        
        html_text = "\n".join(html_lines)
        
        if output_file:
            try:
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(html_text)
                return True
            except Exception as e:
                return False
        else:
            return html_text
    
    def get_crawler_data(self, crawler_name):
        """ Retrieve collected data from a specific crawler """
        return self.all_data.get(crawler_name, {})
    
    def get_all_data(self):
        """ Retrieve all collected data from all crawlers """
        return self.all_data
    
    def _flatten_for_json(self, obj):
        """ Recursively convert OrderedDict and nested structures to regular dicts """
        if isinstance(obj, OrderedDict):
            return {k: self._flatten_for_json(v) for k, v in obj.items()}
        elif isinstance(obj, dict):
            return {k: self._flatten_for_json(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._flatten_for_json(item) for item in obj]
        else:
            return obj


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
    
    # Generate reports
    if not dry_run:
        print("[*] Generating reports...\n")
        
        aggregator.export_to_json(pretty=True, output_file="system_report.json")
        print("[+] JSON report generated")
        
        aggregator.export_to_text_report(output_file="system_report.log")
        print("[+] Log report generated")
        
        aggregator.export_to_csv(output_file="system_report.csv")
        print("[+] CSV report generated")
        
        aggregator.export_to_html(output_file="system_report.html")
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