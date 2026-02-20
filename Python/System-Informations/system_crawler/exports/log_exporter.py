#!/usr/bin/env python3.6
# -*- coding: utf-8 -*-

########################################################################################################################################
# LOG EXPORTER - HUMAN-READABLE TEXT FORMAT FOR EASY REVIEW AND ARCHIVAL.                                                              #
# EXPORTS SYSTEM INFORMATION IN PLAIN TEXT FORMAT WITH CLEAR SECTIONS, INDENTATION, AND FORMATTING FOR EASY READING AND DOCUMENTATION. #
# VERSION: 0.0.1                                                                                                                       #
# AUTHOR: ALEXANDRU FILCU                                                                                                              #
########################################################################################################################################

from base_exporter import BaseExporter
from datetime import datetime


class LOGExporter(BaseExporter):
    """ Export data to plain text log format """
    
    def export(self, output_file=None):
        """ Export collected data to plain text log format """
        report_lines = []
        
        # Add report header
        report_lines.append("=" * 80)
        report_lines.append("COMPLETE SYSTEM INFORMATION REPORT")
        report_lines.append("=" * 80 + "\n")
        
        # Add metadata
        report_lines.append("Generated: {}\n".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        report_lines.append("Total Crawlers: {}".format(len(self.selected_crawlers)))
        report_lines.append("Execution Time: {:.2f} seconds\n".format(self.execution_time))
        report_lines.append("=" * 80 + "\n")
        
        # Add data for each crawler
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
        
        # Write to file or return string
        if output_file:
            try:
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(report_text)
                return True
            except Exception as e:
                return False
        else:
            return report_text