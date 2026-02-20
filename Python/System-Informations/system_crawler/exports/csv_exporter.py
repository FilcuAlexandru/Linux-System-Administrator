#!/usr/bin/env python3.6
# -*- coding: utf-8 -*-

################################################################################################################################################
# CSV EXPORTER - SPREADSHEET-COMPATIBLE FORMAT FOR DATA ANALYSIS.                                                                              #
# EXPORTS SYSTEM INFORMATION IN CSV FORMAT SUITABLE FOR IMPORT INTO EXCEL, GOOGLE SHEETS, OR OTHER SPREADSHEET APPLICATIONS FOR DATA ANALYSIS. #
# VERSION: 0.0.1                                                                                                                               #
# AUTHOR: ALEXANDRU FILCU                                                                                                                      #
################################################################################################################################################

from base_exporter import BaseExporter


class CSVExporter(BaseExporter):
    """ Export data to CSV format """
    
    def export(self, output_file=None):
        """ Export collected data to CSV format """
        csv_lines = []
        csv_lines.append("Crawler,Key,Value")
        
        # Convert data to CSV format
        for crawler_name, data in self.all_data.items():
            for key, value in data.items():
                if isinstance(value, str):
                    value_str = value.replace(',', ';').replace('\n', ' ')[:100]
                else:
                    value_str = str(value)[:100]
                
                csv_lines.append("{},{},{}".format(crawler_name, key, value_str))
        
        csv_text = "\n".join(csv_lines)
        
        # Write to file or return string
        if output_file:
            try:
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(csv_text)
                return True
            except Exception as e:
                return False
        else:
            return csv_text