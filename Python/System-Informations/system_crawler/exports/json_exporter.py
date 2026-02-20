#!/usr/bin/env python3.6
# -*- coding: utf-8 -*-

##########################################################################################
# JSON EXPORTER - STRUCTURED DATA FORMAT FOR MACHINE READING AND API USAGE.              #
# EXPORTS SYSTEM INFORMATION IN JSON FORMAT WITH METADATA AND HIERARCHICAL ORGANIZATION. #
# SUPPORTS PRETTY PRINTING FOR HUMAN READABILITY.                                        #
# VERSION: 0.0.1                                                                         #
# AUTHOR: ALEXANDRU FILCU                                                                #
##########################################################################################

import json
from collections import OrderedDict
from base_exporter import BaseExporter
from datetime import datetime


class JSONExporter(BaseExporter):
    """ Export data to JSON format """
    
    def export(self, pretty=True, output_file=None):
        """ Export collected data to JSON format """
        data = self._flatten_for_json(self.all_data)
        
        # Add metadata
        metadata = OrderedDict()
        metadata['timestamp'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        metadata['total_crawlers'] = len(self.selected_crawlers)
        metadata['execution_time_seconds'] = self.execution_time
        
        final_data = OrderedDict()
        final_data['metadata'] = metadata
        final_data['system_data'] = data
        
        # Serialize to JSON
        if pretty:
            json_output = json.dumps(final_data, indent=2, ensure_ascii=False)
        else:
            json_output = json.dumps(final_data, ensure_ascii=False)
        
        # Write to file or return string
        if output_file:
            try:
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(json_output)
                return True
            except Exception as e:
                return False
        else:
            return json_output