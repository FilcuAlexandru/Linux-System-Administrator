#!/usr/bin/env python3.6
# -*- coding: utf-8 -*-

#################################################################################
# BASE EXPORTER CLASS - FOUNDATION FOR ALL EXPORT FORMAT IMPLEMENTATIONS.       #
# PROVIDES COMMON FUNCTIONALITY AND INTERFACE FOR JSON, CSV, LOG, HTML EXPORTS. #
# HANDLES DATA FLATTENING AND COMMON OPERATIONS ACROSS ALL EXPORTERS.           #
# VERSION: 0.0.1                                                                #
# AUTHOR: ALEXANDRU FILCU                                                       #
#################################################################################

from collections import OrderedDict
from datetime import datetime


class BaseExporter:
    """ Base class for all export formats """
    
    def __init__(self, aggregator):
        """ Initialize exporter with aggregator data """
        self.aggregator = aggregator
        self.all_data = aggregator.all_data
        self.selected_crawlers = aggregator.selected_crawlers
        self.execution_time = aggregator.execution_time
    
    def export(self, output_file=None):
        """ Export data - to be implemented by subclasses """
        raise NotImplementedError("Subclasses must implement export method")
    
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