# -*- coding: utf-8 -*-

"""
"""

import unittest
import json
from jsonschema import validate

class TestSum(unittest.TestCase):
    my_json_file = 'assassin/lib/serviceDetections.json'

    def test_json(self):
        """
        Describe what kind of json you expect.

        If JSON file is not formatted properly, this test will fail. 
        """
        schema = {
        "type" : "object",
            "properties": {
                "service detections": {
                    "signatures": {"type": "string"},
                    "exceptions": {"type": "string"},
                    "tags": {
                        "name": {"type" : "string"},
                        "type": {"type": "string"},
                        "severity": {"type": "string"},
                        "description": {"type": "string"},
                        "recommendations": {"type": "string"}
                     },   
                },
            }
        }
        with open(self.my_json_file, 'r') as f:
            json_file = f.read()
        my_json = json.loads(json_file)
        #print(my_json)
        validate(my_json, schema)


__author__     = ''
__copyright__  = ''
__credits__    = ['{credit_list}']
__license__    = 'http://www.apache.org/licenses/LICENSE-2.0'
__version__    = ''
__maintainer__ = ''
__email__      = ''
