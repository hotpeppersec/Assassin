# -*- coding: utf-8 -*-

"""
"""

import pytest
from assassin.lib.summary import add_map_style
from assassin.lib.summary import add_map_to_summary
from assassin.lib.summary import generate_summary
import os


def test_add_map_style():
    '''
    Test creation of goog maps css style in summary header
    '''
    sumfile = "/tmp/test-summary.html"
    sum = open(sumfile, "w+")
    add_map_style(sum)
    sum.close()
    sum = open(sumfile, 'r') 
    result = sum.read()
    sum.close()
    assert '  #map {\n' and '</style>\n' in result
    os.remove(sumfile)


def test_add_map_to_summary():
    '''
    test adding the map section to summary

    would be cool to pull a key from vault and call the API
    '''
    summary = {'Name': 'Test', 'Test': 123}
    GoogleMapsKey = 'TEST_ONLY'
    sumfile = "/tmp/test-summary.html"
    sum = open(sumfile, "w+")
    add_map_to_summary(sum, summary, GoogleMapsKey)
    sum.close()
    sum = open(sumfile, 'r') 
    result = sum.read()
    sum.close()
    assert 'Global Technology Distribution<br>\n' and "</script>\n" in result
    os.remove(sumfile)


def test_generate_summary():
    '''
    test full summary generation
    '''
    summary = {'Name': 'Test', 'Test': 123}
    GoogleMapsKey = 'TEST_ONLY'
    sumfile = "/tmp/test-summary.html"
    sum = open(sumfile, "w+")
    generate_summary(sum, summary, GoogleMapsKey)
    sum.close()
    sum = open(sumfile, 'r') 
    result = sum.read()
    sum.close()
    assert '<br>Vulnerabilities<br>\n' in result
    os.remove(sumfile)


__author__ = 'Franklin Diaz'
__copyright__ = ''
__credits__ = ['']
__license__ = 'http://www.apache.org/licenses/LICENSE-2.0'
__version__ = ''
__maintainer__ = ''
__email__ = 'fdiaz@paloaltonetworks.com'