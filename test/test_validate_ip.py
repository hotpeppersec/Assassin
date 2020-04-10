# -*- coding: utf-8 -*-

"""
"""

import pytest
from assassin.lib.helper_functions import validate_ip


def test_validate_ip_success():
    '''
    Test Validate IP good
    '''
    assert validate_ip('173.245.58.51')


def test_validate_ip_fail_host():
    '''
    Test Validate IP bad
    '''
    assert not validate_ip('bitsmasher.net')


def test_validate_ip_fail_ip():
    '''
    Test Validate IP bad
    '''
    assert not validate_ip('256.1.2.3')


def test_validate_ip_FQDN():
  # should capture ValueError Exception, we catch and return False
  assert not validate_ip('login.gslb.paloaltonetworks.com')


__author__ = 'Franklin Diaz'
__copyright__ = ''
__credits__ = ['']
__license__ = 'http://www.apache.org/licenses/LICENSE-2.0'
__version__ = ''
__maintainer__ = ''
__email__ = 'fdiaz@paloaltonetworks.com'
