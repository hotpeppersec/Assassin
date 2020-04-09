# -*- coding: utf-8 -*-

"""
"""

import pytest
import json
from assassin.lib.helper_functions import getFwdDns


def test_getFwdDns_com_str():
  response = getFwdDns('www.microsoft.com')
  assert b'www.microsoft.com-c-3.edgekey.net.' in response

def test_getFwdDns_com_byte():
  response = getFwdDns(b'www.microsoft.com')
  assert b'www.microsoft.com-c-3.edgekey.net.' in response


__author__     = 'Franklin Diaz'
__copyright__  = ''
__credits__    = ['{credit_list}']
__license__    = '{license}'
__version__    = ''
__maintainer__ = ''
__email__      = 'fdiaz@paloaltonetworks.com'