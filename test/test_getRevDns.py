# -*- coding: utf-8 -*-

"""
"""

import pytest
import json
from assassin.lib.helper_functions import getRevDns


def test_getRevDns_com():
  response = getRevDns('173.245.58.51')
  assert b'ns1.digitalocean.com.' in response


__author__     = 'Franklin Diaz'
__copyright__  = ''
__credits__    = ['{credit_list}']
__license__    = '{license}'
__version__    = ''
__maintainer__ = ''
__email__      = 'fdiaz@paloaltonetworks.com'