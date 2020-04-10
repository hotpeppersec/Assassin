# -*- coding: utf-8 -*-

"""
"""

import pytest
import json
from assassin.lib.helper_functions import validate_ip
from assassin.lib.helper_functions import getRevDns


def test_getRevDns_com(capsys):
  response = []
  response = getRevDns('173.245.58.51')
  assert 'ns1.digitalocean.com.' in response


__author__     = 'Franklin Diaz'
__copyright__  = ''
__credits__    = ['{credit_list}']
__license__    = 'http://www.apache.org/licenses/LICENSE-2.0'
__version__    = ''
__maintainer__ = ''
__email__      = 'fdiaz@paloaltonetworks.com'