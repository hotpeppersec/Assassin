# -*- coding: utf-8 -*-

"""
"""

import pytest
import json
from assassin.lib.helper_functions import validate_ip
from assassin.lib.helper_functions import getFwdDns


def test_getFwdDns_com_str(capsys):
  response = []
  response = getFwdDns('www.bitsmasher.net')
  assert '178.62.60.55' in response


__author__     = 'Franklin Diaz'
__copyright__  = ''
__credits__    = ['{credit_list}']
__license__    = 'http://www.apache.org/licenses/LICENSE-2.0'
__version__    = ''
__maintainer__ = ''
__email__      = 'fdiaz@paloaltonetworks.com'