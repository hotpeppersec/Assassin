# -*- coding: utf-8 -*-

"""
"""

import pytest
from assassin.lib.helper_functions import getShodan
import assassin.apiKeys


def test_getShodan(capsys):
  if assassin.apiKeys.shodanKey:
    local_shodanKey = assassin.apiKeys.shodanKey
    print('Found Shodan Key: %s' % local_shodanKey)
  response = getShodan('173.245.58.51', local_shodanKey)
  # fix this test

__author__ = 'Franklin Diaz'
__copyright__ = ''
__credits__ = ['']
__license__ = 'http://www.apache.org/licenses/LICENSE-2.0'
__version__ = ''
__maintainer__ = ''
__email__ = 'fdiaz@paloaltonetworks.com'