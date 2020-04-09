# -*- coding: utf-8 -*-

"""
"""

import pytest
from assassin.lib.helper_functions import getWhois


def test_getWhois():
  response = getWhois('173.245.58.51')
  assert 'CLOUDFLARENET' in response


__author__ = 'Franklin Diaz'
__copyright__ = ''
__credits__ = ['']
__license__ = 'http://www.apache.org/licenses/LICENSE-2.0'
__version__ = ''
__maintainer__ = ''
__email__ = 'fdiaz@paloaltonetworks.com'