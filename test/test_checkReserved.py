# -*- coding: utf-8 -*-

"""
"""

import pytest
from assassin.lib.helper_functions import validate_ip
from assassin.lib.helper_functions import checkReserved


def test_checkReserved_false(capsys):
  '''
  Test Public IP
  '''
  assert not checkReserved('173.245.58.51')

def test_checkPrivate_true(capsys):
  '''
  Test Private IP
  '''
  assert checkReserved('253.0.0.1')

__author__ = 'Franklin Diaz'
__copyright__ = ''
__credits__ = ['']
__license__ = 'http://www.apache.org/licenses/LICENSE-2.0'
__version__ = ''
__maintainer__ = ''
__email__ = 'fdiaz@paloaltonetworks.com'