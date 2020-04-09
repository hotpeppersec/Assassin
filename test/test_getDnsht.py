# -*- coding: utf-8 -*-

"""
"""

import pytest
from assassin.lib.helper_functions import getDnsht


def test_getDnsht_com():
  '''
  Their API will rate limit us without auth
  '''
  response = getDnsht('cnn.com')
  if not 'API count exceeded - Increase Quota with Membership' in response:
    assert 'proxy.cnn.com' in response


def test_getDnsht_net():
  '''
  Their API will rate limit us without auth
  '''
  response = getDnsht('bitsmasher.net')
  if not 'API count exceeded - Increase Quota with Membership' in response:
    assert 'bitsmasher.net' in response


__author__     = 'Franklin Diaz'
__copyright__  = ''
__credits__    = ['{credit_list}']
__license__    = '{license}'
__version__    = ''
__maintainer__ = ''
__email__      = 'fdiaz@paloaltonetworks.com'