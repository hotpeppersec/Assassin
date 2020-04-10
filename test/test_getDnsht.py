# -*- coding: utf-8 -*-

"""
"""

import pytest
from assassin.lib.helper_functions import getDnsht


def test_getDnsht_bad(capsys):
  '''
  Test a bad TLD
  '''
  response = []
  response = getDnsht('com.zzz')
  assert 'error check your search parameter' in response


def test_getDnsht_com(capsys):
  '''
  Test a .com 
  Their API will rate limit us without auth 
  'API count exceeded - Increase Quota with Membership'

  Success case returns var: output

  Should check on the cound in output
  '''
  response = []
  response = getDnsht('cnn.com')
  assert 'proxy.cnn.com' in response


def test_getDnsht_net(capsys):
  '''
  Test a .net 
  Their API will rate limit us without auth

  Success case returns var: output
  Should check on the cound in output
  '''
  response = []
  response = getDnsht('bitsmasher.net')
  assert 'bitsmasher.net' in response

"""
def test_bad_decoded_html(capsys):
  '''
  Hacker target can't find domain
  '''
"""

__author__     = 'Franklin Diaz'
__copyright__  = ''
__credits__    = ['{credit_list}']
__license__    = 'http://www.apache.org/licenses/LICENSE-2.0'
__version__    = ''
__maintainer__ = ''
__email__      = 'fdiaz@paloaltonetworks.com'