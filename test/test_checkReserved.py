# -*- coding: utf-8 -*-

"""
"""

import pytest
from assassin.assassin import checkReserved


def test_checkReserved_false():
  '''
  Test Public IP
  '''
  assert not checkReserved('173.245.58.51')

def test_checkPrivate_true():
  '''
  Test Private IP
  '''
  assert checkReserved('253.0.0.1')