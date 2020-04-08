# -*- coding: utf-8 -*-

"""
"""

import pytest
from assassin.assassin import getWhois


def test_getWhois():
  response = getWhois('173.245.58.51')
  assert 'CLOUDFLARENET' in response