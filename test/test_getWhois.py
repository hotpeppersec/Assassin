# -*- coding: utf-8 -*-

"""
"""

import pytest
from assassin.lib.helper_functions import getWhois


def test_getWhois():
  response = getWhois('173.245.58.51')
  assert 'CLOUDFLARENET' in response