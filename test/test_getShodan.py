# -*- coding: utf-8 -*-

"""
"""

import pytest
from assassin.assassin import getShodan
import assassin.apiKeys


def test_getShodan():
  if assassin.apiKeys.shodanKey:
    local_shodanKey = assassin.apiKeys.shodanKey
    print('Found Shodan Key: %s' % local_shodanKey)
  response = getShodan('173.245.58.51', local_shodanKey)
  # fix this test