# -*- coding: utf-8 -*-

"""
"""

import pytest
import json
from assassin.lib.helper_functions import validate_ip
from assassin.lib.helper_functions import getDomainInfo


def test_getDomaininfo_com(capsys):
  response = getDomainInfo('cnn.com')
  temp = json.dumps(response)
  json_data = json.loads(temp)
  assert 'objectClassName' in json_data


def test_getDomaininfo_net(capsys):
  response = getDomainInfo('bitsmasher.net')
  temp = json.dumps(response)
  json_data = json.loads(temp)
  assert 'objectClassName' in json_data


def test_getDomaininfo_org(capsys):
  with pytest.raises(SystemExit):
    response = getDomainInfo('slashdot.org')
  out, err = capsys.readouterr()
  assert out == 'Lookup slashdot.org via Verisign\nSee https://www.verisign.com/en_US/domain-names/registration-data-access-protocol/index.xhtml for documentation.\n'
  print(out, err)


__author__     = 'Franklin Diaz'
__copyright__  = ''
__credits__    = ['{credit_list}']
__license__    = 'http://www.apache.org/licenses/LICENSE-2.0'
__version__    = ''
__maintainer__ = ''
__email__      = 'fdiaz@paloaltonetworks.com'