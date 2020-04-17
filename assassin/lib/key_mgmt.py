# -*- coding: utf-8 -*-

import os
import logging
from pathlib import Path

def load_shodan_key():
  '''
  Function to load keys from environment vars rather that static file
  '''
  if 'SHODAN_KEY' in os.environ:
    shodanKey = os.environ['SHODAN_KEY']
    logging.debug('Found SHODAN_KEY in env vars')
    return shodanKey
  else:
    logging.debug('Did NOT find SHODAN_KEY in env vars')
    return False
