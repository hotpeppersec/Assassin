# -*- coding: utf-8 -*-

import os
import logging
import logging.handlers
from pathlib import Path


def get_logger():

  '''
  Configure logger properties
  '''
  __LOG_PATH = '/var/log/secops'
  __LOG_FILE = '%s/assassin.log' % (__LOG_PATH,)
  __LOG_FORMAT = '[%(asctime)s] [%(filename)s:%(lineno)s - %(funcName)5s() - %(processName)s] %(levelname)s - %(message)s'

  '''
  Configure logger
  '''
  Path(__LOG_PATH).mkdir(parents=True, exist_ok=True)

  # Set up a specific logger with our desired output level
  logger = logging.getLogger('Assassin')
  logger.setLevel(logging.DEBUG)
  # Add the log message handler to the logger
  handler = logging.FileHandler(__LOG_FILE)
  handler.setLevel(logging.DEBUG)
  formatter = logging.Formatter(__LOG_FORMAT)
  handler.setFormatter(formatter)
  logger.addHandler(handler)
  logger.info('Completed configuring logger()!')
  return logger


__author__ = 'Franklin Diaz'
__copyright__ = ''
__credits__ = ['']
__license__ = 'http://www.apache.org/licenses/LICENSE-2.0'
__version__ = ''
__maintainer__ = ''
__email__ = 'fdiaz@paloaltonetworks.com'