# -*- coding: utf-8 -*-

import logging
from pathlib import Path

'''
add to modules: 

s = Logger()
logger = s.myLogger()
'''

class Logger:
  logger = None

  __LOG_PATH = '/var/log/secops'
  __LOG_FILE = '%s/assassin.log' % (__LOG_PATH,)
  __LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'


  def myLogger(self):
    if None == self.logger:
      '''
      Configure logger
      '''
      Path(Logger.__LOG_PATH).mkdir(parents=True, exist_ok=True)
        # create logger
      self.logger = logging.getLogger('assassinLogger')
      self.logger.setLevel(logging.DEBUG)
      # create file handler which logs even debug messages
      fh = logging.FileHandler(Logger.__LOG_FILE)
      fh.setLevel(logging.DEBUG)
      # create console handler with a higher log level
      #ch = logging.StreamHandler()
      #ch.setLevel(logging.ERROR)
      # create formatter and add it to the handlers
      formatter = logging.Formatter(Logger.__LOG_FORMAT)
      fh.setFormatter(formatter)
      #ch.setFormatter(formatter)
      # add the handlers to the logger
      self.logger.addHandler(fh)
      #logger.addHandler(ch)
    return self.logger


__author__ = 'Franklin Diaz'
__copyright__ = ''
__credits__ = ['']
__license__ = 'http://www.apache.org/licenses/LICENSE-2.0'
__version__ = ''
__maintainer__ = ''
__email__ = 'fdiaz@paloaltonetworks.com'