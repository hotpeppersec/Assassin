# -*- coding: utf-8 -*-

"""
Find the latest version here: https://github.com/wwce/Assassin
"""
import logging
from pathlib import Path
import json

import sys
import os
import ssl
if (not os.environ.get('PYTHONHTTPSVERIFY', '') and
        getattr(ssl, '_create_unverified_context', None)):
    ssl._create_default_https_context = ssl._create_unverified_context

'''
apiKeys.py is a custom file you need to create & update
Put it in the same directory as assassin.py
'''
try:
  import apiKeys as apiKeys
  from lib.helper_functions import *
  from lib.reporting import *
  from lib.summary import *
except ImportError:
  DEBUG = False
try:
  import assassin.apiKeys as apiKeys
  from assassin.lib.helper_functions import *
  from assassin.lib.reporting import *
  from assassin.lib.summary import *
except ImportError:
  DEBUG = True
if apiKeys.shodanKey:
  shodanKey = apiKeys.shodanKey

'''
Configure logger properties
'''
__LOG_PATH = '/var/log/secops'
__LOG_FILE = '%s/assassin.log' % (__LOG_PATH,)
__LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
'''
Configure logger
'''
Path(__LOG_PATH).mkdir(parents=True, exist_ok=True)
  # create logger
logger = logging.getLogger('assassinLogger')
logger.setLevel(logging.DEBUG)
# create file handler which logs even debug messages
fh = logging.FileHandler(__LOG_FILE)
fh.setLevel(logging.DEBUG)
# create console handler with a higher log level
#ch = logging.StreamHandler()
#ch.setLevel(logging.ERROR)
# create formatter and add it to the handlers
formatter = logging.Formatter(__LOG_FORMAT)
fh.setFormatter(formatter)
#ch.setFormatter(formatter)
# add the handlers to the logger
logger.addHandler(fh)
#logger.addHandler(ch)
logger.info('Logging configured')

summary = {}

def main():
    domain = input("What domain would you like to search (.com/.net)? ")
    reportfile = "%s-detail.html" % (domain.split(".")[0], )
    report = open(reportfile, "w")
    report_header(report, domain)
    domaindata = getDomainInfo(domain)
    if domaindata:
      domain_xfer(report, domaindata)
      domain_expiration(report, domaindata)
    hosts = getDnsht(domain)
    if not hosts:
      print("No DNS entries discovered for target domain %s" % domain)
      logger.debug('No DNS entries discovered for target domain %s' % (domain))
      report.close()
      sys.exit()
    else:
      summary['hosts'] = len(hosts)
      for host in hosts:
        print("Processing host: %s" % (host))
        logger.debug('Processing host: %s' % (host))
        report.write('<div class="host">%s</div>\n' % (host, ))
        logger.debug('Calling check_non_prod for host: %s' % (host, ))
        check_non_prod(report, host, summary)
        # hostname/domain/URL tags will go here in the future
        ips = getFwdDns(host)
        if ips:
          if not 'ips' in summary:
            summary['ips'] = 0
          summary['ips'] += 1
          for ip in ips:
            ip = convert_ip(ip)
            report.write('<div class="ip">IP: %s</div>\n' % (ip, ))
            logger.debug('Calling report_ip: %s' % (ip))
            report_ip(report, domain, ip, summary)
            logger.debug('Calling report_whois: %s' % (ip))
            report_whois(report,ip)
            logger.debug('Calling getShodan: %s' % (ip))
            shodan = getShodan(ip, shodanKey)
            if shodan:
              logger.debug('Calling report_shodan: %s %s' % (domain,ip))
              report_shodan(report, domain, ip, shodan, summary)
    close_report(report)
    # Generate the Summary
    sumfile = "%s-summary.html" % (domain.split(".")[0], )
    sum = open(sumfile, "w")
    logger.debug('Calling generate_summary')
    generate_summary(sum, summary)


if __name__ == "__main__":
    main()


__author__ = ''
__copyright__ = ''
__credits__ = ['']
__license__ = 'http://www.apache.org/licenses/LICENSE-2.0'
__version__ = ''
__maintainer__ = ''
__email__ = 'fdiaz@paloaltonetworks.com'
