# -*- coding: utf-8 -*-

"""
Find the latest version here: https://github.com/wwce/Assassin
"""
import json
import logging
from pathlib import Path
import sys, argparse
import os
import ssl
if (not os.environ.get('PYTHONHTTPSVERIFY', '') and
        getattr(ssl, '_create_unverified_context', None)):
    ssl._create_default_https_context = ssl._create_unverified_context

try:
  from lib.helper_functions import *
  from lib.reporting import *
  from lib.summary import *
  from lib.key_mgmt import *
except ImportError:
  DEBUG = False
try:
  from assassin.lib.helper_functions import *
  from assassin.lib.reporting import *
  from assassin.lib.summary import *
  from assassin.lib.key_mgmt import *
except ImportError:
  DEBUG = True

summary = {}


def main():
    ''' Figure out which domain to test '''
    domain=''
    parser = argparse.ArgumentParser()
    parser.add_argument("--domain", help="Specify a target domain")
    args = parser.parse_args()
    if args.domain:
        domain = args.domain
    else:
        domain = input("What domain would you like to search? ")
    print("Target domain specified: %s" % domain)
    logging.debug("Target domain specified: %s" % domain)

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
      logging.debug('No DNS entries discovered for target domain %s' % (domain))
      report.close()
      sys.exit()
    else:
      summary['hosts'] = len(hosts)
      for host in hosts:
        if 'API count exceeded - Increase Quota with Membership' in host:
          print ('Hacker Target said too many recent API calls, quitting')
          logging.debug('Hacker Target said no, too many recent API calls')
          sys.exit(1)
        print("Processing host: %s" % (host))
        logging.debug('Processing host: %s' % (host))
        report.write('<div class="host">%s</div>\n' % (host, ))
        logging.debug('Calling check_non_prod for host: %s' % (host, ))
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
            logging.debug('Calling report_ip: %s' % (ip))
            report_ip(report, domain, ip, summary)
            logging.debug('Calling report_whois: %s' % (ip))
            report_whois(report,ip)
            shodanKey = shodan_key()
            if shodanKey != False:
              logging.debug('Calling getShodan: %s' % (ip))
              ''' Call Shodan service to get results for an IP address '''
              shodan = getShodan(ip, shodanKey)
              if shodan:
                logging.debug('Calling report_shodan: %s %s' % (domain,ip))
                report_shodan(report, domain, ip, host, hosts, shodan, summary)
            else:
              logging.debug('No usable shodanKey, skipping Shodan analysis')
    close_report(report)
    # Generate the Summary
    GoogleMapsKey = google_maps_key()
    sumfile = "%s-summary.html" % (domain.split(".")[0], )
    sum = open(sumfile, "w")
    logging.debug('Calling generate_summary')
    generate_summary(sum, summary, GoogleMapsKey)


if __name__ == "__main__":
    main()


__author__ = ''
__copyright__ = ''
__credits__ = ['']
__license__ = 'http://www.apache.org/licenses/LICENSE-2.0'
__version__ = ''
__maintainer__ = ''
__email__ = 'fdiaz@paloaltonetworks.com'
