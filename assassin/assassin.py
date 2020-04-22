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
  from lib.key_mgmt import *
  from lib.reporting import *
  from lib.shodan import *
  from lib.summary import *
except ImportError:
  DEBUG = False
try:
  from assassin.lib.helper_functions import *
  from assassin.lib.key_mgmt import *
  from assassin.lib.reporting import *
  from assassin.lib.shodan import *
  from assassin.lib.summary import *
except ImportError:
  DEBUG = True


class my_domain:

    def __init__(self, name):
        self.name = name
        self.report = {}
        self.reportfile = "%s-detail.html" % (self.name.split(".")[0], )
        self.summary = {}
        self.sumfile = "%s-summary.html" % (self.name.split(".")[0], )
        self.hosts = getDnsht(self.name)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--domain", help="Specify a target domain")
    args = parser.parse_args()
    if args.domain:
        dom_name = args.domain
    else:
        dom_name = input("What domain would you like to search ? ")
    dom = my_domain(dom_name)
    print("Target domain specified: %s" % dom.name)
    logging.debug("Target domain specified: %s" % dom.name)
    report = open(dom.reportfile, "w")
    report_header(report, dom.name)
    domaindata = getDomainInfo(dom.name)

    if domaindata:
      domain_xfer(report, domaindata)
      domain_expiration(report, domaindata)
    if not dom.hosts:
      print("No DNS entries discovered for target domain %s" % dom.name)
      logging.debug('No DNS entries discovered for target domain %s' % (dom.name))
      report.close()
      sys.exit()
    else:
      dom.summary['hosts'] = len(dom.hosts)
      for host in dom.hosts:
        if 'API count exceeded - Increase Quota with Membership' in host:
          print ('Hacker Target said too many recent API calls, quitting')
          logging.debug('Hacker Target said no, too many recent API calls')
          sys.exit(1)
        print("Processing host: %s" % (host))
        logging.debug('Processing host: %s' % (host))
        report.write('<div class="host">%s</div>\n' % (host, ))
        logging.debug('Calling check_non_prod for host: %s' % (host, ))
        check_non_prod(report, host, dom.summary)
        # hostname/domain/URL tags will go here in the future
        ips = getFwdDns(host)
        if ips:
          if not 'ips' in dom.summary:
            dom.summary['ips'] = 0
          dom.summary['ips'] += 1
          for ip in ips:
            ip = convert_ip(ip)
            report.write('<div class="ip">IP: %s</div>\n' % (ip, ))
            logging.debug('Calling report_ip: %s' % (ip))
            report_ip(report, dom.name, ip, dom.summary)
            logging.debug('Calling report_whois: %s' % (ip))
            report_whois(report,ip)
            shodanKey = shodan_key()
            if shodanKey != False:
              logging.debug('Calling getShodan: %s' % (ip))
              ''' Call Shodan service to get results for an IP address '''
              shodan = getShodan(ip, shodanKey)
              if shodan:
                logging.debug('Calling report_shodan: %s %s' % (dom.name,ip))
                report_shodan(report, dom, ip, host, shodan)
            else:
              logging.debug('No usable shodanKey, skipping Shodan analysis')
    close_report(report)
    # Generate the Summary
    GoogleMapsKey = google_maps_key()
    sum = open(dom.sumfile, "w")
    logging.debug('Calling generate_summary')
    generate_summary(sum, dom.summary, GoogleMapsKey)


if __name__ == "__main__":
    main()


__author__ = ''
__copyright__ = ''
__credits__ = ['']
__license__ = 'http://www.apache.org/licenses/LICENSE-2.0'
__version__ = ''
__maintainer__ = ''
__email__ = 'fdiaz@paloaltonetworks.com'
