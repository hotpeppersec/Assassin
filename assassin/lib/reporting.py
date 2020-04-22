# -*- coding: utf-8 -*-

import logging
from pathlib import Path

try:
  from lib.helper_functions import *
except ImportError:
  DEBUG = False
try:
  from assassin.lib.helper_functions import *
except ImportError:
  DEBUG = True


def report_header(report, domain):
    logging.debug('Create report header for domain: %s' % domain)
    report.write('<html>\n')
    report.write('<head>\n')
    report.write('<title>Assassin Report for %s</title>\n' % (domain, ))
    # writing out some style guidelines
    report.write('<style>\n')
    style = open("style.css", "r")
    for line in style:
        report.write(line)
    style.close()
    report.write('</style>\n')
    report.write('</head>\n')
    report.write('<body>\n')
    report.write('<img src="../docs/images/Assassin.png" width="500px"><br>\n')
    report.write('<div class="title">%s</div>\n' % (domain, ))


def domain_xfer(report, domaindata):
    '''
    DOMAIN TRANSFER
    '''
    logging.debug('domain transfer status')
    clientDelete = True
    clientTransfer = True
    clientUpdate = True
    if 'status' in domaindata:
        statuses = domaindata['status']
        if len(statuses) > 0:
            if "client delete prohibited" in statuses:
                clientDelete = False
            if "client transfer prohibited" in statuses:
                clientTransfer = False
            if "client update prohibited" in statuses:
                clientUpdate = False
            report.write(
                '<table class="domain" cellpadding="2" cellspacing="0" border="0">\n')
            report.write(
                '<tr class="domain"><td class="domain">Client Delete:</td>')
            report.write('<td class="domain" align="center">')
            if clientDelete:
                report.write('<font color="red">Enabled</font>')
            else:
                report.write('<font color="green">Disabled</font>')
            report.write('</td>')
            report.write('</tr>\n')
            report.write(
                '<tr class="domain"><td class="domain">Client Transfer:</td>')
            report.write('<td class="domain" align="center">')
            if clientTransfer:
                report.write('<font color="red">Enabled</font>')
            else:
                report.write('<font color="green">Disabled</font>')
            report.write('</td>')
            report.write('</tr>\n')
            report.write(
                '<tr class="domain"><td class="domain">Client Update:</td>')
            report.write('<td class="domain" align="center">')
            if clientUpdate:
                report.write('<font color="red">Enabled</font>')
            else:
                report.write('<font color="green">Disabled</font>')
            report.write('</td>')
            report.write('</tr>\n')


def domain_expiration(report, domaindata):
    '''
    DOMAIN EXPIRATION
    '''
    logging.debug('Domain expiration')
    if 'events' in domaindata:
        for event in domaindata['events']:
            if 'eventAction' in event and 'eventDate' in event:
                if event['eventAction'] == "expiration":
                    report.write('<tr class="domain">')
                    report.write('<td class="domain">Expiration:</td>')
                    datedata = event['eventDate'].split('T')[0]
                    eventyear = datedata.split('-')[0]
                    eventmonth = datedata.split('-')[1]
                    eventday = datedata.split('-')[2]
                    report.write('<td class="domain">%s/%s/%s</td>' %
                                 (eventmonth, eventday, eventyear))
                    report.write('</tr>\n')
    report.write('</table>\n')


def check_non_prod(report, host, summary):
    '''
    NONPROD HOSTS
    '''
    logging.debug('Check for non prod string in hostname: %s' % host.lower())
    if (
        "demo" in host.lower() or
        "qa" in host.lower() or
        "test" in host.lower() or
        ("dev" in host.lower() and "device" not in host.lower() and "developers" not in host.lower()) or
        "beta" in host.lower() or
        "preprod" in host.lower() or
        "uat" in host.lower() or
        "staging" in host.lower() or
        "poc" in host.lower() or
        "nonprod" in host.lower() or
        ("stage" in host.lower() or "staging" in host.lower())
    ):
        report.write(
            '<span class="hostwarn">Possible non-production system</span>')
        if not 'nonprod' in summary:
            summary['nonprod'] = 0
        summary['nonprod'] += 1


def report_ip(report, domain, ip, summary):
    '''
    '''    
    ip = convert_ip(ip)
    logging.debug('Create report for IP: %s' % ip)
    if checkPrivate(ip):
        if not 'privateips' in summary:
            summary['privateips'] = 0
        summary['privateips'] += 1
        report.write(
            '<span class="iperror">Private</span>')
    if checkReserved(ip):
        if not 'reservedips' in summary:
            summary['reservedips'] = 0
        summary['reserverips'] += 1
        report.write(
            '<span class="iperror">Reserved</span>')
    else:
        # REVERSE DNS
        reverse = getRevDns(ip)
        if reverse:
            cleanreverse = str(reverse).lower().rstrip('.')
            logging.debug('Adding reverse %s to report' % cleanreverse)
            report.write(
                '<div class="ip">Reverse DNS: %s</div>\n' % (cleanreverse, ))
            if '.amazonaws.com' in cleanreverse:
                if not 'cloudaws' in summary:
                    summary['cloudaws'] = 0
                summary['cloudaws'] += 1
                report.write('<span class="ipinfo">AWS</span>')
                if len(cleanreverse.replace('.amazonaws.com', '').split('.')) > 1:
                    awsregion = cleanreverse.split('.')[1]
                else:
                    awsregion = cleanreverse.split('.')[0]
                if awsregion == 'compute-1':
                    awsregion = 'us-east-1'
                if not 'cloudawsregions' in summary:
                    summary['cloudawsregions'] = []
                if awsregion not in summary['cloudawsregions']:
                    summary['cloudawsregions'].append(
                        awsregion)
                report.write(
                    '<span class="ipinfo">AWS Region: %s</span>' % awsregion)
            if 'bc.googleusercontent.com' in cleanreverse:
                report.write('<span class="ipinfo">GCP</span>')
                if not 'cloudgcp' in summary:
                    summary['cloudgcp'] = 0
                summary['cloudgcp'] += 1
            if '.cloudfront.net' in cleanreverse:
                report.write('<span class="ipinfo">AWS</span>')
            if (
                domain not in cleanreverse and
                '.in-addr.arpa' not in cleanreverse and
                '.amazonaws.com' not in cleanreverse and
                '.akamaitechnologies.com' not in cleanreverse and
                '.cloudfront.net' not in cleanreverse and
                '.bc.googleusercontent.com' not in cleanreverse
            ):
                if not 'reversednspivottargets' in summary:
                    summary['reversednspivottargets'] = []
                if cleanreverse not in summary['reversednspivottargets']:
                    summary['reversednspivottargets'].append(
                        cleanreverse)


def report_whois(report,ip):
    '''
    '''
    ip = convert_ip(ip)
    logging.debug('Add whois to report for IP: %s' % ip)
    whois = getWhois(ip)
    if whois:
        report.write('<div class="ip">WhoIs: %s</div>\n' % (whois, ))


def close_report(report):
    '''
    '''
    logging.debug('Closing out the report file')
    report.write('</body>\n')
    report.write('</html>\n')
    report.close()

__author__ = 'Franklin Diaz'
__copyright__ = ''
__credits__ = ['']
__license__ = 'http://www.apache.org/licenses/LICENSE-2.0'
__version__ = ''
__maintainer__ = ''
__email__ = 'fdiaz@paloaltonetworks.com'
