# -*- coding: utf-8 -*-

"""
Find the latest version here: https://github.com/wwce/Assassin
"""
import logging
from pathlib import Path
from ipaddress import ip_address
import ipaddress
import json
try:
    # For Python 3.0 and later
    from urllib.request import urlopen
except ImportError:
    # Fall back to Python 2's urllib2
    from urllib2 import urlopen
import sys
# this is a custom file you need to create & update
import assassin.apiKeys as apiKeys

import os
import ssl
if (not os.environ.get('PYTHONHTTPSVERIFY', '') and
        getattr(ssl, '_create_unverified_context', None)):
    ssl._create_default_https_context = ssl._create_unverified_context

if apiKeys.shodanKey:
    shodanKey = apiKeys.shodanKey

summary = {}

try:
    detectjson = open("serviceDetections.json", "r")
    detectdata = json.load(detectjson)
    detects = detectdata['service detections']
    print("Signatures loaded")
except:
    print("Signature file is either missing or corrupt.")


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
ch = logging.StreamHandler()
ch.setLevel(logging.ERROR)
# create formatter and add it to the handlers
formatter = logging.Formatter(__LOG_FORMAT)
fh.setFormatter(formatter)
ch.setFormatter(formatter)
# add the handlers to the logger
logger.addHandler(fh)
logger.addHandler(ch)
logger.info('Logging configured')


def getDomainInfo(domain):
  ext = domain.split('.')
  
  print('Lookup %s.%s via Verisign' % (ext[0], ext[1]))
  logger.info('Lookup %s.%s via Verisign' % (ext[0], ext[1]))

  if ext[1] == "com":
    url = "https://rdap.verisign.com/com/v1/domain/%s" % (domain)
  elif ext[1] == "net":
    url = "https://rdap.verisign.com/net/v1/domain/%s" % (domain)
  else:
    print('See https://www.verisign.com/en_US/domain-names/registration-data-access-protocol/index.xhtml for documentation.')
    sys.exit()
  logger.debug('Checking %s with URL: %s' % (ext[1], url))
  try:
    jsonresponse = urlopen(url)
    response = json.loads(jsonresponse.read())
    logger.debug(response)
    return response
  except Exception as e:
    print(e)
    sys.exit()


def getDnsht(domain):
    print("Hacker Target")
    logger.info('Hacker Target')
    url = "https://api.hackertarget.com/hostsearch/?q=%s" % (domain)
    try:
        response = urlopen(url)
        html_response = response.read()
        encoding = response.headers.get_content_charset('utf-8')
        decoded_html = html_response.decode(encoding, 'ignore')
        logger.debug('Hacker Target response: %s' % decoded_html)
        if decoded_html == "error check your search parameter":
            logger.debug('Hacker Target says bad domain name')
            return False
        else:
            output = []
            lines = decoded_html.split("\n")
            for line in lines:
                fields = line.split(",")
                host = fields[0]
                output.append(host)
            print("Received %s hosts from Hacker Target" % (len(lines), ))
            logger.debug('Received %s hosts from Hacker Target' %
                         (len(lines), ))
            return output
    except Exception as err:
        logger.debug('Handling run-time error: %s', (err))
        return False
    print("Combined to a total of %s hosts" % len(output))
    logger.debug('Combined to a total of %s hosts' % len(output))
    if len(output) > 0:
        return(output)
    else:
        return False


def getFwdDns(host):
    if type(host) != str:
      host = host.decode("utf-8", "strict")
    output = []
    url = 'https://dns.google.com/resolve?name=%s&type=A' % (host, )
    try:
        output = []
        jsonresponse = urlopen(url)
        response = json.loads(jsonresponse.read())
        if 'Answer' in response:
            answers = response["Answer"]
            for answer in answers:
                if "data" in answer:
                    try:
                        output.append(answer["data"].encode("ascii"))
                    except:
                        pass
        return output
    except:
        return False


def getRevDns(ip):
    '''
    '''
    if type(ip) != str:
        ip = ip.decode("utf-8", "strict")
    reverseip = ip_address(ip).reverse_pointer
    logger.debug('Checking reverse IP: %s' % reverseip)
    url = 'https://dns.google.com/resolve?name=%s&type=PTR' % (reverseip, )
    try:
        jsonresponse = urlopen(url)
        response = json.loads(jsonresponse.read())
        if "Answer" in response:
            answers = response["Answer"]
            for answer in answers:
                if "data" in answer:
                    return answer["data"].encode("ascii")
    except:
        return False


def getShodan(ip, shodanKey):
    url = 'https://api.shodan.io/shodan/host/%s?key=%s' % (ip, shodanKey)
    try:
        jsonresponse = urlopen(url)
        response = json.loads(jsonresponse.read())
        return response
    except:
        logger.info('NOTE: Shodan does not work on Palo Alto corp network')
        return False


def checkPrivate(ip):
    '''
    Determine if an IPv4 address is private
    '''
    if type(ip) != str:
      ip = ip.decode("utf-8", "strict")
    logger.info('Check private IP: %s' % ip)
    if (ipaddress.ip_address(ip).is_private):
      return True
    else:
      return False


def checkReserved(ip):
    '''
    Determine if an IPv4 address is reserved
    '''
    if type(ip) != str:
      ip = ip.decode("utf-8", "strict")
    logger.info('Check reserved IP: %s' % ip)
    if (ipaddress.ip_address(ip).is_reserved):
      return True
    else:
      return False



def getWhois(ip):
    '''
    Do a whois lookup on an IP address
    '''
    url = "http://rdap.arin.net/registry/ip/%s" % (ip, )
    try:
        jsonresponse = urlopen(url)
        response = json.loads(jsonresponse.read())
        if "name" in response:
            return response['name']
    except Exception as e:
        print(e)
        return False


def main():
    domain = input("What domain would you like to search? ")

    reportfile = "%s-detail.html" % (domain.split(".")[0], )
    report = open(reportfile, "w")
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
    report.write('<img src="Assassin.png" width="500px"><br>\n')
    report.write('<div class="title">%s</div>\n' % (domain, ))

    '''
    DOMAIN
    '''
    domaindata = getDomainInfo(domain)
    if domaindata:

        '''
        DOMAIN TRANSFER
        '''
        logger.info('domain transfer status')
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

    '''
    DOMAIN EXPIRATION
    '''
    logger.info('Domain expiration')
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
    '''
    HOSTS
    '''
    logger.info('hosts')
    hosts = getDnsht(domain)

    if not hosts:
        print("No DNS entries discovered for target domain %s" % domain)
        logger.debug(
            'No DNS entries discovered for target domain %s' % (domain))
        report.close()
        sys.exit()
    else:
        summary['hosts'] = len(hosts)
        for host in hosts:
            print("Processing host: %s" % (host))
            logger.debug('Processing host: %s' % (host))
            report.write('<div class="host">%s</div>\n' % (host, ))

    # NONPROD

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

            # hostname/domain/URL tags will go here in the future

            ips = getFwdDns(host)
            if ips:
                for ip in ips:
                    if not 'ips' in summary:
                        summary['ips'] = 0
                    summary['ips'] += 1
                    report.write('<div class="ip">IP: %s</div>\n' % (ip, ))
                    if checkPrivate(ip) or checkReserved(ip):
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
                            cleanreverse = reverse.lower().rstrip('.')
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

    # WHOIS

                        whois = getWhois(ip)
                        if whois:
                            report.write(
                                '<div class="ip">WhoIs: %s</div>\n' % (whois, ))

                        # Add more IP checks here...

    # SHODAN

                        shodan = getShodan(ip, shodanKey)
                        if shodan:

                            if 'latitude' in shodan and 'longitude' in shodan:
                                if not 'mapdata' in summary:
                                    summary['mapdata'] = []
                                if {"latitude": shodan['latitude'], "longitude": shodan['longitude']} not in summary['mapdata']:
                                    summary['mapdata'].append(
                                        {"latitude": shodan['latitude'], "longitude": shodan['longitude']})

                            if 'data' in shodan:

                                for service in shodan['data']:
                                    if not 'services' in summary:
                                        summary['services'] = 0
                                    summary['services'] += 1

                                    report.write('<div class="service">\n')
                                    if 'transport' in service and 'port' in service and 'product' in service:
                                        report.write(
                                            "Service: %s/%s - %s\n" % (service['transport'], service['port'], service['product']))
                                    else:
                                        report.write(
                                            "Service: %s/%s\n" % (service['transport'], service['port']))
                                    report.write('</div>\n')

                                    servicetags = []

                                    if 'tags' in service:
                                        for tag in service['tags']:
                                            if tag == "cloud":
                                                servicetags.append({"severity": "info", "name": "cloud", "type": "service",
                                                                    "description": "This service is hosted in a cloud service provider.", "recommendations": [], "matches": []})
                                                if not 'cloudservices' in summary:
                                                    summary['cloudservices'] = 0
                                                summary['cloudservices'] += 1
                                            if tag == "starttls":
                                                servicetags.append({"severity": "warn", "name": "starttls", "type": "hardening",
                                                                    "description": "This service is potentially vulnerable to a startTLS attack.", "recommendations": [], "matches": []})
                                                if not 'starttlsservices' in summary:
                                                    summary['starttlsservices'] = 0
                                                summary['starttlsservices'] += 1

                                    if 'data' in service:
                                        report.write(
                                            '<div class="data"><pre>\n')
                                        report.write(service['data'].encode(
                                            'ascii', 'ignore').strip().replace("<", "&lt").replace(">", "&gt"))
                                        report.write('\n</pre></div>\n')

    # DETECT SERVICES

                                        for line in service['data'].encode('ascii', 'ignore').split('\n'):
                                            for detect in detects:
                                                for signature in detect['signatures']:
                                                    if signature in line:
                                                        for tag in detect['tags']:
                                                            candidate = {"name": tag['name'], "severity": tag['severity'], "type": tag['type'], "description": tag[
                                                                'description'], "recommendations": tag['recommendations'], "matches": [line.strip()]}
                                                            tagfound = False
                                                            for servicetag in servicetags:
                                                                if candidate['name'] == servicetag['name']:
                                                                    servicetag['matches'].append(
                                                                        line.strip())
                                                                    tagfound = True
                                                            if not tagfound:
                                                                servicetags.append(
                                                                    candidate)

    # OBSOLETE DETECTIONS THAT NEED TO BE RE-WRITTEN

    # MAIL

                                        if (
                                            "dovecot" in service['data'].lower() or
                                            "exim" in service['data'].lower() or
                                            "smtp" in service['data'].lower() or
                                            "imap" in service['data'].lower()
                                        ):
                                            report.write(
                                                '<span class="datainfo">Mail</span>')
                                            if not 'servicemail' in summary:
                                                summary['servicemail'] = 0
                                            summary['servicemail'] += 1

    # HTTP

                                        if "HTTP" in service['data'].encode('ascii', 'ignore').split('\n')[0]:
                                            linezero = service['data'].encode(
                                                'ascii', 'ignore').split('\n')[0]
                                            if len(linezero.split(' ')) > 1:
                                                httpstatus = service['data'].encode(
                                                    'ascii', 'ignore').split('\n')[0].split(' ')[1]
                                                if len(httpstatus) == 3:
                                                    if httpstatus[0] == "3":
                                                        if 'httpredirect' in summary:
                                                            summary['httpredirect'] += 1
                                                        else:
                                                            summary['httpredirect'] = 1
                                                        for line in service['data'].split("\n"):
                                                            if line.find("Location: ", 0, 10) != -1:
                                                                if ip in line:
                                                                    report.write(
                                                                        '<span class="datawarning">Redirect to same IP</span>')
                                                                    if not 'redirectsameip' in summary:
                                                                        summary['redirectsameip'] = 0
                                                                    summary['redirectsameip'] += 1
                                                                elif host in line:
                                                                    report.write(
                                                                        '<span class="datainfo">Redirect to same host</span>')
                                                                    if not 'redirectsamehost' in summary:
                                                                        summary['redirectsamehost'] = 0
                                                                    summary['redirectsamehost'] += 1
                                                                else:
                                                                    if domain not in line.split('?')[0]:
                                                                        pivottarget = line.split('?')[0].split(' ')[1].lstrip(
                                                                            'https://').lstrip('http://').rstrip().rstrip('/').split('/')[0].replace('www.', '')
                                                                        report.write(
                                                                            '<span class="dataerror">Pivot Target: %s</span>' % pivottarget)
                                                                        if not 'redirectdifferentdomain' in summary:
                                                                            summary['redirectdifferentdomain'] = 0
                                                                        summary['redirectdifferentdomain'] += 1
                                                                        if not 'redirectpivottargets' in summary:
                                                                            summary['redirectpivottargets'] = [
                                                                            ]
                                                                        if pivottarget not in summary['redirectpivottargets']:
                                                                            summary['redirectpivottargets'].append(
                                                                                pivottarget)
                                                                    else:
                                                                        report.write(
                                                                            '<span class="datawarning">Redirect to different IP/host in the domain</span>')
                                                                        if not 'redirectdifferentiphost' in summary:
                                                                            summary['redirectdifferentiphost'] = 0
                                                                        summary['redirectdifferentiphost'] += 1

    # DISPLAY HEADER TAGS

                                    for tag in servicetags:
                                        if tag['severity'] == "info":
                                            report.write(
                                                '<span class="datainfo">%s</span>\n' % (tag['name'], ))
                                        if tag['severity'] == "warn":
                                            report.write(
                                                '<span class="datawarning">%s</span>\n' % (tag['name'], ))
                                        if tag['severity'] == "error":
                                            report.write(
                                                '<span class="dataerror">%s</span>\n' % (tag['name'], ))
                                        if tag['severity'] == "critical":
                                            report.write(
                                                '<span class="datacritical">%s</span>\n' % (tag['name'], ))
                                        report.write('<div class="tagdata">\n')
                                        for match in tag['matches']:
                                            report.write('Match: %s<br>\n' % (
                                                match.replace('<', '&lt').replace('>', '&gt')))
                                        report.write('Description: %s<br>\n' %
                                                     (tag['description'], ))
                                        for recommendation in tag['recommendations']:
                                            report.write(
                                                'Recommendation: %s<br>\n' % (recommendation, ))
                                        if not tag['type'] in summary:
                                            summary[tag['type']] = 0
                                        summary[tag['type']] += 1
                                        report.write('</div>\n')

    # HTML

                                    if 'http' in service:
                                        if 'html' in service['http']:
                                            if service['http']['html'] is not None:
                                                htmllines = service['http']['html'].encode(
                                                    'ascii', 'ignore').strip().split("\n")
                                                report.write(
                                                    '<div class="data"><pre>\n')
                                                for line in htmllines:
                                                    if len(line.strip().rstrip("\n")) > 0:
                                                        report.write("%s\n" % (line.encode('ascii', 'ignore').replace(
                                                            "<", "&lt").replace(">", "&gt"), ))
                                                        if ("&key=" in line.lower() or "apikey" in line.lower()) and ("googleapis.com" not in line.lower()):
                                                            report.write(
                                                                '</pre></dev>\n')
                                                            report.write(
                                                                '<span class="dataerror">Possible API Key Leak</span>')
                                                            report.write(
                                                                '<div class="data"><pre>\n')
                                                            if not 'keyleaks' in summary:
                                                                summary['keyleaks'] = 0
                                                            summary['keyleaks'] += 1
                                                        if 'a href="' in line.lower() and ("http://" in line.lower() or "https://" in line.lower()):
                                                            # print line

                                                            linkhost = line.lower().replace(">", "").replace("<", "").split('a href="')[
                                                                1].split('"')[0].replace("http://", "").replace("https://", "").split("/")[0]

                                                            if domain in linkhost:
                                                                if linkhost not in hosts:
                                                                    print(
                                                                        "Discovered additional host from HTML link: %s" % (linkhost, ))
                                                                    hosts.append(
                                                                        linkhost)
                                                            else:
                                                                if not 'linkpivottargets' in summary:
                                                                    summary['linkpivottargets'] = [
                                                                    ]
                                                                if linkhost not in summary['linkpivottargets']:
                                                                    summary['linkpivottargets'].append(
                                                                        linkhost)
                                                                    print(
                                                                        "New potential pivot from link: %s" % (linkhost, ))

    # HTML FORMS

                                                        if "&ltform " in line.lower():
                                                            #report.write("%s\n" % (line.encode('ascii', 'ignore').replace("<", "&lt").replace(">", "&gt"), ))
                                                            report.write(
                                                                '</pre></dev>\n')
                                                            report.write(
                                                                '<span class="datainfo">HTML Form</span>')
                                                            report.write(
                                                                '<div class="data"><pre>\n')
                                                            if not 'htmlforms' in summary:
                                                                summary['htmlforms'] = 0
                                                            summary['htmlforms'] += 1

                                                report.write('</pre></div>\n')

    # ROBOTS

                                        if 'robots' in service['http']:
                                            robots = service['http']['robots']
                                            if robots is not None:
                                                if len(robots.encode('ascii', 'ignore').strip()) > 0:
                                                    report.write(
                                                        '<div class="ssl">Robots</div>\n')
                                                    report.write(
                                                        '<div class="ssldata">\n')
                                                    for robotline in robots.split('\n'):
                                                        report.write('%s<br>\n' % (
                                                            robotline.strip().encode('ascii', 'ignore'), ))
                                                    report.write('</div>\n')

    # SSL

                                    if 'ssl' in service:
                                        #                  report.write('%s<br>\n' % (service['ssl'], ))
                                        if 'cert' in service['ssl']:

                                            # SSL SUBJECT

                                            if 'subject' in service['ssl']['cert']:
                                                report.write(
                                                    '<div class="ssl">SSL Subject</div>\n')
                                                report.write(
                                                    '<div class="ssldata">\n')
                                                subject = service['ssl']['cert']['subject']
                                                if 'OU' in subject:
                                                    report.write('OU: %s<br>\n' % (
                                                        subject['OU'].encode('ascii', 'ignore'), ))
                                                if 'emailAddress' in subject:
                                                    report.write('Email: %s<br>\n' % (
                                                        subject['emailAddress'].encode('ascii', 'ignore'), ))
                                                if 'O' in subject:
                                                    report.write('O: %s<br>\n' % (
                                                        subject['O'].encode('ascii', 'ignore'), ))
                                                if 'CN' in subject:
                                                    report.write('CN: %s<br>\n' % (
                                                        subject['CN'].encode('ascii', 'ignore'), ))
                                                    report.write('</div>\n')
                                                    if domain not in subject['CN'].lower():
                                                        if not 'sslnotdomain' in summary:
                                                            summary['sslnotdomain'] = 0
                                                        summary['sslnotdomain'] += 1
                                                        pivottarget = subject['CN'].encode('ascii', 'ignore').lower().lstrip(
                                                            '*.').rstrip('/').replace('www.', '')
                                                        if ip == pivottarget:
                                                            report.write(
                                                                '<span class="sslwarning">Pivot Target: %s</span>' % pivottarget)
                                                        else:
                                                            if (
                                                                "cloudflaressl.com" not in pivottarget and
                                                                "cloudfront.net" not in pivottarget
                                                            ):
                                                                report.write(
                                                                    '<span class="sslerror">Pivot Target: %s</span>' % pivottarget)
                                                                if not 'sslpivottargets' in summary:
                                                                    summary['sslpivottargets'] = [
                                                                    ]
                                                                if pivottarget not in summary['sslpivottargets']:
                                                                    summary['sslpivottargets'].append(
                                                                        pivottarget)

    # SSL WILDCARD

                                                    if service['ssl']['cert']['subject']['CN'][0] == "*":
                                                        report.write(
                                                            '<span class="sslwarning">Wildcard</span>')
                                                        if not 'sslwildcard' in summary:
                                                            summary['sslwildcard'] = 0
                                                        summary['sslwildcard'] += 1

    # SSL SELF-SIGNED

                                            if 'issuer' in service['ssl']['cert'] and 'subject' in service['ssl']['cert']:
                                                subject = service['ssl']['cert']['subject']
                                                issuer = service['ssl']['cert']['issuer']
                                                if subject and issuer:
                                                    if subject == issuer:
                                                        report.write(
                                                            '<span class="sslerror">Self-Signed</span>')
                                                        if not 'selfsignedservices' in summary:
                                                            summary['selfsignedservices'] = 0
                                                        summary['selfsignedservices'] += 1

    # SSL ISSUER

                                            if 'issuer' in service['ssl']['cert']:
                                                report.write(
                                                    '<div class="ssl">SSL Issuer</div>\n')
                                                report.write(
                                                    '<div class="ssldata">\n')
                                                issuer = service['ssl']['cert']['issuer']
                                                if 'OU' in issuer:
                                                    report.write('OU: %s<br>\n' % (
                                                        issuer['OU'].encode('ascii', 'ignore'), ))
                                                if 'emailAddress' in issuer:
                                                    report.write('Email: %s<br>\n' % (
                                                        issuer['emailAddress'].encode('ascii', 'ignore'), ))
                                                if 'O' in issuer:
                                                    report.write('O: %s<br>\n' % (
                                                        issuer['O'].encode('ascii', 'ignore'), ))
                                                if 'CN' in issuer:
                                                    report.write('CN: %s<br>\n' % (
                                                        issuer['CN'].encode('ascii', 'ignore'), ))
                                                report.write('</div>\n')

    # SSL CERT EXPIRATION

                                            if 'expires' in service['ssl']['cert']:
                                                expires = service['ssl']['cert']['expires'].encode(
                                                    'ascii', 'ignore')
                                                certyear = expires[0:4]
                                                certmonth = expires[4:6]
                                                certday = expires[6:8]
                                                report.write(
                                                    '<div class="ssl">SSL Certificate Expiration: %s/%s/%s</div>' % (certmonth, certday, certyear))

                                            if 'expired' in service['ssl']['cert']:
                                                if service['ssl']['cert']['expired']:
                                                    report.write(
                                                        '<span class="sslerror">Expired</span>')
                                                    if 'sslexpired' in summary:
                                                        summary['sslexpired'] = 0
                                                    summary['sslexpired'] += 1

    # SSL VERSIONS

                                        if 'versions' in service['ssl']:
                                            report.write(
                                                '<div class="ssl">SSL Versions</div>\n')
                                            report.write(
                                                '<div class="ssldata">\n')
                                            errorversions = [
                                                'TLSv1', 'SSLv2', 'SSLv3', '-TLSv1.2']
                                            warnversions = ['TLSv1.1']
                                            for version in service['ssl']['versions']:
                                                if version.strip() in errorversions:
                                                    report.write('</div>\n')
                                                    report.write(
                                                        '<span class="sslerror">%s</span>\n' % (version, ))
                                                    report.write(
                                                        '<div class="ssldata">\n')
                                                    if 'sslerrorversion' in summary:
                                                        summary['sslerrorversion'] = 0
                                                    summary['sslerrorversion'] += 1
                                                elif version.strip() in warnversions:
                                                    report.write('</div>\n')
                                                    report.write(
                                                        '<span class="sslwarning">%s</span>\n' % (version, ))
                                                    report.write(
                                                        '<div class="ssldata">\n')
                                                    if not 'sslwarnversion' in summary:
                                                        summary['sslwarnversion'] = 0
                                                    summary['sslwarnversion'] += 1
                                                else:
                                                    report.write(
                                                        '%s<br>\n' % (version, ))
                                            report.write('</div>\n')

    # SSL CIPHERS

                                        if 'cipher' in service['ssl']:
                                            goodciphers = []
                                            goodciphers.append(
                                                'ECDHE-ECDSA-AES256-GCM-SHA384')
                                            goodciphers.append(
                                                'ECDHE-RSA-AES256-GCM-SHA384')
                                            goodciphers.append(
                                                'ECDHE-ECDSA-CHACHA20-POLY1305')
                                            goodciphers.append(
                                                'ECDHE-RSA-CHACHA20-POLY1305')
                                            goodciphers.append(
                                                'ECDHE-ECDSA-AES128-GCM-SHA256')
                                            goodciphers.append(
                                                'ECDHE-RSA-AES128-GCM-SHA256')
                                            goodciphers.append(
                                                'ECDHE-ECDSA-AES256-SHA384')
                                            goodciphers.append(
                                                'ECDHE-RSA-AES256-SHA384')
                                            goodciphers.append(
                                                'ECDHE-ECDSA-AES128-SHA256')
                                            goodciphers.append(
                                                'ECDHE-RSA-AES128-SHA256')

                                            if 'name' in service['ssl']['cipher']:
                                                cipher = service['ssl']['cipher']['name']
                                                report.write(
                                                    '<div class="ssl">SSL Cipher</div>\n')
                                                report.write(
                                                    '<div class="ssldata">\n')
                                                report.write(
                                                    'Cipher Suite: %s<br>\n' % (cipher, ))
                                                cipherparts = cipher.split('-')
                                                if len(cipherparts) == 5:
                                                    report.write(
                                                        'Key Exchange: %s<br>\n' % (cipherparts[0], ))
                                                    report.write(
                                                        'Authentication: %s<br>\n' % (cipherparts[1], ))
                                                    report.write(
                                                        'Block/Stream Ciphers: %s-%s<br>\n' % (cipherparts[2], cipherparts[3]))
                                                    report.write(
                                                        'Message Authentication: %s<br>\n' % (cipherparts[4], ))
                                                elif len(cipherparts) == 4:
                                                    report.write(
                                                        'Key Exchange: %s<br>\n' % (cipherparts[0], ))
                                                    report.write(
                                                        'Authentication: %s<br>\n' % (cipherparts[1], ))
                                                    report.write(
                                                        'Block/Stream Ciphers: %s<br>\n' % (cipherparts[2], ))
                                                    report.write(
                                                        'Message Authentication: %s<br>\n' % (cipherparts[3], ))
                                                report.write('</div>\n')
                                                if cipher not in goodciphers:
                                                    report.write(
                                                        '<span class="sslwarning">Less Secure Cipher</span>')
                                                    if not 'sslbadcipher' in summary:
                                                        summary['sslbadcipher'] = 0
                                                    summary['sslbadcipher'] += 1

    # VULN

                                    if 'vulns' in service:
                                        report.write(
                                            '<table class="vulnerability">\n')
                                        report.write("<tr>")
                                        report.write(
                                            '<td class="vulnerability" align="center" width="150px">CVE</td>')
                                        report.write(
                                            '<td class="vulnerability" align="center" width="150px">CVSS</td>')
                                        report.write(
                                            '<td class="vulnerability" align="center">Summary</td>')
                                        report.write("</tr>\n")
                                        vulns = service['vulns']
                                        for vuln in vulns:
                                            if not 'vulntotal' in summary:
                                                summary['vulntotal'] = 0
                                            summary['vulntotal'] += 1
                                            if 'cvss' in vulns[vuln] and 'summary' in vulns[vuln]:
                                                report.write(
                                                    '<tr class="vulnerability">')
                                                report.write(
                                                    '<td class="vulnerability" align="center">%s</td>' % (vuln, ))
                                                report.write(
                                                    '<td class="vulnerability" align="center"')
                                                cvss = vulns[vuln]['cvss']
                                                if 0.1 <= float(cvss) < 4:
                                                    report.write(
                                                        ' bgcolor="yellow"')
                                                    if not 'vulnlow' in summary:
                                                        summary['vulnlow'] = 0
                                                    summary['vulnlow'] += 1
                                                elif 4 <= float(cvss) < 7:
                                                    report.write(
                                                        ' bgcolor="orange"')
                                                    if not 'vulnmedium' in summary:
                                                        summary['vulnmedium'] = 0
                                                    summary['vulnmedium'] += 1
                                                elif 7 <= float(cvss) < 9:
                                                    report.write(
                                                        ' bgcolor="red"')
                                                    if not 'vulnhigh' in summary:
                                                        summary['vulnhigh'] = 0
                                                    summary['vulnhigh'] += 1
                                                elif 9 <= float(cvss):
                                                    report.write(
                                                        ' bgcolor="purple"')
                                                    if not 'vulncritical' in summary:
                                                        summary['vulncritical'] = 0
                                                    summary['vulncritical'] += 1
                                                report.write(
                                                    '>%s</td>' % (cvss, ))
                                                report.write(
                                                    '<td class="vulnerability">%s</td>' % (vulns[vuln]['summary'], ))
                                                report.write("</tr>\n")
                                        report.write("</table>")

    report.write('</body>\n')
    report.write('</html>\n')
    report.close()

    # for key in summary:
    #  print("%s: %s" % (key, summary[key]))

    sumfile = "%s-summary.html" % (domain.split(".")[0], )
    sum = open(sumfile, "w")
    sum.write("<html>")
    sum.write("Hosts: %s<br>\n" % (summary['hosts'], ))
    if 'nonprod' in summary:
        sum.write("Non-Production Hosts: %s<br>\n" %
                  (str(summary['nonprod']), ))
    if 'cloudaws' in summary:
        sum.write("AWS Hosts: %s<br>\n" % (str(summary['cloudaws']), ))
        if 'cloudawsregions' in summary:
            sum.write("AWS Regions:<br>\n")
            for region in summary['cloudawsregions']:
                sum.write("%s<br>\n" % region)
    if 'cloudgcp' in summary:
        sum.write("GCP Hosts: %s<br>\n" % (str(summary['cloudgcp']), ))

    sum.write("<br>IPs<br>\n")
    if 'ips' in summary:
        sum.write("Total: %s<br>\n" % (summary['ips'], ))
    if 'privateips' in summary:
        sum.write("Private: %s<br>\n" % (summary['privateips'], ))
    if 'reservedips' in summary:
        sum.write("Reserved: %s<br>\n" % (summary['reservedips'], ))

    sum.write("<br>Services<br>\n")
    if 'sevices' in summary:
        sum.write("Total: %s<br>\n" % (summary['services'], ))
    if 'cloudservices' in summary:
        sum.write("Cloud: %s<br>\n" % (summary['cloudservices'], ))

    sum.write("<br>HTTP Hardening<br>\n")
    if 'waf' in summary:
        sum.write("Web services protected by a WAF: %s<br>\n" %
                  (summary['waf'], ))
    if 'http1' in summary:
        sum.write("Web services that respond to HTTP/1.0 requests: %s<br>\n" %
                  (summary['http1'], ))
    if 'serviceversions' in summary:
        sum.write("Web services that identify their version: %s<br>\n" %
                  (summary['serviceversions'], ))
    if 'servicephp' in summary:
        sum.write("Web Services Utilizing PHP: %s<br>\n" %
                  (summary['servicephp'], ))
    if 'serviceasp' in summary:
        sum.write("Web Services Utilizing ASP: %s<br>\n" %
                  (summary['serviceasp'], ))
    if 'http200' in summary:
        sum.write("Web services that need to be hardened with an App-ID: %s<br>\n" %
                  (summary['http200'], ))
    if 'htmlforms' in summary:
        sum.write("HTML Forms Detected: %s<br>\n" % (summary['htmlforms'], ))
    if 'keyleaks' in summary:
        sum.write("Possible API Key Leaks Detected: %s<br>\n" %
                  (summary['keyleaks'], ))
    if 'http3xx' in summary:
        sum.write("Redirects Total: %s<br>\n" % (summary['http3xx'], ))
    if 'redirectsamehost' in summary:
        sum.write("Proper redirects to the same DNS host: %s<br>\n" %
                  (summary['redirectsamehost'], ))
    if 'redirectsameip' in summary:
        sum.write("Redirects to the same IP (should point to DNS name instead): %s<br>\n" % (
            summary['redirectsameip'], ))
    if 'redirectdifferentiphost' in summary:
        sum.write("Redirects to the same domain (need lifecycle management): %s<br>\n" % (
            summary['redirectdifferentiphost'], ))
    if 'redirectdifferentdomain' in summary:
        sum.write("Redirects to different domains (pivot targets): %s<br>\n" %
                  (summary['redirectdifferentdomain'], ))
    if 'http5xx' in summary:
        sum.write("Application/Server Errors: %s<br>\n" %
                  (summary['http5xx'], ))
    if 'serviceeol' in summary:
        sum.write("End-of-life Services: %s<br>\n" % (summary['serviceeol'], ))
    if 'serviceeos' in summary:
        sum.write("End-of-support Services: %s<br>\n" %
                  (summary['serviceeos'], ))

    sum.write("<br>SSL<br>\n")
    if 'sslwildcard' in summary:
        sum.write("Wildcard Certificates: %s<br>\n" %
                  (summary['sslwildcard'], ))
    if 'starttlsservices' in summary:
        sum.write("Vulnerable TLS Mail Services: %s<br>\n" %
                  (summary['starttlsservices'], ))
    if 'selfsignedservices' in summary:
        sum.write("Self-Signed Certificates: %s<br>\n" %
                  (summary['selfsignedservices'], ))
    if 'sslerrorversion' in summary:
        sum.write("Insecure SSL Versions: %s<br>\n" %
                  (summary['sslerrorversion'], ))
    if 'sslwarnversion' in summary:
        sum.write("Non-compliant SSL Versions: %s<br>\n" %
                  (summary['sslwarnversion'], ))
    if 'sslwarnversion' in summary:
        sum.write("Weak SSL Ciphers: %s<br>\n" % (summary['sslwarnversion'], ))
    if 'sslexpired' in summary:
        sum.write("Expired Certificates: %s<br>\n" % (summary['sslexpired'], ))
    if 'sslnotdomain' in summary:
        sum.write("Potential pivot targets identified by SSL certificate: %s<br>\n" % (
            summary['sslnotdomain'], ))

    sum.write("<br>Vulnerabilities<br>\n")
    if 'vulntotal' in summary:
        sum.write("Total: %s<br>\n" % (summary['vulntotal'], ))
    if 'vulnlow' in summary:
        sum.write("Low: %s<br>\n" % (summary['vulnlow'], ))
    if 'vulnmedium' in summary:
        sum.write("Medium: %s<br>\n" % (summary['vulnmedium'], ))
    if 'vulnhigh' in summary:
        sum.write("High: %s<br>\n" % (summary['vulnhigh'], ))
    if 'vulncritical' in summary:
        sum.write("Critical: %s<br>\n" % (summary['vulncritical'], ))

    if 'reversednspivottargets' in summary:
        sum.write("<br>Reverse DNS Pivot Targets<br>\n")
        for target in summary['reversednspivottargets']:
            sum.write("%s<br>\n" % (target, ))
    if 'redirectpivottargets' in summary:
        sum.write("<br>Redirect Pivot Targets<br>\n")
        for target in summary['redirectpivottargets']:
            sum.write("%s<br>\n" % (target, ))
    if 'sslpivottargets' in summary:
        sum.write("<br>SSL Pivot Targets<br>\n")
        for target in summary['sslpivottargets']:
            sum.write("%s<br>\n" % (target, ))
    sum.write("</body></html>")
    sum.close()


if __name__ == "__main__":
    main()

__author__ = ''
__copyright__ = ''
__credits__ = ['{credit_list}']
__license__ = '{license}'
__version__ = ''
__maintainer__ = ''
__email__ = ''
