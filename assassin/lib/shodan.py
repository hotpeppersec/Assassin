# -*- coding: utf-8 -*-

import logging
from pathlib import Path
import json


try:
  from lib.key_mgmt import *
except ImportError:
  DEBUG = False
try:
  from assassin.lib.key_mgmt import *
except ImportError:
  DEBUG = True

class Shodan:

    shodanKey = shodan_key()

# move this to a better place
detects = {}
try:
    detectjson = open("lib/serviceDetections.json", "r")
    detectdata = json.load(detectjson)
    detects = detectdata['service detections']
    print("Signatures loaded")
    logging.debug('Signatures loaded')
except:
    print("Signature file is either missing or corrupt.")
    logging.debug('Signature file is either missing or corrupt')


def report_shodan(report, dom, ip, host, shodan):
    '''
    '''
    logging.debug('shodan')
    
    if 'latitude' in shodan and 'longitude' in shodan:
        if not 'mapdata' in dom.summary:
            dom.summary['mapdata'] = []
        if {"latitude": shodan['latitude'], "longitude": shodan['longitude']} not in dom.summary['mapdata']:
            dom.summary['mapdata'].append(
                {"latitude": shodan['latitude'], "longitude": shodan['longitude']})

    if 'data' in shodan:
        for service in shodan['data']:
            if not 'services' in dom.summary:
                logging.debug('Reset service summary counter')
                dom.summary['services'] = 0
            dom.summary['services'] += 1
            logging.debug('Increment service summary counter')

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
                        if not 'cloudservices' in dom.summary:
                            dom.summary['cloudservices'] = 0
                        dom.summary['cloudservices'] += 1
                    if tag == "starttls":
                        servicetags.append({"severity": "warn", "name": "starttls", "type": "hardening",
                                            "description": "This service is potentially vulnerable to a startTLS attack.", "recommendations": [], "matches": []})
                        if not 'starttlsservices' in dom.summary:
                            dom.summary['starttlsservices'] = 0
                        dom.summary['starttlsservices'] += 1

            if 'data' in service:
                report.write('<div class="data"><pre>\n')
                logging.debug('Writing service data: %s' % service['data'])
                report.write(service['data'].strip().replace("<", "&lt").replace(">", "&gt"))
                report.write('\n</pre></div>\n')

                # DETECT SERVICES
                for line in service['data'].split('\n'):
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
                    if not 'servicemail' in dom.summary:
                        dom.summary['servicemail'] = 0
                    dom.summary['servicemail'] += 1

                # HTTP
                if "HTTP" in service['data'].split('\n')[0]:
                    linezero = service['data'].split('\n')[0]
                    if len(linezero.split(' ')) > 1:
                        httpstatus = service['data'].split('\n')[0].split(' ')[1]
                        if len(httpstatus) == 3:
                            if httpstatus[0] == "3":
                                if 'httpredirect' in dom.summary:
                                    dom.summary['httpredirect'] += 1
                                else:
                                    dom.summary['httpredirect'] = 1
                                for line in service['data'].split("\n"):
                                    if line.find("Location: ", 0, 10) != -1:
                                        if ip in line:
                                            report.write(
                                                '<span class="datawarning">Redirect to same IP</span>')
                                            if not 'redirectsameip' in dom.summary:
                                                dom.summary['redirectsameip'] = 0
                                            dom.summary['redirectsameip'] += 1
                                        elif host in line:
                                            report.write(
                                                '<span class="datainfo">Redirect to same host</span>')
                                            if not 'redirectsamehost' in dom.summary:
                                                dom.summary['redirectsamehost'] = 0
                                            dom.summary['redirectsamehost'] += 1
                                        else:
                                            if dom.name not in line.split('?')[0]:
                                                pivottarget = line.split('?')[0].split(' ')[1].lstrip(
                                                    'https://').lstrip('http://').rstrip().rstrip('/').split('/')[0].replace('www.', '')
                                                report.write(
                                                    '<span class="dataerror">Pivot Target: %s</span>' % pivottarget)
                                                if not 'redirectdifferentdomain' in dom.summary:
                                                    dom.summary['redirectdifferentdomain'] = 0
                                                dom.summary['redirectdifferentdomain'] += 1
                                                if not 'redirectpivottargets' in dom.summary:
                                                    dom.summary['redirectpivottargets'] = [
                                                    ]
                                                if pivottarget not in dom.summary['redirectpivottargets']:
                                                    dom.summary['redirectpivottargets'].append(
                                                        pivottarget)
                                            else:
                                                report.write(
                                                    '<span class="datawarning">Redirect to different IP/host in the domain</span>')
                                                if not 'redirectdifferentiphost' in dom.summary:
                                                    dom.summary['redirectdifferentiphost'] = 0
                                                dom.summary['redirectdifferentiphost'] += 1

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
                if not tag['type'] in dom.summary:
                    dom.summary[tag['type']] = 0
                dom.summary[tag['type']] += 1
                report.write('</div>\n')

# HTML

            if 'http' in service:
                if 'html' in service['http']:
                    if service['http']['html'] is not None:
                        htmllines = service['http']['html'].split("\n")
                        report.write(
                            '<div class="data"><pre>\n')
                        for line in htmllines:
                            if len(line.strip().rstrip("\n")) > 0:
                                try:
                                  #logging.debug("line from htmllines in report_shodan(): %s" % line)
                                  report.write("%s\n" % (line.replace("<", "&lt").replace(">", "&gt"), ))
                                except UnicodeEncodeError as e:
                                    logging.debug("Unicode error from htmllines in report_shodan(): %s" % e)
                                if ("&key=" in line.lower() or "apikey" in line.lower()) and ("googleapis.com" not in line.lower()):
                                    report.write(
                                        '</pre></dev>\n')
                                    report.write(
                                        '<span class="dataerror">Possible API Key Leak</span>')
                                    report.write(
                                        '<div class="data"><pre>\n')
                                    if not 'keyleaks' in dom.summary:
                                        dom.summary['keyleaks'] = 0
                                    dom.summary['keyleaks'] += 1
                                if 'a href="' in line.lower() and ("http://" in line.lower() or "https://" in line.lower()):
                                    # print line
                                    logging.debug("line from report_shodan(): %s" % line)

                                    linkhost = line.lower().replace(">", "").replace("<", "").split('a href="')[
                                        1].split('"')[0].replace("http://", "").replace("https://", "").split("/")[0]

                                    if dom.name in linkhost:
                                        if linkhost not in dom.hosts:
                                            print("Discovered additional host from HTML link: %s" % (linkhost, ))
                                            logging.debug("Discovered additional host from HTML link: %s" % (linkhost, ))
                                            dom.hosts.append(linkhost)
                                    else:
                                        if not 'linkpivottargets' in dom.summary:
                                            dom.summary['linkpivottargets'] = [
                                            ]
                                        if linkhost not in dom.summary['linkpivottargets']:
                                            dom.summary['linkpivottargets'].append(
                                                linkhost)
                                            print(
                                                "New potential pivot from link: %s" % (linkhost, ))
                                            logging.debug("New potential pivot from link: %s" % (linkhost, ))

# HTML FORMS

                                if "&ltform " in line.lower():
                                    #report.write("%s\n" % (line.encode('ascii', 'ignore').replace("<", "&lt").replace(">", "&gt"), ))
                                    report.write(
                                        '</pre></dev>\n')
                                    report.write(
                                        '<span class="datainfo">HTML Form</span>')
                                    report.write(
                                        '<div class="data"><pre>\n')
                                    if not 'htmlforms' in dom.summary:
                                        dom.summary['htmlforms'] = 0
                                    dom.summary['htmlforms'] += 1

                        report.write('</pre></div>\n')

# ROBOTS

                if 'robots' in service['http']:
                    robots = service['http']['robots']
                    if robots is not None:
                        if len(robots.strip()) > 0:
                            report.write(
                                '<div class="ssl">Robots</div>\n')
                            report.write('<div class="ssldata">\n')
                            for robotline in robots.split('\n'):
                                report.write('%s<br>\n' % robotline.strip())
                            report.write('</div>\n')

# SSL

            if 'ssl' in service:
                #report.write('%s<br>\n' % (service['ssl'], ))
                if 'cert' in service['ssl']:
                    # SSL SUBJECT
                    if 'subject' in service['ssl']['cert']:
                        report.write(
                            '<div class="ssl">SSL Subject</div>\n')
                        report.write(
                            '<div class="ssldata">\n')
                        subject = service['ssl']['cert']['subject']
                        if 'OU' in subject:
                            report.write('OU: %s<br>\n' % subject['OU'])
                        if 'emailAddress' in subject:
                            report.write('Email: %s<br>\n' % (
                                subject['emailAddress']))
                        if 'O' in subject:
                            report.write('O: %s<br>\n' % (
                                subject['O']))
                        if 'CN' in subject:
                            report.write('CN: %s<br>\n' % (
                                subject['CN']))
                            report.write('</div>\n')
                            if dom.name not in subject['CN'].lower():
                                if not 'sslnotdomain' in dom.summary:
                                    dom.summary['sslnotdomain'] = 0
                                dom.summary['sslnotdomain'] += 1
                                pivottarget = subject['CN'].lower().lstrip(
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
                                        if not 'sslpivottargets' in dom.summary:
                                            dom.summary['sslpivottargets'] = [
                                            ]
                                        if pivottarget not in dom.summary['sslpivottargets']:
                                            dom.summary['sslpivottargets'].append(
                                                pivottarget)

# SSL WILDCARD

                            if service['ssl']['cert']['subject']['CN'][0] == "*":
                                report.write(
                                    '<span class="sslwarning">Wildcard</span>')
                                if not 'sslwildcard' in dom.summary:
                                    logging.debug('Reset sslwildcard counter')
                                    dom.summary['sslwildcard'] = 0
                                dom.summary['sslwildcard'] += 1

# SSL SELF-SIGNED

                    if 'issuer' in service['ssl']['cert'] and 'subject' in service['ssl']['cert']:
                        subject = service['ssl']['cert']['subject']
                        issuer = service['ssl']['cert']['issuer']
                        if subject and issuer:
                            if subject == issuer:
                                report.write(
                                    '<span class="sslerror">Self-Signed</span>')
                                if not 'selfsignedservices' in dom.summary:
                                    logging.debug('Reset selfsignedservices counter')
                                    dom.summary['selfsignedservices'] = 0
                                dom.summary['selfsignedservices'] += 1

# SSL ISSUER

                    if 'issuer' in service['ssl']['cert']:
                        report.write(
                            '<div class="ssl">SSL Issuer</div>\n')
                        report.write(
                            '<div class="ssldata">\n')
                        issuer = service['ssl']['cert']['issuer']
                        if 'OU' in issuer:
                            report.write('OU: %s<br>\n' % (
                                issuer['OU']))
                        if 'emailAddress' in issuer:
                            report.write('Email: %s<br>\n' % (
                                issuer['emailAddress']))
                        if 'O' in issuer:
                            report.write('O: %s<br>\n' % (
                                issuer['O']))
                        if 'CN' in issuer:
                            report.write('CN: %s<br>\n' % (
                                issuer['CN']))
                        report.write('</div>\n')

# SSL CERT EXPIRATION

                    if 'expires' in service['ssl']['cert']:
                        expires = service['ssl']['cert']['expires']
                        certyear = expires[0:4]
                        certmonth = expires[4:6]
                        certday = expires[6:8]
                        report.write(
                            '<div class="ssl">SSL Certificate Expiration: %s/%s/%s</div>' % (certmonth, certday, certyear))

                    if 'expired' in service['ssl']['cert']:
                        if service['ssl']['cert']['expired']:
                            report.write(
                                '<span class="sslerror">Expired</span>')
                            if not 'sslexpired' in dom.summary:
                                logging.debug('Reset sslexpired counter')
                                dom.summary['sslexpired'] = 0
                            dom.summary['sslexpired'] += 1

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
                            if not 'sslerrorversion' in dom.summary:
                                logging.debug('Reset sslerrorversion counter')
                                dom.summary['sslerrorversion'] = 0
                            else:
                                logging.debug('Increment sslerrorversion counter')
                                dom.summary['sslerrorversion'] += 1
                        elif version.strip() in warnversions:
                            report.write('</div>\n')
                            report.write(
                                '<span class="sslwarning">%s</span>\n' % (version, ))
                            report.write(
                                '<div class="ssldata">\n')
                            if not 'sslwarnversion' in dom.summary:
                                dom.summary['sslwarnversion'] = 0
                            dom.summary['sslwarnversion'] += 1
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
                            if not 'sslbadcipher' in dom.summary:
                                dom.summary['sslbadcipher'] = 0
                            dom.summary['sslbadcipher'] += 1

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
                    if not 'vulntotal' in dom.summary:
                        dom.summary['vulntotal'] = 0
                    dom.summary['vulntotal'] += 1
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
                            if not 'vulnlow' in dom.summary:
                                dom.summary['vulnlow'] = 0
                            dom.summary['vulnlow'] += 1
                        elif 4 <= float(cvss) < 7:
                            report.write(
                                ' bgcolor="orange"')
                            if not 'vulnmedium' in dom.summary:
                                dom.summary['vulnmedium'] = 0
                            dom.summary['vulnmedium'] += 1
                        elif 7 <= float(cvss) < 9:
                            report.write(
                                ' bgcolor="red"')
                            if not 'vulnhigh' in dom.summary:
                                dom.summary['vulnhigh'] = 0
                            dom.summary['vulnhigh'] += 1
                        elif 9 <= float(cvss):
                            report.write(
                                ' bgcolor="purple"')
                            if not 'vulncritical' in dom.summary:
                                dom.summary['vulncritical'] = 0
                            dom.summary['vulncritical'] += 1
                        report.write(
                            '>%s</td>' % (cvss, ))
                        report.write(
                            '<td class="vulnerability">%s</td>' % (vulns[vuln]['summary'], ))
                        report.write("</tr>\n")
                report.write("</table>")