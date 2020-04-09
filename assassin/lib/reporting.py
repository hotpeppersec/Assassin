# -*- coding: utf-8 -*-

try:
  from lib.helper_functions import *
except ImportError:
  DEBUG = False
try:
  from assassin.lib.helper_functions import *
except ImportError:
  DEBUG = True

import logging

# attach logger
logger = logging.getLogger('assassinLogger')

# move this to a better place
detects = {}
try:
    detectjson = open("serviceDetections.json", "r")
    detectdata = json.load(detectjson)
    detects = detectdata['service detections']
    print("Signatures loaded")
    logger.debug('Signatures loaded')
except:
    print("Signature file is either missing or corrupt.")
    logger.debug('Signature file is either missing or corrupt')


def report_header(report, domain):
    logger.debug('Create report header for domain: %s' % domain)
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


def domain_xfer(report, domaindata):
    '''
    DOMAIN TRANSFER
    '''
    logger.debug('domain transfer status')
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
    logger.debug('Domain expiration')
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
    logger.debug('Check for non prod string in hostname: %s' % host.lower())
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
    logger.debug('Create report for IP: %s' % ip)
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
            cleanreverse = str(reverse).lower().rstrip('.')
            logger.debug('Adding reverse %s to report' % cleanreverse)
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
    logger.debug('Add whois to report for IP: %s' % ip)
    whois = getWhois(ip)
    if whois:
        report.write('<div class="ip">WhoIs: %s</div>\n' % (whois, ))


def report_shodan(report, domain, ip, shodan, summary):
    '''
    '''
    logger.debug('shodan')
    
    if 'latitude' in shodan and 'longitude' in shodan:
        if not 'mapdata' in summary:
            summary['mapdata'] = []
        if {"latitude": shodan['latitude'], "longitude": shodan['longitude']} not in summary['mapdata']:
            summary['mapdata'].append(
                {"latitude": shodan['latitude'], "longitude": shodan['longitude']})

    if 'data' in shodan:
        for service in shodan['data']:
            if not 'services' in summary:
                logger.debug('Reset service summary counter')
                summary['services'] = 0
            summary['services'] += 1
            logger.debug('Increment service summary counter')

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
                report.write('<div class="data"><pre>\n')
                logger.debug('Writing service data: %s' % service['data'])
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
                    if not 'servicemail' in summary:
                        summary['servicemail'] = 0
                    summary['servicemail'] += 1

                # HTTP
                if "HTTP" in service['data'].split('\n')[0]:
                    linezero = service['data'].split('\n')[0]
                    if len(linezero.split(' ')) > 1:
                        httpstatus = service['data'].split('\n')[0].split(' ')[1]
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
                        htmllines = service['http']['html'].split("\n")
                        report.write(
                            '<div class="data"><pre>\n')
                        for line in htmllines:
                            if len(line.strip().rstrip("\n")) > 0:
                                report.write("%s\n" % (line.replace("<", "&lt").replace(">", "&gt"), ))
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
                            if domain not in subject['CN'].lower():
                                if not 'sslnotdomain' in summary:
                                    summary['sslnotdomain'] = 0
                                summary['sslnotdomain'] += 1
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
                            if not 'sslerrorversion' in summary:
                                logger.debug('Reset sslerrorversion counter')
                                summary['sslerrorversion'] = 0
                            else:
                                logger.debug('Increment sslerrorversion counter')
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

def close_report(report):
    '''
    '''
    logger.debug('Closing out the report file')
    report.write('</body>\n')
    report.write('</html>\n')
    report.close()