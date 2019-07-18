#!/usr/bin/env python

import ipaddress
import urllib2
import json

summary = { 
  "hosts": 0,
  "nonprod": 0,
  "ips": 0,
  "privateips": 0,
  "reservedips": 0,
  "services": 0,
  "cloudservices": 0,
  "cloudaws": 0,
  "cloudawsregions": [],
  "cloudgcp": 0,
  "starttlsservices": 0,
  "selfsignedservices": 0,
  "servicessh": 0,
  "servicentp": 0,
  "serviceftp": 0,
  "servicemail": 0,
  "servicejenkins": 0,
  "servicephp": 0,
  "serviceasp": 0,
  "serviceversions": 0,
  "serviceeol": 0,
  "serviceeos": 0,
  "http1": 0,
  "http200": 0,
  "http3xx": 0,
  "htmlforms": 0,
  "redirectsameip": 0,
  "redirectsamehost": 0,
  "redirectdifferentiphost": 0,
  "redirectdifferentdomain": 0,
  "http5xx": 0,
  "sslexpired": 0,
  "sslwildcard": 0,
  "sslnotdomain": 0,
  "sslerrorversion": 0,
  "sslwarnversion": 0,
  "sslbadcipher": 0,
  "vulntotal": 0,
  "vulnlow": 0,
  "vulnmedium": 0,
  "vulnhigh": 0,
  "vulncritical": 0,
  "keyleaks": 0,
  "waf": 0,
  "mapdata": [],
  "reversednspivottargets": [],
  "redirectpivottargets": [],
  "sslpivottargets": [],
}

def getDomainInfo(domain):
  url = "https://rdap-pilot.verisignlabs.com/rdap/v1/domain/%s" % (domain, )
  try:
    jsonresponse = urllib2.urlopen(url)
    response=json.loads(jsonresponse.read())
    return response
  except Exception as e:
    print e
    return False

def getDnsht(domain):
  url = "https://api.hackertarget.com/hostsearch/?q=%s" % (domain, )
  try:
    response = urllib2.urlopen(url)
    data = response.read().strip()
    if data == "error check your search parameter":
      return False
    else:
      output = []
      lines = data.split("\n")
      for line in lines:
        fields = line.split(",")
        host = fields[0]
        output.append(host)
      print "Received %s hosts from Hacker Target" % (len(lines), )
      return output
  except:
    return False

def getDnsdb(domain):
  dnsdbkey = "dce-cc9d0395d2c77b3bc8fe487a5e9c65059667137b74d7e588585fac7321e9"
  urlbase = "https://api.dnsdb.info/lookup/rrset/name/"
  headers = { "X-API-Key": dnsdbkey }
  data = ""
  url = "%s*.%s/A" % (urlbase, domain)
  request = urllib2.Request(url, data, headers)
  try:
    output = []
    response = urllib2.urlopen(request)
    for result in response.read().split("\n"):
      if (result.strip() != "" and result[0] != ";"):
        fields = result.split(" ")
        if (fields[2] == "A"):
          output.append(fields[0].rstrip('.'))
    if output == []:
      return False
    else:
      print "Received %s hosts from DNSDB" % (len(output), )
      return output
  except:
    return False

def getVtdomain(domain):
  vtkey='7b047d96daebcbe4fc683016b07c4b82580603bbfab4a7a2fc055f1b6d5a0318'
  url='https://www.virustotal.com/vtapi/v2/domain/report?domain=%s&apikey=%s' % (domain, vtkey)
  try:
    jsonresponse = urllib2.urlopen(url)
    response = json.loads(jsonresponse.read())
#    print response
    print "Received %s hosts from VirusTotal" % (len(response['subdomains']), )
    print "Verdict: %s" % (response['Webutation domain info']['Verdict'], )
    print "Adult Content: %s" % (response['Webutation domain info']['Adult content'], )
    print "Safety Score: %s" % (response['Webutation domain info']['Safety score'], )
    return response['subdomains']
  except:
    return False

def dnsCombine(dnsht, dnsdb, dnsvt):
  print "Combining and de-duplicating hosts"
  output = []
  if dnsht:
    for entry in dnsht:
      if entry not in output:
        output.append(entry)
  if dnsdb:
    for entry in dnsdb:
      if entry not in output:
        output.append(entry)
  if dnsvt:
    for entry in dnsvt:
      if entry not in output:
        output.append(entry)

  print "Combined to a total of %s hosts" % len(output)

  if len(output) > 0:
    return(output)
  else:
    return False

def getFwdDns(host):
  output = []
  url='https://dns.google.com/resolve?name=%s&type=A' % (host, )
  try:
    output = []
    jsonresponse = urllib2.urlopen(url)
    response = json.loads(jsonresponse.read())
    if response.has_key("Answer"):
      answers = response["Answer"]
      for answer in answers:
        if answer.has_key("data"):
          try:
            address = ipaddress.ip_address(answer["data"])
            output.append(answer["data"].encode("ascii"))
          except:
            pass
    return output
  except:
    return False

def getRevDns(ip):
  reverseip = "%s.%s.%s.%s.in-addr.arpa." % (ip.split(".")[3], ip.split(".")[2], ip.split(".")[1], ip.split(".")[0])
  url='https://dns.google.com/resolve?name=%s&type=PTR' % (reverseip, )
  try:
    jsonresponse = urllib2.urlopen(url)
    response = json.loads(jsonresponse.read())
    if response.has_key("Answer"):
      answers = response["Answer"]
      for answer in answers:
        if answer.has_key("data"):
          return answer["data"].encode("ascii")
  except:
    return False

def getShodan(ip):
  shodankey='C9tNjcBpKWoDmuqbbZ9lzeXKrv58iug8'
  url='https://api.shodan.io/shodan/host/%s?key=%s' % (ip, shodankey)
  try:
    jsonresponse = urllib2.urlopen(url)
    response = json.loads(jsonresponse.read())
    return response  
  except:
    return False

def checkPrivate(ip):
  unicodeip = unicode(str(ip), "utf-8")
  if (ipaddress.ip_address(unicodeip)):
    if (ipaddress.ip_address(unicodeip).is_private):
      return True
    else:
      return False
  else:
    return False

def checkReserved(ip):
  unicodeip = unicode(str(ip), "utf-8")
  if (ipaddress.ip_address(unicodeip)):
    if (ipaddress.ip_address(unicodeip).is_reserved):
      return True
    else:
      return False
  else:
    return False

def getWhois(ip):
  url = "http://rdap.arin.net/registry/ip/%s" % (ip, )
  try:
    jsonresponse = urllib2.urlopen(url)
    response=json.loads(jsonresponse.read())
    if response.has_key("name"):
      return response['name']
#    return response
  except Exception as e:
    print e
    return False

domain = raw_input("What domain would you like to search? ")

reportfile = "%s-detail.html" % (domain.split(".")[0], )
report = open(reportfile, "w")
report.write('<html>\n')
report.write('<head>\n')
report.write('<title>Assassin Report for %s</title>\n' % (domain, ))
#writing out some style guidelines
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

#DOMAIN

domaindata = getDomainInfo(domain)
if domaindata:

#DOMAIN TRANSFER

  clientDelete = True
  clientTransfer = True
  clientUpdate = True
  if domaindata.has_key('status'):
    statuses = domaindata['status']
    if len(statuses) > 0:
      if "client delete prohibited" in statuses:
        clientDelete = False
      if "client transfer prohibited" in statuses:
        clientTransfer = False
      if "client update prohibited" in statuses:
        clientUpdate = False

  report.write('<table class="domain" cellpadding="2" cellspacing="0" border="0">\n')

  report.write('<tr class="domain"><td class="domain">Client Delete:</td>')
  report.write('<td class="domain" align="center">')
  if clientDelete:
    report.write('<font color="red">Enabled</font>')
  else:
    report.write('<font color="green">Disabled</font>')
  report.write('</td>')
  report.write('</tr>\n')

  report.write('<tr class="domain"><td class="domain">Client Transfer:</td>')
  report.write('<td class="domain" align="center">')
  if clientTransfer:
    report.write('<font color="red">Enabled</font>')
  else:
    report.write('<font color="green">Disabled</font>')
  report.write('</td>')
  report.write('</tr>\n')

  report.write('<tr class="domain"><td class="domain">Client Update:</td>')
  report.write('<td class="domain" align="center">')
  if clientUpdate:
    report.write('<font color="red">Enabled</font>')
  else:
    report.write('<font color="green">Disabled</font>')
  report.write('</td>')
  report.write('</tr>\n')

#DOMAIN EXPIRATION

  if domaindata.has_key('events'):
    if len(domaindata['events']) > 0:
      for event in domaindata['events']:
        if event.has_key('eventAction') and event.has_key('eventDate'):
          report.write('<tr class="domain">')
          if event['eventAction'] == "registration":
            report.write('<td class="domain">Registration:</td>')
          elif event['eventAction'] == "last changed":
            report.write('<td class="domain">Last Changed:</td>')
          elif event['eventAction'] == "expiration":
            report.write('<td class="domain">Expiration:</td>')
          datedata = event['eventDate'].split('T')[0]
          eventyear = datedata.split('-')[0]
          eventmonth = datedata.split('-')[1]
          eventday = datedata.split('-')[2]
          report.write('<td class="domain">%s/%s/%s</td>' % (eventmonth, eventday, eventyear))
          report.write('</tr>\n')
  report.write('</table>\n')

#HOSTS

dnsht = getDnsht(domain)
dnsdb = getDnsdb(domain)
dnsvt = getVtdomain(domain)
hosts = dnsCombine(dnsht, dnsdb, dnsvt)

if not hosts:
  print "No DNS entries discovered for target domain"
  report.close()
else:
  summary['hosts'] = len(hosts)
  for host in hosts:
    print "Processing host: %s" % (host)
    report.write('<div class="host">%s</div>\n' % (host, ))

#NONPROD

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
      report.write('<span class="hostwarn">Possible non-production system</span>')
      summary['nonprod'] += 1

    #hostname/domain/URL tags will go here in the future

    ips = getFwdDns(host)
    if ips:
      for ip in ips:
        summary['ips'] += 1
        report.write('<div class="ip">IP: %s</div>\n' % (ip, ))
        if checkPrivate(ip) or checkReserved(ip):
          if checkPrivate(ip):
            summary['privateips'] += 1
            report.write('<span class="iperror">Private</span>')
          if checkReserved(ip):
            summary['reservedips'] += 1
            report.write('<span class="iperror">Reserved</span>')
        else:

#REVERSE DNS

          reverse = getRevDns(ip)
          if reverse:
            cleanreverse = reverse.lower().rstrip('.')
            report.write('<div class="ip">Reverse DNS: %s</div>\n' % (cleanreverse, ))
            if '.amazonaws.com' in cleanreverse:
              summary['cloudaws'] += 1
              report.write('<span class="ipinfo">AWS</span>')
              if len(cleanreverse.replace('.amazonaws.com', '').split('.')) > 1:
                awsregion = cleanreverse.split('.')[1]
              else:
                awsregion = cleanreverse.split('.')[0]
              if awsregion == 'compute-1':
                awsregion = 'us-east-1'
              if awsregion not in summary['cloudawsregions']:
                summary['cloudawsregions'].append(awsregion)
              report.write('<span class="ipinfo">AWS Region: %s</span>' % awsregion)
            if 'bc.googleusercontent.com' in cleanreverse:
              report.write('<span class="ipinfo">GCP</span>')
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
              if cleanreverse not in summary['reversednspivottargets']:
                summary['reversednspivottargets'].append(cleanreverse)

#WHOIS

          whois = getWhois(ip)
          if whois:
            report.write('<div class="ip">WhoIs: %s</div>\n' % (whois, ))

          #Add more IP checks here...

#SHODAN

          shodan = getShodan(ip)
          if shodan:

            if shodan.has_key('latitude') and shodan.has_key('longitude'):
              if {"latitude": shodan['latitude'], "longitude": shodan['longitude'] } not in summary['mapdata']:
                summary['mapdata'].append({"latitude": shodan['latitude'], "longitude": shodan['longitude'] })
              

            if shodan.has_key('data'):

              for service in shodan['data']:
                summary['services'] += 1

                report.write('<div class="service">\n')
                if service.has_key('transport') and service.has_key('port') and service.has_key('product'):
                  report.write("Service: %s/%s - %s\n" % (service['transport'], service['port'], service['product']))
                else:
                  report.write("Service: %s/%s\n" % (service['transport'], service['port']))
                report.write('</div>\n')

#LOAD SERVICE SIGNATURES

                detectjson = open("serviceDetections.json", "r")
                detectdata=json.load(detectjson)
                detects = detectdata['service detections']

                servicetags = []

                if service.has_key('tags'):
                  for tag in service['tags']:
                    if tag == "cloud":
                      servicetags.append({"severity": "info", "name": "cloud", "type": "service", "description": "This service is hosted in a cloud service provider.", "recommendations": [], "matches": []})
                      summary['cloudservices'] += 1
                    if tag == "starttls":
                      summary['starttlsservices'] += 1
                      servicetags.append({"severity": "warn", "name": "starttls", "type": "hardening", "description": "This service is potentially vulnerable to a startTLS attack.", "recommendations": [], "matches": []})

                if service.has_key('data'):
                  report.write('<div class="data"><pre>\n')
                  report.write(service['data'].encode('ascii', 'ignore').strip().replace("<", "&lt").replace(">", "&gt"))
                  report.write('\n</pre></div>\n')


#DETECT SERVICES

                  for line in service['data'].encode('ascii', 'ignore').split('\n'):
                    for detect in detects:
                      for signature in detect['signatures']:
                        if signature in line:
                          for tag in detect['tags']:
                            candidate = {"name": tag['name'], "severity": tag['severity'], "type": tag['type'], "description": tag['description'], "recommendations": tag['recommendations'], "matches": [line.strip()]}
                            tagfound = False
                            for servicetag in servicetags:
                              if candidate['name'] == servicetag['name']:
                                servicetag['matches'].append(line.strip())
                                tagfound = True
                            if not tagfound:
                              servicetags.append(candidate)

#OBSOLETE DETECTIONS THAT NEED TO BE RE-WRITTEN

#MAIL

                  if (
                    "dovecot" in service['data'].lower() or
                    "exim" in service['data'].lower() or
                    "smtp" in service['data'].lower() or
                    "imap" in service['data'].lower()
                    ):
                    report.write('<span class="datainfo">Mail</span>')
                    summary['servicemail'] += 1

#HTTP

                  if "HTTP" in service['data'].encode('ascii', 'ignore').split('\n')[0]:
                    httpstatus = service['data'].encode('ascii', 'ignore').split('\n')[0].split(' ')[1]
                    if httpstatus[0] == "3":
                      summary['http3xx'] += 1
                      for line in service['data'].split("\n"):
                        if line.find("Location: ", 0, 10) <> -1:
                          if ip in line:
                            report.write('<span class="datawarning">Redirect to same IP</span>')
                            summary['redirectsameip'] += 1
                          elif host in line:
                            report.write('<span class="datainfo">Redirect to same host</span>')
                            summary['redirectsamehost'] += 1
                          else:
                            if domain not in line.split('?')[0]:
                              pivottarget = line.split('?')[0].split(' ')[1].lstrip('https://').lstrip('http://').rstrip().rstrip('/').split('/')[0].replace('www.', '')
                              report.write('<span class="dataerror">Pivot Target: %s</span>' % pivottarget)
                              summary['redirectdifferentdomain'] += 1
                              if pivottarget not in summary['redirectpivottargets']:
                                summary['redirectpivottargets'].append(pivottarget)
                            else:
                              report.write('<span class="datawarning">Redirect to different IP/host in the domain</span>')
                              summary['redirectdifferentiphost'] += 1
#DISPLAY HEADER TAGS

                for tag in servicetags:
                  if tag['severity'] == "info":
                    report.write('<span class="datainfo">%s</span>\n' % (tag['name'], ))
                  if tag['severity'] == "warn":
                    report.write('<span class="datawarning">%s</span>\n' % (tag['name'], ))
                  if tag['severity'] == "error":
                    report.write('<span class="dataerror">%s</span>\n' % (tag['name'], ))
                  if tag['severity'] == "critical":
                    report.write('<span class="datacritical">%s</span>\n' % (tag['name'], ))
                  report.write('<div class="tagdata">\n')
                  for match in tag['matches']:
                    report.write('Match: %s<br>\n' % (match, ))
                  report.write('Description: %s<br>\n' % (tag['description'], ))
                  for recommendation in tag['recommendations']:
                    report.write('Recommendation: %s<br>\n' % (recommendation, ))
                  report.write('</div>\n')

#HTML

                if service.has_key('http'):
                  if service['http'].has_key('html'):
                    if service['http']['html'] is not None:
                      htmllines = service['http']['html'].encode('ascii', 'ignore').strip().replace("<", "&lt").replace(">", "&gt").split("\n")
                      report.write('<div class="data"><pre>\n')
                      for line in htmllines:
                        if len(line.strip().rstrip("\n")) > 0:
                          report.write("%s\n" % (line.encode('ascii', 'ignore').replace("<", "&lt").replace(">", "&gt"), ))
                          if ("&key=" in line.lower() or "\"apikey\":" in line.lower()) and ("googleapis.com" not in line.lower()):
                            report.write('</pre></dev>\n')
                            report.write('<span class="dataerror">Possible Key Leak (High Confidence)</span>')
                            report.write('<div class="data"><pre>\n')
                            summary['keyleaks'] += 1
                          elif ((("api" in line.lower() and "key=" in line.lower()) or ("authorization=" in line.lower())) and ("googleapis.com" not in line.lower())):
                            report.write('</pre></dev>\n')
                            report.write('<span class="datawarning">Possible Key Leak (Low Confidence)</span>')
                            report.write('<div class="data"><pre>\n')
                            summary['keyleaks'] += 1

#HTML FORMS

                          if "&ltform " in line.lower():
                            report.write('</pre></dev>\n')
                            report.write('<span class="datainfo">HTML Form</span>')
                            report.write('<div class="data"><pre>\n')
                            summary['htmlforms'] += 1

                      report.write('</pre></div>\n')

#ROBOTS

                  if service['http'].has_key('robots'):
                    robots = service['http']['robots']
                    if robots is not None:
                      if len(robots.encode('ascii', 'ignore').strip()) > 0:
                        report.write('<div class="ssl">Robots</div>\n')
                        report.write('<div class="ssldata">\n')
                        for robotline in robots.split('\n'):
                          report.write('%s<br>\n' % (robotline.strip().encode('ascii', 'ignore'), ))
                        report.write('</div>\n')

#SSL

                if service.has_key('ssl'):
#                  report.write('%s<br>\n' % (service['ssl'], ))
                  if service['ssl'].has_key('cert'):

#SSL SUBJECT

                    if service['ssl']['cert'].has_key('subject'):
                      report.write('<div class="ssl">SSL Subject</div>\n')
                      report.write('<div class="ssldata">\n')
                      subject = service['ssl']['cert']['subject']
                      if subject.has_key('OU'):
                        report.write('OU: %s<br>\n' % (subject['OU'].encode('ascii', 'ignore'), ))
                      if subject.has_key('emailAddress'):
                        report.write('Email: %s<br>\n' % (subject['emailAddress'].encode('ascii', 'ignore'), ))
                      if subject.has_key('O'):
                        report.write('O: %s<br>\n' % (subject['O'].encode('ascii', 'ignore'), ))
                      if subject.has_key('CN'):
                        report.write('CN: %s<br>\n' % (subject['CN'].encode('ascii', 'ignore'), ))
                        report.write('</div>\n')
                        if domain not in subject['CN'].lower():
                          summary['sslnotdomain'] += 1
                          pivottarget = subject['CN'].encode('ascii', 'ignore').lower().lstrip('*.').rstrip('/').replace('www.', '')
                          if ip == pivottarget:
                            report.write('<span class="sslwarning">Pivot Target: %s</span>' % pivottarget)
                          else:
                            if ( 
                              "cloudflaressl.com" not in pivottarget and
                              "cloudfront.net" not in pivottarget
                              ):
                              report.write('<span class="sslerror">Pivot Target: %s</span>' % pivottarget)
                              if pivottarget not in summary['sslpivottargets']:
                                summary['sslpivottargets'].append(pivottarget)

#SSL WILDCARD

                        if service['ssl']['cert']['subject']['CN'][0] == "*":
                          report.write('<span class="sslwarning">Wildcard</span>')
                          summary['sslwildcard'] += 1

#SSL SELF-SIGNED

                    if service['ssl']['cert'].has_key('issuer') and service['ssl']['cert'].has_key('subject'):
                      subject = service['ssl']['cert']['subject']
                      issuer = service['ssl']['cert']['issuer']
                      if subject and issuer:
                        if subject == issuer:
                          report.write('<span class="sslerror">Self-Signed</span>')
                          summary['selfsignedservices'] += 1

#SSL ISSUER

                    if service['ssl']['cert'].has_key('issuer'):
                      report.write('<div class="ssl">SSL Issuer</div>\n')
                      report.write('<div class="ssldata">\n')
                      issuer = service['ssl']['cert']['issuer']
                      if issuer.has_key('OU'):
                        report.write('OU: %s<br>\n' % (issuer['OU'].encode('ascii', 'ignore'), ))
                      if issuer.has_key('emailAddress'):
                        report.write('Email: %s<br>\n' % (issuer['emailAddress'].encode('ascii', 'ignore'), ))
                      if issuer.has_key('O'):
                        report.write('O: %s<br>\n' % (issuer['O'].encode('ascii', 'ignore'), ))
                      if issuer.has_key('CN'):
                        report.write('CN: %s<br>\n' % (issuer['CN'].encode('ascii', 'ignore'), ))
                      report.write('</div>\n')

#SSL CERT EXPIRATION

                    if service['ssl']['cert'].has_key('expires'):
                      expires = service['ssl']['cert']['expires'].encode('ascii', 'ignore')
                      certyear = expires[0:4]
                      certmonth = expires[4:6]
                      certday = expires[6:8]
                      report.write('<div class="ssl">SSL Certificate Expiration: %s/%s/%s</div>' % (certmonth, certday, certyear))

                    if service['ssl']['cert'].has_key('expired'):
                      if service['ssl']['cert']['expired']:
                        report.write('<span class="sslerror">Expired</span>')
                        summary['sslexpired'] += 1

#SSL VERSIONS

                  if service['ssl'].has_key('versions'):
                    report.write('<div class="ssl">SSL Versions</div>\n')
                    report.write('<div class="ssldata">\n')
                    errorversions = ['TLSv1', 'SSLv2', 'SSLv3', '-TLSv1.2']
                    warnversions = ['TLSv1.1']
                    for version in service['ssl']['versions']:
                      if version.strip() in errorversions:
                        report.write('</div>\n')
                        report.write('<span class="sslerror">%s</span>\n' % (version, ))
                        report.write('<div class="ssldata">\n')
                        summary['sslerrorversion'] += 1
                      elif version.strip() in warnversions:
                        report.write('</div>\n')
                        report.write('<span class="sslwarning">%s</span>\n' % (version, ))
                        report.write('<div class="ssldata">\n')
                        summary['sslwarnversion'] += 1
                      else:
                        report.write('%s<br>\n' % (version, ))
                    report.write('</div>\n')

#SSL CIPHERS

                  if service['ssl'].has_key('cipher'):
                    goodciphers = []
                    goodciphers.append('ECDHE-ECDSA-AES256-GCM-SHA384')
                    goodciphers.append('ECDHE-RSA-AES256-GCM-SHA384')
                    goodciphers.append('ECDHE-ECDSA-CHACHA20-POLY1305')
                    goodciphers.append('ECDHE-RSA-CHACHA20-POLY1305')
                    goodciphers.append('ECDHE-ECDSA-AES128-GCM-SHA256')
                    goodciphers.append('ECDHE-RSA-AES128-GCM-SHA256')
                    goodciphers.append('ECDHE-ECDSA-AES256-SHA384')
                    goodciphers.append('ECDHE-RSA-AES256-SHA384')
                    goodciphers.append('ECDHE-ECDSA-AES128-SHA256')
                    goodciphers.append('ECDHE-RSA-AES128-SHA256')

                    if service['ssl']['cipher'].has_key('name'):
                      cipher = service['ssl']['cipher']['name']
                      report.write('<div class="ssl">SSL Cipher</div>\n')
                      report.write('<div class="ssldata">\n')
                      report.write('Cipher Suite: %s<br>\n' % (cipher, ))
                      cipherparts = cipher.split('-')
                      if len(cipherparts) == 5:
                        report.write('Key Exchange: %s<br>\n' % (cipherparts[0], ))
                        report.write('Authentication: %s<br>\n' % (cipherparts[1], ))
                        report.write('Block/Stream Ciphers: %s-%s<br>\n' % (cipherparts[2], cipherparts[3]))
                        report.write('Message Authentication: %s<br>\n' % (cipherparts[4], ))
                      elif len(cipherparts) == 4:
                        report.write('Key Exchange: %s<br>\n' % (cipherparts[0], ))
                        report.write('Authentication: %s<br>\n' % (cipherparts[1], ))
                        report.write('Block/Stream Ciphers: %s<br>\n' % (cipherparts[2], ))
                        report.write('Message Authentication: %s<br>\n' % (cipherparts[3], ))
                      report.write('</div>\n')
                      if cipher not in goodciphers:
                        report.write('<span class="sslwarning">Less Secure Cipher</span>')
                        summary['sslbadcipher'] += 1

#VULN

                if service.has_key('vulns'):
                  report.write('<table class="vulnerability">\n')
                  report.write("<tr>")
                  report.write('<td class="vulnerability" align="center" width="150px">CVE</td>')
                  report.write('<td class="vulnerability" align="center" width="150px">CVSS</td>')
                  report.write('<td class="vulnerability" align="center">Summary</td>')
                  report.write("</tr>\n")
                  vulns = service['vulns']
		  for vuln in vulns:
                    summary['vulntotal'] += 1
                    if vulns[vuln].has_key('cvss') and vulns[vuln].has_key('summary'):
                      report.write('<tr class="vulnerability">')
                      report.write('<td class="vulnerability" align="center">%s</td>' % (vuln, ))
                      report.write('<td class="vulnerability" align="center"')
                      cvss = vulns[vuln]['cvss']
                      if 0.1 <= float(cvss) < 4:
                        report.write(' bgcolor="yellow"')
                        summary['vulnlow'] += 1
                      elif 4 <= float(cvss) < 7:
                        report.write(' bgcolor="orange"')
                        summary['vulnmedium'] += 1
                      elif 7 <= float(cvss) < 9:
                        report.write(' bgcolor="red"')
                        summary['vulnhigh'] += 1
                      elif 9 <= float(cvss):
                        report.write(' bgcolor="purple"')
                        summary['vulncritical'] += 1
                      report.write('>%s</td>' % (cvss, ))
                      report.write('<td class="vulnerability">%s</td>' % (vulns[vuln]['summary'], ))
                      report.write("</tr>\n")
                  report.write("</table>")
 
report.write('</body>\n')
report.write('</html>\n')
report.close()

sumfile = "%s-summary.html" % (domain.split(".")[0], )
sum = open(sumfile, "w")
sum.write("""<html>
  <head>
    <style>
      #map {
        height: 400px;
        width: 800px;
        align: center;
       }
    </style>
  </head>
  <body>
    Global Technology Distribution<br>
    <div id="map"></div>
    <script>
function initMap() {
  var center = {lat: 10, lng: 0};
""")


entrycounter = 1
for entry in summary['mapdata']:
  sum.write("  var point%s = {lat: %s, lng: %s};\n" % (str(entrycounter), entry['latitude'], entry['longitude']))
  entrycounter += 1
sum.write("  var map = new google.maps.Map(document.getElementById('map'), {zoom: 1.75, center: center});\n")

entrycounter = 1
for entry in summary['mapdata']:
  sum.write("  var marker%s = new google.maps.Marker({position: point%s, map: map});\n" % (entrycounter, entrycounter))
  entrycounter += 1

sum.write("""}
    </script>
    <script async defer
    src="https://maps.googleapis.com/maps/api/js?key=AIzaSyDCRRZ3p8yhxJP1-9IscmsxB78zAAL64AU&callback=initMap">
    </script>
""")

sum.write("<br>\n")
sum.write("Hosts: %s<br>\n" % (summary['hosts'], ))
sum.write("Non-Production Hosts: %s<br>\n" % (str(summary['nonprod']), ))
if summary['cloudaws'] > 0:
  sum.write("AWS Hosts: %s<br>\n" % (str(summary['cloudaws']), ))
  sum.write("AWS Regions:<br>\n")
  for region in summary['cloudawsregions']:
    sum.write("%s<br>\n" % region)
if summary['cloudgcp'] > 0:
  sum.write("GCP Hosts: %s<br>\n" % (str(summary['cloudgcp']), ))

sum.write("<br>IPs<br>\n")
sum.write("Total: %s<br>\n" % (summary['ips'], ))
sum.write("Private: %s<br>\n" % (summary['privateips'], ))
sum.write("Reserved: %s<br>\n" % (summary['reservedips'], ))

sum.write("<br>Services<br>\n")
sum.write("Total: %s<br>\n" % (summary['services'], ))
sum.write("Cloud: %s<br>\n" % (summary['cloudservices'], ))

sum.write("SSH Services: %s<br>\n" % (summary['servicessh'], ))
sum.write("FTP Services: %s<br>\n" % (summary['serviceftp'], ))
sum.write("NTP Services: %s<br>\n" % (summary['servicentp'], ))
sum.write("Mail Services: %s<br>\n" % (summary['servicemail'], ))
sum.write("Jenkins Services: %s<br>\n" % (summary['servicejenkins'], ))

sum.write("<br>HTTP Hardening<br>\n")
sum.write("Web services protected by a WAF: %s<br>\n" % (summary['waf'], ))
sum.write("Web services that respond to HTTP/1.0 requests: %s<br>\n" % (summary['http1'], ))
sum.write("Web services that identify their version: %s<br>\n" % (summary['serviceversions'], ))
sum.write("Web Services Utilizing PHP: %s<br>\n" % (summary['servicephp'], ))
sum.write("Web Services Utilizing ASP: %s<br>\n" % (summary['servicephp'], ))
sum.write("Web services that need to be hardened with an App-ID: %s<br>\n" % (summary['http200'], ))
sum.write("HTML Forms Detected: %s<br>\n" % (summary['htmlforms'], ))
sum.write("Possible API Key Leaks Detected: %s<br>\n" % (summary['keyleaks'], ))
sum.write("Redirects Total: %s<br>\n" % (summary['http3xx'], ))
sum.write("Proper redirects to the same DNS host: %s<br>\n" % (summary['redirectsamehost'], ))
sum.write("Redirects to the same IP (should point to DNS name instead): %s<br>\n" % (summary['redirectsameip'], ))
sum.write("Redirects to the same domain (need lifecycle management): %s<br>\n" % (summary['redirectdifferentiphost'], ))
sum.write("Redirects to different domains (pivot targets): %s<br>\n" % (summary['redirectdifferentdomain'], ))
sum.write("Application/Server Errors: %s<br>\n" % (summary['http5xx'], ))
sum.write("End-of-life Services: %s<br>\n" % (summary['serviceeol'], ))
sum.write("End-of-support Services: %s<br>\n" % (summary['serviceeos'], ))

sum.write("<br>SSL<br>\n")
sum.write("Wildcard Certificates: %s<br>\n" % (summary['sslwildcard'], ))
sum.write("Vulnerable TLS Mail Services: %s<br>\n" % (summary['starttlsservices'], ))
sum.write("Self-Signed Certificates: %s<br>\n" % (summary['selfsignedservices'], ))
sum.write("Insecure SSL Versions: %s<br>\n" % (summary['sslerrorversion'], ))
sum.write("Non-compliant SSL Versions: %s<br>\n" % (summary['sslwarnversion'], ))
sum.write("Bad SSL Ciphers: %s<br>\n" % (summary['sslbadcipher'], ))
sum.write("Expired Certificates: %s<br>\n" % (summary['sslexpired'], ))
sum.write("Potential pivot targets identified by SSL certificate: %s<br>\n" % (summary['sslnotdomain'], ))

sum.write("<br>Vulnerabilities<br>\n")
sum.write("Total: %s<br>\n" % (summary['vulntotal'], ))
sum.write("Low: %s<br>\n" % (summary['vulnlow'], ))
sum.write("Medium: %s<br>\n" % (summary['vulnmedium'], ))
sum.write("High: %s<br>\n" % (summary['vulnhigh'], ))
sum.write("Critical: %s<br>\n" % (summary['vulncritical'], ))

if len(summary['reversednspivottargets']) > 0:
  sum.write("<br>Reverse DNS Pivot Targets<br>\n")
  for target in summary['reversednspivottargets']:
    sum.write("%s<br>\n" % (target, ))
if len(summary['redirectpivottargets']) > 0:
  sum.write("<br>Redirect Pivot Targets<br>\n")
  for target in summary['redirectpivottargets']:
    sum.write("%s<br>\n" % (target, ))
if len(summary['sslpivottargets']) > 0:
  sum.write("<br>SSL Pivot Targets<br>\n")
  for target in summary['sslpivottargets']:
    sum.write("%s<br>\n" % (target, ))
sum.write("</body></html>")
sum.close()
