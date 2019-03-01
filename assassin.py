#!/usr/bin/env python

import socket
import ipaddress
from ipwhois import IPWhois
import urllib2
import json

domain = raw_input("What domain would you like to search? ")
print domain

dnsnames = 0
livehosts = 0
privateips = 0
liveservices = 0
vulnerabilities = 0
severitynone = 0
severitylow = 0
severitymedium = 0
severityhigh = 0
severitycritical = 0
amazon = 0
azure = 0
google = 0
oracle = 0
digitalocean = 0
rackspace = 0
akamai = 0
sslservices = 0
expiredcerts = 0
wildcardcert = 0
httplisteners = 0
http200s = 0
sshlisteners = 0
ipaddresses = []

def getDns(domain):
  output = []
  url = "https://api.hackertarget.com/hostsearch/?q=%s" % (domain, )
  try:
    response = urllib2.urlopen(url)
    domains = response.read().strip().split("\n")
    #print domains
    for domain in domains:
      output.append(domain.split(",")[0])
    return output
  except urllib2.HTTPError, e:
    pass

def getShodan(ip):
  shodankey='C9tNjcBpKWoDmuqbbZ9lzeXKrv58iug8'
  url='https://api.shodan.io/shodan/host/%s?key=%s' % (ip, shodankey)
  try:
    jsonresponse = urllib2.urlopen(url)
    try:
      response = json.loads(jsonresponse.read())
      return response  
    except ValueError as e:
      pass
  except urllib2.HTTPError, e:
    pass

def checkPrivate(ip):
  unicodeip = unicode(str(ip), "utf-8")
  if (ipaddress.ip_address(unicodeip)):
    if (ipaddress.ip_address(unicodeip).is_private):
      return True
    else:
      return False
  else:
    return False

def getCve(cve):
  output = []
  url = "http://cve.circl.lu/api/cve/%s" % (cve, )
  try:
    jsonresponse = urllib2.urlopen(url)
    cvss = ""
    severity = ""
    summary = ""
    try:
      response = json.loads(jsonresponse.read())
      if response.has_key("cvss"):
        cvss = response["cvss"]
        if (float(response["cvss"]) == 0):
          severity = "None"
          global severitynone
          severitynone += 1
        elif (0 < float(response["cvss"]) < 4):
          severity = "Low"
          global severitylow
          severitylow += 1
        elif (4 <= float(response["cvss"]) < 7):
          severity = "Medium"
          global severitymedium
          severitymedium += 1
        elif (7 <= float(response["cvss"]) < 9):
          severity = "High"
          global severityhigh
          severityhigh += 1
        elif (9 <= float(response["cvss"])):
          severity = "Critical"
          global severitycritical
          severitycritical += 1
        else:
          severity = "Unknown"
      if response.has_key("summary"):
        summary = response["summary"]
      return {"cvss": cvss, "severity": severity, "summary": summary}
    except ValueError as e:
      pass
  except urllib2.HTTPError, e:
    pass

dns = getDns(domain)
if (len(dns) > 0):
  dnsnames = len(dns)  
  for host in dns:
    try:
      resolve = socket.gethostbyname_ex(host)
      print host
      if (len(resolve[1]) > 0):
        livehosts = livehosts + 1
        for alias in resolve[1]:
          print "\tAlias: %s" % (alias,)
      if (len(resolve[2]) > 0):
        for ip in resolve[2]:
          if (ip in ipaddresses):
            print "\t%s - IP address already analyzed" % (ip, )
          else:
            ipaddresses.append(ip)
            if (checkPrivate(ip)):
              privateips = privateips + 1
            else:
              isamazon = False
              isazure = False
              isgoogle = False
              isoracle = False
              isdigitalocean = False
              israckspace = False
              isakamai = False
              try:
                reversedns = socket.getfqdn(ip)
                if("amazon" in reversedns) or ("cloudfront" in reversedns):
                  isamazon = True
                if("azure" in reversedns):
                  isazure = True
                if("google" in reversedns):
                  isgoogle = True
                if("akamai" in reversedns):
                  isakamai = True
                print "\tIP Address: %s" % (ip,)
                print "\tReverse DNS: %s" % (reversedns,)
                try:
                  whoisclient = IPWhois(str(ip))
                  whoisresult = whoisclient.lookup_rdap(depth=1)
                  if (whoisresult.has_key("org_name")):
                    whois = whoisresult["org_name"]
                    if ("Amazon.com" in whois):
                      isamazon = True
                    if ("Microsoft Corporation" in whois):
                      isazure = True
                    if ("Google" in whois):
                      isgoogle = True
                    if ("Oracle Corporation" in whois):
                      isoracle = True
                    print "\tWhois: %s" % (whois, )
                  elif (whoisresult.has_key("asn_description")):
                    whois = whoisresult["asn_description"]
                    if ("Amazon.com" in whois):
                      isamazon = True
                    if ("Microsoft Corporation" in whois):
                      isazure = True
                    if ("Google" in whois):
                      isgoogle = True
                    if ("Oracle Corporation" in whois):
                      isoracle = True
                    print "\tWhois: %s" % (whois, )
                except:
                  pass
                shodan = getShodan(ip)
                if (shodan is not None):
                  if shodan.has_key("vulns"):
                    for vuln in shodan["vulns"]:
                      vulnerabilities += 1  
                      cvedata = getCve(vuln)
                      print "\tVulnerability: %s - %s - %s:" % (vuln, cvedata["cvss"], cvedata["severity"], )
                      print "\t\t%s" % (cvedata["summary"], )
                  if shodan.has_key("org"):
                    if (shodan["org"] is not None):
                      print "\tOrg: %s" % (shodan["org"],)
                      if ("Amazon" in shodan["org"]):
                        isamazon = True
                      if ("Microsoft Azure" in shodan["org"]):
                        isazure = True
                      if ("Google Cloud" in shodan["org"]):
                        isgoogle = True
                      if ("Oracle" in shodan["org"]):
                        isoracle = True
                      if ("Digital Ocean" in shodan["org"]):
                        isdigitalocean = True
                      if ("Rackspace" in shodan["org"]):
                        israckspace = True
                  if shodan.has_key("data"):
                    for service in shodan["data"]:
                      if service.has_key("transport"):
                        print "\t\tTransport: %s" % (service["transport"], )
                      if service.has_key("port"):
                        print "\t\tPort: %s" % (service["port"], )
                      if service.has_key("data"):
                        liveservices = liveservices + 1
                        print "\t\tData:"
                        data = service["data"].split("\n")                      
                        for rawline in data:
                          line = rawline.encode('ascii', 'ignore').decode('ascii').strip()
                          if (len(line) > 0):
                            if ("HTTP" in line):
                              httplisteners = httplisteners + 1
                            if ("HTTP/1.1 200 OK" in line):
                              http200s = http200s + 1
                            if ("SSH" in line):
                              sshlisteners = sshlisteners + 1
                            print "\t\t\t%s" % (line, )
                      if service.has_key("ssl"):
                        sslservices = sslservices + 1
                        print "\t\tSSL:"
                        if service["ssl"].has_key("cert"):
                          if service["ssl"]["cert"].has_key("expired"):
                            if (service["ssl"]["cert"]["expired"] == True):
                              expiredcerts = expiredcerts + 1
                            print "\t\t\tExpired: %s" % (service["ssl"]["cert"]["expired"], )
                          if service["ssl"]["cert"].has_key("issuer"):
                            if service["ssl"]["cert"]["issuer"].has_key("O"):
                              print "\t\t\tIssuer: %s" % (service["ssl"]["cert"]["issuer"]["O"], )
                          if service["ssl"]["cert"].has_key("subject"):
                            if service["ssl"]["cert"]["subject"].has_key("CN"):
                              if("*" in service["ssl"]["cert"]["subject"]["CN"]):
                                wildcardcert = wildcardcert + 1
                              print "\t\t\tCommon Name: %s" % (service["ssl"]["cert"]["subject"]["CN"], )
                if (isamazon):
                  amazon = amazon + 1
                if (isazure):
                  azure = azure + 1
                if (isgoogle):
                  google = google + 1
                if (isoracle):
                  oracle = oracle + 1
                if (isdigitalocean):
                  digitalocean = digitalocean + 1
                if (israckspace):
                  rackspace = rackspace + 1
                if (isakamai):
                  akamai = akamai + 1
              except socket.gaierror, err:
                print "\t%s" % (ip,)
    except socket.gaierror, err:
      pass

summary = "<html><body><h1>%s</h1><br>\n" % (domain, )
summary = summary + "<table cellpadding=0 cellspacing=0 border=1>\n"
summary = summary + "<tr><td>DNS Entries</td><td align=right>%s</td></tr>\n" % (dnsnames, )
summary = summary + "<tr><td>Live DNS Entries</td><td align=right>%s</td></tr>\n" % (livehosts, )
summary = summary + "<tr><td>Hostings Information</td><td>\n"
summary = summary + "\t<table cellpadding=5 cellspacing=0 border=1 bordercolor=gray width=100%>\n"
summary = summary + "\t<tr><td>Total IPs Analyzed</td><td align=right>%s</td></tr>\n" % (len(ipaddresses), )
summary = summary + "\t<tr><td>Private IPs</td><td align=right>%s</td></tr>\n" % (privateips, )
summary = summary + "\t<tr><td>Amazon</td><td align=right>%s</td></tr>\n" % (amazon, )
summary = summary + "\t<tr><td>Azure</td><td align=right>%s</td></tr>\n" % (azure, )
summary = summary + "\t<tr><td>Google</td><td align=right>%s</td></tr>\n" % (google, )
summary = summary + "\t<tr><td>Oracle</td><td align=right>%s</td></tr>\n" % (oracle, )
summary = summary + "\t<tr><td>Rackspace</td><td align=right>%s</td></tr>\n" % (rackspace, )
summary = summary + "\t<tr><td>Digital Ocean</td><td align=right>%s</td></tr>\n" % (digitalocean, )
summary = summary + "\t<tr><td>Akamai</td><td align=right>%s</td></tr>\n" % (akamai, )
summary = summary + "\t</table></td></tr>\n"
summary = summary + "</tr><td>Services</td><td>\n"
summary = summary + "\t<table cellpadding=5 cellspacing=0 border=1 bordercolor=gray width=100%>\n"
summary = summary + "\t<tr><td>Total</td><td align=right>%s</td></tr>\n" % (liveservices, )
summary = summary + "\t<tr><td>HTTP(S)</td><td align=right>%s</td></tr>\n" % (httplisteners, )
summary = summary + "\t<tr><td>HTTP(S) 200s</td><td align=right>%s</td></tr>\n" % (http200s, )
summary = summary + "\t<tr><td>SSH</td><td align=right>%s</td></tr>\n" % (sshlisteners, )
summary = summary + "\t<tr><td>SSL</td><td align=right>%s</td></tr>\n" % (sslservices, )
summary = summary + "\t</table></td></tr>\n"
summary = summary + "<tr><td>Certificates</td><td>\n"
summary = summary + "\t<table cellpadding=5 cellspacing=0 border=1 bordercolor=gray width=100%>\n"
summary = summary + "\t<tr><td>Wildcard Certificates</td><td align=right>%s</td></tr>\n" % (wildcardcert, )
summary = summary + "\t</tr><td>Expired Certificates</td><td align=right>%s</td></tr>\n" % (expiredcerts, )
summary = summary + "\t</table></td></tr>\n"
summary = summary + "\t<tr><td>Vulnerabilities</td><td>\n"
summary = summary + "\t<table cellpadding=0 cellspacing=0 border=1 bordercolor=gray width=100%>\n"
summary = summary + "\t<tr><td>Total</td><td align=right>%s</td></tr>\n" % (vulnerabilities, )
summary = summary + "\t<tr><td>None</td><td align=right>%s</td></tr>\n" % severitynone
summary = summary + "\t<tr><td>Low</td><td align=right>%s</td></tr>\n" % severitylow
summary = summary + "\t<tr><td>Medium</td><td align=right>%s</td></tr>\n" % severitymedium
summary = summary + "\t<tr><td>High</td><td align=right>%s</td></tr>\n" % severityhigh
summary = summary + "\t<tr><td>Critical</td><td align=right>%s</td></tr>\n" % severitycritical
summary = summary + "\t</table></td></tr>\n"
summary = summary + "</table></body></html>"

filename = domain.split(".")[0] + ".html"
file = open(filename, "w")
file.write(summary)
file.close
