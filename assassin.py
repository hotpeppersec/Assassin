#!/usr/bin/env python

import socket
import ipaddress
from ipwhois import IPWhois
import urllib2
import json

domain = raw_input("What domain would you like to search? ")

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
report = ""

def getDns(domain):
  output = []
  url = "https://api.hackertarget.com/hostsearch/?q=%s" % (domain, )
  try:
    response = urllib2.urlopen(url)
    domains = response.read().strip().split("\n")
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
      global privateips
      privateips += 1
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
      report += "<br><font face=courier size=5>%s</font><br>\n" % (host, )
      if (len(resolve[1]) > 0):
        for alias in resolve[1]:
          report += "<font face=courier size=2>Alias: %s</font><br>\n" % (alias,)
      if (len(resolve[2]) > 0):
        livehosts = livehosts + 1
        for ip in resolve[2]:
          if (ip in ipaddresses):
            report += "<font face=courier size=2>IP Address: %s - Already analyzed</font><br>\n" % (ip, )
          else:
            ipaddresses.append(ip)
            if (not checkPrivate(ip)):
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
                report += "<font face=courier size=2>IP Address: %s</font><br>\n" % (ip,)
                report += "<font face=courier size=2>Reverse DNS: %s</font><br>\n" % (reversedns,)
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
                    report += "<font face=courier size=2>Whois: %s</font><br>\n" % (whois, )
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
                    report += "<font face=courier size=2>Whois: %s</font><br>\n" % (whois, )
                except:
                  pass
                shodan = getShodan(ip)
                if (shodan is not None):
                  if shodan.has_key("vulns"):
                    for vuln in shodan["vulns"]:
                      vulnerabilities += 1  
                      cvedata = getCve(vuln)
                      report += "<br><font face=courier size=2>Vulnerability: %s - %s - %s</font><br>\n" % (vuln, cvedata["cvss"], cvedata["severity"], )
                      report += "<font face=courier size=1>%s</font><br>\n" % (cvedata["summary"], )
                  if shodan.has_key("org"):
                    if (shodan["org"] is not None):
                      report += "<font face=courier size=2>Org: %s</font><br>\n" % (shodan["org"],)
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
                        report += "<br><font face=courier size=2>Transport: %s</font><br>\n" % (service["transport"], )
                      if service.has_key("port"):
                        report += "<font face=courier size=2>Port: %s</font><br>\n" % (service["port"], )
                      if service.has_key("data"):
                        liveservices = liveservices + 1
                        report += "<font face=courier size=2>Data:</font><br>\n"
                        report += "<xmp>"
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
                            report += line + "\n"
                        report += "</xmp>"  
                      if service.has_key("ssl"):
                        sslservices = sslservices + 1
                        report += "<br><font face=courier size=2>SSL:</font><br>\n"
                        if service["ssl"].has_key("cert"):
                          if service["ssl"]["cert"].has_key("expired"):
                            if (service["ssl"]["cert"]["expired"] == True):
                              expiredcerts = expiredcerts + 1
                            report += "<font face=courier size=2>Expired: %s</font><br>\n" % (service["ssl"]["cert"]["expired"], )
                          if service["ssl"]["cert"].has_key("issuer"):
                            if service["ssl"]["cert"]["issuer"].has_key("O"):
                              report += "<font face=courier size=2>Issuer: %s</font><br>\n" % (service["ssl"]["cert"]["issuer"]["O"], )
                          if service["ssl"]["cert"].has_key("subject"):
                            if service["ssl"]["cert"]["subject"].has_key("CN"):
                              if("*" in service["ssl"]["cert"]["subject"]["CN"]):
                                wildcardcert = wildcardcert + 1
                              report += "<font face=courier size=2>Common Name: %s</font><br>\n" % (service["ssl"]["cert"]["subject"]["CN"], )
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
                report += "<font face=courier size=2>%s</font><br>\n" % (ip,)
    except socket.gaierror, err:
      pass

summary = "<font face=courier size=10>\n"
summary += "%s<br>\n" % (domain, )
summary += "<font face=courier size=2><br>\n"
summary += "DNS Entries: %s<br>\n" % (dnsnames, )
summary += "Live DNS Entries: %s<br>\n" % (livehosts, )
summary += "<br><font face=courier size=3>Hostings Information<font face=courier size=2><br>\n"
summary += "Total IPs Analyzed: %s<br>\n" % (len(ipaddresses), )
summary += "Private IPs: %s<br>\n" % (privateips, )
summary += "Amazon: %s<br>\n" % (amazon, )
summary += "Azure: %s<br>\n" % (azure, )
summary += "Google: %s<br>\n" % (google, )
summary += "Oracle: %s<br>\n" % (oracle, )
summary += "Rackspace: %s<br>\n" % (rackspace, )
summary += "Digital Ocean: %s<br>\n" % (digitalocean, )
summary += "Akamai: %s<br>\n" % (akamai, )
summary += "<br><font face=courier size=3>Services<font face=courier size=2><br>\n"
summary += "Total: %s<br>\n" % (liveservices, )
summary += "HTTP(S): %s<br>\n" % (httplisteners, )
summary += "HTTP(S) 200s: %s<br>\n" % (http200s, )
summary += "SSH: %s<br>\n" % (sshlisteners, )
summary += "SSL: %s<br>\n" % (sslservices, )
summary += "<br><font face=courier size=3>Certificates<font face=courier size=2><br>\n"
summary += "Wildcard Certificates: %s<br>\n" % (wildcardcert, )
summary += "Expired Certificates: %s<br>\n" % (expiredcerts, )
summary += "<br><font face=courier size=3>Vulnerabilities<font face=courier size=2><br>\n"
summary += "Total: %s<br>\n" % (vulnerabilities, )
summary += "None: %s<br>\n" % (severitynone, )
summary += "Low: %s<br>\n" % (severitylow, )
summary += "Medium: %s<br>\n" % (severitymedium, )
summary += "High: %s<br>\n" % (severityhigh, )
summary += "Critical: %s<br>\n" % (severitycritical, )

filename = domain.split(".")[0] + ".html"
file = open(filename, "w")
file.write(summary)
file.write(report)
file.close
