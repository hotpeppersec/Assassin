#!/usr/bin/env python

from dnsdb_query import DnsdbClient
import socket
import ipaddress
from ipwhois import IPWhois
import urllib2
import json

inputDomain = raw_input("What domain would you like to search? ")
queryDomain = "*.%s" % (inputDomain, )
print queryDomain

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
  server='https://api.dnsdb.info'
  dnsdbkey='7fe8201d3d2d75191dd50fcae2a06822381d7138005906209c04f7bf0d69c37b'
  client = DnsdbClient(server, dnsdbkey)
  output = []
  for rrset in client.query_rrset(domain):
    # rrset is a decoded JSON blob
    output.append(rrset["rrname"].rstrip('.'))
  return set(output)

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
  url = "http://cve.circl.lu/api/cve/%s" % (cve, )
  try:
    jsonresponse = urllib2.urlopen(url)
    try:
      response = json.loads(jsonresponse.read())
      return response
    except ValueError as e:
      pass
  except urllib2.HTTPError, e:
    pass

dns = getDns(queryDomain)
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
                      vulnerabilities = vulnerabilities + 1  
                      print "\tVulnerability: %s" % (vuln, )
                      cvedata = getCve(vuln)
                      if cvedata.has_key("cvss"):
                        if (float(cvedata["cvss"]) == 0):
                          severity = "None"
                          severitynone = severitynone + 1
                        elif (0 < float(cvedata["cvss"]) < 4):
                          severity = "Low"
                          severitylow = severitylow + 1
                        elif (4 <= float(cvedata["cvss"]) < 7):
                          severity = "Medium"
                          severitymedium = severitymedium + 1
                        elif (7 <= float(cvedata["cvss"]) < 9):
                          severity = "High"
                          severityhigh = severityhigh + 1
                        elif (9 <= float(cvedata["cvss"])):
                          severity = "Critical"
                          severitycritical = severitycritical + 1
                        else:
                          severity = "Unknown"
                        print "\t\tSeverity: %s - %s" % (cvedata["cvss"], severity)
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

print "DNS Entries: %s" % (dnsnames, )
print "Live DNS Entries: %s" % (livehosts, )
print "Unique IPs Analyzed: %s" % (len(ipaddresses), )
print "\tPrivate IPs: %s" % (privateips, )
print "\tAmazon: %s" % (amazon, )
print "\tAzure: %s" % (azure, )
print "\tGoogle: %s" % (google, )
print "\tOracle: %s" % (oracle, )
print "\tRackspace: %s" % (rackspace, )
print "\tDigital Ocean: %s" % (digitalocean, )
print "\tAkamai: %s" % (akamai, )
print "Services: %s" % (liveservices, )
print "\tHTTP(S): %s" % (httplisteners, )
print "\tHTTP(S) 200 Responses: %s" % (http200s, )
print "\tSSH: %s" % (sshlisteners, )
print "\tSSL: %s" % (sslservices, )
print "\t\tWildcard Certificates: %s" % (wildcardcert, )
print "\t\tExpired Certificates: %s" % (expiredcerts, )
print "Vulnerabilities: %s" % (vulnerabilities, )
print "\tNone: %s" % severitynone
print "\tLow: %s" % severitylow
print "\tMedium: %s" % severitymedium
print "\tHigh: %s" % severityhigh
print "\tCritical: %s" % severitycritical
