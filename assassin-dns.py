#!/usr/bin/env python

from dnsdb_query import DnsdbClient
import socket
import ipaddress
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
amazon = 0
azure = 0
google = 0
rackspace = 0
akamai = 0
sslservices = 0
expiredcerts = 0
wildcardcert = 0

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
    response = json.loads(jsonresponse.read())
    return response  
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
          if (checkPrivate(ip)):
            privateips = privateips + 1
          else:
            try:
              reversedns = socket.getfqdn(ip)
              if("amazon" in reversedns):
                amazon = amazon + 1
              elif("azure" in reversedns):
                azure = azure + 1
              elif("google" in reversedns):
                google = google + 1
              elif("akamai" in reversedns):
                akamai = akamai + 1
              else:
                pass
              print "\tIP Address: %s" % (ip,)
              print "\tReverse DNS: %s" % (reversedns,)
              shodan = getShodan(ip)
              if (shodan is not None):
                if shodan.has_key("vulns"):
                  for vuln in shodan["vulns"]:
                    vulnerabilities = vulnerabilities + 1  
                    print "\tVulnerability: %s" % (vuln,)
                if shodan.has_key("org"):
                  print "\tOrg: %s" % (shodan["org"],)
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
                      for line in data:
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
            except socket.gaierror, err:
              print "\t%s" % (ip,)
    except socket.gaierror, err:
      pass

print "DNS Entries: %s" % (dnsnames, )
print "Live Systems: %s" % (livehosts, )
print "Services: %s" % (liveservices, )
print "Vulnerabilities: %s" % (vulnerabilities, )
print "Private IPs: %s" % (privateips, )
print "Amazon: %s" % (amazon, )
print "Azure: %s" % (azure, )
print "Google: %s" % (google, )
print "Akamai: %s" % (akamai, )
print "SSL Services: %s" % (sslservices, )
print "Wildcard Certificates: %s" % (wildcardcert, )
print "Expired Certificates: %s" % (expiredcerts, )
