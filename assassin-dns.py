#!/usr/bin/env python

from dnsdb_query import DnsdbClient
import socket
import urllib2
import json

domain = "*.arrow.com"

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

dns = getDns(domain)
if (len(dns) > 0):
  for host in dns:
    try:
      resolve = socket.gethostbyname_ex(host)
      print host
      if (len(resolve[1]) > 0):
        for alias in resolve[1]:
          print "\tAlias: %s" % (alias,)
      if (len(resolve[2]) > 0):
        for ip in resolve[2]:
          try:
            reversedns = socket.getfqdn(ip)
            print "\tIP Address: %s" % (ip,)
            print "\tReverse DNS: %s" % (reversedns,)
            shodan = getShodan(ip)
            if (shodan is not None):
              if shodan.has_key("vulns"):
                for vuln in shodan["vulns"]:
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
                    print "\t\tData:"
                    data = service["data"].split("\n")
                    for line in data:
                      print "\t\t\t%s" % (line, )
                  if service.has_key("ssl"):
                    print "\t\tSSL:"
                    if service["ssl"].has_key("cert"):
                      if service["ssl"]["cert"].has_key("expired"):
                        print "\t\t\tExpired: %s" % (service["ssl"]["cert"]["expired"], )
                      if service["ssl"]["cert"].has_key("issuer"):
                        if service["ssl"]["cert"]["issuer"].has_key("O"):
                          print "\t\t\tIssuer: %s" % (service["ssl"]["cert"]["issuer"]["O"], )
                      if service["ssl"]["cert"].has_key("subject"):
                        if service["ssl"]["cert"]["subject"].has_key("CN"):
                          print "\t\t\tCommon Name: %s" % (service["ssl"]["cert"]["subject"]["CN"], )
          except socket.gaierror, err:
            print "\t%s" % (ip,)
    except socket.gaierror, err:
      pass
