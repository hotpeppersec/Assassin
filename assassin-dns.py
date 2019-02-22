#!/usr/bin/env python

from dnsdb_query import DnsdbClient
import socket

server='https://api.dnsdb.info'
apikey='7fe8201d3d2d75191dd50fcae2a06822381d7138005906209c04f7bf0d69c37b'
domain = "*.arrow.com"

def getDns(server, apikey, domain):
  client = DnsdbClient(server, apikey)
  output = []
  for rrset in client.query_rrset(domain):
    # rrset is a decoded JSON blob
    output.append(rrset["rrname"].rstrip('.'))
  return set(output)

dns = getDns(server, apikey, domain)
if (len(dns) > 0):
  for host in dns:
    try:
      resolve = socket.gethostbyname_ex(host)
      print host
      if (len(resolve[1]) > 0):
        for alias in resolve[1]:
          print "\t%s" % (alias,)
      if (len(resolve[2]) > 0):
        for ip in resolve[2]:
          try:
            reversedns = socket.getfqdn(ip)
            print "\t%s: %s" % (ip, reversedns)
          except socket.gaierror, err:
            print "\t%s" % (ip,)
    except socket.gaierror, err:
      pass
