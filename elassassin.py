#!/usr/bin/env python

import ipaddress
import urllib2
import json
from elasticsearch import Elasticsearch
import pymongo

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
    print "Received %s hosts from VirusTotal" % (len(response['subdomains']), )
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
    jsonresponse = urllib2.urlopen(url)
    response = json.loads(jsonresponse.read())
    return response
  except:
    return False

def getRevDns(ip):
  reverseip = "%s.%s.%s.%s.in-addr.arpa." % (ip.split(".")[3], ip.split(".")[2], ip.split(".")[1], ip.split(".")[0])
  url='https://dns.google.com/resolve?name=%s&type=PTR' % (reverseip, )
  try:
    jsonresponse = urllib2.urlopen(url)
    response = json.loads(jsonresponse.read())
    return response
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
    return response
  except:
    return False

def getTime():
  url = "http://worldtimeapi.org/api/timezone/Universal"
  try:
    jsonresponse = urllib2.urlopen(url)
    response=json.loads(jsonresponse.read())
    return response
  except:
    return False

def postElastic(index, document):
  try:
    es=Elasticsearch(
      [{'host':'c7bc7f45699545c7a81e28b36947c7a0.us-west-2.aws.found.io','port':9243}],
      http_auth=('elastic', 'ScUYdZhEZfyWGMO2XSEbhc85'),
      scheme="https"
    )
    res = es.index(index=domain, doc_type="json", body=json.dumps(document))
  except Exception as e:
    print e

domain = raw_input("What domain would you like to search? ")

dnsht = getDnsht(domain)
dnsdb = getDnsdb(domain)
dnsvt = getVtdomain(domain)
hosts = dnsCombine(dnsht, dnsdb, dnsvt)

if not hosts:
  print "No DNS entries discovered for target domain"
else:
  for host in hosts:
    print "Processing host: %s" % (host)
    dns = getFwdDns(host)
    if dns:
      if dns.has_key("Answer"):
        for answer in dns["Answer"]:
          if answer.has_key("type"):
            if answer["type"] == 1:
              if answer.has_key("data"):
                ip = answer["data"]
                print ip
                index = "%s-%s" % (domain, "ip")
                ipdoc = {"domain": domain, "host": host, "ip": ip}
                postElastic(index, ipdoc)

                reversedns = getRevDns(ip)
                if reversedns:
                  print reversedns
                  index = "%s-%s" % (domain, "reversedns")
                  revdoc = {"ip": ip, "reversedns": reversedns}
                  postElastic(index, revdoc) 

                whois = getWhois(ip)
                if whois:
                  print whois
                  index = "%s-%s" % (domain, "whois")
                  whodoc = {"ip": ip, "whois": whois}
                  postElastic(index, whodoc)
                  
                shodan = getShodan(ip)
                if shodan:
                  print shodan
                  index = "%s-%s" % (domain, "shodan")
                  shodandoc = {"ip": ip, "shodan": shodan}
                  postElastic(index, shodandoc)
