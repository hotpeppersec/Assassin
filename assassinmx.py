#! /usr/bin/env python

import urllib2
import json
import ipaddress

domain = raw_input("What domain would you like to search? ")

def getMx(domain):
  output = []
  url='https://dns.google.com/resolve?name=%s&type=MX' % (domain, )
  try:
    jsonresponse = urllib2.urlopen(url)
    try:
      response = json.loads(jsonresponse.read())
      if response.has_key("Answer"):
        answers = response["Answer"]
        for answer in answers:
          if answer.has_key("data"):
            priority = answer["data"].encode("ascii").split(" ")[0]
            host = answer["data"].encode("ascii").split(" ")[1]
            ips = getFwdDns(host)
            ipdata = []
            for ip in ips:
              entry = { "ip": ip }
              reversedns = getRevDns(ip)
              if len(reversedns) > 0:
                entry.update ({ "reversedns": reversedns })
              whois = getWhois(ip)
              if len(whois) > 0:
                entry.update ({ "whois": whois })
              ipdata.append(entry)
            output.append({ "priority": priority, "host": host, "ipdata": ipdata })
    except:
      pass
  except:
    pass
  return output

def getFwdDns(host):
  output = []
  url='https://dns.google.com/resolve?name=%s&type=A' % (host, )
  try:
    jsonresponse = urllib2.urlopen(url)
    try:
      response = json.loads(jsonresponse.read())
      if response.has_key("Answer"):
        answers = response["Answer"]
        for answer in answers:
          if answer.has_key("data"):
            try:
              address = ipaddress.ip_address(answer["data"])
              output.append(answer["data"].encode("ascii"))
            except ValueError as e:
              print "%s is not an IP address" % (e, )
    except:
      pass
  except:
    pass
  return output

def getRevDns(ip):
  reverseip = "%s.%s.%s.%s.in-addr.arpa." % (ip.split(".")[3], ip.split(".")[2], ip.split(".")[1], ip.split(".")[0])
  output = ""
  url='https://dns.google.com/resolve?name=%s&type=PTR' % (reverseip, )
  try:
    jsonresponse = urllib2.urlopen(url)
    try:
      response = json.loads(jsonresponse.read())
      if response.has_key("Answer"):
        answers = response["Answer"]
        for answer in answers:
          if answer.has_key("data"):
            output = answer["data"].encode("ascii")
    except:
      pass
  except:
    pass
  return output

def getWhois(ip):
  output = ""
  url = "http://rdap.arin.net/registry/ip/%s" % (ip, )
  try:
    jsonresponse = urllib2.urlopen(url)
    response=json.loads(jsonresponse.read())
    if response.has_key("name"):
      output = response["name"]
    elif response.has_key("entities"):
      output = response["entities"][0]["handle"]
  except:
    pass
  return output.encode("ascii")

mxrecords = getMx(domain)

for record in mxrecords:
  print record
