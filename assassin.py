#!/usr/bin/env python

import urllib2
import json

def getAsn(query):

  url = "https://api.bgpview.io/search?query_term=%s" % (query,)
  jsonresponse = urllib2.urlopen(url)
  response = json.loads(jsonresponse.read())

  entries = response["data"]["asns"]
  output = []
  for entry in entries:
    output.append({"asn": entry["asn"], "name": entry["name"], "description": entry["description"]})
  return output

def shodanAsn(asn):

  key = "C9tNjcBpKWoDmuqbbZ9lzeXKrv58iug8"
  url = "https://api.shodan.io/shodan/host/search?query=asn:%s&key=%s" % (asn, key)

  jsonresponse = urllib2.urlopen(url)
  response = json.loads(jsonresponse.read())

  return response

query = raw_input("What company would you like to investigate? ")
asns = getAsn(query)
counter = 1
for asn in asns:
  print "%s: AS%s: %s - %s" % (counter, asn["asn"], asn["name"], asn["description"])
  counter = counter + 1
selection = int(raw_input("Which of these appears to be the appropriate company? "))-1
print "You have selected AS%s" % (asns[selection]["asn"],)

queryasn = "AS%s" % (asns[selection]["asn"],)
shodan = shodanAsn(queryasn)
for match in shodan["matches"]:
  for entry in match:
    print "%s: %s" % (entry, match[entry])
