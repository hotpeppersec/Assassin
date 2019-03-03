#!/usr/bin/env python

import socket
import ipaddress
from ipwhois import IPWhois
import urllib2
import json
from sys import stdout

#Let's grab a domain to analyze
domain = raw_input("What domain would you like to search? ")

#These will be used in the summary report generated at the end of the script
dnsnames = 0
livehosts = 0
privateips = 0
hosting = {}
liveservices = 0
vulnerabilities = 0
severitynone = 0
severitylow = 0
severitymedium = 0
severityhigh = 0
severitycritical = 0
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

# Get DNS data for domain from HackerTarget
dns = getDns(domain)

#Make sure we get a result
if (len(dns) > 0):

  #This will be used in the summary report
  dnsnames = (len(dns) + 1)

  #This gives us a nice status indicator on the CLI so the operator knows the script is still running
  dnscounter = 1  
  for host in dns:
    stdout.write("\r" + str(dnscounter) + " out of " + str(dnsnames) + " DNS entries analyzed")
    stdout.flush()
    dnscounter += 1
    report += '<div class="host">%s</div>\n' % (host, )

    #DNS resolve the hostname (This should probably be moved to a function)
    try:
      resolve = socket.gethostbyname_ex(host)

      #Check for alias resolution: just adding the data to the report for now - not recursively resolving these names
      if (len(resolve[1]) > 0):
        report += '<div class="hostinfo">\n'
        for alias in resolve[1]:
          report += "Alias: %s<br>\n" % (alias,)
        report += "</div>\n"

      #Check for IP addresses in DNS resolution
      if (len(resolve[2]) > 0):

        #This is used in the summary report
        livehosts += 1

        for ip in resolve[2]:

          #We don't want to process the same IP address over and over - check to see if IP has already been processed
          if (ip in ipaddresses):
            report += '<div class="hostinfo">IP Address: %s - Already analyzed</div>\n' % (ip, )

          else:
            #Add IP address to the list of processed addresses
            ipaddresses.append(ip)

            report += '<div class="hostinfo">\n'
            report += "IP Address: %s<br>\n" % (ip, )

            #Check to see if the IP address is private
            if (checkPrivate(ip)):
              #The IP address is private - increment the private P address counter for the summary
              privateips += 1

            else:
              #The IP address is public - time to set some variables and try to figure out who is hosting these IPs

              #Some hosting services include their identity in reverse DNS information
              try:
                reversedns = socket.getfqdn(ip)

                #When reverse DNS does not find an entry, it just returns the IP address.
                if (reversedns != ip):

                  report += "Reverse DNS: %s<br>\n" % (reversedns,)

              #What to do if there is a DNS resolution error
              except:
                pass

              #WhoIs should also give a clue about the hosting provider
              try:
                whoisclient = IPWhois(str(ip))
                whoisresult = whoisclient.lookup_rdap(depth=4)

                #The whois client returns data in two useful areas, either org_name or asn_description.  We're checking for ogr_name first
                if (whoisresult.has_key("org_name")):
                  whois = whoisresult["org_name"]

                  #add the whois data into the report
                  report += "Whois: %s<br>\n" % (whois, )

                  if hosting.has_key(whois):
                    hosting[whois] += 1
                  else:
                    hosting[whois] = 1

                  #If the org_name is not returned, we should check for asn_description
                elif (whoisresult.has_key("asn_description")):
                  whois = whoisresult["asn_description"]

                  #Add asn_description into the report
                  report += "Whois: %s<br>\n" % (whois, )

                  if hosting.has_key(whois):
                    hosting[whois] += 1
                  else:
                    hosting[whois] = 1

              #What to do if whois lookup fails
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
                else:
                  report += "</div>\n"
                if shodan.has_key("data"):
                  for service in shodan["data"]:
                    serviceport = ""
                    if service.has_key("transport") and service.has_key("port"):
                      report += '<div class="serviceport">%s/%s</div>\n' % (service["transport"], service["port"])
                    if service.has_key("data"):
                      liveservices = liveservices + 1
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
                      report += "</xmp>\n"  
                    if service.has_key("ssl"):
                      sslservices += 1
                      report += '<div class="ssl">SSL<br>\n'
                      if service["ssl"].has_key("cert"):
                        if service["ssl"]["cert"].has_key("expired"):
                          if (service["ssl"]["cert"]["expired"] == True):
                            expiredcerts += 1
                          report += "Expired: %s<br>\n" % (service["ssl"]["cert"]["expired"], )
                        if service["ssl"]["cert"].has_key("issuer"):
                          if service["ssl"]["cert"]["issuer"].has_key("O"):
                            report += "Issuer: %s<br>\n" % (service["ssl"]["cert"]["issuer"]["O"], )
                        if service["ssl"]["cert"].has_key("subject"):
                          if service["ssl"]["cert"]["subject"].has_key("CN"):
                            if("*" in service["ssl"]["cert"]["subject"]["CN"]):
                              wildcardcert += 1
                            report += "Common Name: %s<br>\n" % (service["ssl"]["cert"]["subject"]["CN"], )
                      report += "</div>\n"
              else:
                report += "</div>\n"

    except socket.gaierror, err:
      pass

summary = "<font face=courier size=10>\n"
summary += "%s\n" % (domain, )
summary += '<div class="summarydata">\n'
summary += "DNS Entries: %s<br>\n" % (dnsnames, )
summary += "Live DNS Entries: %s<br>\n" % (livehosts, )
summary += "</div>\n"
summary += '<div class="summaryheader">Hostings Information</div>\n'
summary += '<div class="summarydata">\n'
summary += "Total IPs Analyzed: %s<br>\n" % (len(ipaddresses), )
summary += "Private IPs: %s<br>\n" % (privateips, )
for host in hosting:
  summary += "%s: %s<br>\n" % (host, hosting[host])
#summary += "Amazon: %s<br>\n" % (amazon, )
#summary += "Azure: %s<br>\n" % (azure, )
#summary += "Google: %s<br>\n" % (google, )
#summary += "Oracle: %s<br>\n" % (oracle, )
#summary += "Rackspace: %s<br>\n" % (rackspace, )
#summary += "Digital Ocean: %s<br>\n" % (digitalocean, )
#summary += "Akamai: %s<br>\n" % (akamai, )
summary += "</div>\n"
summary += '<div class="summaryheader">Services<div>\n'
summary += '<div class="summarydata">\n'
summary += "Total: %s<br>\n" % (liveservices, )
summary += "HTTP(S): %s<br>\n" % (httplisteners, )
summary += "HTTP(S) 200s: %s<br>\n" % (http200s, )
summary += "SSH: %s<br>\n" % (sshlisteners, )
summary += "SSL: %s<br>\n" % (sslservices, )
summary += "</div>"
summary += '<div class="summaryheader">Certificates</div>\n'
summary += '<div class="summarydata">\n'
summary += "Wildcard Certificates: %s<br>\n" % (wildcardcert, )
summary += "Expired Certificates: %s<br>\n" % (expiredcerts, )
summary += "</div>"
summary += '<div class="summaryheader">Vulnerabilities</div>\n'
summary += '<div class="summarydata">\n'
summary += "Total: %s<br>\n" % (vulnerabilities, )
summary += "None: %s<br>\n" % (severitynone, )
summary += "Low: %s<br>\n" % (severitylow, )
summary += "Medium: %s<br>\n" % (severitymedium, )
summary += "High: %s<br>\n" % (severityhigh, )
summary += "Critical: %s<br>\n" % (severitycritical, )
summary += "</div>"

css = "<head>\n"
css += "<style>\n"
css += "div.summaryheader {\n"
css += "\tfont: 15pt courier;\n"
css += "}\n"
css += "div.summarydata {\n"
css += "\tfont: 11pt courier;\n"
css += "\tmargin-left: 25px;\n"
css += "}\n"
css += "div.host {\n"
css += "\tfont: 15pt courier;\n"
css += "}\n"
css += "div.hostinfo {\n"
css += "\tfont: 11pt courier;\n"
css += "}\n"
css += "div.serviceport {\n"
css += "\tfont: 9pt courier;\n"
css += "\tmargin-left: 50px;\n"
css += "}\n"
css += "xmp {\n"
css += "\tfont: 7pt courier;\n"
css +="\tmargin-left: 100px;\n"
css += "}\n"
css += "div.ssl {\n"
css += "\tfont: 7pt courier;\n"
css += "\tmargin-left: 100px;\n"
css += "}\n"
css += "</style>\n"
css += "</head>\n\n"

filename = domain.split(".")[0] + ".html"
file = open(filename, "w")
file.write(css)
file.write(summary)
file.write("<br><br>\n")
file.write(report)
file.close
