#!/usr/bin/env python

import ipaddress
import urllib2
import json

summary = { "hosts": 0, "ips": 0, "privateips": 0, "unspecifiedips": 0, "reservedips": 0, "services": 0, "cloudservices": 0 } 

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
      print "Received hosts from Hacker Target"
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
      print "Received hosts from DNSDB"
      return output
  except:
    return False

def dnsCombine(dnsht, dnsdb):
  if dnsht and dnsdb:
    print "Combining hosts received from Hacker Target and DNSDB"
    for entry in dnsdb:
      if entry not in dnsht:
        dnsht.append(entry)
    return dnsht
  elif dnsht:
    print "Using host data from Hacker Target"
    return dnsht
  elif dnsdb:
    print "Using host data from DNSDB"
    return dnsdb
  else:
    return False

def getFwdDns(host):
  output = []
  url='https://dns.google.com/resolve?name=%s&type=A' % (host, )
  try:
    output = []
    jsonresponse = urllib2.urlopen(url)
    response = json.loads(jsonresponse.read())
    if response.has_key("Answer"):
      answers = response["Answer"]
      for answer in answers:
        if answer.has_key("data"):
          try:
            address = ipaddress.ip_address(answer["data"])
            output.append(answer["data"].encode("ascii"))
          except:
            pass
    return output
  except:
    return False

def getRevDns(ip):
  reverseip = "%s.%s.%s.%s.in-addr.arpa." % (ip.split(".")[3], ip.split(".")[2], ip.split(".")[1], ip.split(".")[0])
  url='https://dns.google.com/resolve?name=%s&type=PTR' % (reverseip, )
  try:
    jsonresponse = urllib2.urlopen(url)
    response = json.loads(jsonresponse.read())
    if response.has_key("Answer"):
      answers = response["Answer"]
      for answer in answers:
        if answer.has_key("data"):
          return answer["data"].encode("ascii")
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

def checkUnspecified(ip):
  unicodeip = unicode(str(ip), "utf-8")
  if (ipaddress.ip_address(unicodeip)):
    if (ipaddress.ip_address(unicodeip).is_unspecified):
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
    if response.has_key("name"):
      return response["name"]
    elif response.has_key("entities"):
      return response["entities"][0]["handle"]
    else:
      return False
  except:
    return False

domain = raw_input("What domain would you like to search? ")
reportfile = "%s-detail.html" % (domain.split(".")[0], )
report = open(reportfile, "w")
report.write('<html>\n')
report.write('<head>\n')
report.write('<title>Assassin Report for %s</title>\n' % (domain, ))
#writing out some style guidelines
report.write('<style>\n')
style = open("style.css", "r")
for line in style:
  report.write(line)
style.close()
report.write('</style>\n')
report.write('</head>\n')
report.write('<body>\n')
report.write('<div class="title">\n')
report.write('%s\n' % (domain, ))
report.write('</div>\n')

dnsht = getDnsht(domain)
dnsdb = getDnsdb(domain)
hosts = dnsCombine(dnsht, dnsdb)

summary['hosts'] = len(hosts)

if not hosts:
  print "No DNS entries discovered for target domain"
  report.close()
else:
  for host in hosts:
    print "Processing host: %s" % (host)
    report.write('<div class="host">\n')
    report.write('%s\n' % (host, ))
    report.write('</div>\n')

    #hostname/domain/URL tags will go here in the future

    ips = getFwdDns(host)
    if ips:
      for ip in ips:
        summary['ips'] += 1
        report.write('<div class="ip">\n')
        report.write('IP: %s<br>\n' % (ip, ))

        if checkPrivate(ip) or checkReserved(ip) or checkUnspecified(ip):
          report.write('</div>\n')
          if checkPrivate(ip):
            summary['privateips'] += 1
            report.write('<span class="iperror">Private</span>')
          if checkReserved(ip):
            summary['reservedips'] += 1
            report.write('<span class="iperror">Reserved</span>')
          if checkUnspecified(ip):
            summary['unspecifiedips'] += 1
            report.write('<span class="iperror">Unspecified</span>')
        else:

          reverse = getRevDns(ip)
          if reverse:
            report.write("Reverse DNS: %s<br>\n" % (reverse, ))

          whois = getWhois(ip)
          if whois:
            report.write("WhoIs: %s<br>\n" % (whois, ))

          report.write('</div>\n')

          #if someCheck(ip):
            #report.write('<span class="iperror">BadTag</span>')

          #Add more IP checks here...

          shodan = getShodan(ip)
          if shodan:

#            if shodan.has_key('latitude') and shodan.has_key('longitude'):
              

            if shodan.has_key('data'):

              for service in shodan['data']:
                summary['services'] += 1
                report.write('<div class="service">\n')
                if service.has_key('transport') and service.has_key('port') and service.has_key('product'):
                  report.write("Service: %s/%s - %s\n" % (service['transport'], service['port'], service['product']))
                else:
                  report.write("Service: %s/%s\n" % (service['transport'], service['port']))
                report.write('</div>\n')

                if service.has_key('tags'):
                  for tag in service['tags']:
                    if tag == "cloud":
                      summary['cloudservices'] += 1
                    report.write('<span class="tag">%s</span>' % (tag, ))

                if service.has_key('data'):
                  report.write('<div class="data">\n')
                  report.write('<pre>')
                  report.write(service['data'].strip().replace("<", "&lt").replace(">", "&gt"))
                  report.write('</pre>\n')
                  report.write('</div>\n')

                if "HTTP" in str(service['data']).split('\n')[0]:
                  httpstatus = str(service['data']).split('\n')[0].split(' ')[1]
                  if httpstatus == "200":
                    report.write('<span class="datawarning">Valid Response with IP Scan</span>')
                  if httpstatus == "500":
                    report.write('<span class="dataerror">Internal Server Error</span>')
                  if httpstatus == "501":
                    report.write('<span class="dataerror">Not Implemented</span>')
                  if httpstatus == "502":
                    report.write('<span class="dataerror">Bad Gateway</span>')
                  if httpstatus == "503":
                    report.write('<span class="dataerror">Service Unavailable</span>')
                  if httpstatus == "504":
                    report.write('<span class="dataerror">Gateway Timeout</span>')
                  if httpstatus == "505":
                    report.write('<span class="dataerror">HTTP Version Not Supported</span>')
                  if httpstatus == "506":
                    report.write('<span class="dataerror">Variant Also Negotiates</span>')
                  if httpstatus == "507":
                    report.write('<span class="dataerror">Insufficient Storage</span>')
                  if httpstatus == "508":
                    report.write('<span class="dataerror">Loop Detected</span>')
                  if httpstatus == "510":
                    report.write('<span class="dataerror">Not Extended</span>')
                  if httpstatus == "511":
                    report.write('<span class="dataerror">Network Authentication Required</span>')
                  if httpstatus == "599":
                    report.write('<span class="dataerror">Network Connection Timeout Error</span>')

                if service.has_key('ssl'):
                  report.write('<div class="ssl">SSL Subject: %s</div>' % (service['ssl']['cert']['subject']['CN'], ))
                  if service['ssl']['cert']['expired']:
                    report.write('<span class="sslerror">Expired</span>')
                  if service['ssl']['cert']['subject']['CN'][0] == "*":
                    report.write('<span class="sslwarning">Wildcard</span>')

                  if service['ssl'].has_key('versions'):
                    badversions = ['TLSv1', 'SSLv2', 'SSLv3', 'TLSv1.1']
                    for version in service['ssl']['versions']:
                      if version in badversions:
                        report.write('<span class="sslerror">%s</span>' % (version, ))

                  if service['ssl'].has_key('cipher'):
                    goodciphers = []
                    goodciphers.append('ECDHE-ECDSA-AES256-GCM-SHA384')
                    goodciphers.append('ECDHE-RSA-AES256-GCM-SHA384')
                    goodciphers.append('ECDHE-ECDSA-CHACHA20-POLY1305')
                    goodciphers.append('ECDHE-RSA-CHACHA20-POLY1305')
                    goodciphers.append('ECDHE-ECDSA-AES128-GCM-SHA256')
                    goodciphers.append('ECDHE-RSA-AES128-GCM-SHA256')
                    goodciphers.append('ECDHE-ECDSA-AES256-SHA384')
                    goodciphers.append('ECDHE-RSA-AES256-SHA384')
                    goodciphers.append('ECDHE-ECDSA-AES128-SHA256')
                    goodciphers.append('ECDHE-RSA-AES128-SHA256')

                    if service['ssl']['cipher'].has_key('name'):
                      cipher = service['ssl']['cipher']['name']
                      if cipher not in goodciphers:
                        report.write('<span class="sslerror">%s</span>' % (cipher, ))

                if service.has_key('vulns'):
                  report.write('<table class="vulnerability">\n')
                  report.write("<tr>")
                  report.write('<td align="center" width="150px">CVE</td>')
                  report.write('<td align="center" width="150px">CVSS</td>')
                  report.write('<td align="center">Summary</td>')
                  report.write("</tr>\n")
                  vulns = service['vulns']
		  for vuln in vulns:
                    if vulns[vuln].has_key('cvss') and vulns[vuln].has_key('summary'):
                      report.write("<tr>")
                      report.write('<td align="center">%s</td>' % (vuln, ))
                      report.write('<td align="center"')
                      cvss = vulns[vuln]['cvss']
                      if 0.1 <= float(cvss) < 4:
                        report.write(' bgcolor="yellow"')
                      elif 4 <= float(cvss) < 7:
                        report.write(' bgcolor="orange"')
                      elif 7 <= float(cvss) < 9:
                        report.write(' bgcolor="red"')
                      elif 9 <= float(cvss):
                        report.write(' bgcolor="purple"')
                      report.write('>%s</td>' % (cvss, ))
                      report.write("<td>%s</td>" % (vulns[vuln]['summary'], ))
                      report.write("</tr>\n")
                  report.write("</table>")
 
report.write('</body>\n')
report.write('</html>\n')

print summary
