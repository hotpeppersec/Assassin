#!/usr/bin/env python

import ipaddress
import urllib2
import json

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

if not hosts:
  print "No DNS entries discovered for target domain"
  report.close()
else:
  for host in hosts:
    print "Processing host: %s" % (host)
    report.write('<div class="host">\n')
    report.write('%s\n' % (host, ))
    report.write('</div>\n')

    ips = getFwdDns(host)
    if ips:
      for ip in ips:
        report.write('<div class="ip">\n')
        report.write('IP: %s<br>\n' % (ip, ))

        if checkPrivate(ip):
          report.write("Private: Yes<br>\n")
          report.write('</div>\n')
        else:

          reverse = getRevDns(ip)
          if reverse:
            report.write("Reverse DNS: %s<br>\n" % (reverse, ))

          whois = getWhois(ip)
          if whois:
            report.write("WhoIs: %s<br>\n" % (whois, ))

          report.write('</div>\n')

          shodan = getShodan(ip)
          if shodan:
            if shodan.has_key('data'):
              for service in shodan['data']:
                report.write('<div class="service">\n')
                if service.has_key('transport') and service.has_key('port') and service.has_key('product'):
                  report.write("Service: %s/%s - %s\n" % (service['transport'], service['port'], service['product']))
                else:
                  report.write("Service: %s/%s\n" % (service['transport'], service['port']))
                report.write('</div>\n')

                if service.has_key('data'):
                  report.write('<div class="data">\n')
                  report.write('<pre>')
                  report.write(service['data'].strip())
                  report.write('</pre>\n')
                  report.write('</div>\n')

                if service.has_key('ssl'):
                  report.write('<div class="ssl">\n')
                  report.write("SSL Subject: %s\n" % (service['ssl']['cert']['subject']['CN'], ))
                  if service['ssl']['cert']['expired']:
                    report.write('<br><font color="red">This certificate is expired!</font>')
                  report.write('</div>\n')

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
                  report.write('</div>\n')
