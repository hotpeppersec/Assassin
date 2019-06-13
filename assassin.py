#!/usr/bin/env python

import ipaddress
import urllib2
import json

summary = { 
  "hosts": 0,
  "ips": 0,
  "privateips": 0,
  "reservedips": 0,
  "services": 0,
  "cloudservices": 0,
  "cloudaws": 0,
  "cloudawsregions": [],
  "starttlsservices": 0,
  "selfsignedservices": 0,
  "http200": 0,
  "http3xx": 0,
  "redirectsameip": 0,
  "redirectsamehost": 0,
  "redirectdifferentiphost": 0,
  "redirectdifferentdomain": 0,
  "http5xx": 0,
  "sslexpired": 0,
  "sslwildcard": 0,
  "sslnotdomain": 0,
  "sslerrorversion": 0,
  "sslwarnversion": 0,
  "sslbadcipher": 0,
  "vulntotal": 0,
  "vulnlow": 0,
  "vulnmedium": 0,
  "vulnhigh": 0,
  "vulncritical": 0,
  "waf": 0,
  "mapdata": [],
  "reversednspivottargets": [],
  "redirectpivottargets": [],
  "sslpivottargets": []
}

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
dnsvt = getVtdomain(domain)
hosts = dnsCombine(dnsht, dnsdb, dnsvt)

if not hosts:
  print "No DNS entries discovered for target domain"
  report.close()
else:
  summary['hosts'] = len(hosts)
  for host in hosts:
    print "Processing host: %s" % (host)
    report.write('<div class="host">%s</div>\n' % (host, ))

    #hostname/domain/URL tags will go here in the future

    ips = getFwdDns(host)
    if ips:
      for ip in ips:
        summary['ips'] += 1
        report.write('<div class="ip">IP: %s</div>\n' % (ip, ))
        if checkPrivate(ip) or checkReserved(ip):
          if checkPrivate(ip):
            summary['privateips'] += 1
            report.write('<span class="iperror">Private</span>')
          if checkReserved(ip):
            summary['reservedips'] += 1
            report.write('<span class="iperror">Reserved</span>')
        else:

          reverse = getRevDns(ip)
          if reverse:
            cleanreverse = reverse.lower().rstrip('.')
            report.write('<div class="ip">Reverse DNS: %s</div>\n' % (cleanreverse, ))
            if '.amazonaws.com' in cleanreverse:
              summary['cloudaws'] += 1
              report.write('<span class="ipinfo">AWS</span>')
              if len(cleanreverse.replace('.amazonaws.com', '').split('.')) > 1:
                awsregion = cleanreverse.split('.')[1]
              else:
                awsregion = cleanreverse.split('.')[0]
              if awsregion == 'compute-1':
                awsregion = 'us-east-1'
              if awsregion not in summary['cloudawsregions']:
                summary['cloudawsregions'].append(awsregion)
              report.write('<span class="ipinfo">AWS Region: %s</span>' % awsregion)
            if '.cloudfront.net' in cleanreverse:
              report.write('<span class="ipinfo">AWS</span>')
            if (
              domain not in cleanreverse and
              '.in-addr.arpa' not in cleanreverse and
              '.amazonaws.com' not in cleanreverse and
              '.akamaitechnologies.com' not in cleanreverse and
              '.cloudfront.net' not in cleanreverse
              ):
              if cleanreverse not in summary['reversednspivottargets']:
                summary['reversednspivottargets'].append(cleanreverse)

          whois = getWhois(ip)
          if whois:
            report.write('<div class="ip">WhoIs: %s</div>\n' % (whois, ))

          #if someCheck(ip):
            #report.write('<span class="iperror">BadTag</span>')

          #Add more IP checks here...

          shodan = getShodan(ip)
          if shodan:

            if shodan.has_key('latitude') and shodan.has_key('longitude'):
              if {"latitude": shodan['latitude'], "longitude": shodan['longitude'] } not in summary['mapdata']:
                summary['mapdata'].append({"latitude": shodan['latitude'], "longitude": shodan['longitude'] })
              

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
                      report.write('<span class="serviceinfo">%s</span>' % (tag, ))
                    if tag == "starttls":
                      summary['starttlsservices'] += 1
                      report.write('<span class="servicewarning">%s</span>' % (tag, ))
                    if tag == "self-signed":
                      summary['selfsignedservices'] += 1
                      report.write('<span class="serviceerror">%s</span>' % (tag, ))

                if service.has_key('data'):
                  report.write('<div class="data"><pre>\n')
                  report.write(service['data'].encode('ascii', 'ignore').strip().replace("<", "&lt").replace(">", "&gt"))
                  report.write('</pre></div>\n')

                  if ("Server: cloudflare" in service['data'] or
                    "CloudFront" in service['data'] or
                    "cloudfront" in service['data'] or
                    "BigIP" in service['data'] or
                    "bigip" in service['data'] or
                    "BIGip" in service['data']):
                    report.write('<span class="datainfo">WAF</span>')
                    summary['waf'] += 1

                  if "HTTP" in service['data'].encode('ascii', 'ignore').split('\n')[0]:
                    httpstatus = service['data'].encode('ascii', 'ignore').split('\n')[0].split(' ')[1]
                    if httpstatus == "200":
                      report.write('<span class="datawarning">Valid Response with IP Scan</span>')
                      summary['http200'] += 1
                    if httpstatus[0] == "3":
                      summary['http3xx'] += 1
                      for line in service['data'].split("\n"):
                        if line.find("Location: ", 0, 10) <> -1:
                          if ip in line:
                            report.write('<span class="datawarning">Redirect to same IP</span>')
                            summary['redirectsameip'] += 1
                          elif host in line:
                            report.write('<span class="datainfo">Redirect to same host</span>')
                            summary['redirectsamehost'] += 1
                          else:
                            if domain not in line.split('?')[0]:
                              pivottarget = line.split('?')[0].split(' ')[1].lstrip('https://').lstrip('http://').rstrip().rstrip('/').split('/')[0].replace('www.', '')
                              report.write('<span class="dataerror">Pivot Target: %s</span>' % pivottarget)
                              summary['redirectdifferentdomain'] += 1
                              if pivottarget not in summary['redirectpivottargets']:
                                summary['redirectpivottargets'].append(pivottarget)
                            else:
                              report.write('<span class="datawarning">Redirect to different IP/host in the domain</span>')
                              summary['redirectdifferentiphost'] += 1
                    if httpstatus[0] == "5":
                      report.write('<span class="datacritical">Server Error</span>')
                      summary['http5xx'] += 1

                if service.has_key('ssl'):
                  if service['ssl'].has_key('cert'):
                    if service['ssl']['cert'].has_key('subject'):
                      if service['ssl']['cert']['subject'].has_key('CN'):
                        report.write('<div class="ssl">SSL Subject: %s</div>' % (service['ssl']['cert']['subject']['CN'], ))
                        if domain not in service['ssl']['cert']['subject']['CN'].lower():
                          summary['sslnotdomain'] += 1
                          pivottarget = service['ssl']['cert']['subject']['CN'].lower().lstrip('*.').rstrip('/').replace('www.', '')
                          report.write('<span class="sslerror">Pivot Target: %s</span>' % pivottarget)
                          if pivottarget not in summary['sslpivottargets']:
                            summary['sslpivottargets'].append(pivottarget)
                        if service['ssl']['cert']['subject']['CN'][0] == "*":
                          report.write('<span class="sslwarning">Wildcard</span>')
                          summary['sslwildcard'] += 1
                    if service['ssl']['cert'].has_key('expired'):
                      if service['ssl']['cert']['expired']:
                        report.write('<span class="sslerror">Expired</span>')
                        summary['sslexpired'] += 1

                  if service['ssl'].has_key('versions'):
                    errorversions = ['TLSv1', 'SSLv2', 'SSLv3']
                    warnversions = ['TLSv1.1']
                    for version in service['ssl']['versions']:
                      if version in errorversions:
                        report.write('<span class="sslerror">%s</span>' % (version, ))
                        summary['sslerrorversion'] += 1
                      elif version in warnversions:
                        report.write('<span class="sslwarning">%s</span>' % (version, ))
                        summary['sslwarnversion'] += 1
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
                        summary['sslbadcipher'] += 1

                if service.has_key('vulns'):
                  report.write('<table class="vulnerability">\n')
                  report.write("<tr>")
                  report.write('<td align="center" width="150px">CVE</td>')
                  report.write('<td align="center" width="150px">CVSS</td>')
                  report.write('<td align="center">Summary</td>')
                  report.write("</tr>\n")
                  vulns = service['vulns']
		  for vuln in vulns:
                    summary['vulntotal'] += 1
                    if vulns[vuln].has_key('cvss') and vulns[vuln].has_key('summary'):
                      report.write("<tr>")
                      report.write('<td align="center">%s</td>' % (vuln, ))
                      report.write('<td align="center"')
                      cvss = vulns[vuln]['cvss']
                      if 0.1 <= float(cvss) < 4:
                        report.write(' bgcolor="yellow"')
                        summary['vulnlow'] += 1
                      elif 4 <= float(cvss) < 7:
                        report.write(' bgcolor="orange"')
                        summary['vulnmedium'] += 1
                      elif 7 <= float(cvss) < 9:
                        report.write(' bgcolor="red"')
                        summary['vulnhigh'] += 1
                      elif 9 <= float(cvss):
                        report.write(' bgcolor="purple"')
                        summary['vulncritical'] += 1
                      report.write('>%s</td>' % (cvss, ))
                      report.write("<td>%s</td>" % (vulns[vuln]['summary'], ))
                      report.write("</tr>\n")
                  report.write("</table>")
 
report.write('</body>\n')
report.write('</html>\n')
report.close()

sumfile = "%s-summary.html" % (domain.split(".")[0], )
sum = open(sumfile, "w")
sum.write("""<html>
  <head>
    <style>
      #map {
        height: 400px;
        width: 800px;
        align: center;
       }
    </style>
  </head>
  <body>
    Global Technology Distribution<br>
    <div id="map"></div>
    <script>
function initMap() {
  var center = {lat: 10, lng: 0};
""")


entrycounter = 1
for entry in summary['mapdata']:
  sum.write("  var point%s = {lat: %s, lng: %s};\n" % (str(entrycounter), entry['latitude'], entry['longitude']))
  entrycounter += 1
sum.write("  var map = new google.maps.Map(document.getElementById('map'), {zoom: 1.75, center: center});\n")

entrycounter = 1
for entry in summary['mapdata']:
  sum.write("  var marker%s = new google.maps.Marker({position: point%s, map: map});\n" % (entrycounter, entrycounter))
  entrycounter += 1

sum.write("""}
    </script>
    <script async defer
    src="https://maps.googleapis.com/maps/api/js?key=AIzaSyDCRRZ3p8yhxJP1-9IscmsxB78zAAL64AU&callback=initMap">
    </script>
""")

sum.write("<br>\n")
sum.write("Hosts: %s<br>\n" % (summary['hosts'], ))
if summary['cloudaws'] > 0:
  sum.write("AWS Hosts: %s<br>\n" % (str(summary['cloudaws']), ))
  sum.write("AWS Regions:<br>\n")
  for region in summary['cloudawsregions']:
    sum.write("%s<br>\n" % region)

sum.write("<br>IPs<br>\n")
sum.write("Total: %s<br>\n" % (summary['ips'], ))
sum.write("Private: %s<br>\n" % (summary['privateips'], ))
sum.write("Reserved: %s<br>\n" % (summary['reservedips'], ))

sum.write("<br>Services<br>\n")
sum.write("Total: %s<br>\n" % (summary['services'], ))
sum.write("Cloud: %s<br>\n" % (summary['cloudservices'], ))

sum.write("<br>HTTP<br>\n")
sum.write("WAF: %s<br>\n" % (summary['waf'], ))
sum.write("Web services that need to be hardened with an App-ID: %s<br>\n" % (summary['http200'], ))
sum.write("Redirects Total: %s<br>\n" % (summary['http3xx'], ))
sum.write("Proper redirects to the same host: %s<br>\n" % (summary['redirectsamehost'], ))
sum.write("Risky redirects to the same IP: %s<br>\n" % (summary['redirectsameip'], ))
sum.write("Redirects that need lifecycle management: %s<br>\n" % (summary['redirectdifferentiphost'], ))
sum.write("Potential pivot targets identified by redirect: %s<br>\n" % (summary['redirectdifferentdomain'], ))
sum.write("Application/Server Errors: %s<br>\n" % (summary['http5xx'], ))

sum.write("<br>SSL<br>\n")
sum.write("Wildcard Certificates: %s<br>\n" % (summary['sslwildcard'], ))
sum.write("Vulnerable TLS Mail Services: %s<br>\n" % (summary['starttlsservices'], ))
sum.write("Self-Signed Certificates: %s<br>\n" % (summary['selfsignedservices'], ))
sum.write("Insecure SSL Versions: %s<br>\n" % (summary['sslerrorversion'], ))
sum.write("Non-compliant SSL Versions: %s<br>\n" % (summary['sslwarnversion'], ))
sum.write("Bad SSL Ciphers: %s<br>\n" % (summary['sslbadcipher'], ))
sum.write("Expired Certificates: %s<br>\n" % (summary['sslexpired'], ))
sum.write("Potential pivot targets identified by SSL certificate: %s<br>\n" % (summary['sslnotdomain'], ))

sum.write("<br>Vulnerabilities<br>\n")
sum.write("Total: %s<br>\n" % (summary['vulntotal'], ))
sum.write("Low: %s<br>\n" % (summary['vulnlow'], ))
sum.write("Medium: %s<br>\n" % (summary['vulnmedium'], ))
sum.write("High: %s<br>\n" % (summary['vulnhigh'], ))
sum.write("Critical: %s<br>\n" % (summary['vulncritical'], ))
sum.write("<br>\n")

sum.write("Reverse DNS Pivot Targets<br>\n")
for target in summary['reversednspivottargets']:
  sum.write("%s<br>\n" % (target, ))
sum.write("<br>\n")
sum.write("Redirect Pivot Targets<br>\n")
for target in summary['redirectpivottargets']:
  sum.write("%s<br>\n" % (target, ))
sum.write("<br>\n")
sum.write("SSL Pivot Targets<br>\n")
for target in summary['sslpivottargets']:
  sum.write("%s<br>\n" % (target, ))
sum.write("</body></html>")
sum.close()
