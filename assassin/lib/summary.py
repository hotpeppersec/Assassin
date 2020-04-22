# -*- coding: utf-8 -*-

import logging
from pathlib import Path


def add_map_style(sum):
    '''
    Write the map style element to the HTML header
    '''
    logging.debug('Write the map style element to the HTML header')
    sum.write('<style>\n')
    sum.write('  #map {\n')
    sum.write('    height: 400px;\n')
    sum.write('    width: 800px;\n')
    sum.write('    align: center;\n')
    sum.write('   }\n')
    sum.write('</style>\n')


def add_map_to_summary(sum, summary, GoogleMapsKey):
    '''
    Write the map points and call the Google Maps API
    '''
    logging.debug('Write the map points and call the Google Maps API')
    sum.write('Global Technology Distribution<br>\n')
    sum.write('<div id="map"></div>')
    sum.write('<script>')
    sum.write('function initMap() {')
    sum.write('  var center = {lat: 10, lng: 0};')
    entrycounter = 1
    if 'mapdata' in summary:
        for entry in summary['mapdata']:
            sum.write("  var point%s = {lat: %s, lng: %s};\n" % (str(entrycounter), entry['latitude'], entry['longitude']))
            entrycounter += 1
        sum.write("  var map = new google.maps.Map(document.getElementById('map'), {zoom: 1.75, center: center});\n")

        entrycounter = 1
        for entry in summary['mapdata']:
            sum.write("  var marker%s = new google.maps.Marker({position: point%s, map: map});\n" % (entrycounter, entrycounter))
            entrycounter += 1
    else:
        logging.debug('No mapdata key in summary dict')
    sum.write("}\n")
    sum.write("</script>\n")
    sum.write('<script async defer src="https://maps.googleapis.com/maps/api/js?key=%s&callback=initMap">\n' % (GoogleMapsKey, ))
    sum.write("</script>\n")
    sum.write("<br>\n")


def generate_summary(sum, summary, GoogleMapsKey):
    logging.debug('Generating summary file')
    sum.write("<html>\n<head>\n")
    if 'mapdata' in summary and GoogleMapsKey:
        add_map_style(sum)
    sum.write("</head>\n")
    if 'mapdata' in summary and GoogleMapsKey:
        add_map_to_summary(sum, summary, GoogleMapsKey)
    if 'hosts' in summary:
        sum.write("Hosts: %s<br>\n" % (summary['hosts'], ))
    if 'nonprod' in summary:
        sum.write("Non-Production Hosts: %s<br>\n" %
                  (str(summary['nonprod']), ))
    if 'cloudaws' in summary:
        sum.write("AWS Hosts: %s<br>\n" % (str(summary['cloudaws']), ))
        if 'cloudawsregions' in summary:
            sum.write("AWS Regions:<br>\n")
            for region in summary['cloudawsregions']:
                sum.write("%s<br>\n" % region)
    if 'cloudgcp' in summary:
        sum.write("GCP Hosts: %s<br>\n" % (str(summary['cloudgcp']), ))

    sum.write("<br>IPs<br>\n")
    if 'ips' in summary:
        sum.write("Total: %s<br>\n" % (summary['ips'], ))
    if 'privateips' in summary:
        sum.write("Private: %s<br>\n" % (summary['privateips'], ))
    if 'reservedips' in summary:
        sum.write("Reserved: %s<br>\n" % (summary['reservedips'], ))

    sum.write("<br>Services<br>\n")
    if 'sevices' in summary:
        sum.write("Total: %s<br>\n" % (summary['services'], ))
    if 'cloudservices' in summary:
        sum.write("Cloud: %s<br>\n" % (summary['cloudservices'], ))

    sum.write("<br>HTTP Hardening<br>\n")
    if 'waf' in summary:
        sum.write("Web services protected by a WAF: %s<br>\n" %
                  (summary['waf'], ))
    if 'http1' in summary:
        sum.write("Web services that respond to HTTP/1.0 requests: %s<br>\n" %
                  (summary['http1'], ))
    if 'serviceversions' in summary:
        sum.write("Web services that identify their version: %s<br>\n" %
                  (summary['serviceversions'], ))
    if 'servicephp' in summary:
        sum.write("Web Services Utilizing PHP: %s<br>\n" %
                  (summary['servicephp'], ))
    if 'serviceasp' in summary:
        sum.write("Web Services Utilizing ASP: %s<br>\n" %
                  (summary['serviceasp'], ))
    if 'http200' in summary:
        sum.write("Web services that need to be hardened with an App-ID: %s<br>\n" %
                  (summary['http200'], ))
    if 'htmlforms' in summary:
        sum.write("HTML Forms Detected: %s<br>\n" % (summary['htmlforms'], ))
    if 'keyleaks' in summary:
        sum.write("Possible API Key Leaks Detected: %s<br>\n" %
                  (summary['keyleaks'], ))
    if 'http3xx' in summary:
        sum.write("Redirects Total: %s<br>\n" % (summary['http3xx'], ))
    if 'redirectsamehost' in summary:
        sum.write("Proper redirects to the same DNS host: %s<br>\n" %
                  (summary['redirectsamehost'], ))
    if 'redirectsameip' in summary:
        sum.write("Redirects to the same IP (should point to DNS name instead): %s<br>\n" % (
            summary['redirectsameip'], ))
    if 'redirectdifferentiphost' in summary:
        sum.write("Redirects to the same domain (need lifecycle management): %s<br>\n" % (
            summary['redirectdifferentiphost'], ))
    if 'redirectdifferentdomain' in summary:
        sum.write("Redirects to different domains (pivot targets): %s<br>\n" %
                  (summary['redirectdifferentdomain'], ))
    if 'http5xx' in summary:
        sum.write("Application/Server Errors: %s<br>\n" %
                  (summary['http5xx'], ))
    if 'serviceeol' in summary:
        sum.write("End-of-life Services: %s<br>\n" % (summary['serviceeol'], ))
    if 'serviceeos' in summary:
        sum.write("End-of-support Services: %s<br>\n" %
                  (summary['serviceeos'], ))

    sum.write("<br>SSL<br>\n")
    if 'sslwildcard' in summary:
        sum.write("Wildcard Certificates: %s<br>\n" %
                  (summary['sslwildcard'], ))
    if 'starttlsservices' in summary:
        sum.write("Vulnerable TLS Mail Services: %s<br>\n" %
                  (summary['starttlsservices'], ))
    if 'selfsignedservices' in summary:
        sum.write("Self-Signed Certificates: %s<br>\n" %
                  (summary['selfsignedservices'], ))
    if 'sslerrorversion' in summary:
        sum.write("Insecure SSL Versions: %s<br>\n" %
                  (summary['sslerrorversion'], ))
    if 'sslwarnversion' in summary:
        sum.write("Non-compliant SSL Versions: %s<br>\n" %
                  (summary['sslwarnversion'], ))
    if 'sslwarnversion' in summary:
        sum.write("Weak SSL Ciphers: %s<br>\n" % (summary['sslwarnversion'], ))
    if 'sslexpired' in summary:
        sum.write("Expired Certificates: %s<br>\n" % (summary['sslexpired'], ))
    if 'sslnotdomain' in summary:
        sum.write("Potential pivot targets identified by SSL certificate: %s<br>\n" % (
            summary['sslnotdomain'], ))
    sum.write("<br>Vulnerabilities<br>\n")
    if 'vulntotal' in summary:
        sum.write("Total: %s<br>\n" % (summary['vulntotal'], ))
    if 'vulnlow' in summary:
        sum.write("Low: %s<br>\n" % (summary['vulnlow'], ))
    if 'vulnmedium' in summary:
        sum.write("Medium: %s<br>\n" % (summary['vulnmedium'], ))
    if 'vulnhigh' in summary:
        sum.write("High: %s<br>\n" % (summary['vulnhigh'], ))
    if 'vulncritical' in summary:
        sum.write("Critical: %s<br>\n" % (summary['vulncritical'], ))
    if 'reversednspivottargets' in summary:
        sum.write("<br>Reverse DNS Pivot Targets<br>\n")
        for target in summary['reversednspivottargets']:
            sum.write("%s<br>\n" % (target, ))
    if 'redirectpivottargets' in summary:
        sum.write("<br>Redirect Pivot Targets<br>\n")
        for target in summary['redirectpivottargets']:
            sum.write("%s<br>\n" % (target, ))
    if 'sslpivottargets' in summary:
        sum.write("<br>SSL Pivot Targets<br>\n")
        for target in summary['sslpivottargets']:
            sum.write("%s<br>\n" % (target, ))
    sum.write("</body></html>")
    sum.close()


__author__ = 'Franklin Diaz'
__copyright__ = ''
__credits__ = ['']
__license__ = 'http://www.apache.org/licenses/LICENSE-2.0'
__version__ = ''
__maintainer__ = ''
__email__ = 'fdiaz@paloaltonetworks.com'