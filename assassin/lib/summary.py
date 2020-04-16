# -*- coding: utf-8 -*-

import logging

logging.basicConfig(
    filename="/var/log/secops/assassin.log",
    level=logging.DEBUG,
    format="%(asctime)s:%(levelname)s:%(message)s"
    )


def generate_summary(sum, summary):
    logging.debug('Generating summary file')
    sum.write("<html>")
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