# -*- coding: utf-8 -*-

import sys
import json
from ipaddress import ip_address
import ipaddress

try:
    # For Python 3.0 and later
    from urllib.request import urlopen
except ImportError:
    # Fall back to Python 2's urllib2
    from urllib2 import urlopen

'''
Configure logger
'''
import logging
from pathlib import Path
Path("/var/log/secops").mkdir(parents=True, exist_ok=True)
logging.basicConfig(
    filename="/var/log/secops/assassin.log",
    level=logging.DEBUG,
    format="[%(asctime)s] [%(filename)s:%(lineno)s - %(funcName)5s() - %(processName)s] %(levelname)s - %(message)s"
)


def convert_ip(ip):
    '''
    Convert bytes to utf-8
    '''
    if type(ip) != str:
        logging.debug('Converting ip: %s' % ip)
        ip = ip.decode("utf-8", "strict")
    return ip


def validate_ip(ip):
    '''
    Verify IP address is valid
    '''
    try:
        ipaddress.ip_address(ip)
    except ValueError as e:
        logging.debug('Failed validate_ip: %s' % (ip))
        logging.debug('Exception: %s' % e)
        return False
    logging.debug('Successful validate_ip: %s' % (ip))
    return True


def getDomainInfo(domain):
    ext = domain.split('.')

    print('Lookup %s.%s via Verisign' % (ext[0], ext[1]))
    logging.info('Lookup %s.%s via Verisign' % (ext[0], ext[1]))

    if ext[1] == "com":
        url = "https://rdap.verisign.com/com/v1/domain/%s" % (domain)
    elif ext[1] == "net":
        url = "https://rdap.verisign.com/net/v1/domain/%s" % (domain)
    else:
        print('See https://www.verisign.com/en_US/domain-names/registration-data-access-protocol/index.xhtml for documentation.')
        sys.exit()
    logging.debug('Checking %s with URL: %s' % (ext[1], url))
    try:
        jsonresponse = urlopen(url)
        response = json.loads(jsonresponse.read())
        logging.debug(response)
        return response
    except Exception as e:
        print(e)
        return ("Exception: %s" % e)


def getDnsht(domain):
    print("Hacker Target")
    logging.info('Hacker Target')
    url = "https://api.hackertarget.com/hostsearch/?q=%s" % (domain)
    # we don't have a key for hacker target
    # url = "https://api.hackertarget.com/dnslookup/?q=%s&apikey=%s" % (domain,htKey)
    try:
        response = urlopen(url)
        html_response = response.read()
        encoding = response.headers.get_content_charset('utf-8')
        decoded_html = html_response.decode(encoding, 'ignore')
        logging.debug('Hacker Target response: %s' % decoded_html)
    except Exception as err:
        logging.debug('Handling run-time error: %s', (err))
        return ("Exception: %s" % err)
    if decoded_html == "error check your search parameter":
        logging.debug('Hacker Target says bad domain name')
        return 'error check your search parameter'
    else:
        output = []
        lines = decoded_html.split("\n")
        for line in lines:
            fields = line.split(",")
            host = fields[0]
            output.append(host)
        print("Received %s hosts from Hacker Target" % (len(lines), ))
        logging.debug('Received %s hosts from Hacker Target' %  (len(lines), ))
        print("Combined to a total of %s hosts" % len(output))
        logging.debug('Combined to a total of %s hosts' % len(output))
        if len(output) > 0:
            return(output)
        else:
            return "err"


def getFwdDns(host):
    if type(host) != str:
        host = host.decode("utf-8", "strict")
    logging.debug('Checking %s in getFwdDns' % host)
    output = []
    url = 'https://dns.google.com/resolve?name=%s&type=A' % (host, )
    try:
        jsonresponse = urlopen(url)
        response = json.loads(jsonresponse.read())
    except Exception as e:
        logging.debug('Exception in getFwdDns: %s' % e)
        return ('Exception in getFwdDns: %s' % e)
    if 'Answer' in response:
        answers = response["Answer"]
        for answer in answers:
            if "data" in answer:
                if validate_ip(answer["data"]):
                    try:
                        logging.debug('getFwdDns adding to answers: %s ' % answer["data"])
                        output.append(answer["data"])
                    except Exception as e:
                        logging.debug('Exception in getFwdDns: %s' % e)
                        pass
                else:
                    return False
    return output


def getRevDns(ip):
    '''
    '''
    ip = convert_ip(ip)
    reverseip = ip_address(ip).reverse_pointer
    logging.debug('Checking reverse IP: %s' % reverseip)
    url = 'https://dns.google.com/resolve?name=%s&type=PTR' % (reverseip, )
    try:
        jsonresponse = urlopen(url)
        response = json.loads(jsonresponse.read())
    except Exception as e:
        logging.debug('Exception in getRevDns: %s' % e)
        return ('Exception in getRevDns: %s' % e)
    if "Answer" in response:
        answers = response["Answer"]
        for answer in answers:
            if "data" in answer:
                validate_ip(answer["data"])
                if type(answer["data"]) != str:
                    logging.debug('getRevDns adding to answers: %s ' % answer["data"])
                    answer["data"] = answer["data"].decode("utf-8", "strict")
                return answer["data"]



def getShodan(ip, shodanKey):
    validate_ip(ip)
    url = 'https://api.shodan.io/shodan/host/%s?key=%s' % (ip, shodanKey)
    try:
        jsonresponse = urlopen(url)
        response = json.loads(jsonresponse.read())
        return response
    except Exception as e:
        print('Shodan error: %s' % e)
        logging.info('Shodan error: %s' % e)
        return False


def checkPrivate(ip):
    '''
    Determine if an IPv4 address is private
    '''
    validate_ip(ip)
    try:
        logging.debug('Check private IP: %s' % ip)
        # if convert_ip failes it returns ValueError
        ip = convert_ip(ip)
    except ValueError as e:
        logging.debug('Check private IP failed: %s' % e)
        return False
    # Now perform True/False check
    if (ipaddress.ip_address(ip).is_private):
        logging.debug('Address in checkPrivate is private: %s' % ip)
        return True
    else:
        logging.debug('Address in checkPrivate is NOT private: %s' % ip)
        return False


def checkReserved(ip):
    '''
    Determine if an IPv4 address is reserved
    '''
    ip = convert_ip(ip)
    validate_ip(ip)
    logging.info('Check reserved IP: %s' % ip)
    if (ipaddress.ip_address(ip).is_reserved):
        logging.debug('Address in checkReserved is reserved: %s' % ip)
        return True
    else:
        logging.debug('Address in checkReserved is NOT reserved: %s' % ip)
        return False


def getWhois(ip):
    '''
    Do a whois lookup on an IP address
    '''
    validate_ip(ip)
    url = "http://rdap.arin.net/registry/ip/%s" % (ip, )
    try:
        jsonresponse = urlopen(url)
        response = json.loads(jsonresponse.read())
        if "name" in response:
            return response['name']
    except Exception as e:
        print(e)
        return False

__author__ = 'Franklin Diaz'
__copyright__ = ''
__credits__ = ['']
__license__ = 'http://www.apache.org/licenses/LICENSE-2.0'
__version__ = ''
__maintainer__ = ''
__email__ = 'fdiaz@paloaltonetworks.com'