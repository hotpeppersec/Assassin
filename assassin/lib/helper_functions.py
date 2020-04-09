# -*- coding: utf-8 -*-

import logging
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

# attach logger
logger = logging.getLogger('assassinLogger')


def convert_ip(ip):
    if type(ip) != str:
        ip = ip.decode("utf-8", "strict")
    return ip


def getDomainInfo(domain):
    ext = domain.split('.')

    print('Lookup %s.%s via Verisign' % (ext[0], ext[1]))
    logger.info('Lookup %s.%s via Verisign' % (ext[0], ext[1]))

    if ext[1] == "com":
        url = "https://rdap.verisign.com/com/v1/domain/%s" % (domain)
    elif ext[1] == "net":
        url = "https://rdap.verisign.com/net/v1/domain/%s" % (domain)
    else:
        print('See https://www.verisign.com/en_US/domain-names/registration-data-access-protocol/index.xhtml for documentation.')
        sys.exit()
    logger.debug('Checking %s with URL: %s' % (ext[1], url))
    try:
        jsonresponse = urlopen(url)
        response = json.loads(jsonresponse.read())
        logger.debug(response)
        return response
    except Exception as e:
        print(e)
        sys.exit()


def getDnsht(domain):
    print("Hacker Target")
    logger.info('Hacker Target')
    url = "https://api.hackertarget.com/hostsearch/?q=%s" % (domain)
    # we don't have a key for hacker target
    # url = "https://api.hackertarget.com/dnslookup/?q=%s&apikey=%s" % (domain,htKey)
    try:
        response = urlopen(url)
        html_response = response.read()
        encoding = response.headers.get_content_charset('utf-8')
        decoded_html = html_response.decode(encoding, 'ignore')
        logger.debug('Hacker Target response: %s' % decoded_html)
        if decoded_html == "error check your search parameter":
            logger.debug('Hacker Target says bad domain name')
            return False
        else:
            output = []
            lines = decoded_html.split("\n")
            for line in lines:
                fields = line.split(",")
                host = fields[0]
                output.append(host)
            print("Received %s hosts from Hacker Target" % (len(lines), ))
            logger.debug('Received %s hosts from Hacker Target' %
                         (len(lines), ))
            return output
    except Exception as err:
        logger.debug('Handling run-time error: %s', (err))
        return False
    print("Combined to a total of %s hosts" % len(output))
    logger.debug('Combined to a total of %s hosts' % len(output))
    if len(output) > 0:
        return(output)
    else:
        return False


def getFwdDns(host):
    if type(host) != str:
        host = host.decode("utf-8", "strict")
    output = []
    url = 'https://dns.google.com/resolve?name=%s&type=A' % (host, )
    try:
        output = []
        jsonresponse = urlopen(url)
        response = json.loads(jsonresponse.read())
        if 'Answer' in response:
            answers = response["Answer"]
            for answer in answers:
                if "data" in answer:
                    try:
                        output.append(answer["data"].encode("ascii"))
                    except:
                        pass
        return output
    except:
        return False


def getRevDns(ip):
    '''
    '''
    ip = convert_ip(ip)
    reverseip = ip_address(ip).reverse_pointer
    logger.debug('Checking reverse IP: %s' % reverseip)
    url = 'https://dns.google.com/resolve?name=%s&type=PTR' % (reverseip, )
    try:
        jsonresponse = urlopen(url)
        response = json.loads(jsonresponse.read())
        if "Answer" in response:
            answers = response["Answer"]
            for answer in answers:
                if "data" in answer:
                    if type(answer["data"]) != str:
                      answer["data"] = answer["data"].decode("utf-8", "strict")
                    return answer["data"]
    except:
        return False


def getShodan(ip, shodanKey):
    url = 'https://api.shodan.io/shodan/host/%s?key=%s' % (ip, shodanKey)
    try:
        jsonresponse = urlopen(url)
        response = json.loads(jsonresponse.read())
        return response
    except Exception as e:
        print('Shodan error: %s' % e)
        logger.info('Shodan error: %s' % e)
        return False


def checkPrivate(ip):
    '''
    Determine if an IPv4 address is private
    '''
    ip = convert_ip(ip)
    logger.debug('Check private IP: %s' % ip)
    if (ipaddress.ip_address(ip).is_private):
        return True
    else:
        return False


def checkReserved(ip):
    '''
    Determine if an IPv4 address is reserved
    '''
    ip = convert_ip(ip)
    logger.info('Check reserved IP: %s' % ip)
    if (ipaddress.ip_address(ip).is_reserved):
        return True
    else:
        return False


def getWhois(ip):
    '''
    Do a whois lookup on an IP address
    '''
    url = "http://rdap.arin.net/registry/ip/%s" % (ip, )
    try:
        jsonresponse = urlopen(url)
        response = json.loads(jsonresponse.read())
        if "name" in response:
            return response['name']
    except Exception as e:
        print(e)
        return False
