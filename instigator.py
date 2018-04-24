#!/usr/bin/env python
'''
=========================================================================================
 instigator.py: v0.83-20180424 Copyright (C) 2018 Chris Buijs <cbuijs@chrisbuijs.com>
=========================================================================================

Python DNS Server with security and filtering features

This is a little study to build a DNS server in Python including some features:

- Blacklist/Whitelist DNS queries and responses based on domain, ip or regex
- Blacklisted DNS queries never leave the building

... to be elaborated

TODO:
- Loads ...
- Better Documentation / Remarks / Comments

=========================================================================================
'''

# Standard modules
import sys, time, datetime

# make sure modules can be found
sys.path.append("/usr/local/lib/python2.7/dist-packages/")

# DNSLib module
from dnslib import RCODE, QTYPE, RR, A, AAAA, CNAME, MX, NS, PTR, SOA, SRV, TXT, RCODE, DNSRecord
from dnslib.proxy import ProxyResolver
from dnslib.server import DNSServer, DNSLogger

# Regex module
import regex

# Use module PyTricia for CIDR/Subnet stuff
import pytricia

# Use CacheTools TTLCache for cache
from cachetools import TTLCache

# Listen for queries
listen_address = '192.168.1.250'
listen_port = 53

# Forwarding queries to
forward_address = '1.1.1.1' # CloudFlare
forward_port = 53
forward_timeout = 20 # Seconds

# Redirect Address, leave empty to generete REFUSED
#redirect_address = ''
redirect_address = '192.168.1.250' # IPv4 only
redirect_host = 'sinkhole' ### !!! TO BE DONE FOR CNAME, MX, SRV, etc... E.G. Records that point to a domainname.

# TTL settings
minttl = 120
maxttl = 3600

# Files
blacklist = '/opt/instigator/black.list'
whitelist = '/opt/instigator/white.list'

# Cache
cachesize = 2500 # Entries
cachettl = 1800 # Seconds

# List Dictionaries
wl_dom = dict() # Domain whitelist
bl_dom = dict() # Domain blacklist
wl_ip4 = pytricia.PyTricia(32) # IPv4 Whitelist
bl_ip4 = pytricia.PyTricia(32) # IPv4 Blacklist
wl_ip6 = pytricia.PyTricia(128) # IPv6 Whitelist
bl_ip6 = pytricia.PyTricia(128) # IPv6 Blacklist
wl_rx = dict() # Regex Whitelist
bl_rx = dict() # Regex Blacklist

# Cache Dictionaries
wl_cache = TTLCache(cachesize, cachettl - 1) # Whitelist hit cache
bl_cache = TTLCache(cachesize, cachettl - 1) # Blacklist hit cache

# Regex to filter IP's out
ip4regex_text = '((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}(/(3[0-2]|[12]?[0-9]))*)'
ip6regex_text = '(((:(:[0-9a-f]{1,4}){1,7}|::|[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){1,6}|::|:[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){1,5}|::|:[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){1,4}|::|:[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){1,3}|::|:[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){1,2}|::|:[0-9a-f]{1,4}(::[0-9a-f]{1,4}|::|:[0-9a-f]{1,4}(::|:[0-9a-f]{1,4}))))))))|(:(:[0-9a-f]{1,4}){0,5}|[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){0,4}|:[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){0,3}|:[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){0,2}|:[0-9a-f]{1,4}(:(:[0-9a-f]{1,4})?|:[0-9a-f]{1,4}(:|:[0-9a-f]{1,4})))))):(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3})(/(12[0-8]|1[01][0-9]|[1-9]?[0-9]))*)'
ipregex4 = regex.compile('^' + ip4regex_text + '$', regex.I)
ipregex6 = regex.compile('^' + ip6regex_text + '$', regex.I)
ipregex = regex.compile('^(' + ip4regex_text + '|' + ip6regex_text +')$', regex.I)

# Regex to match domains/hosts in lists
isdomain = regex.compile('^[a-z0-9\.\-]+$', regex.I) # According RFC, Internet only

# Regex to filter regexes out
isregex = regex.compile('^/.*/$')

##############################################################

# Check if entry matches a list
def in_blacklist(type, value):
    testvalue = value

    if (testvalue in wl_cache):
        print('WHITELIST-CACHE-HIT: ' + type + ' \"' + value + '\"')
        return False
    elif isdomain.match(testvalue) and (testvalue in wl_dom):
        wl_cache[value] = True
        print('WHITELIST-HIT: ' + type + ' \"' + value + '\" matched against \"' + testvalue + '\"')
        return False

    if (testvalue in bl_cache):
        print('BLACKLIST-CACHE-HIT: ' + type + ' \"' + value + '\"')
        return True
    elif isdomain.match(testvalue) and (testvalue in bl_dom):
        bl_cache[value] = True
        print('BLACKLIST-HIT: ' + type + ' \"' + value + '\" matched against \"' + testvalue + '\"')
        return True

    if type == 'REPLY' and ipregex.match(testvalue):
        found = False
        prefix = False
        if ipregex4.match(testvalue):
            wip = wl_ip4
            bip = bl_ip4
        else:
            wip = wl_ip6
            bip = bl_ip6

        if not testvalue in wip:
            if testvalue in bip:
                prefix = bip.get_key(testvalue)
                found = True
        else:
            prefix = wip.get_key(testvalue)

        if found:
            print('BLACKLIST-IP-HIT: ' + type + ' ' + value + ' matched against ' + prefix)
            bl_cache[value] = True
            return True
        elif prefix:
            print('WHITELIST-IP-HIT: ' + type + ' ' + value + ' matched against ' + prefix)
            return False

    else:
        if testvalue.find('.') > 0:
            testvalue = testvalue[testvalue.find('.') + 1:]
            while testvalue:
                if testvalue in wl_dom:
                    wl_cache[value] = True
                    print('WHITELIST-HIT: ' + type + ' \"' + value + '\" matched against \"' + testvalue + '\"')
                    return False
                if testvalue in bl_dom:
                    bl_cache[value] = True
                    print('BLACKLIST-HIT: ' + type + ' \"' + value + '\" matched against \"' + testvalue + '\"')
                    return True
                elif testvalue.find('.') == -1:
                    break
                else:
                    testvalue = testvalue[testvalue.find('.') + 1:]

    for i in wl_rx.keys():
        rx = wl_rx[i]
        if rx.match(value):
            print('WHITELIST-REGEX-HIT: ' + type + ' \"' + value + '\" matched against \"' + i + '\"')
            wl_cache[value] = True
            return False

    for i in bl_rx.keys():
        rx = bl_rx[i]
        if rx.match(value):
            print('BLACKLIST-REGEX-HIT: ' + type + ' \"' + value + '\" matched against \"' + i + '\"')
            bl_cache[value] = True
            return True

    return False
       

# Generate response
def generate_response(request, qname, qtype, redirect_address):
    reply = request.reply()
    if (len(redirect_address) == 0) or (qtype not in ('A', 'CNAME', 'ANY')):
        print('REFUSED for \"' + qname + '\" (RR:' + qtype + ')')
        reply.header.rcode = getattr(RCODE,'REFUSED')
        return reply
    else:
        print('REDIRECT \"' + qname + '\" to \"' + redirect_address + '\" (RR:' + qtype + ')')
        #answer = RR(ttl=cachettl, rdata=A(redirect_address))
        answer = RR(ttl=minttl, rdata=A(redirect_address))

    answer.set_rname(request.q.qname)
    reply.add_answer(answer)
    reply.header.rcode = getattr(RCODE,'NOERROR')

    return reply

def read_list(file, listname, domlist, iplist4, iplist6, rxlist):
    print('Reading \"' + listname + '\" (' + file + ')')

    count = 0
    try:
        with open(file, 'r') as f:
            for line in f:
                count += 1
                entry = line.replace('\r', '').replace('\n', '').strip().lower()
                if not (entry.startswith("#")) and not (len(entry) == 0):
                    if isregex.match(entry):
                        rx = entry.strip('/')
                        rxlist[rx] = regex.compile(rx, regex.I)
                    elif ipregex4.match(entry):
                        iplist4[entry] = True
                    elif ipregex6.match(entry):
                        iplist6[entry] = True
                    elif isdomain.match(entry):
                        domlist[entry] = True
                    else:
                        print(listname + ' INVALID LINE [' + str(count) + ']: ' + entry)

    except BaseException as err:
             print('ERROR: Unable to open/read/process file \"' + file + ' - ' + str(err))

    print(listname + ': ' + str(len(rxlist)) + ' REGEXes, ' + str(len(iplist4)) + ' IPv4 CIDRs, ' + str(len(iplist6)) + ' IPv6 CIDRs and ' + str(len(domlist)) + ' DOMAINS')

    return True


def normalize_ttl(rr):
    ttl = min(x.ttl for x in rr)
    if ttl < minttl:
        ttl = minttl
    elif ttl > maxttl:
        ttl = maxttl

    return ttl


class DNS_Instigator(ProxyResolver):
    def __init__(self, forward_address, forward_port, forward_timeout, redirect_host, redirect_address):
        ProxyResolver.__init__(self, forward_address, forward_port, forward_timeout)

    def resolve(self, request, handler):
        qname = str(request.q.qname).rstrip('.').lower()
        qtype = QTYPE[request.q.qtype]
        query = str(request.q)

        if in_blacklist('REQUEST', qname):
            print('CHECK-REQUEST: ', qname, qtype)
            reply = generate_response(request, qname, qtype, redirect_address)
        else:
            reply = ProxyResolver.resolve(self, request, handler)
            if (RCODE[reply.header.rcode] == 'NOERROR'):
                qtype = QTYPE[reply.q.qtype]
                query = str(reply.q)
                if reply.rr:
                    ttl = normalize_ttl(reply.rr)
                    for record in reply.rr:
                        record.ttl = ttl
                        rqname = str(record.rname).rstrip('.').lower()
                        rqtype = QTYPE[record.rtype]
                        data = str(record.rdata).rstrip('.').lower()
                        print('CHECK-REPLY: ', rqname, rqtype, data)
                        if in_blacklist('REQUEST', rqname) or in_blacklist('REPLY', data):
                            reply = generate_response(request, qname, qtype, redirect_address)
                            break

            else:
                return reply
           
        return reply


# The main beef
if __name__ == '__main__':

    # Read Lists
    read_list(whitelist, 'Whitelist', wl_dom, wl_ip4, wl_ip6, wl_rx)
    read_list(blacklist, 'Blacklist', bl_dom, bl_ip4, bl_ip6, bl_rx)

    # Resolver
    dns_resolver = DNS_Instigator(forward_address=forward_address, forward_port=forward_port, forward_timeout=forward_timeout, redirect_host=redirect_host, redirect_address=redirect_address) 

    # Server
    logger = DNSLogger(log='request, reply, truncated, error', prefix=False)
    dns_server = DNSServer(dns_resolver, address=listen_address, port=listen_port, logger=logger)

    # Start server
    print('Starting DNS Service ...')
    dns_server.start_thread()
    print('DNS Service ready on ' + listen_address + ':' + str(listen_port))

    # Keep things running
    count = 0
    while dns_server.isAlive():
        count += 1
        if count > 30:
           count = 0
           wl_cache.expire()
           bl_cache.expire()
        else:
           time.sleep(1)
         
    quit()

# <EOF>
