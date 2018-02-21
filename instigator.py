#!/usr/bin/env python
'''
=========================================================================================
 instigator.py: v0.62-20180221 Copyright (C) 2018 Chris Buijs <cbuijs@chrisbuijs.com>
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
from dnslib.server import DNSServer

# Regex module
import regex

# Use module pysubnettree
#import SubnetTree

# Listen for queries
listen_address = '192.168.1.250'
listen_port = 53

# Forwarding queries to
forward_address = '9.9.9.9' # Quad9
forward_port = 53
forward_timeout = 20 # Seconds

# Redirect when blacklisted, leave empty for "Refused"
redirect_address = '192.168.1.250'
#redirect_address = ''
redirect_host = 'sinkhole' # TODO: For CNAME, MX, PTR, SRV

# Dictionaries
bl_dom = dict()
#wl_dom = dict()
#bl_ip = dict()
#wl_ip = dict()
#bl_reg = dict()
#wl_reg = dict()

# Test
bl_dom['doubleclick.net'] = True
bl_dom['google-analytics.com'] = True

# Cache
cachesize = 2500
cachettl = 1800
cache = dict()
cacheindex = dict()

# Regex to filter regexes out
#isregex = regex.compile('^/.*/$')

# Regex to filter IP's out
ipregex = regex.compile('^(([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})*|([0-9a-f]{1,4}|:)(:([0-9a-f]{0,4})){1,7}(/[0-9]{1,3})*)$', regex.I)

# Regex to match domains/hosts in lists
#isdomain = regex.compile('^[a-z0-9\.\-]+$', regex.I) # According RFC, Internet only


# Check if entry matches a list
def in_list(type, bw, name):
    testname = name
    blacklisted = False
    if ipregex.match(testname):
        print ('Skipping ' + type + ' IP ' + testname)
    else:
        while True:
            if testname in bl_dom:
                blacklisted = True
                print ('HIT: ' + type + ' \"' + name + '\" matched against \"' + testname + '\"')
                break
            elif testname.find('.') == -1:
                break
            else:
                testname = testname[testname.find('.') + 1:]

    return blacklisted
       

# Generate response
def generate_response(request, qname, qtype, redirect_address):
    reply = request.reply()
    if (len(redirect_address) == 0) or (qtype not in ('A', 'CNAME', 'ANY')):
        print ('REFUSED for \"' + qname + '\" (RR:' + qtype + ')')
        reply.header.rcode = getattr(RCODE,'REFUSED')
        return reply
    else:
        print ('REDIRECT \"' + qname + '\" to \"' + redirect_address + '\" (RR:' + qtype + ')')
        answer = RR(ttl=cachettl, rdata=A(redirect_address))

    answer.set_rname(request.q.qname)
    reply.add_answer(answer)
    reply.header.rcode = getattr(RCODE,'NOERROR')

    return reply


def update_cache(msg):
    print('UPDATING CACHE FROM ' + msg)
    size = len(cacheindex)
    if (size > cachesize):
        index = sorted(cacheindex.keys())[0:size-cachesize]
        for i in index:
            print('CACHE EXPULSION: ' + str(cache[i].q.qname))
            del cache[i]
            del cacheindex[i]

    now = int(datetime.datetime.now().strftime("%s"))
    for query in cache.keys():
       expire = cacheindex[query]
       if expire - now < 0:
           print('CACHE EXPIRATION: ' + str(cache[query].q.qname))
           del cache[query]
           del cacheindex[query]
           
    return True

class DNS_Instigator(ProxyResolver):
    def __init__(self, forward_address, forward_port, forward_timeout, redirect_host, redirect_address):
        ProxyResolver.__init__(self, forward_address, forward_port, forward_timeout)

    def resolve(self, request, handler):
        qname = str(request.q.qname).rstrip('.').lower()
        qtype = QTYPE[request.q.qtype]
        query = str(request.q)
        fromcache = False
        if query in cache:
            expire = cacheindex[query]
            now = int(datetime.datetime.now().strftime("%s"))
            ttl = expire - now
            if ttl < 0:
                print('TTL EXPIRED FOR \"' + qname + '\"')
                ttl = 0
                del cache[query]
                del cacheindex[query]
            else:
                reply = cache[query]
                if (RCODE[reply.header.rcode] == 'NOERROR'):
                    id = request.header.id
                    reply.header.id = id
                    for record in reply.rr:
                        record.ttl = ttl
                    print('RETRIEVED \"' + qname + '/' + qtype + '\" FROM CACHE (TTL = ' + str(ttl) + ')')
                    fromcache = True

        if not fromcache:
            ttl = cachettl
            if in_list('QUERY', 'black', qname):
                reply = generate_response(request, qname, qtype, redirect_address)
            else:
                reply = ProxyResolver.resolve(self, request, handler)
                if (RCODE[reply.header.rcode] == 'NOERROR'):
                    qtype = QTYPE[reply.q.qtype]
                    query = str(reply.q)
                    if reply.rr:
                        ttl = min(x.ttl for x in reply.rr)
                        for record in reply.rr:
                            record.ttl = ttl
                            rqname = str(record.rname).rstrip('.').lower()
                            rqtype = QTYPE[record.rtype]
                            data = str(record.rdata).rstrip('.').lower()
                            if in_list('QUERY', 'black', rqname) or in_list('RESPONSE', 'black', data):
                                reply = generate_response(request, qname, qtype, redirect_address)
                                break
                else:
                    return reply
            
            cache[query] = reply
            now = int(datetime.datetime.now().strftime("%s"))
            expire = now + ttl
            cacheindex[query] = expire
            print('STORED \"' + qname + '/' + qtype + '\" INTO CACHE WITH TTL OF ' + str(ttl) + ' SECONDS')

        return reply


# The main beef
if __name__ == '__main__':

    # Resolver
    dns_resolver = DNS_Instigator(forward_address=forward_address, forward_port=forward_port, forward_timeout=forward_timeout, redirect_host=redirect_host, redirect_address=redirect_address) 

    # Server
    dns_server = DNSServer(dns_resolver, address=listen_address, port=listen_port)

    # Start server
    dns_server.start_thread()

    # Keep things running
    count = 0
    while dns_server.isAlive():
        count += 1
        if count > 60:
           count = 0
           update_cache('60 SECOND LOOP')
        else:
           time.sleep(1)
         

