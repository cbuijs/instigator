#!/usr/bin/env python3
'''
=========================================================================================
 instigator.py: v0.96-20180425 Copyright (C) 2018 Chris Buijs <cbuijs@chrisbuijs.com>
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
sys.path.append("/usr/local/lib/python3.5/dist-packages/")

# Syslogging / Logging
import syslog
syslog.openlog(ident='INSTIGATOR')

# DNSLib module
from dnslib import RCODE, QTYPE, RR, A, AAAA, CNAME, MX, NS, PTR, SOA, SRV, TXT, RCODE, DNSRecord
from dnslib.proxy import ProxyResolver
from dnslib.server import DNSServer, DNSLogger

# Regex module
import regex

# Use module PyTricia for CIDR/Subnet stuff
import pytricia

# Use CacheTools TTLCache for cache
#from cachetools import TTLCache

# Use UUID's
import uuid

###################

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

# Files
blacklist = '/opt/instigator/black.list'
whitelist = '/opt/instigator/white.list'

# Cache Settings
cachesize = 1536 # Entries
cachettl = 1800 # Seconds

# TTL Settings
minttl = 120
maxttl = 7200
rcodettl = 600

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
cache = dict()
cacheindex = dict()
#wl_cache = TTLCache(cachesize, cachettl - 1) # Whitelist hit cache
#bl_cache = TTLCache(cachesize, cachettl - 1) # Blacklist hit cache

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

# Logging
def log_info(message):
    #print(message)
    syslog.syslog(syslog.LOG_INFO, message)
    return True


def log_err(tag, message):
    #print(message)
    syslog.syslog(syslog.LOG_ERR, message)
    return True


# Check if entry matches a list
def in_blacklist(rid, type, value, log):
    id = str(rid)
    testvalue = value

    #if (testvalue in wl_cache):
    #    if log: log_info('WHITELIST-CACHE-HIT [' + id + ']: ' + type + ' \"' + value + '\"')
    #    return False
    #elif isdomain.match(testvalue) and (testvalue in wl_dom):
    if isdomain.match(testvalue) and (testvalue in wl_dom):
        #wl_cache[value] = True
        if log: log_info('WHITELIST-HIT [' + id + ']: ' + type + ' \"' + value + '\" matched against \"' + testvalue + '\"')
        return False

    #if (testvalue in bl_cache):
    #    if log: log_info('BLACKLIST-CACHE-HIT [' + id + ']: ' + type + ' \"' + value + '\"')
    #    return True
    #elif isdomain.match(testvalue) and (testvalue in bl_dom):
    if isdomain.match(testvalue) and (testvalue in bl_dom):
        #bl_cache[value] = True
        if log: log_info('BLACKLIST-HIT [' + id + ']: ' + type + ' \"' + value + '\" matched against \"' + testvalue + '\"')
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
            if log: log_info('BLACKLIST-IP-HIT [' + id + ']: ' + type + ' ' + value + ' matched against ' + prefix)
            #bl_cache[value] = True
            return True
        elif prefix:
            if log: log_info('WHITELIST-IP-HIT [' + id + ']: ' + type + ' ' + value + ' matched against ' + prefix)
            return False

    else:
        if testvalue.find('.') > 0:
            testvalue = testvalue[testvalue.find('.') + 1:]
            while testvalue:
                if testvalue in wl_dom:
                    #wl_cache[value] = True
                    if log: log_info('WHITELIST-HIT [' + id + ']: ' + type + ' \"' + value + '\" matched against \"' + testvalue + '\"')
                    return False
                if testvalue in bl_dom:
                    #bl_cache[value] = True
                    if log: log_info('BLACKLIST-HIT [' + id + ']: ' + type + ' \"' + value + '\" matched against \"' + testvalue + '\"')
                    return True
                elif testvalue.find('.') == -1:
                    break
                else:
                    testvalue = testvalue[testvalue.find('.') + 1:]

    for i in wl_rx.keys():
        rx = wl_rx[i]
        if rx.match(value):
            if log: log_info('WHITELIST-REGEX-HIT [' + id + ']: ' + type + ' \"' + value + '\" matched against \"' + i + '\"')
            #wl_cache[value] = True
            return False

    for i in bl_rx.keys():
        rx = bl_rx[i]
        if rx.match(value):
            if log: log_info('BLACKLIST-REGEX-HIT [' + id + ']: ' + type + ' \"' + value + '\" matched against \"' + i + '\"')
            #bl_cache[value] = True
            return True

    return False
       

# Generate response
def generate_response(request, qname, qtype, redirect_address):
    reply = request.reply()
    if (len(redirect_address) == 0) or (qtype not in ('A', 'CNAME', 'ANY')):
        log_info('REFUSED for \"' + qname + '\" (RR:' + qtype + ')')
        reply.header.rcode = getattr(RCODE,'REFUSED')
        return reply
    else:
        log_info('REDIRECT \"' + qname + '\" to \"' + redirect_address + '\" (RR:' + qtype + ')')
        answer = RR(qname,QTYPE.A,ttl=cachettl,rdata=A(redirect_address))
        auth = RR(qname,QTYPE.SOA,ttl=cachettl,rdata=SOA('ns.sinkhole','hostmaster.sinkhole',(int(datetime.datetime.now().strftime("%s")),cachettl,cachettl,cachettl,cachettl)))
        ar = RR('ns.sinkhole',QTYPE.A,ttl=cachettl,rdata=A('0.0.0.0'))

    answer.set_rname(request.q.qname)
    reply.add_answer(answer)
    reply.add_auth(auth)
    reply.add_ar(ar)
    reply.header.rcode = getattr(RCODE,'NOERROR')

    return reply

def read_list(file, listname, domlist, iplist4, iplist6, rxlist):
    log_info('Reading \"' + listname + '\" (' + file + ')')

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
                        log_err(listname + ' INVALID LINE [' + str(count) + ']: ' + entry)

    except BaseException as err:
        log_err('ERROR: Unable to open/read/process file \"' + file + ' - ' + str(err))

    log_info(listname + ': ' + str(len(rxlist)) + ' REGEXes, ' + str(len(iplist4)) + ' IPv4 CIDRs, ' + str(len(iplist6)) + ' IPv6 CIDRs and ' + str(len(domlist)) + ' DOMAINs')

    return True


def normalize_ttl(rr, getmax):
    if len(rr) > 0:
        if getmax:
            ttl = max(x.ttl for x in rr)
        else:
            ttl = min(x.ttl for x in rr)

        if ttl < minttl:
            ttl = minttl
        elif ttl > maxttl:
            ttl = maxttl

    else:
        ttl = 0

    return ttl


def from_cache(qname, qtype, request):
    query = qname.replace('-','_') + '/' + qtype.upper()
    if query in cache:
        expire = cacheindex[query]
        now = int(datetime.datetime.now().strftime("%s"))
        ttl = expire - now

        if ttl < 0:
            log_info('CACHE-EXPIRED: ' + qname + '/' + qtype)
            del cache[query]
            del cacheindex[query]
            return False

        else:
            reply = cache[query]
            rcode = str(RCODE[reply.header.rcode])
            id = request.header.id
            reply.header.id = id

            #records = ''
            for record in reply.rr:
                record.ttl = ttl
                #rqname = str(record.rname).rstrip('.').lower()
                #rqtype = QTYPE[record.rtype].upper()
                #data = str(record.rdata).rstrip('.').lower()
                #if records:
                #    records = records + ', ' + rqname + '/' + rqtype + '=' + data
                #else:
                #    records = rqname + '/' + rqtype + '=' + data

            #log_info('CACHE-HIT: ' + qname + '/' + qtype + ' ' + rcode + ' (TTL:' + str(ttl) + ') [ ' + records + ' ]')
            log_info('CACHE-HIT: ' + qname + '/' + qtype + ' ' + rcode + ' (TTL:' + str(ttl) + ')')

            return reply

    return False


def to_cache(qname, qtype, reply):
    query = qname.replace('-','_') + '/' + qtype.upper()
    if query not in cache:
        now = int(datetime.datetime.now().strftime("%s"))

        ttl = normalize_ttl(reply.rr, True)

        rcode = str(RCODE[reply.header.rcode])
        if rcode in ('NODATA', 'NOTAUTH', 'NOTIMP', 'NXDOMAIN', 'REFUSED'):
            ttl = rcodettl

        if ttl > 0:
            cache[query] = reply
            expire = now + ttl
            cacheindex[query] = expire
            log_info('CACHE-STORED: ' + qname + '/' + qtype + ' ' + rcode + ' (TTL:' + str(ttl) + ')')

        return ttl

    return False


def cache_maintenance():
    #wl_cache.expire()
    #bl_cache.expire()

    size = len(cacheindex)
    if (size > cachesize):
        for i in sorted(list(cacheindex))[0:size-cachesize]:
            log_info('CACHE-MAINT-EXPULSION: ' + i)
            del cache[i]
            del cacheindex[i]

    now = int(datetime.datetime.now().strftime("%s"))
    for query in list(cache):
       expire = cacheindex[query]
       if expire - now < 0:
           log_info('CACHE-MAINT-EXPIRED: ' + query)
           del cache[query]
           del cacheindex[query]
    
    return True


class DNS_Instigator(ProxyResolver):
    def __init__(self, forward_address, forward_port, forward_timeout, redirect_address):
        ProxyResolver.__init__(self, forward_address, forward_port, forward_timeout)

    def resolve(self, request, handler):
        rid = str(uuid.uuid4().hex[:5])

        cip = str(handler.client_address).split('\'')[1]

        qname = str(request.q.qname).rstrip('.').lower()
        qtype = QTYPE[request.q.qtype]

        log_info('REQUEST [' + str(rid) + '] from ' + cip + ': ' + qname + ' ' + qtype)

        cachereply = from_cache(qname, qtype, request)
        if cachereply:
            reply = cachereply
        else:
            if in_blacklist(rid, 'REQUEST', qname, True):
                reply = generate_response(request, qname, qtype, redirect_address)
            else:
                reply = ProxyResolver.resolve(self, request, handler)
                if (RCODE[reply.header.rcode] == 'NOERROR'):
                    #qtype = QTYPE[reply.q.qtype]
                    if reply.rr:
                        replycount = 0
                        replynum = len(reply.rr)

                        ttl = normalize_ttl(reply.rr, True)

                        seen = set()

                        for record in reply.rr:
                            replycount += 1

                            rqname = str(record.rname).rstrip('.').lower()
                            rqtype = QTYPE[record.rtype]
                            record.ttl = ttl
                            data = str(record.rdata).rstrip('.').lower()

                            log_info('REPLY [' + str(rid) + ':' + str(replycount) + '-' + str(replynum) + ']: ' + rqname + ' ' + rqtype + ' = ' + data)

                            qlog = False
                            if rqname not in seen:
                                qlog = True
                                seen.add(rqname)

                            dlog = False
                            if data not in seen:
                                dlog = True
                                seen.add(data)

                            if rqname != qname and rqtype != qtype:
                                if in_blacklist(rid, 'REQUEST', rqname, qlog) or in_blacklist(rid, 'REPLY', data, dlog):
                                    reply=generate_response(request, qname, qtype, redirect_address)

                else:
                    data = str(RCODE[reply.header.rcode])
                    log_info('REPLY [' + str(rid) + ']: ' + qname + ' ' + qtype + ' = ' + data)

        to_cache(qname, qtype, reply)

        log_info('FINISHED [' + str(rid) + '] from ' + cip + ': ' + qname + ' ' + qtype)
        return reply


# The main beef
if __name__ == "__main__":

    # Read Lists
    read_list(whitelist, 'Whitelist', wl_dom, wl_ip4, wl_ip6, wl_rx)
    read_list(blacklist, 'Blacklist', bl_dom, bl_ip4, bl_ip6, bl_rx)

    # Resolver
    dns_resolver = DNS_Instigator(forward_address=forward_address, forward_port=forward_port, forward_timeout=forward_timeout, redirect_address=redirect_address) 

    # Server
    logger = DNSLogger(log='-recv,-send,-request,-reply,+error,+truncated,-data', prefix=False)
    dns_server = DNSServer(dns_resolver, address=listen_address, port=listen_port, logger=logger, tcp=False) # UDP
    #dns_server = DNSServer(dns_resolver, address=listen_address, port=listen_port, logger=logger, tcp=True)  # TCP

    # Start server
    log_info('Starting DNS Service ...')
    dns_server.start_thread()
    time.sleep(1)
    if dns_server.isAlive():
    	log_info('DNS Service ready on ' + listen_address + ':' + str(listen_port))
    else:
        log_err('DNS Service did not start, aborting ...')
        quit()

    # Keep things running
    count = 0
    try:
        while dns_server.isAlive():
            count += 1
            if count > 10:
               count = 0
               cache_maintenance()
            else:
               time.sleep(1)

    except KeyboardInterrupt:
        pass

    sys.exit(0)


# <EOF>
