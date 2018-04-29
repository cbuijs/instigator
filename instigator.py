#!/usr/bin/env python3
'''
=========================================================================================
 instigator.py: v1.20-20180429 Copyright (C) 2018 Chris Buijs <cbuijs@chrisbuijs.com>
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
from dnslib import QTYPE, RR, A, AAAA, CNAME, MX, NS, PTR, SOA, SRV, TXT, RCODE, DNSRecord, DNSQuestion
from dnslib.proxy import ProxyResolver
from dnslib.server import DNSServer, DNSLogger

# Regex module
import regex

# Use module PyTricia for CIDR/Subnet stuff
import pytricia

# Use UUID's
import uuid

###################

# Listen for queries
listen_address = '192.168.1.250'
listen_port = 53

# Forwarding queries to
forward_address = '1.1.1.1' # CloudFlare
forward_port = 53
forward_timeout = 3 # Seconds

# Redirect Address, leave empty to generete REFUSED
#redirect_address = ''
redirect_address = '192.168.1.250' # IPv4 only

# Files / Lists
lists = dict()
lists['blacklist'] = '/opt/instigator/black.list'
lists['whitelist'] = '/opt/instigator/white.list'
lists['aliases'] = '/opt/instigator/aliases.list'
#lists['ads'] = '/opt/instigator/shallalist/adv/domains'
#lists['banking'] = '/opt/instigator/shallalist/finance/banking/domains'
#lists['costtraps'] = '/opt/instigator/shallalist/costtraps/domains'
#lists['porn'] = '/opt/instigator/shallalist/porn/domains'
#lists['gamble'] = '/opt/instigator/shallalist/gamble/domains'
#lists['spyware'] = '/opt/instigator/shallalist/spyware/domains'
#lists['trackers'] = '/opt/instigator/shallalist/tracker/domains'
#lists['updatesites'] = '/opt/instigator/shallalist/updatesites/domains'
#lists['warez'] = '/opt/instigator/shallalist/warez/domains'
blacklist = list(['blacklist', 'ads', 'costtraps', 'porn', 'gamble', 'spyware', 'warez'])
whitelist = list(['whitelist', 'aliases', 'banking', 'updatesites'])

# Cache Settings
cachesize = 2048 # Entries

# TTL Settings
cachettl = 1800 # Seconds - For filtered/blacklisted entry caching
minttl = 120 # Seconds
maxttl = 7200 # Seconds
rcodettl = minttl # Seconds - For return-codes caching

# Collapse CNAME Chains
collapse = True

# Block IPv6 queries
blockv6 = True

# List Dictionaries
wl_dom = dict() # Domain whitelist
bl_dom = dict() # Domain blacklist
wl_ip4 = pytricia.PyTricia(32) # IPv4 Whitelist
bl_ip4 = pytricia.PyTricia(32) # IPv4 Blacklist
wl_ip6 = pytricia.PyTricia(128) # IPv6 Whitelist
bl_ip6 = pytricia.PyTricia(128) # IPv6 Blacklist
wl_rx = dict() # Regex Whitelist
bl_rx = dict() # Regex Blacklist
aliases = dict()

# Cache Dictionaries
cache = dict()
cacheindex = dict()

# Regex to filter IP's out
ip4regex_text = '((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}(/(3[0-2]|[12]?[0-9]))*)'
ip6regex_text = '(((:(:[0-9a-f]{1,4}){1,7}|::|[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){1,6}|::|:[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){1,5}|::|:[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){1,4}|::|:[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){1,3}|::|:[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){1,2}|::|:[0-9a-f]{1,4}(::[0-9a-f]{1,4}|::|:[0-9a-f]{1,4}(::|:[0-9a-f]{1,4}))))))))|(:(:[0-9a-f]{1,4}){0,5}|[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){0,4}|:[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){0,3}|:[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){0,2}|:[0-9a-f]{1,4}(:(:[0-9a-f]{1,4})?|:[0-9a-f]{1,4}(:|:[0-9a-f]{1,4})))))):(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3})(/(12[0-8]|1[01][0-9]|[1-9]?[0-9]))*)'
ipregex4 = regex.compile('^' + ip4regex_text + '$', regex.I)
ipregex6 = regex.compile('^' + ip6regex_text + '$', regex.I)
ipregex = regex.compile('^(' + ip4regex_text + '|' + ip6regex_text + ')$', regex.I)

# Regex to match domains/hosts in lists
isdomain = regex.compile('^[a-z0-9\.\-\_]+$', regex.I) # Based on RFC1035 plus underscore

# Regex to filter regexes out
isregex = regex.compile('^/.*/$')

##############################################################


# Log INFO messages to syslog
def log_info(message):
    #print(message)
    syslog.syslog(syslog.LOG_INFO, message)
    return True


# Log ERR messages to syslog
def log_err(message):
    #print(message)
    syslog.syslog(syslog.LOG_ERR, message)
    return True


# Check if entry matches a list
def in_blacklist(rid, type, rrtype, value, log):
    id = str(rid)
    testvalue = value

    itisanip = False
    itisadomain = False

    if type == 'REPLY' and rrtype in ('A', 'AAAA') and ipregex.match(testvalue):
        itisanip = True
    else:
        if type == 'REPLY':
            field = False
            if rrtype in ('CNAME', 'NS', 'PTR') and isdomain.match(testvalue):
                itisadomain = True
            elif type == 'MX':
                field = 1
            elif type == 'SOA':
                field = 0
            elif type == 'SRV':
                field = 2

            if field:
                testvalue = regex.split('\s+', testvalue)[field].rstrip('.')
                if isdomain.match(testvalue):
                    itisadomain = True

        else:
            if isdomain.match(testvalue):
                itisadomain = True

    if itisadomain:
        if testvalue in wl_dom:
            if log: log_info('WHITELIST-HIT [' + id + ']: ' + type + ' \"' + value + '\" matched against \"' + testvalue + '\"')
            return False
        elif testvalue in bl_dom:
            if log: log_info('BLACKLIST-HIT [' + id + ']: ' + type + ' \"' + value + '\" matched against \"' + testvalue + '\"')
            return True

    # Check against IP-Lists
    if itisanip:
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
            return True
        elif prefix:
            if log: log_info('WHITELIST-IP-HIT [' + id + ']: ' + type + ' ' + value + ' matched against ' + prefix)
            return False

    # Check against Sub-Domain-Lists
    elif itisadomain and testvalue.find('.') > 0:
        testvalue = testvalue[testvalue.find('.') + 1:]
        while testvalue:
            if testvalue in wl_dom:
                if log: log_info('WHITELIST-HIT [' + id + ']: ' + type + ' \"' + value + '\" matched against \"' + testvalue + '\"')
                return False
            if testvalue in bl_dom:
                if log: log_info('BLACKLIST-HIT [' + id + ']: ' + type + ' \"' + value + '\" matched against \"' + testvalue + '\"')
                return True
            elif testvalue.find('.') == -1:
                break
            else:
                testvalue = testvalue[testvalue.find('.') + 1:]

    # Check agains Regex-Lists
    for i in wl_rx.keys():
        rx = wl_rx[i]
        if rx.match(value):
            if log: log_info('WHITELIST-REGEX-HIT [' + id + ']: ' + type + ' \"' + value + '\" matched against \"' + i + '\"')
            return False

    for i in bl_rx.keys():
        rx = bl_rx[i]
        if rx.match(value):
            if log: log_info('BLACKLIST-REGEX-HIT [' + id + ']: ' + type + ' \"' + value + '\" matched against \"' + i + '\"')
            return True

    return False


# Generate response when blocking
def generate_response(request, qname, qtype, redirect_address):
    reply = request.reply()
    if (len(redirect_address) == 0) or (qtype not in ('A', 'CNAME', 'ANY')):
        log_info('REFUSED for \"' + qname + '\" (RR:' + qtype + ')')
        reply.header.rcode = getattr(RCODE, 'REFUSED')
        return reply
    else:
        log_info('REDIRECT \"' + qname + '\" to \"' + redirect_address + '\" (RR:' + qtype + ')')
        answer = RR(qname, QTYPE.A, ttl=cachettl, rdata=A(redirect_address))
        #auth = RR(qname, QTYPE.SOA, ttl=cachettl, rdata=SOA('ns.sinkhole','hostmaster.sinkhole',(int(datetime.datetime.now().strftime("%s")), cachettl, cachettl, cachettl, cachettl)))
        #ar = RR('ns.sinkhole', QTYPE.A, ttl=cachettl, rdata=A('0.0.0.0'))

    answer.set_rname(request.q.qname)
    reply.add_answer(answer)
    #reply.add_auth(auth)
    #reply.add_ar(ar)
    reply.header.rcode = getattr(RCODE, 'NOERROR')

    return reply


# Read filter lists
def read_list(file, listname, domlist, iplist4, iplist6, rxlist, alist):
    log_info('Fetching \"' + listname + '\" entries from \"' + file + '\"')

    count = 0

    try:
        with open(file, 'r') as f:
            for line in f:
                count += 1
                line = regex.sub('\s*#[^#]*$', '', line.replace('\r', '').replace('\n', ''))
                entry = line.strip().lower().rstrip('.')
                if len(entry) > 0:
                    if isregex.match(entry):
                        rx = entry.strip('/')
                        rxlist[rx] = regex.compile(rx, regex.I)
                    elif isdomain.match(entry):
                        domlist[entry] = True
                    elif ipregex4.match(entry):
                        iplist4[entry] = True
                    elif ipregex6.match(entry):
                        iplist6[entry] = True
                    elif entry.find('='):
                        elements = entry.split('=')
                        domain = elements[0].strip().lower().rstrip('.')
                        alias = elements[1].strip().lower().rstrip('.')
                        if isdomain.match(domain) and (isdomain.match(alias) or ipregex.match(alias)):
                       	    alist[domain] = alias
                    else:
                        log_err(listname + ' INVALID LINE [' + str(count) + ']: ' + entry)

    except BaseException as err:
        log_err('ERROR: Unable to open/read/process file \"' + file + '\" - ' + str(err))

    log_info(listname + ': ' + str(len(rxlist)) + ' REGEXes, ' + str(len(iplist4)) + ' IPv4 CIDRs, ' + str(len(iplist6)) + ' IPv6 CIDRs and ' + str(len(domlist)) + ' DOMAINs')

    return domlist, iplist4, iplist6, rxlist, alist


# Normalize TTL's, take either lowest or highest TTL for all records in RRSET
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


# Retrieve from cache
def from_cache(qname, qtype, request):
    query = qname.replace('-', '_') + '/' + qtype.upper()
    if query in cache:
        expire = cacheindex[query]
        now = int(datetime.datetime.now().strftime("%s"))
        ttl = expire - now

        # If expired, remove from cache
        if ttl < 1:
            log_info('CACHE-EXPIRED: ' + qname + '/' + qtype)
            del cache[query]
            del cacheindex[query]
            return False

        # Retrieve from cache
        else:
            reply = cache[query]
            rcode = str(RCODE[reply.header.rcode])
            id = request.header.id
            reply.header.id = id

            # Gather address and non-address records and do round-robin
            if len(reply.rr) > 1:
                addr = list()
                nonaddr = list()
                for record in reply.rr:
                    record.ttl = ttl
                    rqtype = QTYPE[record.rtype]
                    if rqtype in ('A', 'AAAA'):
                        addr.append(record)
                    else:
                        nonaddr.append(record)

                if len(addr) > 1:
                    addr = round_robin(addr)
                    reply.rr = nonaddr + addr

            else:
                for record in reply.rr:
                    record.ttl = ttl

            log_info('CACHE-HIT: ' + qname + '/' + qtype + ' ' + rcode + ' (TTL-LEFT:' + str(ttl) + ')')

            return reply

    return False


# Store into cache
def to_cache(qname, qtype, reply):
    query = qname.replace('-', '_') + '/' + qtype.upper()

    now = int(datetime.datetime.now().strftime("%s"))

    ttl = normalize_ttl(reply.rr, True)

    rcode = str(RCODE[reply.header.rcode])
    if rcode in ('NODATA', 'NOTAUTH', 'NOTIMP', 'NXDOMAIN', 'REFUSED'):
        ttl = rcodettl
    elif rcode != 'NOERROR':
        log_info('CACHE-SKIPPED: ' + qname + '/' + qtype + ' ' + rcode)
        return

    if ttl > 0:
        cache[query] = reply
        expire = now + ttl
        cacheindex[query] = expire
        entry = len(cache)
        log_info('CACHE-STORED (' + str(entry) + '): ' + qname + '/' + qtype + ' ' + rcode + ' (TTL:' + str(ttl) + ')')

    return True


# Purge cache
def cache_purge():
    # Remove expired entries
    now = int(datetime.datetime.now().strftime("%s"))
    for query in list(cache.keys()):
        expire = cacheindex[query]
        if expire - now < 1:
            log_info('CACHE-MAINT-EXPIRED: ' + query.replace('_', '-'))
            del cache[query]
            del cacheindex[query]

    # Prune cache back to cachesize, removing least TTL first
    size = len(cache)
    if (size > cachesize):
        expire = dict()
        for query in list(cache.keys()):
            expire[query] = cacheindex[query] - now

        for query in list(sorted(expire, key=expire.get))[0:size-cachesize]:
            log_info('CACHE-MAINT-EXPULSION: ' + query.replace('_', '-') + ' (TTL-LEFT:' + str(expire[query]) + ')')
            del cache[query]
            del cacheindex[query]

    log_info('CACHE-STATS: ' + str(len(cache)) + ' entries in cache')
    return True


# Round-Robin cycle list
def round_robin(l):
    return l[1:] + l[:1]


# DNS Filtering proxy main beef
class DNS_Instigator(ProxyResolver):
    def __init__(self, forward_address, forward_port, forward_timeout, redirect_address):
        ProxyResolver.__init__(self, forward_address, forward_port, forward_timeout)
        self.redirect_address = redirect_address

    def resolve(self, request, handler):
        rid = str(uuid.uuid4().hex[:5])

        cip = str(handler.client_address).split('\'')[1]

        qname = str(request.q.qname).rstrip('.').lower()
        qtype = QTYPE[request.q.qtype]

        log_info('REQUEST [' + str(rid) + '] from ' + cip + ': ' + qname + '/' + qtype)

        cachereply = from_cache(qname, qtype, request)
        if cachereply:
            reply = cachereply
        else:
            if blockv6 and (qtype == 'AAAA' or qname.endswith('.ip6.arpa')):
                log_info('IPV6-HIT: ' + qname + '/' + qtype + ' responded with NOTIMP')
                reply = request.reply()
                reply.header.rcode = getattr(RCODE, 'NOTIMP')

            elif qname in aliases and qtype in ('A', 'AAAA', 'CNAME'):
                reply = request.reply()
                reply.header.rcode = getattr(RCODE, 'NOERROR')
                alias = aliases[qname]
                log_info('ALIAS-HIT: ' + qname + ' -> ' + alias)
                if ipregex.match(alias):
                    if alias.find(':') == -1:
                        answer = RR(qname, QTYPE.A, ttl=cachettl, rdata=A(alias))
                    else:
                        answer = RR(qname, QTYPE.AAAA, ttl=cachettl, rdata=AAAA(alias))
                    reply.add_answer(answer)
                else:
                    answer = RR(qname, QTYPE.CNAME, ttl=cachettl, rdata=CNAME(alias))
                    reply.add_answer(answer)
                    aliastype = 'A'
                    while aliastype:
                        query = DNSRecord(q=DNSQuestion(alias,getattr(QTYPE,aliastype)))
                        subreply = DNSRecord.parse(query.send(forward_address, forward_port, timeout=forward_timeout))
                        rcode = str(RCODE[reply.header.rcode])
                        if rcode == 'NOERROR':
                            if subreply.rr:
                                for record in subreply.rr:
                                    rqtype = QTYPE[record.rtype]
                                    data = str(record.rdata).rstrip('.').lower()
                                    if rqtype == 'A':
                                        answer = RR(alias, QTYPE.A, ttl=cachettl, rdata=A(data))
                                        reply.add_answer(answer)
                                    if rqtype == 'AAAA':
                                        answer = RR(alias, QTYPE.AAAA, ttl=cachettl, rdata=AAAA(data))
                                        reply.add_answer(answer)

                                aliastype = False
                        else:
                            if aliastype == 'A':
                                aliastype = 'AAAA'
                            else:
                                aliastype = False
                                reply = request.reply()
                                reply.header.rcode = getattr(RCODE, 'NXDOMAIN')
                                
            elif in_blacklist(rid, 'REQUEST', qtype, qname, True):
                reply = generate_response(request, qname, qtype, redirect_address)

            else:
                try:
                    reply = ProxyResolver.resolve(self, request, handler)
                except socket.timeout:
                    log_err('ERROR Resolving ' + qname + '/' + qtype)
                    reply.header.rcode = getattr(RCODE, 'SERVFAIL')

                rcode = str(RCODE[reply.header.rcode])
                if rcode == 'NOERROR':
                    if reply.rr:
                        replycount = 0
                        replynum = len(reply.rr)

                        ttl = normalize_ttl(reply.rr, True)

                        seen = set()
                        addr = list()
                        firstrqtype = False

                        for record in reply.rr:
                            replycount += 1

                            rqname = str(record.rname).rstrip('.').lower()
                            rqtype = QTYPE[record.rtype]
                            if not firstrqtype:
                                firstrqtype = rqtype

                            record.ttl = ttl
                            data = str(record.rdata).rstrip('.').lower()

                            if collapse and firstrqtype == 'CNAME' and rqtype in ('A', 'AAAA'):
                                addr.append(data)

                            log_info('REPLY [' + str(rid) + ':' + str(replycount) + '-' + str(replynum) + ']: ' + rqname + ' ' + rqtype + ' = ' + data)

                            qlog = False
                            if rqname not in seen:
                                qlog = True
                                seen.add(rqname)

                            dlog = False
                            if data not in seen:
                                dlog = True
                                seen.add(data)

                            if in_blacklist(rid, 'REQUEST', rqtype, rqname, qlog) or in_blacklist(rid, 'REPLY', rqtype, data, dlog):
                                reply = generate_response(request, qname, qtype, redirect_address)

                        if collapse and firstrqtype == 'CNAME' and addr:
                            log_info('REPLY [' + str(rid) + ']: COLLAPSE ' + qname + '/CNAME')
                            reply = request.reply()
                            reply.header.rcode = getattr(RCODE, 'NOERROR')
                            for ip in addr:
                                if ip.find(':') == -1:
                                    answer = RR(qname, QTYPE.A, ttl=ttl, rdata=A(ip))
                                else:
                                    answer = RR(qname, QTYPE.AAAA, ttl=ttl, rdata=AAAA(ip))

                                reply.add_answer(answer)

                else:
                    reply = request.reply()
                    reply.header.rcode = getattr(RCODE, rcode)

                    log_info('REPLY [' + str(rid) + ']: ' + qname + ' ' + qtype + ' = ' + rcode)

            to_cache(qname, qtype, reply)

        log_info('FINISHED [' + str(rid) + '] from ' + cip + ': ' + qname + '/' + qtype)
        return reply


# Main
if __name__ == "__main__":

    log_info('Initializing INSTIGATOR')

    # Read Lists
    for lst in sorted(lists.keys()):
        if lst in whitelist:
            wl_dom, wl_ip4, wl_ip6, wl_rx, aliases = read_list(lists[lst], 'Whitelist', wl_dom, wl_ip4, wl_ip6, wl_rx, aliases)
        else:
            bl_dom, bl_ip4, bl_ip6, bl_rx, aliases = read_list(lists[lst], 'Blacklist', bl_dom, bl_ip4, bl_ip6, bl_rx, aliases)

    # Resolver
    dns_resolver = DNS_Instigator(forward_address=forward_address, forward_port=forward_port, forward_timeout=forward_timeout, redirect_address=redirect_address)

    # Server / Proxy
    logger = DNSLogger(log='-recv,-send,-request,-reply,+error,+truncated,-data', prefix=False)
    dns_server = DNSServer(dns_resolver, address=listen_address, port=listen_port, logger=logger, tcp=False) # UDP

    # Start Service
    log_info('Starting DNS Service ...')
    dns_server.start_thread()
    time.sleep(0.5)
    if dns_server.isAlive():
        log_info('DNS Service ready on ' + listen_address + ':' + str(listen_port))
    else:
        log_err('DNS Service did not start, aborting ...')
        quit()

    # Keep things running
    try:
        while dns_server.isAlive():
            time.sleep(30) # Seconds
            cache_purge()

    except KeyboardInterrupt:
        pass

    dns_server.stop

    sys.exit(0)

# <EOF>
