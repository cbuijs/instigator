#!/usr/bin/env python3
'''
=========================================================================================
 instigator.py: v1.90-20180503 Copyright (C) 2018 Chris Buijs <cbuijs@chrisbuijs.com>
=========================================================================================

Python DNS Server with security and filtering features

This is a little study to build a DNS server in Python including some features:

- Blacklist/Whitelist DNS queries and responses based on domain, ip or regex
- Blacklisted DNS queries never leave the building

... to be elaborated

TODO:
- Loads ...
- Better Documentation / Remarks / Comments

- dns_query, when all servers have errors, clear cache and restart
- Make recursor '1.2.3.4'.split('.')[::-1]

=========================================================================================
'''

# Standard modules
import sys, time, socket, pickle

# make sure modules can be found
sys.path.append("/usr/local/lib/python3.5/dist-packages/")

# Syslogging / Logging
import syslog
syslog.openlog(ident='INSTIGATOR')

# DNSLib module
#from dnslib import CLASS, QTYPE, RR, A, AAAA, CNAME, MX, NS, PTR, SOA, SRV, TXT, RCODE, DNSRecord, DNSQuestion, DNSError
#from dnslib.server import DNSServer, DNSLogger, BaseResolver
from dnslib import *
from dnslib.server import *

# Regex module
import regex

# Use module PyTricia for CIDR/Subnet stuff
import pytricia

###################

# Listen for queries
listen_on = list(['127.0.0.1:53', '192.168.1.250:53'])

# Forwarding queries to
forward_timeout = 2 # Seconds
forward_servers = dict()
#forward_servers['.'] = list(['1.1.1.1:53','1.0.0.1:53']) # DEFAULT Cloudflare
forward_servers['.'] = list(['209.244.0.3:53','209.244.0.4:53']) # DEFAULT Level-3
#forward_servers['.'] = list(['8.8.8.8:53','8.8.4.4:53']) # DEFAULT Google
#forward_servers['.'] = list(['9.9.9.9:53','149.112.112.112:53']) # DEFAULT Quad9
#forward_servers['.'] = list(['208.67.222.222:53','208.67.220.220:53']) # DEFAULT OpenDNS

# Redirect Address, leave empty to generete REFUSED
#redirect_address = ''
redirect_address = '192.168.1.250' # IPv4 or IPv6

# Return-code when query hits a list and cannot be redirected, only use NXDOMAIN or REFUSED
hitrcode = 'REFUSED'

# Files / Lists
defaultlist = list([None, 0, ''])
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
persistentcachefile = '/opt/instigator/cache.file'

# TTL Settings
cachettl = 1800 # Seconds - For filtered/blacklisted entry caching
minttl = 300 # Seconds
maxttl = 7200 # Seconds
rcodettl = 120 # Seconds - For return-codes caching

# Minimal Responses
minresp = True

# Roundrobin of address-records
roundrobin = True

# Collapse/Flatten CNAME Chains
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

# Regex to filter IP CIDR's out
ip4regex_text = '((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}(/(3[0-2]|[12]?[0-9]))*)'
ip6regex_text = '(((:(:[0-9a-f]{1,4}){1,7}|::|[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){1,6}|::|:[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){1,5}|::|:[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){1,4}|::|:[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){1,3}|::|:[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){1,2}|::|:[0-9a-f]{1,4}(::[0-9a-f]{1,4}|::|:[0-9a-f]{1,4}(::|:[0-9a-f]{1,4}))))))))|(:(:[0-9a-f]{1,4}){0,5}|[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){0,4}|:[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){0,3}|:[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){0,2}|:[0-9a-f]{1,4}(:(:[0-9a-f]{1,4})?|:[0-9a-f]{1,4}(:|:[0-9a-f]{1,4})))))):(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3})(/(12[0-8]|1[01][0-9]|[1-9]?[0-9]))*)'
ipregex4 = regex.compile('^' + ip4regex_text + '$', regex.I)
ipregex6 = regex.compile('^' + ip6regex_text + '$', regex.I)
ipregex = regex.compile('^(' + ip4regex_text + '|' + ip6regex_text + ')$', regex.I)

# Regex to filter IP:PORT's out
ip4portregex_text = '((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}(:(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{0,3}|0))*)'
ip6portregex_text = '(((:(:[0-9a-f]{1,4}){1,7}|::|[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){1,6}|::|:[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){1,5}|::|:[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){1,4}|::|:[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){1,3}|::|:[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){1,2}|::|:[0-9a-f]{1,4}(::[0-9a-f]{1,4}|::|:[0-9a-f]{1,4}(::|:[0-9a-f]{1,4}))))))))|(:(:[0-9a-f]{1,4}){0,5}|[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){0,4}|:[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){0,3}|:[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){0,2}|:[0-9a-f]{1,4}(:(:[0-9a-f]{1,4})?|:[0-9a-f]{1,4}(:|:[0-9a-f]{1,4})))))):(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3})(:(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{0,3}|0))*)'
ipportregex4 = regex.compile('^' + ip4portregex_text + '$', regex.I)
ipportregex6 = regex.compile('^' + ip6portregex_text + '$', regex.I)
ipportregex = regex.compile('^(' + ip4portregex_text + '|' + ip6portregex_text + ')$', regex.I)

# Regex to match domains/hosts in lists
isdomain = regex.compile('^[a-z0-9\.\-\_]+$', regex.I) # Based on RFC1035 plus underscore

# Regex to filter regexes out
isregex = regex.compile('^/.*/$')

# Regex for AS(N) Numbers
isasn = regex.compile('^AS[0-9]+$', regex.I)

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
# Returns:
#   True = Black-listed
#   False = White-listed
#   None = None-listed
def match_blacklist(rid, type, rrtype, value, log):
    id = id_str(rid)
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
        if testvalue:
            wl_found = in_domain(testvalue, wl_dom)
            if wl_found != False:
                if log: log_info('WHITELIST-HIT [' + id + ']: ' + type + ' \"' + value + '\" matched against \"' + wl_found + '\"')
                return False
            else:
                bl_found = in_domain(testvalue, bl_dom)
                if bl_found != False:
                    if log: log_info('BLACKLIST-HIT [' + id + ']: ' + type + ' \"' + value + '\" matched against \"' + bl_found + '\"')
                    return True
    
        #while testvalue:
        #    if testvalue in wl_dom:
        #        if log: log_info('WHITELIST-HIT [' + id + ']: ' + type + ' \"' + value + '\" matched against \"' + testvalue + '\"')
        #        return False
        #    if testvalue in bl_dom:
        #        if log: log_info('BLACKLIST-HIT [' + id + ']: ' + type + ' \"' + value + '\" matched against \"' + testvalue + '\"')
        #        return True
        #    elif testvalue.find('.') == -1:
        #        break
        #    else:
        #        testvalue = testvalue[testvalue.find('.') + 1:]

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

    if log: log_info('NONE-HIT [' + id + ']: ' + type + ' \"' + value + '\" does not match against any lists')

    return None


# Check if name is domain or sub-domain
def in_domain(name, domlist):
    testname = name
    while testname:
        if testname in domlist:
            return testname
        elif testname.find('.') == -1:
            break
        else:
            testname = testname[testname.find('.') + 1:]

    return False


# Do query
def dns_query(qname, qtype, use_tcp, id, cip):
    queryname = qname + '/IN/' + qtype

    server = in_domain(qname, forward_servers)
    if server:
        servername = 'FORWARD-HIT: ' + server
    else:
        server = '.'
        servername = 'DEFAULT'

    reply = None

    forward_server = forward_servers.get(server, None)
    if forward_server:
        query = DNSRecord(q = DNSQuestion(qname, getattr(QTYPE, qtype)))

        addrs = round_robin(forward_server)
        forward_servers[server] = list(addrs)

        for addr in addrs:
            forward_address = addr.split(':')[0]
            if addr.find(':') > 0:
                forward_port = int(addr.split(':')[1])
            else:
                forward_port = 53
    
            if (forward_address != cip) and (query_hash(forward_address, 'FORWARDER', str(forward_port)) not in cache):
                log_info('DNS-QUERY [' + id_str(id) + ']: querying ' + forward_address + ':' + str(forward_port) + ' (' + servername + ') for ' + queryname)

                try:
                    reply = DNSRecord.parse(query.send(forward_address, forward_port, tcp = use_tcp, timeout = forward_timeout))

                    ttl = normalize_ttl(reply.rr, False)
                    for record in reply.rr:
                        record.ttl = ttl

                    break

                except socket.timeout:
                    log_err('DNS-QUERY [' + id_str(id) + ']: ERROR Resolving ' + queryname + ' using ' + forward_address + ':' + str(forward_port))
                    to_cache(forward_address, 'FORWARDER', str(forward_port), query.response())
                    reply = None

    else:
        log_err('DNS-QUERY [' + id_str(id) + ']: ERROR Resolving ' + queryname + ' (' + servername + ') - NO DNS SERVER TO USE!')

    if reply == None:
        log_err('DNS-QUERY [' + id_str(id) + ']: ERROR Resolving ' + queryname)
        cache.clear()
        reply = query.reply()
        reply.header.rcode = getattr(RCODE, 'SERVFAIL')

    reply.header.id = id

    return reply


# Generate response when blocking
def generate_response(request, qname, qtype, redirect_address):
    queryname = qname + '/IN/' + qtype
    reply = request.reply()
    if (len(redirect_address) == 0) or (qtype not in ('A', 'AAAA', 'CNAME', 'ANY')) or (not ipregex.match(redirect_address)):
        log_info(hitrcode + ' for ' + queryname)
        reply.header.rcode = getattr(RCODE, hitrcode)
        return reply
    else:
        log_info('REDIRECT ' + queryname + ' to ' + redirect_address)

        if redirect_address.find(':') == -1:
            answer = RR(qname, QTYPE.A, ttl=cachettl, rdata=A(redirect_address))
        else:
            answer = RR(qname, QTYPE.AAAA, ttl=cachettl, rdata=AAAA(redirect_address))

        #auth = RR(qname, QTYPE.SOA, ttl=cachettl, rdata=SOA('ns.sinkhole','hostmaster.sinkhole',(int(time.time()), cachettl, cachettl, cachettl, cachettl)))
        #ar = RR('ns.sinkhole', QTYPE.A, ttl=cachettl, rdata=A('0.0.0.0'))

    answer.set_rname(request.q.qname)
    reply.add_answer(answer)
    #reply.add_auth(auth)
    #reply.add_ar(ar)
    reply.header.rcode = getattr(RCODE, 'NOERROR')

    return reply


# Generate alias response
def generate_alias(request, qname, qtype, use_tcp):
    queryname = qname + '/IN/' + qtype

    realqname = str(request.q.qname).rstrip('.').lower()

    reply = request.reply()
    reply.header.id = request.header.id
    reply.header.rcode = getattr(RCODE, 'NOERROR')

    if qname in aliases:
        alias = aliases[qname]
    else:
        aqname = in_domain(qname, aliases)
        if aqname:
            log_info('ALIAS-HIT: ' + qname + ' subdomain of alias ' + aqname)
            alias = aliases[aqname]
        else:
            alias = 'NXDOMAIN'

    if alias.upper() in ('PASSTHRU'):
        log_info('ALIAS-HIT: ' + queryname + ' = PASSTHRU')
        alias = qname

    aliasqname = False
    if alias.upper() in ('NOTAUTH', 'NXDOMAIN', 'REFUSED'):
        log_info('ALIAS-HIT: ' + queryname + ' = ' + alias.upper())
        reply = request.reply()
        reply.header.rcode = getattr(RCODE, alias.upper())

    elif ipregex.match(alias):
        log_info('ALIAS-HIT: ' + queryname + ' = REDIRECT-TO-IP')
        if alias.find(':') == -1:
            answer = RR(realqname, QTYPE.A, ttl=cachettl, rdata=A(alias))
        else:
            answer = RR(realqname, QTYPE.AAAA, ttl=cachettl, rdata=AAAA(alias))

        reply.add_answer(answer)

    else:
        log_info('ALIAS-HIT: ' + queryname + ' = REDIRECT-TO-NAME')
        if not collapse and qname != alias:
            answer = RR(realqname, QTYPE.CNAME, ttl=cachettl, rdata=CNAME(alias))
            reply.add_answer(answer)

        if qtype not in ('A', 'AAAA'):
            qtype = 'A'

        subreply = dns_query(alias, qtype, use_tcp, request.header.id, '127.0.0.1')
        rcode = str(RCODE[subreply.header.rcode])
        if rcode == 'NOERROR':
            if subreply.rr:
                if collapse:
                    aliasqname = realqname
                else:
                    aliasqname = alias

                for record in subreply.rr:
                    rqtype = QTYPE[record.rtype]
                    data = str(record.rdata).rstrip('.').lower()
                    if rqtype == 'A':
                        answer = RR(aliasqname, QTYPE.A, ttl=cachettl, rdata=A(data))
                        reply.add_answer(answer)
                    if rqtype == 'AAAA':
                        answer = RR(aliasqname, QTYPE.AAAA, ttl=cachettl, rdata=AAAA(data))
                        reply.add_answer(answer)

        else:
            reply = request.reply()
            reply.header.rcode = getattr(RCODE, rcode)


    log_info('ALIAS-HIT: ' + qname + ' -> ' + alias + ' ' + str(RCODE[reply.header.rcode]))
    if collapse and aliasqname:
        log_info('ALIAS-HIT: COLLAPSE ' + qname + '/IN/CNAME')

    return reply


# Read filter lists, see "accomplist" lists for compatibility:
# https://github.com/cbuijs/accomplist
def read_list(file, listname, domlist, iplist4, iplist6, rxlist, alist, flist):
    log_info('Fetching \"' + listname + '\" entries from \"' + file + '\"')

    count = 0

    try:
        f = open(file, 'r')
        lines = f.readlines()
        f.close()

    except BaseException as err:
        log_err('ERROR: Unable to open/read/process file \"' + file + '\" - ' + str(err))

    for line in lines:
        count += 1
        entry = regex.sub('\s*#[^#]*$', '', line.replace('\r', '').replace('\n', ''))
        if entry.startswith('/'):
            entry = regex.sub('/\s+[^/]+$', '/', entry)
        else:
            entry = regex.split('\s+', entry)[0]
        entry = entry.strip().lower().rstrip('.')

        # If entry ends in questionmark, it is a "forced" entry. Not used for the moment. Heritage of unbound dns-firewall.
        if entry.endswith('!'):
            entry = entry[:-1]

        # If entry ends in ampersand, it is a "safelisted" entry. Not used for the moment. Heritage of unbound dns-firewall.
        if entry.endswith('&'):
            entry = ''

        if len(entry) > 0 and (not entry.startswith('#')):
            if isregex.match(entry):
                rx = entry.strip('/')
                rxlist[rx] = regex.compile(rx, regex.I)

            elif isasn.match(entry):
                # ASN Number, just discard for now
                pass

            elif isdomain.match(entry):
                domlist[entry] = True

            elif ipregex4.match(entry):
                iplist4[entry] = True

            elif ipregex6.match(entry):
                iplist6[entry] = True

            elif entry.find('=') > 0:
                elements = entry.split('=')
                if len(elements) > 1:
                    domain = elements[0].strip().lower().rstrip('.')
                    alias = elements[1].strip().lower().rstrip('.')
                    if isdomain.match(domain) and (isdomain.match(alias) or ipregex.match(alias)):
                   	    alist[domain] = alias
                    else:
                        log_err(listname + ' INVALID ALIAS [' + str(count) + ']: ' + entry)
                else:
                    log_err(listname + ' INVALID ALIAS [' + str(count) + ']: ' + entry)

            elif entry.find('>') > 0:
                elements = entry.split('>')
                if len(elements) > 1:
                    domain = elements[0].strip().lower().rstrip('.')
                    ips = elements[1].strip().lower().rstrip('.')
                    if isdomain.match(domain):
                        addrs = list()
                        for addr in ips.split(','):
                            if ipportregex.match(addr):
                                addrs.append(addr)
                            else:
                                log_err(listname + ' INVALID FORWARD-ADDRESS [' + str(count) + ']: ' + addr)
            
                        if addrs:
                            flist[domain] = addrs
                    else:
                        log_err(listname + ' INVALID FORWARD [' + str(count) + ']: ' + entry)
                else:
                    log_err(listname + ' INVALID FORWARD [' + str(count) + ']: ' + entry)

            else:
                log_err(listname + ' INVALID LINE [' + str(count) + ']: ' + entry)

    log_info(listname + ': ' + str(len(rxlist)) + ' REGEXes, ' + str(len(iplist4)) + ' IPv4 CIDRs, ' + str(len(iplist6)) + ' IPv6 CIDRs, ' + str(len(domlist)) + ' DOMAINs, ' + str(len(alist)) + ' ALIASes and ' + str(len(flist)) + ' FORWARDs')

    return domlist, iplist4, iplist6, rxlist, alist, flist


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
def from_cache(queryhash, id):
    expire = cache.get(queryhash, defaultlist)[1]
    now = int(time.time())
    ttl = expire - now

    # If expired, remove from cache
    if ttl < 1:
        log_info('CACHE-EXPIRED: ' + cache[queryhash][2])
        del_cache_entry(queryhash)
        return None

    # Retrieve from cache
    else:
        reply = cache.get(queryhash, defaultlist)[0]
        reply.header.id = id

        # Gather address and non-address records and do round-robin
        if roundrobin and len(reply.rr) > 1:
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
                reply.rr = nonaddr + round_robin(addr)

        else:
            for record in reply.rr:
                record.ttl = ttl

        log_info('CACHE-HIT: ' + cache[queryhash][2] + ' ' + str(RCODE[reply.header.rcode]) + ' (TTL-LEFT:' + str(ttl) + ')')

        return reply


# Store into cache
def to_cache(qname, qclass, qtype, reply):
    queryname = qname + '/' + qclass + '/' + qtype
    ttl = normalize_ttl(reply.rr, True)

    rcode = str(RCODE[reply.header.rcode])
    if rcode in ('NODATA', 'NOTAUTH', 'NOTIMP', 'NXDOMAIN', 'REFUSED'):
        ttl = rcodettl
    elif rcode == 'SERVFAIL':
        ttl = 10
    elif rcode != 'NOERROR':
        log_info('CACHE-SKIPPED: ' + queryname + ' ' + rcode)
        return

    if ttl > 0:
        expire = int(time.time()) + ttl
        queryhash = add_cache_entry(qname, qclass, qtype, expire, reply)
        entry = len(cache)
        log_info('CACHE-STORED (' + str(entry) + '): ' + queryname + ' ' + rcode + ' (TTL:' + str(ttl) + ')')

    return True

# Purge cache
def cache_purge():
    # Remove expired entries
    now = int(time.time())
    for queryhash in list(cache.keys()):
        expire = cache.get(queryhash, defaultlist)[1]
        if expire - now < 1:
            log_info('CACHE-MAINT-EXPIRED: ' + cache[queryhash][2])
            del_cache_entry(queryhash)

    # Prune cache back to cachesize, removing least TTL first
    size = len(cache)
    if (size > cachesize):
        expire = dict()
        for queryhash in list(cache.keys()):
            expire[queryhash] = cache.get(queryhash, defaultlist)[1] - now

        for queryhash in list(sorted(expire, key=expire.get))[0:size-cachesize]:
            log_info('CACHE-MAINT-EXPULSION: ' + cache.get(queryhash, defaultlist)[2] + ' (TTL-LEFT:' + str(expire[queryhash]) + ')')
            del_cache_entry(queryhash)

    log_info('CACHE-STATS: ' + str(len(cache)) + ' entries in cache')
    return True


def query_hash(qname, qclass, qtype):
    return hash(qname + '/' + qclass + '/' + qtype)


def add_cache_entry(qname, qclass, qtype, expire, reply):
    hashname = qname + '/' + qclass + '/' + qtype
    queryhash = query_hash(qname, qclass, qtype)
    cache[queryhash] = list([reply, expire, hashname])

    return queryhash


def del_cache_entry(queryhash):
    _ = cache.pop(queryhash, None)
    return True


def load_cache(file):
    global cache

    log_info('CACHE-LOAD: Retrieving cache from \"' + file + '\"')

    try:
        f = open(file, 'rb')
        cache = pickle.load(f)
        f.close()
        cache_purge()

    except BaseException as err:
        log_err('ERROR: Unable to open/read file \"' + file + '\" - ' + str(err))

    return True


def save_cache(file):
    log_info('CACHE-SAVE: Saving cache to \"' + file + '\"')

    cache_purge()

    try:
        f = open(file, 'wb')
        pickle.dump(cache, f)
        f.close()

    except BaseException as err:
        log_err('ERROR: Unable to open/write file \"' + file + '\" - ' + str(err))

    return True


# Round-Robin cycle list
def round_robin(l):
    return l[1:] + l[:1]


def id_str(id):
    return str(id).zfill(5)


# DNS Filtering proxy main beef
class DNS_Instigator(BaseResolver):

    def resolve(self, request, handler):
        rid = request.header.id

        cip = str(handler.client_address).split('\'')[1]

        if handler.protocol == 'udp':
            use_tcp = False
        else:
            use_tcp = True

        qname = str(request.q.qname).rstrip('.').lower()
        if qname == '':
            qname = '.'

        qclass = CLASS[request.q.qclass].upper()
        qtype = QTYPE[request.q.qtype].upper()
        queryname = qname + '/' + qclass + '/' + qtype

        log_info('REQUEST [' + id_str(rid) + '] from ' + cip + ' for ' + queryname + ' (' + handler.protocol.upper() + ')')

        reply = None
        queryhash = query_hash(qname, qclass, qtype)
        if queryhash in cache:
            reply = from_cache(queryhash, rid)

        if reply == None:
            if qtype == 'ANY' or qclass != 'IN' or (qtype not in ('A', 'AAAA', 'CNAME', 'MX', 'NS', 'PTR', 'SOA', 'SRV', 'TXT')):
                log_info('REQUEST [' + id_str(rid) + '] from ' + cip + ': ' + queryname + ' NOTIMP (' + handler.protocol.upper() + ')')
                reply = request.reply()
                reply.header.rcode = getattr(RCODE, 'NOTIMP')

            elif blockv6 and (qtype == 'AAAA' or qname.endswith('.ip6.arpa')):
                log_info('IPV6-HIT: ' + queryname + ' responded with NXDOMAIN')
                reply = request.reply()
                reply.header.rcode = getattr(RCODE, 'NXDOMAIN')

            elif qtype in ('A', 'AAAA', 'CNAME') and in_domain(qname, aliases):
                reply = generate_alias(request, qname, qtype, use_tcp)

            else:
                ismatch = match_blacklist(rid, 'REQUEST', qtype, qname, True)
                if ismatch == True: # Blacklisted
                    reply = generate_response(request, qname, qtype, redirect_address)

                else:
                    reply = dns_query(qname, qtype, use_tcp, rid, cip)
                    if ismatch == None: # None-Listed, when False it is whitelisted
                        rcode = str(RCODE[reply.header.rcode])
                        if rcode == 'NOERROR':
                            if reply.rr:
                                replycount = 0
                                replynum = len(reply.rr)

                                ttl = normalize_ttl(reply.rr, True)

                                seen = set()
                                seen.add(qname)

                                addr = list()
                                firstrqtype = False

                                for record in reply.rr:
                                    replycount += 1

                                    rqname = str(record.rname).rstrip('.').lower()
                                    rqtype = QTYPE[record.rtype].upper()

                                    if rqtype in ('A', 'AAAA', 'CNAME') and in_domain(rqname, aliases):
                                        reply = generate_alias(request, rqname, rqtype, use_tcp)
                                        break

                                    if not firstrqtype:
                                        firstrqtype = rqtype

                                    record.ttl = ttl

                                    data = str(record.rdata).rstrip('.').lower()

                                    if collapse and firstrqtype == 'CNAME' and rqtype in ('A', 'AAAA'):
                                        addr.append(data)

                                    qlog = False
                                    if rqname not in seen:
                                        qlog = True
                                        seen.add(rqname)

                                    dlog = False
                                    if data not in seen:
                                        dlog = True
                                        seen.add(data)

                                    if (qlog and match_blacklist(rid, 'REQUEST', rqtype, rqname, qlog)) or (dlog and match_blacklist(rid, 'REPLY', rqtype, data, dlog)):
                                        log_info('REPLY [' + id_str(rid) + ':' + str(replycount) + '-' + str(replynum) + ']: ' + rqname + '/IN/' + rqtype + ' = ' + data + ' BLACKLIST-HIT')
                                        reply = generate_response(request, qname, qtype, redirect_address)
                                        break
                                    else:
                                        log_info('REPLY [' + id_str(rid) + ':' + str(replycount) + '-' + str(replynum) + ']: ' + rqname + '/IN/' + rqtype + ' = ' + data + ' NOERROR')

                                if collapse and firstrqtype == 'CNAME' and addr:
                                    log_info('REPLY [' + id_str(rid) + ']: COLLAPSE ' + qname + '/IN/CNAME')
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

                            log_info('REPLY [' + id_str(rid) + ']: ' + queryname + ' = ' + rcode)

        # Minimum responses
        if minresp:
            reply.auth = list()
            reply.ar = list()

        if queryhash not in cache:
            to_cache(qname, qclass, qtype, reply)

        log_info('FINISHED [' + id_str(rid) + '] from ' + cip + ' for ' + queryname)

        return reply


# Main
if __name__ == "__main__":
    log_info('-----------------------')
    log_info('Initializing INSTIGATOR')

    # Read Lists
    for lst in sorted(lists.keys()):
        if lst in whitelist:
            wl_dom, wl_ip4, wl_ip6, wl_rx, aliases, forward_servers = read_list(lists[lst], 'Whitelist', wl_dom, wl_ip4, wl_ip6, wl_rx, aliases, forward_servers)
        else:
            bl_dom, bl_ip4, bl_ip6, bl_rx, aliases, forward_servers = read_list(lists[lst], 'Blacklist', bl_dom, bl_ip4, bl_ip6, bl_rx, aliases, forward_servers)

    if persistentcachefile:
        load_cache(persistentcachefile)

    # DNS-Server/Resolver
    logger = DNSLogger(log='-recv,-send,-request,-reply,+error,+truncated,-data', prefix=False)
    udp_dns_server = dict()
    tcp_dns_server = dict()
    for listen in listen_on:
        if ipportregex.match(listen):
            elements = listen.split(':')
            listen_address = elements[0]
            if len(elements) > 1:
                listen_port = int(elements[1])
            else:
                listen_port = 53

            serverhash = hash(listen_address + ':' + str(listen_port))

            udp_dns_server[serverhash] = DNSServer(DNS_Instigator(), address=listen_address, port=listen_port, logger=logger, tcp=False) # UDP
            tcp_dns_server[serverhash] = DNSServer(DNS_Instigator(), address=listen_address, port=listen_port, logger=logger, tcp=True) # TCP

            # Start Service as threads
            log_info('Starting DNS Service on ' + listen_address + ':' + str(listen_port) + ' ...')
            udp_dns_server[serverhash].start_thread() # UDP
            tcp_dns_server[serverhash].start_thread() # TCP

            time.sleep(1)

            if udp_dns_server[serverhash].isAlive() and tcp_dns_server[serverhash].isAlive():
                log_info('DNS Service ready on ' + listen_address + ':' + str(listen_port))
            else:
                log_err('DNS Service did not start, aborting ...')
                sys.exit(1)

    # Keep things running
    count = 0
    try:
        while True:
            time.sleep(1) # Seconds
            count += 1
            if count > 29:
                count = 0
                if persistentcachefile:
                    save_cache(persistentcachefile)
                else:
                    cache_purge()

    except (KeyboardInterrupt, SystemExit):
        pass

    for listen in listen_on:
        if ipportregex.match(listen):
            elements = listen.split(':')
            listen_address = elements[0]
            if len(elements) > 1:
                listen_port = int(elements[1])
            else:
                listen_port = 53

            serverhash = hash(listen_address + ':' + str(listen_port))

            log_info('DNS Service shutdown on ' + listen_address + ':' + str(listen_port))
            udp_dns_server[serverhash].stop() # UDP
            tcp_dns_server[serverhash].stop() # TCP


    if persistentcachefile:
        save_cache(persistentcachefile)

    log_info('INSTIGATOR EXIT')
    log_info('---------------')
    sys.exit(0)

# <EOF>
