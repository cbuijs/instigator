#!/usr/bin/env python3
'''
=========================================================================================
 instigator.py: v2.37-20180514 Copyright (C) 2018 Chris Buijs <cbuijs@chrisbuijs.com>
=========================================================================================

Python DNS Forwarder/Proxy with security and filtering features

This is a little study to build a DNS server in Python including some features:

- Blacklist/Whitelist DNS queries and responses based on domain, ip or regex
- Blacklisted DNS queries never leave the building

... to be elaborated

TODO:
- Loads ...
- Better Documentation / Remarks / Comments

=========================================================================================
'''

# sys module and path
import sys
sys.path.append("/usr/local/lib/python3.5/dist-packages/")

# Standard modules
import time, socket, shelve

# Syslogging / Logging
import syslog
syslog.openlog(ident='INSTIGATOR')

# DNSLib module
from dnslib import *
from dnslib.server import *

# Regex module
import regex

# Use module PyTricia for CIDR/Subnet stuff
import pytricia

###################

# Listen for queries
listen_on = list(['127.0.0.1:53', '192.168.1.251:53']) # IPv4 only for now.

# Forwarding queries to
forward_timeout = 2 # Seconds
forward_servers = dict()
#forward_servers['.'] = list(['1.1.1.1:53','1.0.0.1:53']) # DEFAULT Cloudflare
# Alternatives:
forward_servers['.'] = list(['209.244.0.3:53','209.244.0.4:53']) # DEFAULT Level-3
#forward_servers['.'] = list(['8.8.8.8:53','8.8.4.4:53']) # DEFAULT Google
#forward_servers['.'] = list(['9.9.9.9:53','149.112.112.112:53']) # DEFAULT Quad9
#forward_servers['.'] = list(['208.67.222.222:53','208.67.220.220:53']) # DEFAULT OpenDNS
#forward_servers['.'] = list(['8.26.56.26:53','8.20.247.20:53']) # DEFAULT Comodo
#forward_servers['.'] = list(['199.85.126.10:53','199.85.127.10:53']) # DEFAULT Norton
#forward_servers['.'] = list(['64.6.64.6:53','64.6.65.6:53']) # DEFAULT Verisign
#forward_servers['.'] = list(['156.154.70.2:53','156.154.71.2:53']) # DEFAULT Neustar

# Redirect Address, leave empty to generete REFUSED
#redirect_addrs = list()
redirect_addrs = list(['192.168.1.251', '0000:0000:0000:0000:0000:0000:0000:0000'])

# Return-code when query hits a list and cannot be redirected, only use NXDOMAIN or REFUSED
#hitrcode = 'NXDOMAIN'
hitrcode = 'REFUSED'

# Only load cached/fast files when not older then maxfileage
maxfileage = 3600 # Seconds

# Files / Lists
savefile = '/opt/instigator/save'
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
cachefile = '/opt/instigator/cache'
cachesize = 2048 # Entries
cache_maintenance_now = False

# TTL Settings
cachettl = 1800 # Seconds - For filtered/blacklisted/alias entry caching
minttl = 300 # Seconds
maxttl = 7200 # Seconds
rcodettl = 120 # Seconds - For return-codes caching

# Minimal Responses
minresp = True

# Roundrobin of address/forward-records
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

# Cache
cache = dict()

## Regexes

# Use fast (less precisie) versions of regexes
fastregex = True

# Regex to filter IP CIDR's out
if fastregex:
    ip4regex_text = '([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})*'
    ip6regex_text = '([0-9a-f]{1,4}|:)(:([0-9a-f]{0,4})){1,7}(/[0-9]{1,3})*'
else:
    ip4regex_text = '((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}(/(3[0-2]|[12]?[0-9]))*)'
    ip6regex_text = '(((:(:[0-9a-f]{1,4}){1,7}|::|[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){1,6}|::|:[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){1,5}|::|:[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){1,4}|::|:[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){1,3}|::|:[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){1,2}|::|:[0-9a-f]{1,4}(::[0-9a-f]{1,4}|::|:[0-9a-f]{1,4}(::|:[0-9a-f]{1,4}))))))))|(:(:[0-9a-f]{1,4}){0,5}|[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){0,4}|:[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){0,3}|:[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){0,2}|:[0-9a-f]{1,4}(:(:[0-9a-f]{1,4})?|:[0-9a-f]{1,4}(:|:[0-9a-f]{1,4})))))):(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3})(/(12[0-8]|1[01][0-9]|[1-9]?[0-9]))*)'

ipregex4 = regex.compile('^' + ip4regex_text + '$', regex.I)
ipregex6 = regex.compile('^' + ip6regex_text + '$', regex.I)
ipregex = regex.compile('^(' + ip4regex_text + '|' + ip6regex_text + ')$', regex.I)

# Regex to filter IP:PORT's out
if fastregex:
    ip4portregex_text = '([0-9]{1,3}\.){3}[0-9]{1,3}(:[0-9]{1,5})*'
    ip6portregex_text = '([0-9a-f]{1,4}|:)(:([0-9a-f]{0,4})){1,7}(:[0-9]{1,5})*'
else:
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


# Check if file exists and return age (in seconds) if so
def file_exist(file):
    if file:
        try:
            if os.path.isfile(file):
                fstat = os.stat(file)
                fsize = fstat.st_size
                if fsize > 0:
                    fexists = True
                    mtime = int(fstat.st_mtime)
                    currenttime = int(time.time())
                    age = int(currenttime - mtime)
                    log_info('FILE-EXIST: ' + file + ' = ' + str(age) + ' seconds old')
                    return age
        except:
            return False

    return False


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

    #if type == 'REPLY' and rrtype in ('A', 'AAAA') and ipregex.search(testvalue):
    if type == 'REPLY' and rrtype in ('A', 'AAAA'):
        itisanip = True
    else:
        if type == 'REPLY':
            field = False
            #if rrtype in ('CNAME', 'NS', 'PTR', 'SOA') and isdomain.search(testvalue):
            if rrtype in ('CNAME', 'NS', 'PTR', 'SOA'):
                field = 0
            elif type == 'MX':
                field = 1
            elif type == 'SRV':
                field = 2

            if field:
                testvalue = regex.split('\s+', testvalue)[field].rstrip('.')
                #if isdomain.search(testvalue):
                #    itisadomain = True
                itisadomain = True

        else:
            itisadomain = True

    if itisadomain:
        if (testvalue in wl_dom):
            if log: log_info('WHITELIST-HIT [' + id + ']: ' + type + ' \"' + value + '\" matched against \"' + testvalue + '\"')
            return False
        elif testvalue in bl_dom:
            if log: log_info('BLACKLIST-HIT [' + id + ']: ' + type + ' \"' + value + '\" matched against \"' + testvalue + '\"')
            return True

    # Check against IP-Lists
    if itisanip:
        found = False
        prefix = False

        #if ipregex4.search(testvalue):
        if testvalue.find(':') == -1:
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
    
    # Check agains Regex-Lists
    for i in wl_rx.keys():
        rx = wl_rx[i]
        if rx.search(value):
            if log: log_info('WHITELIST-REGEX-HIT [' + id + ']: ' + type + ' \"' + value + '\" matched against \"' + i + '\"')
            return False

    for i in bl_rx.keys():
        rx = bl_rx[i]
        if rx.search(value):
            if log: log_info('BLACKLIST-REGEX-HIT [' + id + ']: ' + type + ' \"' + value + '\" matched against \"' + i + '\"')
            return True

    #if log: log_info('NONE-HIT [' + id + ']: ' + type + ' \"' + value + '\" does not match against any lists')

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
def dns_query(request, qname, qtype, use_tcp, id, cip, checkbl, checkalias):
    # Get from cache if any
    reply = from_cache(qname, 'IN', qtype, id)
    if reply != None:
        return reply

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
                    q = query.send(forward_address, forward_port, tcp = use_tcp, timeout = forward_timeout)
                    reply = DNSRecord.parse(q)
                    ttl = normalize_ttl(reply.rr, False)
                    break

                except socket.timeout:
                    log_err('DNS-QUERY [' + id_str(id) + ']: ERROR Resolving ' + queryname + ' using ' + forward_address + ':' + str(forward_port))
                    to_cache(forward_address, 'FORWARDER', str(forward_port), list())
                    reply = None

    else:
        log_err('DNS-QUERY [' + id_str(id) + ']: ERROR Resolving ' + queryname + ' (' + servername + ') - NO DNS SERVERS AVAILBLE!')

    if reply == None:
        log_err('DNS-QUERY [' + id_str(id) + ']: ERROR Resolving ' + queryname)
        cache.clear()
        reply = query.reply()
        reply.header.id = id
        reply.header.rcode = getattr(RCODE, 'SERVFAIL')
        return reply

    if checkbl:
        rcode = str(RCODE[reply.header.rcode])
        if rcode == 'NOERROR':
            if reply.rr:
                replycount = 0
                replynum = len(reply.rr)

                seen = set()
                seen.add(qname)

                for record in reply.rr:
                    replycount += 1

                    rqname = str(record.rname).rstrip('.').lower()
                    rqtype = QTYPE[record.rtype].upper()

                    if checkalias and rqtype in ('A', 'AAAA', 'CNAME') and in_domain(rqname, aliases):
                        reply = generate_alias(request, rqname, rqtype, use_tcp)
                        break

                    data = str(record.rdata).rstrip('.').lower()

                    qlog = seen_it(rqname, seen)
                    dlog = seen_it(data, seen)

                    if (qlog and match_blacklist(id, 'REQUEST', rqtype, rqname, qlog)) or (dlog and match_blacklist(id, 'REPLY', rqtype, data, dlog)):
                        log_info('REPLY [' + id_str(id) + ':' + str(replycount) + '-' + str(replynum) + ']: ' + rqname + '/IN/' + rqtype + ' = ' + data + ' BLACKLIST-HIT')
                        reply = generate_response(request, qname, qtype, redirect_addrs)
                        break
                    else:
                        log_info('REPLY [' + id_str(id) + ':' + str(replycount) + '-' + str(replynum) + ']: ' + rqname + '/IN/' + rqtype + ' = ' + data + ' NOERROR')

        else:
            reply = request.reply()
            reply.header.rcode = getattr(RCODE, rcode)
            log_info('REPLY [' + id_str(id) + ']: ' + queryname + ' = ' + rcode)


    # Match up ID
    reply.header.id = id

    # Collapse CNAME
    if collapse:
        reply = collapse_cname(request, reply, id)

    # Minimum responses
    if minresp:
        reply.auth = list()
        reply.ar = list()

    # Stash in cache
    to_cache(qname, 'IN', qtype, reply)

    return reply


# Generate response when blocking
def generate_response(request, qname, qtype, redirect_addrs):
    queryname = qname + '/IN/' + qtype

    reply = request.reply()

    if (len(redirect_addrs) == 0) or (qtype not in ('A', 'AAAA', 'CNAME', 'ANY')):
        log_info('GENERATE: ' + hitrcode + ' for ' + queryname)
        reply.header.rcode = getattr(RCODE, hitrcode)

    else:
        addanswer = False
        for addr in redirect_addrs:
            answer = None
            if qtype == 'A' and ipregex4.search(addr):
                answer = RR(qname, QTYPE.A, ttl=cachettl, rdata=A(addr))
            elif qtype == 'AAAA' and ipregex6.search(addr):
                answer = RR(qname, QTYPE.AAAA, ttl=cachettl, rdata=AAAA(addr))
        
            if answer != None:
                addanswer = True
                answer.set_rname(request.q.qname)
                reply.add_answer(answer)

        if addanswer:
            log_info('GENERATE: REDIRECT/NOERROR for ' + queryname)
            reply.header.rcode = getattr(RCODE, 'NOERROR')
        else:
            log_info('GENERATE: ' + hitrcode + ' for ' + queryname)
            reply.header.rcode = getattr(RCODE, hitrcode)

    to_cache(qname, 'IN', qtype, reply)

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

    elif ipregex.search(alias):
        log_info('ALIAS-HIT: ' + queryname + ' = REDIRECT-TO-IP -> ' + alias)
        if alias.find(':') == -1:
            answer = RR(realqname, QTYPE.A, ttl=cachettl, rdata=A(alias))
        else:
            answer = RR(realqname, QTYPE.AAAA, ttl=cachettl, rdata=AAAA(alias))

        reply.add_answer(answer)

    else:
        log_info('ALIAS-HIT: ' + queryname + ' = REDIRECT-TO-NAME -> ' + alias)
        if not collapse and qname != alias:
            answer = RR(realqname, QTYPE.CNAME, ttl=cachettl, rdata=CNAME(alias))
            reply.add_answer(answer)

        if qtype not in ('A', 'AAAA'):
            qtype = 'A'

        subreply = dns_query(request, alias, qtype, use_tcp, request.header.id, '127.0.0.1', True, False)

        rcode = str(RCODE[subreply.header.rcode])
        if rcode == 'NOERROR':
            ttl = subreply.rr[0].ttl
            if subreply.rr:
                if collapse:
                    aliasqname = realqname
                else:
                    aliasqname = alias

                for record in subreply.rr:
                    rqtype = QTYPE[record.rtype]
                    data = str(record.rdata).rstrip('.').lower()
                    if rqtype == 'A':
                        answer = RR(aliasqname, QTYPE.A, ttl=ttl, rdata=A(data))
                        reply.add_answer(answer)
                    if rqtype == 'AAAA':
                        answer = RR(aliasqname, QTYPE.AAAA, ttl=ttl, rdata=AAAA(data))
                        reply.add_answer(answer)

        else:
            reply = request.reply()
            reply.header.rcode = getattr(RCODE, rcode)


    log_info('ALIAS-HIT: ' + qname + ' -> ' + alias + ' ' + str(RCODE[reply.header.rcode]))
    if collapse and aliasqname:
        log_info('ALIAS-HIT: COLLAPSE ' + qname + '/IN/CNAME')

    to_cache(qname, 'IN', qtype, reply)

    return reply


def save_cache(file):
    log_info('CACHE-SAVE: Saving to \"' + file + '.db\"')

    try:
        s = shelve.open(file, flag = 'n', protocol = 2)
        s['cache'] = cache
        s.close()

    except BaseException as err:
        log_err('ERROR: Unable to open/write file \"' + file + '.db\" - ' + str(err))
        return False

    return True


def load_cache(file):
    global cache

    age = file_exist(file + '.db')
    if age and age < maxfileage:
        log_info('CACHE-LOAD: Loading from \"' + file + '.db\"')
        try:
            s = shelve.open(file, flag = 'r', protocol = 2)
            cache = s['cache']
            s.close()

        except BaseException as err:
            log_err('ERROR: Unable to open/read file \"' + file + '.db\" - ' + str(err))
            return False

        cache_purge()

    else:
        log_info('CACHE-LOAD: Skip loading cache from \"' + file + '.db\" - non-existant or older then ' + str(maxfileage) + ' seconds')
        return False

    return True


def save_lists(file):
    log_info('LIST-SAVE: Saving to \"' + file + '.db\"')

    try:
        s = shelve.open(file, flag = 'n', protocol = 2)

        s['wl_dom'] = wl_dom
        s['wl_ip4'] = wl_ip4.keys()
        s['wl_ip6'] = wl_ip6.keys()
        s['wl_rx'] = wl_rx
        s['aliases'] = aliases
        s['forward_servers'] = forward_servers

        s['bl_dom'] = bl_dom
        s['bl_ip4'] = bl_ip4.keys()
        s['bl_ip6'] = bl_ip6.keys()
        s['bl_rx'] = bl_rx

        s.close()

    except BaseException as err:
        log_err('ERROR: Unable to open/write file \"' + file + '.db\" - ' + str(err))
        return False


    return True


def load_lists(file):

    global wl_dom
    global wl_ip4
    global wl_ip6
    global wl_rx
    global aliases
    global forward_servers

    global bl_dom
    global bl_ip4
    global bl_ip6
    global bl_rx

    global cache

    age = file_exist(file + '.db')
    if age and age < maxfileage:
        log_info('LIST-LOAD: Loading from \"' + file + '.db\"')
        try:
            s = shelve.open(file, flag = 'r', protocol = 2)

            wl_dom = s['wl_dom']
            wl_ip4 = pytricia.PyTricia(32)
            for i in s['wl_ip4']:
                wl_ip4[i] = True
            wl_ip6 = pytricia.PyTricia(128)
            for i in s['wl_ip6']:
                wl_ip6[i] = True
            wl_rx = s['wl_rx']
            aliases = s['aliases']
            forward_servers = s['forward_servers']

            bl_dom = s['bl_dom']
            bl_ip4 = pytricia.PyTricia(32)
            for i in s['bl_ip4']:
                bl_ip4[i] = True
            bl_ip6 = pytricia.PyTricia(128)
            for i in s['bl_ip6']:
                bl_ip6[i] = True

            bl_rx = s['bl_rx']

            s.close()

        except BaseException as err:
            log_err('ERROR: Unable to open/read file \"' + file + '.db\" - ' + str(err))
            return False

    else:
        log_info('LIST-LOAD: Skip loading lists from \"' + file + '.db\" - non-existant or older then ' + str(maxfileage) + ' seconds')
        return False

    return True


def log_total():
    log_info('WHITELIST: ' + str(len(wl_rx)) + ' REGEXes, ' + str(len(wl_ip4)) + ' IPv4 CIDRs, ' + str(len(wl_ip6)) + ' IPv6 CIDRs, ' + str(len(wl_dom)) + ' DOMAINs, ' + str(len(aliases)) + ' ALIASes and ' + str(len(forward_servers)) + ' FORWARDs')
    log_info('BLACKLIST: ' + str(len(bl_rx)) + ' REGEXes, ' + str(len(bl_ip4)) + ' IPv4 CIDRs, ' + str(len(bl_ip6)) + ' IPv6 CIDRs and ' + str(len(bl_dom)) + ' DOMAINs')

    return True


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
        #entry = regex.sub('\s*#[^#]*$', '', line.text.encode('ascii', 'ignore').replace('\r', '').replace('\n', '')) # Strip comments and line-feeds
        entry = regex.sub('\s*#[^#]*$', '', line.replace('\r', '').replace('\n', '')) # Strip comments and line-feeds
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
            if isregex.search(entry):
                rx = entry.strip('/')
                rxlist[rx] = regex.compile(rx, regex.I)

            elif isasn.search(entry):
                # ASN Number, just discard for now
                pass

            elif isdomain.search(entry):
                domlist[entry] = True

            elif ipregex4.search(entry):
                iplist4[entry] = True

            elif ipregex6.search(entry):
                iplist6[entry] = True

            elif entry.find('=') > 0:
                elements = entry.split('=')
                if len(elements) > 1:
                    domain = elements[0].strip().lower().rstrip('.')
                    alias = elements[1].strip().lower().rstrip('.')
                    if isdomain.search(domain) and (isdomain.search(alias) or ipregex.search(alias)):
                        alist[domain] = alias
                        domlist[domain] = True # Whitelist it
                    else:
                        log_err(listname + ' INVALID ALIAS [' + str(count) + ']: ' + entry)
                else:
                    log_err(listname + ' INVALID ALIAS [' + str(count) + ']: ' + entry)

            elif entry.find('>') > 0:
                elements = entry.split('>')
                if len(elements) > 1:
                    domain = elements[0].strip().lower().rstrip('.')
                    ips = elements[1].strip().lower().rstrip('.')
                    if isdomain.search(domain):
                        domlist[domain] = True # Whitelist it
                        addrs = list()
                        for addr in ips.split(','):
                            if ipportregex.search(addr):
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

        for x in rr:
            x.ttl = ttl

    else:
        ttl = 0

    return ttl


# Retrieve from cache
def from_cache(qname, qclass, qtype, id):
    queryhash = query_hash(qname, qclass, qtype)
    cacheentry = cache.get(queryhash, defaultlist)
    if cacheentry == defaultlist:
        return None

    expire = cacheentry[1]
    now = int(time.time())
    ttl = expire - now

    # If expired, remove from cache
    if ttl < 1:
        log_info('CACHE-EXPIRED: ' + cacheentry[2])
        del_cache_entry(queryhash)
        return None

    # Retrieve from cache
    else:
        reply = cacheentry[0]
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
          
        if len(reply.rr) > 0:
            log_info('CACHE-HIT: Retrieved ' + str(len(reply.rr)) + ' RRs for ' + cacheentry[2] + ' ' + str(RCODE[reply.header.rcode]) + ' (TTL-LEFT:' + str(ttl) + ')')
        else:
            log_info('CACHE-HIT: Retrieved ' + str(RCODE[reply.header.rcode]) + ' for ' + cacheentry[2] + ' (TTL-LEFT:' + str(ttl) + ')')

        return reply

    return None


# Store into cache
def to_cache(qname, qclass, qtype, reply):
    if reply == defaultlist or reply == None:
        return False

    if query_hash(qname, qclass, qtype) in cache:
        return True

    queryname = qname + '/' + qclass + '/' + qtype
    rcode = str(RCODE[reply.header.rcode])

    if qclass == 'FORWARDER':
        ttl = 10
    else:
        if rcode in ('NODATA', 'NOTAUTH', 'NOTIMP', 'NXDOMAIN', 'REFUSED'):
            ttl = rcodettl
        elif rcode == 'SERVFAIL':
            ttl = 10
        elif rcode != 'NOERROR' or len(reply.rr) == 0:
            log_info('CACHE-SKIPPED: ' + queryname + ' ' + rcode)
            return False
        else:
            ttl = reply.rr[0].ttl

    if ttl > 0:
        expire = int(time.time()) + ttl
        queryhash = add_cache_entry(qname, qclass, qtype, expire, reply)
        entry = len(cache)
        log_info('CACHE-STORED (' + str(entry) + '): ' + queryname + ' ' + rcode + ' (TTL:' + str(ttl) + ')')

    if len(cache) > cachesize:
        cache_maintenance_now = True

    return True

# Purge cache
def cache_purge():
    cache_maintenance_now = False

    before = len(cache)

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

    after = len(cache)
    log_info('CACHE-STATS: purged ' + str(before - after) + ' entries, ' + str(after) + ' left in cache')

    if before != after:
        save_cache(cachefile)

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


# Round-Robin cycle list
def round_robin(l):
    return l[1:] + l[:1]


def id_str(id):
    return str(id).zfill(5)


def collapse_cname(request, reply, rid):
    if reply.rr:
        firstqtype = QTYPE[reply.rr[0].rtype].upper()
        if firstqtype == 'CNAME':
            qname = str(reply.rr[0].rname).rstrip('.').lower()
            ttl = reply.rr[0].ttl
            addr = list()
            for record in reply.rr:
                qtype = QTYPE[record.rtype].upper()
                if qtype in ('A', 'AAAA'):
                    ip = str(record.rdata).rstrip('.').lower()
                    addr.append(ip)

            if len(addr) > 0:
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
                reply.header.rcode = getattr(RCODE, 'NXDOMAIN')

    return reply


def seen_it(name, seen):
    if name not in seen:
        seen.add(name)
        return True

    return False


# DNS request/reply processing, main beef
class DNS_Instigator(BaseResolver):

    def resolve(self, request, handler):
        rid = request.header.id

        cip = str(handler.client_address).split('\'')[1]

        use_tcp = False
        if handler.protocol == 'tcp':
            use_tcp = True

        qname = str(request.q.qname).rstrip('.').lower()
        if qname == '':
            qname = '.'

        qclass = CLASS[request.q.qclass].upper()
        qtype = QTYPE[request.q.qtype].upper()
        queryname = qname + '/' + qclass + '/' + qtype

        log_info('REQUEST [' + id_str(rid) + '] from ' + cip + ' for ' + queryname + ' (' + handler.protocol.upper() + ')')

        # Quick response when in cache
        reply = from_cache(qname, qclass, qtype, rid)

        if reply == None:
            if qtype == 'ANY' or qclass != 'IN' or (qtype not in ('A', 'AAAA', 'CNAME', 'MX', 'NS', 'PTR', 'SOA', 'SRV', 'TXT')):
                log_info('REQUEST [' + id_str(rid) + '] from ' + cip + ': ' + queryname + ' NOTIMP (' + handler.protocol.upper() + ')')
                reply = request.reply()
                reply.header.rcode = getattr(RCODE, 'NOTIMP')

            elif blockv6 and (qtype == 'AAAA' or qname.endswith('.ip6.arpa')):
                #log_info('IPV6-HIT: ' + queryname + ' responded with NXDOMAIN')
                #reply = request.reply()
                #reply.header.rcode = getattr(RCODE, 'NXDOMAIN')
                log_info('IPV6-HIT: ' + queryname)
                reply = generate_response(request, qname, qtype, redirect_addrs)

            elif qtype in ('A', 'AAAA', 'CNAME') and in_domain(qname, aliases):
                reply = generate_alias(request, qname, qtype, use_tcp)

            else:
                ismatch = match_blacklist(rid, 'REQUEST', qtype, qname, True)
                if ismatch == True: # Blacklisted
                    reply = generate_response(request, qname, qtype, redirect_addrs)

                else:
                    if ismatch == None:
                        reply = dns_query(request, qname, qtype, use_tcp, rid, cip, True, True)
                    else:
                        reply = dns_query(request, qname, qtype, use_tcp, rid, cip, False, True)



        log_info('FINISHED [' + id_str(rid) + '] from ' + cip + ' for ' + queryname)

        return reply


# Main
if __name__ == "__main__":
    log_info('-----------------------')
    log_info('Initializing INSTIGATOR')

    # Read Lists
    if not load_lists(savefile):
        for lst in sorted(lists.keys()):
            if lst in whitelist:
                wl_dom, wl_ip4, wl_ip6, wl_rx, aliases, forward_servers = read_list(lists[lst], 'Whitelist', wl_dom, wl_ip4, wl_ip6, wl_rx, aliases, forward_servers)
            else:
                bl_dom, bl_ip4, bl_ip6, bl_rx, _, _ = read_list(lists[lst], 'Blacklist', bl_dom, bl_ip4, bl_ip6, bl_rx, dict(), dict())

        save_lists(savefile)

    log_total()

    load_cache(cachefile)

    # DNS-Server/Resolver
    logger = DNSLogger(log='-recv,-send,-request,-reply,+error,+truncated,-data', prefix=False)
    udp_dns_server = dict()
    tcp_dns_server = dict()
    for listen in listen_on:
        if ipportregex.search(listen):
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
            if cache_maintenance_now or count > 29:
                count = 0
                cache_purge()

    except (KeyboardInterrupt, SystemExit):
        pass

    for listen in listen_on:
        if ipportregex.search(listen):
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

    save_cache(cachefile)

    log_info('INSTIGATOR EXIT')
    log_info('---------------')
    sys.exit(0)

# <EOF>
