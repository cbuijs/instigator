#!/usr/bin/env python3
'''
=========================================================================================
 instigator.py: v3.03-20180724 Copyright (C) 2018 Chris Buijs <cbuijs@chrisbuijs.com>
=========================================================================================

Python DNS Forwarder/Proxy with security and filtering features

This is a little study to build a DNS server in Python including some features:

- Blacklist/Whitelist DNS queries and responses based on domain, ip or regex
- Blacklisted DNS queries never leave the building

... to be elaborated

TODO:
- Loads ...
- Logging only option (no blocking)
- Listen on IPv6 or use IPv6 as transport (need help!)
- Better Documentation / Remarks / Comments
- Optimize code for better cache/resolution performance
- Switch to dnspython or more modern lib as DNS 'engine' (backburner or seperate project)
- DNSSEC support (validation only)
- Itterative resolution besides only forwarding (as is today)

=========================================================================================
'''

# sys module and path
import sys
sys.path.append("/usr/local/lib/python3.5/dist-packages/")

# Standard modules
import os, time, socket, shelve, dbm, gc
gc.enable() # Enable garbage collection

# Random
import random
random.seed(os.urandom(128))

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

debug = False
if len(sys.argv) > 1: # Any argument on command-line will put debug-mode on, printing all messages to TTY.
    debug = True

# Listen for queries
listen_on = list(['192.168.1.251@53', '127.0.0.1@53']) # IPv4 only for now.
#listen_on = list(['172.16.1.251@53', '127.0.0.1@53']) # IPv4 only for now.
#listen_on = list(['127.0.0.1@53']) # IPv4 only for now.

# Forwarding queries to
forward_timeout = 5 # Seconds
forward_servers = dict()
#forward_servers['.'] = list(['1.1.1.1@53','1.0.0.1@53']) # DEFAULT Cloudflare !!! TTLs inconsistent !!!
#forward_servers['.'] = list(['9.9.9.9@53','149.112.112.112@53']) # DEFAULT Quad9 !!! TTLs inconsistent !!!
#forward_servers['.'] = list(['128.52.130.209@53']) # DEFAULT OpenNIC MIT
# Alternatives:
forward_servers['.'] = list(['9.9.9.10@53', '149.112.112.10@53', '1.1.1.1@53', '1.0.0.1@53', '8.8.8.8@53', '8.8.4.4@53']) # Default Quad9/CloudFlare/Google (Unfiltered versions)
#forward_servers['.'] = list(['172.16.1.1@53']) # DEFAULT Eero/Gateway
#forward_servers['.'] = list(['172.16.1.1@53','9.9.9.9@53', '149.112.112.112@53']) # DEFAULT Eero/Gateway fallback Quad9
#forward_servers['.'] = list(['172.16.1.1@53','209.244.0.3@53','209.244.0.4@53']) # DEFAULT Eero/Gateway plus fallback level-3
#forward_servers['.'] = list(['209.244.0.3@53','209.244.0.4@53']) # DEFAULT Level-3
#forward_servers['.'] = list(['8.8.8.8@53','8.8.4.4@53']) # DEFAULT Google !!! TTLs inconsistent !!!
#forward_servers['.'] = list(['208.67.222.222@443','208.67.220.220@443', '208.67.222.220@443', '208.67.220.222@443']) # DEFAULT OpenDNS
#forward_servers['.'] = list(['208.67.222.123@443','208.67.220.123@443']) # DEFAULT OpenDNS FamilyShield
#forward_servers['.'] = list(['8.26.56.26@53','8.20.247.20@53']) # DEFAULT Comodo
#forward_servers['.'] = list(['199.85.126.10@53','199.85.127.10@53']) # DEFAULT Norton
#forward_servers['.'] = list(['64.6.64.6@53','64.6.65.6@53']) # DEFAULT Verisign
#forward_servers['.'] = list(['156.154.70.2@53','156.154.71.2@53']) # DEFAULT Neustar
#forward_servers['.'] = list(['8.34.34.34@53', '8.35.35.35.35@53']) # DEFAULT ZScaler Shift
#forward_servers['.'] = list(['71.243.0.14@53', '68.237.161.14@53']) # DEFAULT Verizon New England area (Boston and NY opt-out)
#forward_servers['.'] = list(['127.0.0.1@53053']) # DEFAULT Stubby

# Redirect Address, leave empty to generete REFUSED
#redirect_addrs = list()
#redirect_addrs = list(['0.0.0.0', '0000:0000:0000:0000:0000:0000:0000:0000'])
#redirect_addrs = list(['172.16.1.1', '0000:0000:0000:0000:0000:0000:0000:0000'])
redirect_addrs = list(['192.168.1.251'])
#redirect_addrs = list(['172.16.1.1'])
#redirect_addrs = list(['blocked.eero.com'])

# Return-code when query hits a list and cannot be redirected, only use NXDOMAIN or REFUSED
hitrcode = 'NXDOMAIN'
#hitrcode = 'REFUSED'

# Only load cached/fast files when not older then maxfileage
maxfileage = 1800 # Seconds

# Files / Lists
savefile = '/opt/instigator/save.shelve'
defaultlist = list([None, 0, '', 0, 0]) # reply - expire - qname/class/type - hits - orgttl
lists = dict()
lists['blacklist'] = '/opt/instigator/black.list'
lists['whitelist'] = '/opt/instigator/white.list'
lists['aliases'] = '/opt/instigator/aliases.list'
lists['malicious-ip'] = '/opt/instigator/malicious-ip.list'
#lists['ads'] = '/opt/instigator/shallalist/adv/domains'
#lists['banking'] = '/opt/instigator/shallalist/finance/banking/domains'
#lists['costtraps'] = '/opt/instigator/shallalist/costtraps/domains'
#lists['porn'] = '/opt/instigator/shallalist/porn/domains'
#lists['gamble'] = '/opt/instigator/shallalist/gamble/domains'
#lists['spyware'] = '/opt/instigator/shallalist/spyware/domains'
#lists['trackers'] = '/opt/instigator/shallalist/tracker/domains'
#lists['updatesites'] = '/opt/instigator/shallalist/updatesites/domains'
#lists['warez'] = '/opt/instigator/shallalist/warez/domains'
blacklist = list(['blacklist', 'ads', 'costtraps', 'porn', 'gamble', 'spyware', 'warez', 'malicious-ip'])
whitelist = list(['whitelist', 'aliases', 'banking', 'updatesites'])

# Cache Settings
cachefile = '/opt/instigator/cache.shelve'
cachesize = 2048 # Entries
cache_maintenance_now = False
cache_maintenance_busy = False
persistentcache = True

# TTL Settings
if debug:
    cachettl = 20 # Seconds - For filtered/blacklisted/alias entry caching
    minttl = 5 # Seconds
    maxttl = cachettl # Seconds
    rcodettl = minttl # Seconds - For return-codes caching
else:
    cachettl = 900 # Seconds - For filtered/blacklisted/alias entry caching
    minttl = 30 # Seconds
    maxttl = 1800 # Seconds
    rcodettl = 15 # Seconds - For return-codes caching

# Filtering on or off
filtering = True

# Make queries anyway and check response (including request) after
makequery = False

# Check responses
checkresponse = True # When False, only queries are checked and responses are ignored (passthru)

# Minimal Responses
minresp = True

# Roundrobin of address/forward-records
roundrobin = True
forwardroundrobin = True

# Collapse/Flatten CNAME Chains
collapse = True

# Block IPV4 or IPv6 based queries
blockv4 = False
blockv6 = True

# Prefetch
if debug:
    prefetch = True
    prefetchgettime = 3
    prefetchhitrate = 10
else:
    prefetch = True
    prefetchgettime = 5 # Fetch at 1/x-th of TTL time
    prefetchhitrate = 120 # 1 cache-hit per xx seconds needed to get prefetched

# Command TLD to interpert as instructions, only allowed from localhost
command = 'command'

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
ttls = dict()

# Cache
cache = dict()

# Pending IDs
pending = dict()


## Regexes

# Use fast (less precisie) versions of regexes
fastregex = False

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
    ip4portregex_text = '([0-9]{1,3}\.){3}[0-9]{1,3}(@[0-9]{1,5})*'
    ip6portregex_text = '([0-9a-f]{1,4}|:)(:([0-9a-f]{0,4})){1,7}(@[0-9]{1,5})*'
else:
    ip4portregex_text = '((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}(@(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{0,3}|0))*)'
    ip6portregex_text = '(((:(:[0-9a-f]{1,4}){1,7}|::|[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){1,6}|::|:[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){1,5}|::|:[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){1,4}|::|:[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){1,3}|::|:[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){1,2}|::|:[0-9a-f]{1,4}(::[0-9a-f]{1,4}|::|:[0-9a-f]{1,4}(::|:[0-9a-f]{1,4}))))))))|(:(:[0-9a-f]{1,4}){0,5}|[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){0,4}|:[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){0,3}|:[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){0,2}|:[0-9a-f]{1,4}(:(:[0-9a-f]{1,4})?|:[0-9a-f]{1,4}(:|:[0-9a-f]{1,4})))))):(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3})(@(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{0,3}|0))*)'

ipportregex4 = regex.compile('^' + ip4portregex_text + '$', regex.I)
ipportregex6 = regex.compile('^' + ip6portregex_text + '$', regex.I)
ipportregex = regex.compile('^(' + ip4portregex_text + '|' + ip6portregex_text + ')$', regex.I)

# Regex to match domains/hosts in lists
isdomain = regex.compile('^[a-z0-9\.\_\-]+$', regex.I) # Based on RFC1035 plus underscore

# Regex to filter regexes out
isregex = regex.compile('^/.*/$')

# Regex for AS(N) Numbers
isasn = regex.compile('^AS[0-9]+$', regex.I)

##############################################################

# Log INFO messages to syslog
def log_info(message):
    if debug: print(message)
    syslog.syslog(syslog.LOG_INFO, message)
    return True


# Log ERR messages to syslog
def log_err(message):
    message = 'STRESS: ' + message
    if debug: print(message)
    syslog.syslog(syslog.LOG_ERR, message)
    return True


# Check if file exists and return age (in seconds) if so
def file_exist(file, isdb):
    if file:
        if isdb and sys.platform.startswith('linux'):
            file = file + '.db'

        try:
            if os.path.isfile(file):
                fstat = os.stat(file)
                fsize = fstat.st_size
                if fsize > 0: # File-size must be greater then zero
                    fexists = True
                    mtime = int(fstat.st_mtime)
                    currenttime = int(time.time())
                    age = int(currenttime - mtime)
                    if debug: log_info('FILE-EXIST: ' + file + ' = ' + str(age) + ' seconds old')
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
    if type == 'REPLY':
        if rrtype in ('A', 'AAAA'):
            itisanip = True
        else:
            testvalue = normalize_dom(regex.split('\s+', testvalue)[-1])

    # Check against IP-Lists
    if itisanip:
        found = False
        prefix = False

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
            if log: log_info('BLACKLIST-IP-HIT [' + id + ']: ' + type + ' ' + testvalue + ' matched against ' + prefix + ' (' + bip[prefix] + ')')
            return True
        elif prefix:
            if log: log_info('WHITELIST-IP-HIT [' + id + ']: ' + type + ' ' + testvalue + ' matched against ' + prefix + ' (' + wip[prefix] + ')')
            return False

    # Check against Sub-Domain-Lists
    elif testvalue.find('.') > 0 and isdomain.search(testvalue):
        wl_found = in_domain(testvalue, wl_dom)
        if wl_found != False:
            if log: log_info('WHITELIST-HIT [' + id + ']: ' + type + ' \"' + value + '\" matched against \"' + wl_found + '\" (' + wl_dom[wl_found] + ')')
            return False
        else:
            bl_found = in_domain(testvalue, bl_dom)
            if bl_found != False:
                if log: log_info('BLACKLIST-HIT [' + id + ']: ' + type + ' \"' + value + '\" matched against \"' + bl_found + '\" (' + bl_dom[bl_found] + ')')
                return True
    
    # Check agains Regex-Lists
    for i in wl_rx.keys():
        rx = wl_rx[i]
        if rx.search(value):
            lst = regex.split(':\s+', i)[0]
            rxn = ' '.join(regex.split(':\s+', i)[1:])
            if log: log_info('WHITELIST-REGEX-HIT [' + id + ']: ' + type + ' \"' + value + '\" matched against \"' + rxn + '\" (' + lst + ')')
            return False

    for i in bl_rx.keys():
        rx = bl_rx[i]
        if rx.search(value):
            lst = regex.split(':\s+', i)[0]
            rxn = ' '.join(regex.split(':\s+', i)[1:])
            if log: log_info('BLACKLIST-REGEX-HIT [' + id + ']: ' + type + ' \"' + value + '\" matched against \"' + rxn + '\" (' + lst + ')')
            return True

    if debug and log: log_info('NONE-HIT [' + id + ']: ' + type + ' \"' + value + '\" does not match against any lists')

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
def dns_query(request, qname, qtype, use_tcp, id, cip, checkbl, checkalias, force):
    queryname = qname + '/IN/' + qtype

    if checkbl: queryname = 'BL:' + queryname
    if checkalias: queryname = 'AL:' + queryname
    if force: queryname = 'F:' + queryname

    # Process already pending/same query
    uid = hash(qname + '/' + qtype + '/' + cip + '/' + str(id))
    count = 0
    while uid in pending:
        count += 1
        if count > 2: # Disembark after 3 seconds
            log_info('DNS-QUERY [' + id_str(id) + ']: Skipping query for ' + queryname + ' - ID already processing, takes more then 3 secs')
            reply = request.reply()
            reply.header.rcode = getattr(RCODE, 'SERVFAIL')
            return reply

        log_info('DNS-QUERY [' + id_str(id) + ']: delaying (' + str(count) + ') query for ' + queryname + ' - ID already in progress, waiting to finish')
        time.sleep(1) # Seconds

    # Get from cache if any
    if not force:
        reply = from_cache(qname, 'IN', qtype, id)
        if reply != None:
            return reply

    pending[uid] = int(time.time())

    server = in_domain(qname, forward_servers)
    if server:
        servername = 'FORWARD-HIT: ' + server
    else:
        server = '.'
        servername = 'DEFAULT'

    reply = None

    forward_server = forward_servers.get(server, False)
    if forward_server:
        query = DNSRecord(q = DNSQuestion(qname, getattr(QTYPE, qtype)))

        if forwardroundrobin and len(forward_server) > 1:
            addrs = round_robin(forward_server)
            forward_servers[server] = list(addrs)
        else:
            addrs = forward_server

        for addr in addrs:
            forward_address = addr.split('@')[0]
            if addr.find('@') > 0:
                forward_port = int(addr.split('@')[1])
            else:
                forward_port = 53
    
            if (forward_address != cip) and (query_hash(forward_address, 'BROKEN-FORWARDER', str(forward_port)) not in cache):
                log_info('DNS-QUERY [' + id_str(id) + ']: forwarding query from ' + cip + ' to ' + forward_address + '@' + str(forward_port) + ' (' + servername + ') for ' + queryname)

                error = 'None'
                failed = False
                try:
                    useip6 = False
                    if forward_address.find(':') > 0:
                        useip6 = True

                    q = query.send(forward_address, forward_port, tcp = use_tcp, timeout = forward_timeout, ipv6 = useip6)
                    reply = DNSRecord.parse(q)
                    rcode = str(RCODE[reply.header.rcode])
                    if rcode != 'SERVFAIL':
                        ttl = normalize_ttl(qname, reply.rr)
                        break
                    else:
                        error = 'SERVFAIL'
                        failed = True

                #except socket.timeout:
                except BaseException as err:
                    error = err
                    failed = True

                if failed:
                    log_err('DNS-QUERY [' + id_str(id) + ']: ERROR Resolving ' + queryname + ' using ' + forward_address + '@' + str(forward_port) + ' - ' + str(error))
                    if error != 'SERVFAIL':
                        to_cache(forward_address, 'BROKEN-FORWARDER', str(forward_port), request.reply(), force, False)
                    reply = None

            if debug: log_info('DNS-QUERY [' + id_str(id) + ']: Skipped broken/invalid forwarder ' + forward_address + '@' + str(forward_port))

    else:
        log_err('DNS-QUERY [' + id_str(id) + ']: ERROR Resolving ' + queryname + ' (' + servername + ') - NO DNS SERVERS AVAILBLE!')

    # No response, generate servfail
    if reply == None:
        log_err('DNS-QUERY [' + id_str(id) + ']: ERROR Resolving ' + queryname)
        cache.clear()
        reply = query.reply()
        reply.header.id = id
        reply.header.rcode = getattr(RCODE, 'SERVFAIL')
        _ = pending.pop(uid, None)
        return reply

    # Lets process response
    rcode = str(RCODE[reply.header.rcode])
    if rcode == 'NOERROR':
        if checkbl and reply.rr:
            replycount = 0
            replynum = len(reply.rr)

            for record in reply.rr:
                replycount += 1

                rqname = normalize_dom(record.rname)
                rqtype = QTYPE[record.rtype].upper()
                data = normalize_dom(record.rdata)

                if checkalias and rqtype in ('A', 'AAAA', 'CNAME') and in_domain(rqname, aliases):
                    reply = generate_alias(request, rqname, rqtype, use_tcp, force)
                    break

                blockit = False
                if replycount > 1 or makequery: # Request itself should already be caught during request/query phase
                    matchreq = match_blacklist(id, 'CHAIN', rqtype, rqname, True)
                    if matchreq == False:
                        break
                    elif matchreq == True:
                        blockit = True
                else:
                    log_info('REPLY-QUERY-SKIP: ' + rqname + '/IN/' + rqtype)

                if blockit == False:
                    matchrep = match_blacklist(id, 'REPLY', rqtype, data, True)
                    if matchrep == False:
                        break
                    elif matchrep == True:
                        blockit = True

                if blockit:
                    log_info('REPLY [' + id_str(id) + ':' + str(replycount) + '-' + str(replynum) + ']: ' + rqname + '/IN/' + rqtype + ' = ' + data + ' BLACKLIST-HIT')
                    reply = generate_response(request, qname, qtype, redirect_addrs, force)
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
        #reply.add_ar(EDNS0())

    # Stash in cache
    to_cache(qname, 'IN', qtype, reply, force, False)

    _ = pending.pop(uid, None)

    return reply


# Generate response when blocking
def generate_response(request, qname, qtype, redirect_addrs, force):
    queryname = qname + '/IN/' + qtype

    reply = request.reply()

    if (len(redirect_addrs) == 0) or (qtype not in ('A', 'AAAA', 'CNAME', 'ANY')):
        log_info('GENERATE: ' + hitrcode + ' for ' + queryname)
        reply.header.rcode = getattr(RCODE, hitrcode)

    else:
        addanswer = list()
        for addr in redirect_addrs:
            answer = None
            if qtype == 'A' and ipregex4.search(addr):
                answer = RR(qname, QTYPE.A, ttl=cachettl, rdata=A(addr))
            elif qtype == 'AAAA' and ipregex6.search(addr):
                answer = RR(qname, QTYPE.AAAA, ttl=cachettl, rdata=AAAA(addr))
            elif (qtype in ('A', 'AAAA')) and (not ipregex.search(addr)):
                answer = RR(qname, QTYPE.CNAME, ttl=cachettl, rdata=CNAME(addr))
        
            if answer != None:
                addanswer.append(addr)
                answer.set_rname(request.q.qname)
                reply.add_answer(answer)

        if len(addanswer) > 0:
            log_info('GENERATE: REDIRECT/NOERROR for ' + queryname + ' -> ' + ', '.join(addanswer))
            reply.header.rcode = getattr(RCODE, 'NOERROR')
        else:
            log_info('GENERATE: ' + hitrcode + ' for ' + queryname)
            reply.header.rcode = getattr(RCODE, hitrcode)

    to_cache(qname, 'IN', qtype, reply, force, False)

    return reply


# Generate alias response
def generate_alias(request, qname, qtype, use_tcp, force):
    queryname = qname + '/IN/' + qtype

    realqname = normalize_dom(request.q.qname)

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

        subreply = dns_query(request, alias, qtype, use_tcp, request.header.id, 'ALIAS-RESOLVER', False, False, False)  # To prevent loop "checkalias" must be always False (second-last argument)

        rcode = str(RCODE[subreply.header.rcode])
        if rcode == 'NOERROR' and subreply.rr:
            if collapse:
                aliasqname = realqname
            else:
                aliasqname = alias

            ttl = normalize_ttl(aliasqname, subreply.rr)

            if subreply.rr:
                for record in subreply.rr:
                    rqtype = QTYPE[record.rtype]
                    data = normalize_dom(record.rdata)
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

    to_cache(qname, 'IN', qtype, reply, force, False)

    return reply


def save_cache(file):
    if not persistentcache:
        return False

    log_info('CACHE-SAVE: Saving to \"' + file + '\"')

    try:
        #s = shelve.open(file, flag = 'n', protocol = 4)
        s = shelve.DbfilenameShelf(file, flag = 'n', protocol = 4)
        s['cache'] = cache
        s.close()

    except BaseException as err:
        log_err('ERROR: Unable to open/write file \"' + file + '\" - ' + str(err))
        return False

    return True


def load_cache(file):
    if not persistentcache:
        return False

    global cache

    age = file_exist(file, True)
    if age and age < maxfileage:
        log_info('CACHE-LOAD: Loading from \"' + file + '\"')
        try:
            #s = shelve.open(file, flag = 'r', protocol = 4)
            s = shelve.DbfilenameShelf(file, flag = 'r', protocol = 4)
            cache = s['cache']
            s.close()

        except BaseException as err:
            log_err('ERROR: Unable to open/read file \"' + file + '\" - ' + str(err))
            return False

        cache_purge(False)

    else:
        log_info('CACHE-LOAD: Skip loading cache from \"' + file + '\" - non-existant or older then ' + str(maxfileage) + ' seconds')
        return False

    return True


def to_dict(iplist):
    newlist = dict()
    for i in iplist.keys():
        newlist[i] = iplist[i]
    return newlist


def from_dict(fromlist, tolist):
    for i in fromlist.keys():
        tolist[i] = fromlist[i]
    return tolist


def save_lists(file):
    log_info('LIST-SAVE: Saving to \"' + file + '\"')

    try:
        #s = shelve.open(file, flag = 'n', protocol = 4)
        s = shelve.DbfilenameShelf(file, flag = 'n', protocol = 4)

        s['wl_dom'] = wl_dom
        s['wl_ip4'] = to_dict(wl_ip4)
        s['wl_ip6'] = to_dict(wl_ip6)
        s['wl_rx'] = wl_rx
        s['aliases'] = aliases
        s['forward_servers'] = forward_servers
        s['ttls'] = ttls

        s['bl_dom'] = bl_dom
        s['bl_ip4'] = to_dict(bl_ip4)
        s['bl_ip6'] = to_dict(bl_ip6)
        s['bl_rx'] = bl_rx

        s.close()

    except BaseException as err:
        log_err('ERROR: Unable to open/write file \"' + file + '\" - ' + str(err))
        return False


    return True


def load_lists(file):

    global wl_dom
    global wl_ip4
    global wl_ip6
    global wl_rx
    global aliases
    global forward_servers
    global ttls

    global bl_dom
    global bl_ip4
    global bl_ip6
    global bl_rx

    global cache

    age = file_exist(file, True)
    if age and age < maxfileage:
        log_info('LIST-LOAD: Loading from \"' + file + '\"')
        try:
            #s = shelve.open(file, flag = 'r', protocol = 4)
            s = shelve.DbfilenameShelf(file, flag = 'r', protocol = 4)

            wl_dom = s['wl_dom']
            wl_ip4 = pytricia.PyTricia(32)
            from_dict(s['wl_ip4'], wl_ip4)
            wl_ip6 = pytricia.PyTricia(128)
            from_dict(s['wl_ip6'], wl_ip6)
            wl_rx = s['wl_rx']
            aliases = s['aliases']
            forward_servers = s['forward_servers']
            ttls = s['ttls']

            bl_dom = s['bl_dom']
            bl_ip4 = pytricia.PyTricia(32)
            from_dict(s['bl_ip4'], bl_ip4)
            bl_ip6 = pytricia.PyTricia(128)
            from_dict(s['bl_ip6'], bl_ip6)

            bl_rx = s['bl_rx']

            s.close()

        except BaseException as err:
            log_err('ERROR: Unable to open/read file \"' + file + '\" - ' + str(err))
            return False

    else:
        log_info('LIST-LOAD: Skip loading lists from \"' + file + '\" - non-existant or older then ' + str(maxfileage) + ' seconds')
        return False

    return True


def log_total():
    log_info('WHITELIST: ' + str(len(wl_rx)) + ' REGEXes, ' + str(len(wl_ip4)) + ' IPv4 CIDRs, ' + str(len(wl_ip6)) + ' IPv6 CIDRs, ' + str(len(wl_dom)) + ' DOMAINs, ' + str(len(aliases)) + ' ALIASes, ' + str(len(forward_servers)) + ' FORWARDs and ' + str(len(ttls)) + ' TTLs')
    log_info('BLACKLIST: ' + str(len(bl_rx)) + ' REGEXes, ' + str(len(bl_ip4)) + ' IPv4 CIDRs, ' + str(len(bl_ip6)) + ' IPv6 CIDRs and ' + str(len(bl_dom)) + ' DOMAINs')

    return True


# Reverse IP
def rev_ip(cidr):

    if cidr.find('/') == -1:
        ip = cidr
        if cidr.find(':') == -1:
            bits = 32
        else:
            bits = 128
    else:
        ip, bits  = cidr.split('/')

    if ip.find(':') == -1:
        if bits in ('8', '16', '24', '32'):
            cut = int(int(bits) / 8)
            arpa = '.'.join('.'.join(ip.split('.')[:cut]).split('.')[::-1]) + '.in-addr.arpa'  # Add IPv4 in-addr.arpa
        else:
            arpa = 'dummy-' + cidr

    else:
        a = ip.replace(':', '')
        arpa = '.'.join(a[i:i+1] for i in range(0, len(a), 1))[::-1] + '.ip6.arpa'  # Add IPv6 ip6.arpa

    return arpa


def normalize_dom(dom):
    return str(dom).strip().strip('.').lower() or '.'


# Read filter lists, see "accomplist" to provide ready-2-use lists:
# https://github.com/cbuijs/accomplist
def read_list(file, listname, bw, domlist, iplist4, iplist6, rxlist, alist, flist, tlist):
    log_info('Fetching ' + bw + ' \"' + listname + '\" entries from \"' + file + '\"')

    count = 0
    fetched = 0

    if file_exist(file, False):
        try:
            f = open(file, 'r')
            lines = f.readlines()
            f.close()

        except BaseException as err:
            log_err('ERROR: Unable to open/read/process file \"' + file + '\" - ' + str(err))

        for line in lines:
            count += 1
            entry = regex.sub('\s*#[^#]*$', '', line.replace('\r', '').replace('\n', '')) # Strip comments and line-feeds

            if entry.startswith('/'):
                id = ' '.join(regex.split('\t+', entry)[1:]).strip() or listname
                entry = regex.sub('/\s+[^/]+$', '/', entry).strip()
            else:
                id = ' '.join(regex.split('\s+', entry)[1:]).strip() or listname
                entry = regex.split('\s+', entry)[0].strip()

            # If entry ends in questionmark, it is a "forced" entry. Not used for the moment. Heritage of unbound dns-firewall.
            if entry.endswith('!'):
                entry = entry[:-1]

            # If entry ends in ampersand, it is a "safelisted" entry. Not used for the moment. Heritage of unbound dns-firewall.
            if entry.endswith('&'):
                entry = ''

            if entry and len(entry) > 0 and (not entry.startswith('#')):

                # REGEX
                if isregex.search(entry):
                    fetched += 1
                    rx = entry.strip('/')
                    rxlist[id + ': ' + rx] = regex.compile(rx, regex.I)

                # ASN
                elif isasn.search(entry):
                    _ = entry

                # DOMAIN
                elif isdomain.search(entry):
                    entry = normalize_dom(entry)
                    if entry != '.':
                        fetched += 1
                        domlist[entry] = id

                # IPV4
                elif ipregex4.search(entry):
                    fetched += 1
                    iplist4[entry] = id
                    domlist[rev_ip(entry)] = 'Auto-Reverse ' + entry + ' - ' + id

                # IPV6
                elif ipregex6.search(entry):
                    fetched += 1
                    iplist6[entry] = id
                    domlist[rev_ip(entry)] = 'Auto-Reverse ' + entry + ' - ' + id

                #### !!! From here on there are functional entries, which are always condidered "whitelist"
                # ALIAS - domain.com=ip or domain.com=otherdomain.com
                elif entry.find('=') > 0:
                    elements = entry.split('=')
                    if len(elements) > 1:
                        domain = normalize_dom(elements[0])
                        alias = normalize_dom(elements[1])
                        if isdomain.search(domain) and (isdomain.search(alias) or ipregex.search(alias)):
                            fetched += 1
                            alist[domain] = alias
                            domlist[domain] = 'Alias' # Whitelist it
                        else:
                            log_err(listname + ' INVALID ALIAS [' + str(count) + ']: ' + entry)
                    else:
                        log_err(listname + ' INVALID ALIAS [' + str(count) + ']: ' + entry)

                # FORWARD - domain.com>ip
                elif entry.find('>') > 0:
                    elements = entry.split('>')
                    if len(elements) > 1:
                        domain = normalize_dom(elements[0])
                        ips = elements[1].strip().lower().strip('.')
                        if isdomain.search(domain):
                            domlist[domain] = 'Forward-Domain' # Whitelist it
                            addrs = list()
                            for addr in ips.split(','):
                                if ipportregex.search(addr):
                                    addrs.append(addr)
                                else:
                                    log_err(listname + ' INVALID FORWARD-ADDRESS [' + str(count) + ']: ' + addr)
        
                            if addrs:
                                fetched += 1
                                flist[domain] = addrs
                        else:
                            log_err(listname + ' INVALID FORWARD [' + str(count) + ']: ' + entry)
                    else:
                        log_err(listname + ' INVALID FORWARD [' + str(count) + ']: ' + entry)

                # TTLS - domain.com!ttl (TTL = integer)
                elif entry.find('!') > 0:
                    elements = entry.split('!')
                    if len(elements) > 1:
                        domain = normalize_dom(elements[0])
                        ttl = elements[1].strip()
                        if isdomain.search(domain) and ttl.isdecimal():
                            fetched += 1
                            tlist[domain] = int(ttl)
                            domlist[domain] = 'TTL-Override' # Whitelist it
                        else:
                            log_err(listname + ' INVALID TTL [' + str(count) + ']: ' + entry)
                    else:
                        log_err(listname + ' INVALID TTL [' + str(count) + ']: ' + entry)

                # BOGUS
                else:
                    log_err(listname + ' INVALID LINE [' + str(count) + ']: ' + entry)

    else:
        log_err('ERROR: Cannot open \"' + file + '\" - Does not exist')

    log_info(listname + ' Processed ' + str(count) + ' lines and used ' + str(fetched))

    return domlist, iplist4, iplist6, rxlist, alist, flist, tlist


# Normalize TTL's, take either lowest or highest TTL for all records in RRSET
def normalize_ttl(qname, rr):
    if rr and len(rr) > 0:
        overridettl = False
        if filtering:
            newttl = in_domain(qname, ttls)
            if newttl:
                overridettl = ttls.get(newttl, False)
        
        if overridettl:
            log_info('TTL-HIT: Setting TTL for ' + qname + ' (' + newttl + ') to ' + str(overridettl))
            ttl = overridettl
        else:
            if len(rr) == 1:
                ttl = rr[0].ttl
            else:
                #ttl = min(x.ttl for x in rr) # Lowest TTL
                #ttl = max(x.ttl for x in rr) # Highest TTL
                ttl = int(sum(x.ttl for x in rr) / len(rr)) # Average TTL

            if ttl < minttl:
                #ttl = minttl
                #ttl = random.randint(minttl,maxttl)
                ttl += minttl
            elif ttl > maxttl:
                ttl = maxttl

        for x in rr:
            x.ttl = ttl

    else:
        ttl = 0

    return ttl


# Update hits
def update_hits(queryhash):
    if queryhash in cache:
        cache[queryhash][3] += 1
        return cache[queryhash][3]

    return 0


# Prefetch
def prefetch_it(queryhash):
    record = cache.get(queryhash, defaultlist)
    expire = record[1]
    if expire != 0 and record[0].rr:
        rcode = str(RCODE[record[0].header.rcode])
        if rcode == 'NOERROR':
            now = int(time.time())
            ttlleft = expire - now
            queryname = record[2]
            hits = record[3]
            orgttl = record[4]
            hitsneeded = int(round(orgttl / prefetchhitrate))

            log_info('CACHE-PREFETCH: ' + queryname + ' ' + rcode + ' [' + str(hits) + '/' + str(hitsneeded) + ' hits] (TTL-LEFT:' + str(ttlleft) + '/' + str(orgttl) + ')')

            _ = cache.pop(queryhash, defaultlist)
            qname, qclass, qtype = queryname.split('/')
            request = DNSRecord.question(qname, qtype, qclass)
            #request.header.id = 0 # !!! TEST
            request.header.id = random.randint(1,65535)
            handler = DNSHandler
            handler.protocol = 'udp'
            handler.client_address = '\'PREFETCHER\''
            _ = do_query(request, handler, True) # Query and update cache
            return True

    return False


# Retrieve from cache
def from_cache(qname, qclass, qtype, id):
    queryhash = query_hash(qname, qclass, qtype)
    cacheentry = cache.get(queryhash, defaultlist)
    if cacheentry == defaultlist or cacheentry == None:
        return None

    expire = cacheentry[1]
    now = int(time.time())
    ttl = expire - now

    # If expired, remove from cache
    if ttl < 1:
        orgttl = cacheentry[4]
        hitsneeded = int(round(orgttl / prefetchhitrate))
        rcode = str(RCODE[cacheentry[0].header.rcode])
        log_info('CACHE-EXPIRED: ' + cacheentry[2] + ' ' + rcode + ' [' + str(cacheentry[3]) + '/' + str(hitsneeded) + ' hits]' + ' (TTL-EXPIRED:' + str(ttl) + '/' + str(cacheentry[4]) + ')')
        del_cache_entry(queryhash)
        return None

    # Pull from cache
    else:
        reply = cacheentry[0]
        reply.header.id = id

        numhits = update_hits(queryhash)

        redirected = "STANDARD"

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

        elif len(reply.rr) > 0:
            reply.rr[0].ttl = ttl
            rdata = str(reply.rr[0].rdata)
            if rdata in redirect_addrs:
                redirected = 'REDIRECT->' + rdata
          
        if len(reply.rr) > 0:
            log_info('CACHE-HIT (' + str(numhits) + ' hits) : Retrieved ' + str(len(reply.rr)) + ' RRs for ' + cacheentry[2] + ' ' + str(RCODE[reply.header.rcode]) + '/' + redirected + ' (TTL-LEFT:' + str(ttl) + '/' + str(cacheentry[4]) + ')')
        else:
            log_info('CACHE-HIT (' + str(numhits) + ' hits) : Retrieved ' + str(RCODE[reply.header.rcode]) + '/' + redirected + ' for ' + cacheentry[2] + ' (TTL-LEFT:' + str(ttl) + '/' + str(cacheentry[4]) + ')')

        return reply

    return None


# Store into cache
def to_cache(qname, qclass, qtype, reply, force, newttl):
    if reply == defaultlist or reply == None:
        return False

    if (not force) and query_hash(qname, qclass, qtype) in cache:
        return True

    queryname = qname + '/' + qclass + '/' + qtype
    rcode = str(RCODE[reply.header.rcode])

    if qclass == 'BROKEN-FORWARDER':
        ttl = 5 # Seconds before trying again
    else:
        if rcode in ('NODATA', 'NOTAUTH', 'NOTIMP', 'NXDOMAIN', 'REFUSED'):
            ttl = rcodettl
        elif rcode == 'SERVFAIL':
            ttl = 10
        elif rcode == 'NOERROR' and len(reply.rr) == 0:
            log_info('CACHE-SKIPPED: ' + queryname + ' ' + rcode + ' (NO ANSWERS)')
            return False
        elif rcode != 'NOERROR':
            log_info('CACHE-SKIPPED: ' + queryname + ' ' + rcode)
            return False
        else:
            if newttl:
                ttl = newttl
            else:
                ttl = reply.rr[0].ttl

    if ttl > 0:
        expire = int(time.time()) + ttl
        queryhash = add_cache_entry(qname, qclass, qtype, expire, ttl, reply, force)

    if len(cache) > cachesize:
        cache_maintenance_now = True

    return True


# get list of purgable items
def cache_expired_list():
    now = int(time.time())
    return list(dict((k,v) for k,v in cache.items() if v[1] - now < 1).keys())


# Get list of prefetchable items
def cache_prefetch_list():
    now = int(time.time())
    # Formula: At least 2 cache-hits, hirate > 0 and hits are above/equal hitrate
    # value list entries: 0:reply - 1:expire - 2:qname/class/type - 3:hits - 4:orgttl
    return list(dict((k,v) for k,v in cache.items() if v[3] > 1 and int(round(v[4] / prefetchhitrate)) > 0 and v[1] - now < int(round(v[4] / prefetchgettime)) and v[3] >= int((round(v[4] / prefetchhitrate)) - (round((v[1] - now) / prefetchhitrate)))).keys())


# Purge cache
def cache_purge(flushall):
    global cache_maintenance_busy
    global cache_maintenance_now

    if cache_maintenance_busy:
        return False

    log_info('CACHE-MAINT: Start')

    cache_maintenance_busy = True
    cache_maintenance_now = False

    # Remove old pending
    for p in list(dict((k,v) for k,v in pending.items() if int(time.time()) - v > 10).keys()):
        timestamp = pending.get(p, False)
        if timestamp and int(time.time()) - timestamp > 10: #Seconds
            log_info('PENDING: Removed stale UID ' + str(p))
            _ = pending.pop(d, None)

    before = len(cache)

    # Prefetch
    for queryhash in cache_prefetch_list():
        prefetch_it(queryhash)

    # Remove expired entries
    if flushall:
        lst = list(cache.keys())
    else:
        lst = cache_expired_list()

    for queryhash in lst:
        record = cache.get(queryhash, defaultlist)
        now = int(time.time())
        if flushall:
            expire = now
        else:
            expire = record[1]
        ttlleft = expire - now
        orgttl = record[4]
        hitsneeded = int(round(orgttl / prefetchhitrate))
        rcode = str(RCODE[record[0].header.rcode])
        log_info('CACHE-MAINT-EXPIRED: ' + record[2] + ' ' + rcode + ' [' + str(record[3]) + '/' + str(hitsneeded) + ' hits] (TTL-EXPIRED:' + str(ttlleft) + '/' + str(orgttl) + ')')
        del_cache_entry(queryhash)

    # Prune cache back to cachesize, removing lowest TTLs first
    size = len(cache)
    if (size > cachesize):
        expire = dict()
        for queryhash in list(cache.keys()):
            now = int(time.time())
            expire[queryhash] = cache.get(queryhash, defaultlist)[1] - now

        for queryhash in list(sorted(expire, key=expire.get))[0:size-cachesize]:
            log_info('CACHE-MAINT-EXPULSION: ' + cache.get(queryhash, defaultlist)[2] + ' (TTL-LEFT:' + str(expire[queryhash]) + ')')
            del_cache_entry(queryhash)

    after = len(cache)

    if before != after:
        log_info('CACHE-STATS: purged ' + str(before - after) + ' entries, ' + str(after) + ' left in cache')
        save_cache(cachefile)

    log_info('CACHE-MAINT: Finish')

    gc.collect();

    cache_maintenance_busy = False

    return True


def query_hash(qname, qclass, qtype):
    return hash(qname + '/' + qclass + '/' + qtype)


def add_cache_entry(qname, qclass, qtype, expire, ttl, reply, force):
    hashname = qname + '/' + qclass + '/' + qtype
    rcode = str(RCODE[reply.header.rcode])
    queryhash = query_hash(qname, qclass, qtype)

    cache[queryhash] = list([reply, expire, hashname, 1, ttl]) # reply - expire - qname/class/type - hits - orgttl

    log_info('CACHE-UPDATE (' + str(len(cache)) + ' entries): ' + hashname + ' ' + rcode + ' (TTL:' + str(ttl) + ')')

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
    if filtering and reply.rr:
        firstqtype = QTYPE[reply.rr[0].rtype].upper()
        if firstqtype == 'CNAME':
            qname = normalize_dom(reply.rr[0].rname)
            ttl = reply.rr[0].ttl
            addr = list()
            for record in reply.rr:
                qtype = QTYPE[record.rtype].upper()
                if qtype in ('A', 'AAAA'):
                    ip = str(record.rdata).lower()
                    addr.append(ip)

            if len(addr) > 0:
                reply = request.reply()
                reply.header.rcode = getattr(RCODE, 'NOERROR')
                count = 0
                total = str(len(addr))
                for ip in addr:
                    count += 1
                    if ip.find(':') == -1:
                        rrtype = "A"
                        answer = RR(qname, QTYPE.A, ttl=ttl, rdata=A(ip))
                    else:
                        rrtype = "AAAA"
                        answer = RR(qname, QTYPE.AAAA, ttl=ttl, rdata=AAAA(ip))

                    log_info('REPLY [' + id_str(rid) + ':' + str(count) + '-' + total + ']: COLLAPSE ' + qname + '/IN/CNAME -> ' + str(ip) + '/' + rrtype)

                    reply.add_answer(answer)
            else:
                reply = request.reply()
                reply.header.rcode = getattr(RCODE, 'NXDOMAIN')

    return reply


def execute_command(qname):
    global filtering

    qname = regex.sub('\.' + command + '$', '', qname)

    log_info('COMMAND: ' + qname)

    if qname in ('flush', 'pause', 'resume', 'show'):
        now = int(time.time())

        if qname == 'show':
            count = 0
            total = str(len(cache))
            for i in list(cache.keys()):
                count += 1
                record = cache.get(i, defaultlist)
                if record[0] != None:
                    log_info('CACHE-INFO (' + str(count) + '/' + total + '): ' + cache[i][2] + ' [' + str(record[3]) + ' Hits] (TTL-LEFT:' + str(record[1] - now) + '/' + str(record[4]) + ')')

        else:
            cache_purge(True)

        if qname == 'resume':
            filtering = True

        elif qname == 'pause':
            filtering = False

        return True

    log_info('COMMAND: ' + qname + ' UNKNOWN/FAILED')
    return False


def seen_it(name, seen):
    if name not in seen:
        seen.add(name)
    else:
        return True

    return False


# Query
def do_query(request, handler, force):
    rid = request.header.id

    cip = str(handler.client_address).split('\'')[1]

    use_tcp = False
    if handler.protocol == 'tcp':
        use_tcp = True

    qname = normalize_dom(request.q.qname)
    qclass = CLASS[request.q.qclass].upper()
    qtype = QTYPE[request.q.qtype].upper()

    queryname = qname + '/' + qclass + '/' + qtype

    log_info('REQUEST [' + id_str(rid) + '] from ' + cip + ' for ' + queryname + ' (' + handler.protocol.upper() + ')')

    # Quick response when in cache
    reply = None

    if command and qname.endswith('.' + command):
        reply = request.reply()
        if cip in ('127.0.0.1', '::1'):
            if execute_command(qname):
                reply.header.rcode = getattr(RCODE, 'NXDOMAIN')
            else:
                reply.header.rcode = getattr(RCODE, 'SERVFAIL')
        else:
            reply.header.rcode = getattr(RCODE, 'REFUSED')

    if reply == None and (not force):
        reply = from_cache(qname, qclass, qtype, rid)

    if reply == None:
        if not isdomain.search(qname):
            log_err('REQUEST [' + id_str(rid) + '] from ' + cip + ': ' + queryname + ' SERVFAIL - INVALID SYNTAX (' + handler.protocol.upper() + ')')
            reply = request.reply()
            reply.header.rcode = getattr(RCODE, 'SERVFAIL')

        elif qtype == 'ANY' or qclass != 'IN' or (qtype not in ('A', 'AAAA', 'CNAME', 'MX', 'NS', 'PTR', 'SOA', 'SRV', 'TXT')):
            log_info('REQUEST [' + id_str(rid) + '] from ' + cip + ': ' + queryname + ' NOTIMP (' + handler.protocol.upper() + ')')
            reply = request.reply()
            reply.header.rcode = getattr(RCODE, 'NOTIMP')

        elif filtering and blockv4 and (qtype == 'A' or qname.endswith('.in-addr.arpa')):
            log_info('IPV4-HIT: ' + queryname)
            reply = generate_response(request, qname, qtype, redirect_addrs, force)

        elif filtering and blockv6 and (qtype == 'AAAA' or qname.endswith('.ip6.arpa')):
            log_info('IPV6-HIT: ' + queryname)
            reply = generate_response(request, qname, qtype, redirect_addrs, force)

        elif filtering and qtype in ('A', 'AAAA', 'CNAME') and in_domain(qname, aliases):
            reply = generate_alias(request, qname, qtype, use_tcp, force)

        else:
            if filtering:
                if makequery: # Make query anyway and check it after response instead of before sending query
                    log_info('MAKEQUERY: ' + queryname)
                    reply = dns_query(request, qname, qtype, use_tcp, rid, cip, True, True, force)
                else:
                    ismatch = match_blacklist(rid, 'REQUEST', qtype, qname, True)
                    if ismatch == True: # Blacklisted
                        reply = generate_response(request, qname, qtype, redirect_addrs, force)
                    else:
                        if ismatch == None and checkresponse:
                            reply = dns_query(request, qname, qtype, use_tcp, rid, cip, True, True, force)
                        else:
                            reply = dns_query(request, qname, qtype, use_tcp, rid, cip, False, True, force)
            else:
                reply = dns_query(request, qname, qtype, use_tcp, rid, cip, False, False, force)


    log_info('FINISHED [' + id_str(rid) + '] from ' + cip + ' for ' + queryname)

    return reply


# DNS request/reply processing, main beef
class DNS_Instigator(BaseResolver):

    def resolve(self, request, handler):

        return do_query(request, handler, False)


# Main
if __name__ == "__main__":
    log_info('-----------------------')
    log_info('Initializing INSTIGATOR')

    if debug: log_info('RUNNING INSTIGATOR IN DEBUG MODE')

    # Read Lists
    for addr in redirect_addrs:
        if ipregex4.search(addr):
            bl_ip4[addr] = 'Redirect Address'
        elif ipregex6.search(addr):
            bl_ip6[addr] = 'Redirect Address'

    if not load_lists(savefile):
        for lst in sorted(lists.keys()):
            if lst in whitelist:
                wl_dom, wl_ip4, wl_ip6, wl_rx, aliases, forward_servers, ttls = read_list(lists[lst], lst, 'Whitelist', wl_dom, wl_ip4, wl_ip6, wl_rx, aliases, forward_servers, ttls)
            else:
                bl_dom, bl_ip4, bl_ip6, bl_rx, _, _, _ = read_list(lists[lst], lst, 'Blacklist', bl_dom, bl_ip4, bl_ip6, bl_rx, dict(), dict(), dict())

        save_lists(savefile)

    wl_dom[command] = 'Command-TLD'

    log_total()

    if not debug:
        load_cache(cachefile)

    # DNS-Server/Resolver
    logger = DNSLogger(log='-recv,-send,-request,-reply,+error,+truncated,-data', prefix=False)
    udp_dns_server = dict()
    tcp_dns_server = dict()
    handler = DNSHandler
    for listen in listen_on:
        if ipportregex.search(listen):
            elements = listen.split('@')
            listen_address = elements[0]
            if len(elements) > 1:
                listen_port = int(elements[1])
            else:
                listen_port = 53


            log_info('Starting DNS Service on ' + listen_address + ' at port ' + str(listen_port) + ' ...')

            # Define Service
            #handler = DNSHandler
            if ipregex6.search(listen_address):
                log_info('LISTENING on IPv6 not supported yet!')
                serverhash = False
            else:
                serverhash = hash(listen_address + '@' + str(listen_port))
                udp_dns_server[serverhash] = DNSServer(DNS_Instigator(), address=listen_address, port=listen_port, logger=logger, tcp=False, handler=handler) # UDP
                tcp_dns_server[serverhash] = DNSServer(DNS_Instigator(), address=listen_address, port=listen_port, logger=logger, tcp=True, handler=handler) # TCP

            # Start Service as threads
            if serverhash:
                try:
                    udp_dns_server[serverhash].start_thread() # UDP
                    tcp_dns_server[serverhash].start_thread() # TCP
                except BaseException as err:
                    log_err('ERROR: Unable to start service on ' + listen_address + ' at port ' + str(listen_port) + ' - ' + str(err) + ', ABORTING')
                    sys.exit(1)

                time.sleep(0.5)

                if udp_dns_server[serverhash].isAlive() and tcp_dns_server[serverhash].isAlive():
                    log_info('DNS Service ready on ' + listen_address + ' at port ' + str(listen_port))
                else:
                    log_err('DNS Service did not start, aborting ...')
                    sys.exit(1)


    # Keep things running
    count = 0
    try:
        while True:
            time.sleep(1) # Seconds
            count += 1

            if not cache_maintenance_busy:
                if cache_maintenance_now or count > 29 or cache_expired_list() or cache_prefetch_list():
                    count = 0
                    cache_purge(False)

    except (KeyboardInterrupt, SystemExit):
        pass


    for listen in listen_on:
        if ipportregex.search(listen):
            elements = listen.split('@')
            listen_address = elements[0]
            if len(elements) > 1:
                listen_port = int(elements[1])
            else:
                listen_port = 53

            serverhash = hash(listen_address + '@' + str(listen_port))

            log_info('DNS Service shutdown on ' + listen_address + ' at port ' + str(listen_port))

            try:
                udp_dns_server[serverhash].stop() # UDP
                tcp_dns_server[serverhash].stop() # TCP
            except BaseException as err:
                log_err('ERROR: Unable to stop service on ' + listen_address + ' at port ' + str(listen_port) + ' - ' + str(err))
                pass

    save_cache(cachefile)

    log_info('INSTIGATOR EXIT')
    log_info('---------------')
    sys.exit(0)

# <EOF>
