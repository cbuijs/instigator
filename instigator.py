#!/usr/bin/env python3
'''
=========================================================================================
 instigator.py: v4.07-20180929 Copyright (C) 2018 Chris Buijs <cbuijs@chrisbuijs.com>
=========================================================================================

Python DNS Forwarder/Proxy with security and filtering features

GitHub: https://github.com/cbuijs/instigator

This is a little study to build a DNS server in Python including some features:

- Blacklist/Whitelist DNS queries and responses based on domain, ip or regex
- Blacklisted DNS queries never leave the building

... to be elaborated.

ToDo/Ideas:
- Loads ...
- Use configuration file in easy format to configure Instigator. Status: Partly Done.
- Logging only option (no blocking). Status: Partly Done.
- Listen on IPv6 or use IPv6 as transport. Status: Help Needed.
- Better Documentation / Remarks / Comments. Status: Ongoing.
- Optimize code for better cache/resolution performance. Status: Ongoing.
- Cleanup code and optimize. Some of it is hacky-quick-code. Status: Ongoing.
- Switch to dnspython or more modern lib as DNS 'engine'. Status: Backburner.
- DNSSEC support (validation only), like DNSMasq. Status: Backburner.
- Itterative resolution besides only forwarding (as is today). Status: Backburner.
- Add more security-features against hammering, dns-drip, ddos, etc. Status: Backburner.
- Fix SYSLOG on MacOS. Status: To-be-done.
- Convert all concatenated strings into .format ones. Status: In Progress

=========================================================================================
'''

# sys module and path
import sys
sys.path.append('/usr/local/lib/python3.5/dist-packages/')

# Standard modules
import os, time, shelve, dbm, gc # DBM used for Shelve
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

# Debugging
debug = False
if len(sys.argv) > 1: # Any argument on command-line will put debug-mode on, printing all messages to TTY.
    debug = True

# Config
configfile = '/opt/instigator/instigator.conf'

# Listen for queries
#listen_on = list(['192.168.1.251@53', '127.0.0.1@53']) # IPv4 only for now.
listen_on = list(['172.16.1.251@53', '127.0.0.1@53']) # IPv4 only for now.
#listen_on = list(['@53']) # Listen on all interfaces/ip's
#listen_on = list(['127.0.0.1@53']) # IPv4 only for now.

# Forwarding queries to
forward_timeout = 5 # Seconds
forward_servers = dict()
#forward_servers['.'] = list(['1.1.1.1@53','1.0.0.1@53']) # DEFAULT Cloudflare !!! TTLs inconsistent !!!
#forward_servers['.'] = list(['9.9.9.9@53','149.112.112.112@53']) # DEFAULT Quad9 !!! TTLs inconsistent !!!
#forward_servers['.'] = list(['128.52.130.209@53']) # DEFAULT OpenNIC MIT
# Alternatives:
#forward_servers['.'] = list(['9.9.9.10@53', '149.112.112.10@53', '1.1.1.1@53', '1.0.0.1@53', '8.8.8.8@53', '8.8.4.4@53']) # Default Quad9/CloudFlare/Google (Unfiltered versions)
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
#forward_servers['.'] = list(['127.0.0.1@53001', '127.0.0.1@53002', '127.0.0.1@53003', '127.0.0.1@53004']) # DEFAULT Stubby
forward_servers['.'] = list(['172.16.1.1@53053']) # Stubby on router

# Redirect Address, leave empty to generete REFUSED
#redirect_addrs = list()
redirect_addrs = list(['NODATA'])
#redirect_addrs = list(['0.0.0.0', '0000:0000:0000:0000:0000:0000:0000:0000'])
#redirect_addrs = list(['172.16.1.1', '0000:0000:0000:0000:0000:0000:0000:0000'])
#redirect_addrs = list(['172.16.1.251'])
#redirect_addrs = list(['block.frutch'])
#redirect_addrs = list(['172.16.1.1'])
#redirect_addrs = list(['blocked.eero.com']) # test with eero-plus stuff

# ACL's
aclrcode = 'REFUSED'
allow_query4 = pytricia.PyTricia(32)
allow_query4['10.0.0.0/8'] = 'RFC1918 10.0.0.0/8'
allow_query4['127.0.0.1/32'] = 'RFC990 Localhost'
allow_query4['172.16.0.0/12'] = 'RFC1918 172.16.0.0/12'
allow_query4['192.168.0.0/16'] = 'RFC1918 192.168.0.0/16'
allow_query6 = pytricia.PyTricia(128)
allow_query6['::1/128'] = 'RFC4291 Localhost'

# Return-code when query hits a list and cannot be redirected, only use NODATA, NXDOMAIN or REFUSED
#hitrcode = 'NODATA'
hitrcode = 'NXDOMAIN'
#hitrcode = 'REFUSED'

# Only load cached/fast files when not older then maxfileage
maxfileage = 43200 # Seconds

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
searchdom = set()

# Root servers # !!! WIP
#root_servers = list(['198.41.0.4', '2001:503:ba3e::2:30', '199.9.14.201', '2001:500:200::b', '192.33.4.12', '2001:500:2::c', '199.7.91.13', '2001:500:2d::d', '192.203.230.10', '2001:500:a8::e', '192.5.5.241', '2001:500:2f::f', '192.112.36.4', '2001:500:12::d0d', '198.97.190.53', '2001:500:1::53', '192.36.148.17', '2001:7fe::53', '192.58.128.30', '2001:503:c27::2:30', '193.0.14.129', '2001:7fd::1', '199.7.83.42', '2001:500:9f::42', '202.12.27.33', '2001:dc3::35'])

# Cache Settings
nocache = False # Don't change this
cachefile = '/opt/instigator/cache.shelve'
cachesize = 2048 # Entries
cache_maintenance_now = False
cache_maintenance_busy = False
persistentcache = True

# TTL Settings
ttlstrategy = 'average' # average/lowest/highest/random - Egalize TTL on all RRs in RRSET
filterttl = 900 # Seconds - For filtered/blacklisted/alias entry caching
minttl = 60 # Seconds
maxttl = 86400 # Seconds - 3600 = 1 Hour, 86400 = 1 Day, 604800 = 1 Week
rcodettl = 30 # Seconds - For return-codes caching
failttl = 10 # Seconds - When failure/error happens
retryttl = 5 # Seconds - Retry time
nottl = 0 # Seconds - when no TTL or zero ttl

# Filtering on or off
filtering = True

# Force to make queries anyway and check response (including request) after, e.g. query is ALWAYS done
forcequery = False

# Check responses
checkresponse = True # When False, only queries are checked and responses are ignored (passthru)

# Minimal Responses
minresp = True

# Minimum number of dots in a domain-name
mindots = 1

# Roundrobin of address/forward-records
roundrobin = True
forwardroundrobin = True

# Collapse/Flatten CNAME Chains
collapse = True

# Block IPV4 or IPv6 based queries
blockv4 = False
blockv6 = True # Put on False as default

# Block undotted names
blockundotted = True

# Block illegal names
blockillegal = True

# Block weird
blockweird = True

# Block subdomains for NODATA, NXDOMAIN, REFUSED and SERVFAIL rcodes received for parent
blocksub = True

# Block queries in search-domains (from /etc/resolv.conf) if entry already exist in cache without searchdomain
blocksearchdom = True

# Block rebinding, meaning that IP-Addresses in responses that match against below ranges,
# must come from a DNS server with an IP-Address also in below ranges
blockrebind = True
rebind4 = pytricia.PyTricia(32)
rebind4['0.0.0.0/8'] = 'Only valid as source'
rebind4['10.0.0.0/8'] = 'Private'
rebind4['127.0.0.0/8'] = 'Loopback'
rebind4['168.254.0.0/16'] = 'Link-Local/APIPA'
rebind4['172.16.0.0/12'] = 'Private'
rebind4['192.0.0.0/24'] = 'Private, Protocol Assignements'
rebind4['192.0.2.0/24'] = 'Documentation/Examples TEST-NET-1'
rebind4['192.168.0.0/16'] = 'Private'
rebind4['198.18.0.0/15'] = 'Private, Benchmarking'
rebind4['198.51.100.0/24'] = 'Documentation/Examples TEST-NET-2'
rebind4['203.0.113.0/24'] = 'Documentation/Examples TEST-NET-3'
rebind4['224.0.0.0/4'] = 'Multicast'
rebind4['240.0.0.0/4'] = 'Reserved (Class-E)'
rebind6 = pytricia.PyTricia(128)
rebind6['::/128'] = 'Reserved/Unspecified'
rebind6['::1/128'] = 'Loopback'
rebind6['2001:db8::/32'] = 'Documentation/Examples'
rebind6['fc00::/7'] = 'Private'
rebind6['fe80::/10'] = 'Link-Local'
rebind6['ff00::/8'] = 'Multicast'
rebind6['ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128'] = True

# Prefetch
prefetch = True
prefetching_busy = False
prefetchgettime = 10 # Fetch at 1/x-th of TTL time
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

# Use fast (less precisie, sometimes faster) versions of regexes
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

# Regex for arpa's
ip4arpa = regex.compile('^([0-9]{1,3}\.){4}in-addr\.arpa$', regex.I)
ip6arpa = regex.compile('^([0-9a-f]\.){32}ip6\.arpa$', regex.I)

# Regex to match domains/hosts in lists
isdomain = regex.compile('^[a-z0-9\.\_\-]+$', regex.I) # Based on RFC1035 plus underscore

# Regex to filter regexes out
isregex = regex.compile('^/.*/$')

# Regex for AS(N) Numbers
isasn = regex.compile('^AS[0-9]+$', regex.I)

##############################################################

# Log INFO messages to syslog
def log_info(message):
    if debug:
        print('{0} {1}'.format(time.strftime('%a %d-%b-%Y %H:%M:%S'), message))
        sys.stdout.flush()
    syslog.syslog(syslog.LOG_INFO, message) # !!! Fix SYSLOG on MacOS
    return True


# Log ERR messages to syslog
def log_err(message):
    message = '!!! STRESS: {0}'.format(message)
    if debug:
        print('{0} {1}'.format(time.strftime('%a %d-%b-%Y %H:%M:%S'), message))
        sys.stdout.flush()
    syslog.syslog(syslog.LOG_ERR, message) # !!! Fix SYSLOG on MacOS
    return True


# Check if file exists and return age (in seconds) if so
def file_exist(file, isdb):
    if file:
        if isdb and sys.platform.startswith('linux'): # Shelve-DB File
            file = file + '.db'

        try:
            if os.path.isfile(file):
                fstat = os.stat(file)
                fsize = fstat.st_size
                if fsize > 0: # File-size must be greater then zero
                    mtime = int(fstat.st_mtime)
                    currenttime = int(time.time())
                    age = int(currenttime - mtime)
                    if debug: log_info('FILE-EXIST: ' + file + ' = ' + str(age) + ' seconds old')
                    return age
        except BaseException as err:
            log_err('FILE-EXIST-ERROR: ' + str(err))
            return False

    return False


# Check if entry matches a list
# Returns:
#   True = Black-listed
#   False = White-listed
#   None = None-listed
def match_blacklist(rid, rtype, rrtype, value, log):
    tid = id_str(rid)

    testvalue = value

    itisanip = False

    if rtype == 'REQUEST' and rrtype == 'PTR':
        ip = False
        if ip4arpa.search(testvalue):
            ip = '.'.join(testvalue.split('.')[0:4][::-1])
        elif ip6arpa.search(testvalue):
            ip = ':'.join(filter(None, regex.split('(.{4,4})', ''.join(testvalue.split('.')[0:32][::-1]))))

        if ip:
            itisanip = True
            testvalue = ip

    elif rtype == 'REPLY':
        if rrtype in ('A', 'AAAA'):
            itisanip = True
        else:
            testvalue = normalize_dom(regex.split('\s+', testvalue)[-1])


    # Check against IP-Lists
    if itisanip:
        if testvalue.find(':') == -1:
            wip = wl_ip4
            bip = bl_ip4
        else:
            wip = wl_ip6
            bip = bl_ip6

        found = False
        prefix = False

        if not testvalue in wip:
            if testvalue in bip:
                prefix = bip.get_key(testvalue)
                found = True
        else:
            prefix = wip.get_key(testvalue)

        if testvalue != value:
            testvalue = value + '/' + testvalue

        if found:
            if log: log_info('BLACKLIST-IP-HIT [' + tid + ']: ' + rtype + ' ' + testvalue + ' matched against ' + prefix + ' (' + bip[prefix] + ')')
            return True
        elif prefix:
            if log: log_info('WHITELIST-IP-HIT [' + tid + ']: ' + rtype + ' ' + testvalue + ' matched against ' + prefix + ' (' + wip[prefix] + ')')
            return False


    # Check against Sub-Domain-Lists
    elif testvalue.find('.') > 0 and isdomain.search(testvalue):
        wl_found = in_domain(testvalue, wl_dom)
        if wl_found is not False:
            if log: log_info('WHITELIST-HIT [' + tid + ']: ' + rtype + ' \"' + value + '\" matched against \"' + wl_found + '\" (' + wl_dom[wl_found] + ')')
            return False
        else:
            bl_found = in_domain(testvalue, bl_dom)
            if bl_found is not False:
                if log: log_info('BLACKLIST-HIT [' + tid + ']: ' + rtype + ' \"' + value + '\" matched against \"' + bl_found + '\" (' + bl_dom[bl_found] + ')')
                return True


    # Catchall: Check agains Regex-Lists
    for i in wl_rx.keys():
        rx = wl_rx[i]
        if rx.search(value):
            lst = regex.split(':\s+', i)[0]
            rxn = ' '.join(regex.split(':\s+', i)[1:])
            if log: log_info('WHITELIST-REGEX-HIT [' + tid + ']: ' + rtype + ' \"' + value + '\" matched against \"' + rxn + '\" (' + lst + ')')
            return False

    for i in bl_rx.keys():
        rx = bl_rx[i]
        if rx.search(value):
            lst = regex.split(':\s+', i)[0]
            rxn = ' '.join(regex.split(':\s+', i)[1:])
            if log: log_info('BLACKLIST-REGEX-HIT [' + tid + ']: ' + rtype + ' \"' + value + '\" matched against \"' + rxn + '\" (' + lst + ')')
            return True

    # No hits
    if debug and log: log_info('NONE-HIT [' + tid + ']: ' + rtype + ' \"' + value + '\" does not match against any lists')

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
def dns_query(request, qname, qtype, use_tcp, tid, cip, checkbl, checkalias, force):
    queryname = qname + '/IN/' + qtype

    if debug and checkbl: queryname = 'BL:' + queryname
    if debug and checkalias: queryname = 'AL:' + queryname
    if debug and force: queryname = 'F:' + queryname

    # Process already pending/same query
    uid = hash(qname + '/' + qtype + '/' + cip + '/' + str(tid))
    count = 0
    while uid in pending:
        count += 1
        if count > 2: # Disembark after 3 seconds
            log_info('DNS-QUERY [' + id_str(tid) + ']: Skipping query for ' + queryname + ' - ID (' + id_str(tid) + ') already processing, takes more then 3 secs')
            reply = request.reply()
            reply.header.rcode = getattr(RCODE, 'SERVFAIL')
            return reply

        log_info('DNS-QUERY [' + id_str(tid) + ']: delaying (' + str(count) + ') query for ' + queryname + ' - ID (' + id_str(tid) + ') already in progress, waiting to finish')
        time.sleep(1) # Seconds

    # Get from cache if any
    if not force:
        reply = from_cache(qname, 'IN', qtype, tid)
        if reply is not None:
            return reply

    pending[uid] = int(time.time())

    server = in_domain(qname, forward_servers)
    if server:
        servername = 'FORWARD-HIT: ' + server
    else:
        server = '.'
        servername = 'DEFAULT'

    reply = None

    #if recursion: # !!! WIP
    #    labelcount = 0
    #    labels = qname.split('.')[::-1]
    #    auth_servers = list()
    #    while labelcount < len(labels) - 1:
    #        if labelcount is 0:
    #            parent = "."
    #            domain = labels[labelcount]
    #            ns = root_servers
    #        else:
    #            parent = labels[labelcount - 1]
    #            domain = labels[labelcount]
    #            ns = auth_servers
    #
    #        log_info('RECURSION: Asking \"' + parent + '\" servers for NS of \"' + domain + '\"')
    #
    #        labelcount += 1

    rcttl = False

    forward_server = forward_servers.get(server, False)
    if forward_server:
        query = DNSRecord(q=DNSQuestion(qname, getattr(QTYPE, qtype)))

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

            if not in_cache(forward_address, 'BROKEN-FORWARDER', str(forward_port)):
                log_info('DNS-QUERY [' + id_str(tid) + ']: forwarding query from ' + cip + ' to ' + forward_address + '@' + str(forward_port) + ' (' + servername + ') for ' + queryname)

                error = 'None'
                failed = False
                try:
                    useip6 = False
                    if forward_address.find(':') > 0:
                        useip6 = True

                    q = query.send(forward_address, forward_port, tcp=use_tcp, timeout=forward_timeout, ipv6=useip6)
                    reply = DNSRecord.parse(q)
                    rcode = str(RCODE[reply.header.rcode])
                    if rcode != 'SERVFAIL':
                        if reply.auth and rcode != 'NOERROR':
                            rcttl = normalize_ttl(qname, reply.auth)
                            if rcttl:
                                log_info('SOA-TTL: Taking TTL={1} of SOA \"{0}\" for {2} {3}'.format(regex.split('\s+', str(reply.auth[0]))[0].strip('.'), rcttl, queryname, rcode))
                        else:
                            _ = normalize_ttl(qname, reply.rr)

                        break

                    else:
                        error = 'SERVFAIL'
                        failed = True

                #except socket.timeout:
                except BaseException as err:
                    error = err
                    failed = True

                if failed:
                    log_err('DNS-QUERY [' + id_str(tid) + ']: ERROR Resolving ' + queryname + ' using ' + forward_address + '@' + str(forward_port) + ' - ' + str(error))
                    if error != 'SERVFAIL':
                        to_cache(forward_address, 'BROKEN-FORWARDER', str(forward_port), request.reply(), force, retryttl)

                    reply = None

            if debug: log_info('DNS-QUERY [' + id_str(tid) + ']: Skipped broken/invalid forwarder ' + forward_address + '@' + str(forward_port))

    else:
        log_err('DNS-QUERY [' + id_str(tid) + ']: ERROR Resolving ' + queryname + ' (' + servername + ') - NO DNS SERVERS AVAILBLE!')

    # No response, generate servfail
    if reply is None:
        log_err('DNS-QUERY [' + id_str(tid) + ']: ERROR Resolving ' + queryname)
        cache.clear()
        reply = query.reply()
        reply.header.id = tid
        reply.header.rcode = getattr(RCODE, 'SERVFAIL')
        _ = pending.pop(uid, None)
        return reply

    else:
        # Clear broken-forwarder cache entries
        if broken_exist():
            for queryhash in no_noerror_list():
                record = cache.get(queryhash, None)
                if record is not None:
                    rcode = str(RCODE[record[0].header.rcode])
                    log_info('CACHE-MAINT-PURGE: ' + record[2] + ' ' + rcode + ' (One or more DNS Servers responding again)')
                    del_cache_entry(queryhash)


    blockit = False

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

                #if checkalias and rqtype in ('A', 'AAAA', 'CNAME') and in_domain(rqname, aliases):
                if checkalias and in_domain(rqname, aliases):
                    reply = generate_alias(request, rqname, rqtype, use_tcp, force)
                    break

                if replycount > 1: #or forcequery: # Request itself should already be caught during request/query phase
                    matchreq = match_blacklist(tid, 'CHAIN', rqtype, rqname, True)
                    if matchreq is False:
                        break
                    elif matchreq is True:
                        blockit = True
                else:
                    if debug: log_info('REPLY-QUERY-SKIP: ' + rqname + '/IN/' + rqtype)

                if blockit is False:
                    if blockrebind and ((rqtype == 'A' and data in rebind4) or (rqtype == 'AAAA' and data in rebind6)):
                        if rqtype == 'AAAA' and forward_address not in rebind6:
                            blockit = True
                            prefix = rebind6.get_key(data)
                            desc = rebind6.get(data, 'None')
                        elif rqtype == 'A' and forward_address not in rebind4:
                            blockit = True
                            prefix = rebind4.get_key(data)
                            desc = rebind4.get(data, 'None')

                        if blockit:
                            log_info('REBIND-BLOCK: ' + rqname + '/IN/' + rqtype + ' = ' + data + ' matches ' + prefix + ' (' + desc + ')')
                        else:
                            log_info('REBIND-ALLOW: ' + rqname + '/IN/' + rqtype + ' = ' + data + '(DNS Server in REBIND ranges)')

                    if blockit is False:
                        matchrep = match_blacklist(tid, 'REPLY', rqtype, data, True)
                        if matchrep is False:
                            break
                        elif matchrep is True:
                            blockit = True

                if blockit:
                    log_info('REPLY [' + id_str(tid) + ':' + str(replycount) + '-' + str(replynum) + ']: ' + rqname + '/IN/' + rqtype + ' = ' + data + ' BLACKLIST-HIT')
                    reply = generate_response(request, qname, qtype, redirect_addrs, force)
                    break

                else:
                    log_info('REPLY [' + id_str(tid) + ':' + str(replycount) + '-' + str(replynum) + ']: ' + rqname + '/IN/' + rqtype + ' = ' + data + ' NOERROR')

    else:
        reply = request.reply()
        if len(reply.rr) > 0 or (len(reply.rr) == 0 and rcode != 'NOERROR'):
            reply.header.rcode = getattr(RCODE, rcode)
            log_info('REPLY [' + id_str(tid) + ']: ' + queryname + ' = ' + rcode)
        else:
            reply.header.rcode = getattr(RCODE, 'NOERROR')
            log_info('REPLY [' + id_str(tid) + ']: ' + queryname + ' = NODATA')


    # Match up ID
    reply.header.id = tid

    # Collapse CNAME
    if collapse and qtype == 'CNAME':
        reply = collapse_cname(request, reply, tid)

    # Minimum responses
    if minresp:
        reply.auth = list()
        reply.ar = list()
        #reply.add_ar(EDNS0())

    # Stash in cache
    if blockit:
        to_cache(qname, 'IN', qtype, reply, force, filterttl)
    elif rcttl:
        to_cache(qname, 'IN', qtype, reply, force, rcttl)
    else:
        to_cache(qname, 'IN', qtype, reply, force, False)

    _ = pending.pop(uid, None)

    return reply


# Generate response when blocking
def generate_response(request, qname, qtype, redirect_addrs, force):
    queryname = qname + '/IN/' + qtype

    reply = request.reply()

    if (len(redirect_addrs) > 0) and any(x in ('NODATA', 'NXDOMAIN', 'REFUSED') for x in redirect_addrs):
        for addr in redirect_addrs:
            if addr in ('NODATA', 'NXDOMAIN', 'REFUSED'):
                log_info('GENERATE: ' + addr + ' for ' + queryname)
                if addr == 'NODATA':
                    reply.header.rcode = getattr(RCODE, 'NOERROR') # just respond with no RR's
                else:
                    reply.header.rcode = getattr(RCODE, addr)
                break

    elif (len(redirect_addrs) == 0) or (qtype not in ('A', 'AAAA', 'CNAME')):
        log_info('GENERATE: ' + hitrcode + ' for ' + queryname)
        if hitrcode == 'NODATA':
            reply.header.rcode = getattr(RCODE, 'NOERROR') # just respond with no RR's
        else:
            reply.header.rcode = getattr(RCODE, hitrcode)

    else:
        addanswer = list()
        for addr in redirect_addrs:
            answer = None
            if qtype == 'A' and ipregex4.search(addr):
                answer = RR(qname, QTYPE.A, ttl=filterttl, rdata=A(addr))
            elif qtype == 'AAAA' and ipregex6.search(addr):
                answer = RR(qname, QTYPE.AAAA, ttl=filterttl, rdata=AAAA(addr))
            elif (qtype in ('A', 'AAAA', 'CNAME')) and (not ipregex.search(addr)):
                answer = RR(qname, QTYPE.CNAME, ttl=filterttl, rdata=CNAME(addr))

            if answer is not None:
                addanswer.append(addr)
                answer.set_rname(request.q.qname)
                reply.add_answer(answer)

        if len(addanswer) > 0:
            log_info('GENERATE: REDIRECT/NOERROR for ' + queryname + ' -> ' + ', '.join(addanswer))
            reply.header.rcode = getattr(RCODE, 'NOERROR')
        else:
            if hitrcode == 'NODATA':
                rcode = 'NOERROR'
            else:
                rcode = hitrcode
            log_info('GENERATE: ' + hitrcode + ' for ' + queryname)
            reply.header.rcode = getattr(RCODE, rcode)

    to_cache(qname, 'IN', qtype, reply, force, filterttl)

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
            log_info('ALIAS-HIT: ' + qname + ' subdomain of alias \"' + aqname + '\"')
            alias = aliases[aqname]
        else:
            alias = 'NXDOMAIN'

    if alias.upper() == 'PASSTHRU':
        log_info('ALIAS-HIT: ' + queryname + ' = PASSTHRU')
        alias = qname

    elif alias.upper() == 'RANDOM':
        if qtype == 'A':
            alias = str(random.randint(0, 255)) + '.' + str(random.randint(0, 255)) + '.' + str(random.randint(0, 255)) + '.' + str(random.randint(0, 255))
        elif qtype == 'AAAA':
            alias = str(random.randint(1000, 9999)) + '::' + str(random.randint(1000, 9999))
        elif qtype == 'CNAME':
            alias = 'random-' + str(random.randint(1000, 9999)) + '.' + aqname
        else:
            alias = 'NXDOMAIN'

        if alias != 'NXDOMAIN':
            log_info('ALIAS-HIT: ' + queryname + ' = RANDOM: \"' + alias + '\"')

    aliasqname = False
    if alias.upper() in ('NOTAUTH', 'NXDOMAIN', 'RANDOM', 'REFUSED'):
        reply = request.reply()
        if alias.upper() == 'RANDOM':
            log_info('ALIAS-HIT: ' + queryname + ' = RANDOM-NXDOMAIN')
            reply.header.rcode = getattr(RCODE, 'NXDOMAIN')
        else:
            log_info('ALIAS-HIT: ' + queryname + ' = ' + alias.upper())
            reply.header.rcode = getattr(RCODE, alias.upper())

    elif ipregex.search(alias) and qtype in ('A', 'AAAA', 'CNAME'):
        log_info('ALIAS-HIT: ' + queryname + ' = REDIRECT-TO-IP -> ' + alias)
        if alias.find(':') == -1:
            answer = RR(realqname, QTYPE.A, ttl=filterttl, rdata=A(alias))
        else:
            answer = RR(realqname, QTYPE.AAAA, ttl=filterttl, rdata=AAAA(alias))

        reply.add_answer(answer)

    elif qtype in ('A', 'AAAA', 'CNAME'):
        if not collapse and qname != alias and alias.startswith('random-') is False:
            log_info('ALIAS-HIT: ' + queryname + ' = REDIRECT-TO-NAME -> ' + alias + ' (NO RESOLUTION)')
            answer = RR(realqname, QTYPE.CNAME, ttl=filterttl, rdata=CNAME(alias))
            reply.add_answer(answer)

        if qtype == 'CNAME' and alias.startswith('random-'):
            answer = RR(realqname, QTYPE.CNAME, ttl=filterttl, rdata=CNAME(alias))
            reply.add_answer(answer)

        else:
            log_info('ALIAS-HIT: ' + queryname + ' = REDIRECT-TO-NAME -> ' + alias)
            #if qtype not in ('A', 'AAAA'):
            #    qtype = 'A'

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

    else:
        reply = request.reply()
        reply.header.rcode = getattr(RCODE, 'NXDOMAIN')


    if str(RCODE[reply.header.rcode]) == 'NOERROR':
        log_info('ALIAS-HIT: ' + qname + ' -> ' + alias + ' ' + str(RCODE[reply.header.rcode]))
        if collapse and aliasqname:
            log_info('ALIAS-HIT: COLLAPSE ' + qname + '/IN/CNAME')
    else:
        log_info('ALIAS-HIT: ' + queryname + ' Unsupported RR-Type -> ' + str(RCODE[reply.header.rcode]))

    to_cache(qname, 'IN', qtype, reply, force, False)

    return reply


def save_cache(file):
    if not persistentcache:
        return False

    log_info('CACHE-SAVE: Saving to \"' + file + '\"')

    try:
        s = shelve.DbfilenameShelf(file, flag='n', protocol=4)
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
            s = shelve.DbfilenameShelf(file, flag='r', protocol=4)
            cache = s['cache']
            s.close()

        except BaseException as err:
            log_err('ERROR: Unable to open/read file \"' + file + '\" - ' + str(err))
            return False

        cache_purge(False, maxttl, False, False) # Purge everything with has a ttl higher then 60 seconds left

    else:
        log_info('CACHE-LOAD: Skip loading cache from \"' + file + '\" - non-existant or older then ' + str(maxfileage) + ' seconds')
        return False

    if debug: execute_command('show.' + command, False)

    return True


def to_dict(iplist):
    newdict = dict()
    for i in iplist.keys():
        newdict[i] = iplist[i]
    return newdict


def from_dict(fromlist, tolist):
    for i in fromlist.keys():
        tolist[i] = fromlist[i]
    return tolist


def save_lists(file):
    log_info('LIST-SAVE: Saving to \"' + file + '\"')

    try:
        s = shelve.DbfilenameShelf(file, flag='n', protocol=4)

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
            s = shelve.DbfilenameShelf(file, flag='r', protocol=4)

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


def log_totals():
    log_info('WHITELIST-TOTALS: ' + str(len(wl_rx)) + ' REGEXes, ' + str(len(wl_ip4)) + ' IPv4 CIDRs, ' + str(len(wl_ip6)) + ' IPv6 CIDRs, ' + str(len(wl_dom)) + ' DOMAINs, ' + str(len(aliases)) + ' ALIASes, ' + str(len(forward_servers)) + ' FORWARDs and ' + str(len(ttls)) + ' TTLs')
    log_info('BLACKLIST-TOTALS: ' + str(len(bl_rx)) + ' REGEXes, ' + str(len(bl_ip4)) + ' IPv4 CIDRs, ' + str(len(bl_ip6)) + ' IPv6 CIDRs and ' + str(len(bl_dom)) + ' DOMAINs')
    log_info('CACHE-TOTALS: ' + str(len(cache)) + ' Cache Entries')

    return True


def normalize_dom(dom):
    return str(dom).strip().strip('.').lower() or '.'


# Read filter lists, see "accomplist" to provide ready-2-use lists:
# https://github.com/cbuijs/accomplist
def read_list(file, listname, bw, domlist, iplist4, iplist6, rxlist, alist, flist, tlist):
    listname = listname.upper()
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
                name = ' '.join(regex.split('\t+', entry)[1:]).strip() or listname
                entry = regex.sub('/\s+[^/]+$', '/', entry).strip()
            else:
                name = ' '.join(regex.split('\s+', entry)[1:]).strip() or listname
                entry = regex.split('\s+', entry)[0].strip()

            # Accomplist specific clean-up

            # If entry ends in exclaimation, it is a "forced" entry, blacklisted will overrule whitelisted.
            # !!! Note: Accomplist already did the logic and clean whitelist. If using other cleanup yourself, no code for that here.
            if entry.endswith('!'):
                entry = entry[:-1]

            # If entry ends in ampersand, it is a "safelisted" entry. Not supported.
            if entry.endswith('&'):
                entry = False

            # Process entry
            if entry and len(entry) > 0 and (not entry.startswith('#')):

                # REGEX
                if isregex.search(entry):
                    fetched += 1
                    rx = entry.strip('/')
                    rxlist[name + ': ' + rx] = regex.compile(rx, regex.I)

                # ASN
                elif isasn.search(entry):
                    _ = entry

                # DOMAIN
                elif isdomain.search(entry):
                    entry = normalize_dom(entry)
                    if blockillegal and (len(entry) > 252 or all(len(x) < 64 for x in entry.split('.')) is False):
                        log_err(listname + ' ILLEGAL/FAULTY Entry [' + str(count) + ']: ' + entry)
                    elif entry != '.':
                        fetched += 1
                        domlist[entry] = name

                # IPV4
                elif ipregex4.search(entry):
                    fetched += 1
                    iplist4[entry] = name

                # IPV6
                elif ipregex6.search(entry):
                    fetched += 1
                    iplist6[entry] = name

                #### !!! From here on there are functional entries, which are always condidered "whitelist"
                # ALIAS - domain.com=ip or domain.com=otherdomain.com
                elif bw == 'Whitelist':
                    if entry.find('=') > 0:
                        elements = entry.split('=')
                        if len(elements) > 1:
                            domain = normalize_dom(elements[0])
                            alias = normalize_dom(elements[1])
                            if isdomain.search(domain) and (isdomain.search(alias) or ipregex.search(alias)):
                                fetched += 1
                                alist[domain] = alias
                                if alias.upper() != 'RANDOM':
                                    domlist[domain] = 'Alias' # Whitelist it
                                if debug: log_info('ALIAS-ALIAS: \"' + domain + '\" = \"' + alias + '\"')
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
                                        if debug: log_info('ALIAS-FORWARDER: \"' + domain + '\" to ' + addr)
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
                                if debug: log_info('ALIAS-TTL: \"' + domain + '\" = ' + ttl)
                            else:
                                log_err(listname + ' INVALID TTL [' + str(count) + ']: ' + entry)
                        else:
                            log_err(listname + ' INVALID TTL [' + str(count) + ']: ' + entry)

                    # Search Domains
                    elif entry.endswith('*'):
                        sdom = normalize_dom(entry.rstrip('*').strip())
                        if isdomain.search(sdom):
                            if sdom not in searchdom:
                                fetched += 1
                                searchdom.add(sdom)
                                if debug: log_info('ALIAS-SEARCH-DOMAIN: \"' + sdom + '\"')
                        else:
                            log_err(listname + ' INVALID SEARCH-DOMAIN [' + str(count) + ']: ' + entry)

                # Invalid/Unknown Syntax or BOGUS entry
                else:
                    log_err(listname + ' INVALID/BOGUS LINE [' + str(count) + ']: ' + entry)

    else:
        log_err('ERROR: Cannot open \"' + file + '\" - Does not exist')

    log_info(listname + ' Processed ' + str(count) + ' lines and used ' + str(fetched))

    return domlist, iplist4, iplist6, rxlist, alist, flist, tlist


# Normalize TTL's, all RR's in a RRSET will get the same TTL based on strategy (see below)
def normalize_ttl(qname, rr):
    if filtering:
        newttl = in_domain(qname, ttls)
        if newttl:
            ttl = ttls.get(newttl, nottl)
            log_info('TTL-HIT: Setting TTL for ' + qname + ' (' + newttl + ') to ' + str(ttl))
            update_ttl(rr, ttl)
            return ttl

    if rr and len(rr) > 0:
        if len(rr) == 1:
            ttl = rr[0].ttl
        else:
            # ttlstrategy: lowest, highest, average and random
            if ttlstrategy == 'lowest':
                ttl = min(x.ttl for x in rr) # Take Lowest TTL found on all RR's
            elif ttlstrategy == 'highest':
                ttl = max(x.ttl for x in rr) # Take Highest TTL found on all RR's
            elif ttlstrategy == 'average':
                ttl = int(sum(x.ttl for x in rr) / len(rr)) # Take Average TTL of all RR's
            else:
                ttl = random.randint(minttl, maxttl) # Random between minttl and maxttl

        if ttl < minttl:
            #ttl = minttl # Minimum TTL enforced
            ttl += minttl # More cachable minimum TTL enforcement
        elif ttl > maxttl:
            ttl = maxttl

        update_ttl(rr, ttl) # Update all RR's TTL.

    else:
        ttl = nottl # No TTL, normaly this is zero (0)

    return ttl


# Update all TTL's in RRSET
def update_ttl(rr, ttl):
    for x in rr:
        x.ttl = ttl

    return None


# Update hits in cache of particular cached RRSET
def update_hits(queryhash):
    if queryhash in cache:
        cache[queryhash][3] += 1
        return cache[queryhash][3]

    return 0


# Prefetch/Update cache on almost expired items with enough hits
def prefetch_it(queryhash):
    global prefetching_busy

    if prefetching_busy:
        return False

    prefetching_busy = True

    record = cache.get(queryhash, None)
    if record is not None:
        now = int(time.time())
        expire = record[1]
        rcode = str(RCODE[record[0].header.rcode])
        ttlleft = expire - now
        queryname = record[2]
        hits = record[3]
        orgttl = record[4]
        hitsneeded = int(round(orgttl / prefetchhitrate)) or 1

        log_info('CACHE-PREFETCH: {0} {1} [{2}/{3} hits] (TTL-LEFT: {4}/{5})'.format(queryname, rcode, hits, hitsneeded, ttlleft, orgttl))

        _ = cache.pop(queryhash, None)
        qname, qclass, qtype = queryname.split('/')
        request = DNSRecord.question(qname, qtype, qclass)
        request.header.id = random.randint(1, 65535)
        handler = DNSHandler
        handler.protocol = 'udp'
        handler.client_address = '\'PREFETCHER\''
        _ = do_query(request, handler, True) # Query and update cache

        prefetching_busy = False
        return True

    prefetching_busy = False
    return False


# Retrieve from cache
def from_cache(qname, qclass, qtype, tid):
    if nocache:
        return None

    queryhash = query_hash(qname, qclass, qtype)
    cacheentry = cache.get(queryhash, None)
    if cacheentry is None:
        return None

    expire = cacheentry[1]
    now = int(time.time())
    ttl = expire - now

    # If expired, remove from cache
    orgttl = cacheentry[4]
    hitsneeded = int(round(orgttl / prefetchhitrate)) or 1
    if ttl < 1:
        rcode = str(RCODE[cacheentry[0].header.rcode])
        numrrs = len(cacheentry[0].rr)
        if numrrs > 0 or (numrrs == 0 and rcode != 'NOERROR'):
            log_info('CACHE-EXPIRED: ' + cacheentry[2] + ' ' + rcode + ' [' + str(cacheentry[3]) + '/' + str(hitsneeded) + ' hits]' + ' (TTL-EXPIRED:' + str(ttl) + '/' + str(cacheentry[4]) + ')')
        else:
            log_info('CACHE-EXPIRED: ' + cacheentry[2] + ' NODATA ' + ' (TTL-EXPIRED:' + str(cacheentry[4]) + ')')
        del_cache_entry(queryhash)
        return None

    # Pull/Fetch from cache
    else:
        reply = cacheentry[0]
        reply.header.id = tid

        numhits = update_hits(queryhash)

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

        numrrs = len(reply.rr)
        rcode = str(RCODE[reply.header.rcode])
        if numrrs == 0 and rcode == 'NOERROR':
            log_info('CACHE-HIT (' + str(numhits) + '/' + str(hitsneeded) + ' hits) : Retrieved NODATA for ' + cacheentry[2] + ' (TTL-LEFT:' + str(ttl) + '/' + str(cacheentry[4]) + ')')
        else:
            log_info('CACHE-HIT (' + str(numhits) + '/' + str(hitsneeded) + ' hits) : Retrieved ' + str(numrrs) + ' RRs for ' + cacheentry[2] + ' ' + rcode + ' (TTL-LEFT:' + str(ttl) + '/' + str(cacheentry[4]) + ')')

        log_replies(reply, 'CACHE-REPLY')

        return reply

    return None


# Log replies
def log_replies(reply, title):
    replycount = 0
    replynum = len(reply.rr)
    if replynum > 0:
        for record in reply.rr:
            replycount += 1
            rqname = normalize_dom(record.rname)
            rqtype = QTYPE[record.rtype].upper()
            data = normalize_dom(record.rdata)
            log_info(title + ' [' + id_str(reply.header.id) + ':' + str(replycount) + '-' + str(replynum) + ']: ' + rqname + '/IN/' + rqtype + ' = ' + data)
    else:
        rqname = normalize_dom(reply.q.qname)
        rqtype = QTYPE[reply.q.qtype].upper()
        rcode = str(RCODE[reply.header.rcode])
        if rcode == 'NOERROR':
            rcode = 'NODATA'
        log_info(title + ' [' + id_str(reply.header.id) + ']: ' + rqname + '/IN/' + rqtype + ' ' + rcode)

    return True


# Check if in cache
def in_cache(qname, qclass, qtype):
    if query_hash(qname, qclass, qtype) in cache:
        if debug: log_info('IN-CACHE-HIT: ' + qname + '/' + qclass + '/' + qtype)
        return True

    return False


# Store into cache
def to_cache(qname, qclass, qtype, reply, force, newttl):
    if nocache or reply == defaultlist or reply is None:
        return False

    if (not force) and in_cache(qname, qclass, qtype):
        return True

    queryname = qname + '/' + qclass + '/' + qtype
    rcode = str(RCODE[reply.header.rcode])
    ttl = nottl

    if not newttl:
        newttl = in_domain(qname, ttls)
        if newttl:
            newttl = ttls.get(newttl, False)

    # Cache return-codes
    if rcode in ('NOTAUTH', 'NOTIMP', 'NXDOMAIN', 'REFUSED'):
        ttl = newttl or rcodettl
    elif rcode == 'NOERROR' and len(reply.rr) == 0: # NODATA
        ttl = newttl or rcodettl
    elif rcode == 'SERVFAIL':
        ttl = newttl or failttl
    elif rcode != 'NOERROR':
        log_info('CACHE-SKIPPED: ' + queryname + ' ' + rcode)
        return False
    else: # Regular/NOERROR record
        ttl = newttl or reply.rr[0].ttl

    if ttl > 0: # cache it if not expired yet
        expire = int(time.time()) + ttl
        _ = add_cache_entry(qname, qclass, qtype, expire, ttl, reply)

    if len(cache) > cachesize: # Cache changed, do maintenance
        cache_maintenance_now = True

    return True


# get list of purgable items
def cache_expired_list():
    now = int(time.time())
    return list(dict((k, v) for k, v in cache.items() if v[1] - now < 1).keys()) or False


# Check if we have broken forwarders
def broken_exist():
    if len(list(dict((k, v) for k, v in cache.items() if v[2].find('/BROKEN-FORWARDER/') > 0).keys())) > 0:
        return True
    return False


# Return all no-noerror list
def no_noerror_list():
    return list(dict((k, v) for k, v in cache.items() if v[0].header.rcode != 0).keys())


# Get list of prefetchable items
def cache_prefetch_list():
    now = int(time.time())
    # Formula: At least 2 cache-hits, hitrate > 0 and hits are above/equal hitrate
    # value list entries: 0:reply - 1:expire - 2:qname/class/type - 3:hits - 4:orgttl - 5:domainname
    return list(dict((k, v) for k, v in cache.items() if v[3] > 1 and int(round(v[4] / prefetchhitrate)) > 0 and v[1] - now <= int(round(v[4] / prefetchgettime)) and v[3] >= int((round(v[4] / prefetchhitrate)) - (round((v[1] - now) / prefetchhitrate)))).keys()) or False


# Get list of domains in cache
def cache_dom_list(qclass, qtype):
    newlist = set()
    for dom in list(cache.values()):
        cqname, cqclass, cqtype = dom[2].split('/')
        if cqclass == qclass and cqtype == qtype:
            newlist.add(cqname)

    return newlist


# Purge cache
def cache_purge(flushall, olderthen, clist, plist):
    global cache_maintenance_busy
    global cache_maintenance_now

    if cache_maintenance_busy:
        return False

    cache_maintenance_busy = True
    cache_maintenance_now = False

    if debug: log_info('CACHE-MAINT: START')

    # Remove old pending
    for p in list(dict((k, v) for k, v in pending.items() if int(time.time()) - v > 10).keys()):
        timestamp = pending.get(p, False)
        if timestamp and int(time.time()) - timestamp > 10: #Seconds
            log_info('PENDING: Removed stale UID {0}'.format(p))
            _ = pending.pop(p, None)

    before = len(cache)

    # Remove expired entries
    elist = list()
    lst = False
    if flushall:
        lst = list(cache.keys()) or False
        if lst:
            log_info('CACHE-MAINT: Flush All')
    else:
        # Prefetch
        if plist and prefetching_busy is False:
            log_info('CACHE-PREFETCH: Prefetching entries that qualify ({0} potential entries)'.format(len(plist)))
            for queryhash in list(plist):
                if not prefetch_it(queryhash):
                    plist.remove(queryhash)

        if olderthen:
            lst = list(cache.keys()) or False
            if lst:
                log_info('CACHE-MAINT: Purging entries with TTL higher then {0} seconds left'.format(olderthen))
        else:
            lst = clist or False
            if lst:
                log_info('CACHE-MAINT: Purging entries with expired TTLs ({0} potential entries)'.format(len(clist)))

        if plist:
            elist = plist

    totalrrs = 0
    if lst:
        for queryhash in lst:
            record = cache.get(queryhash, None)
            if queryhash not in elist:
                if record is not None:
                    now = int(time.time())

                    if flushall:
                        expire = now
                    else:
                        expire = record[1]

                    ttlleft = expire - now
                    if olderthen and ttlleft > 0:
                        if ttlleft > olderthen:
                            ttlleft = 0

                    if ttlleft < 1:
                        orgttl = record[4]
                        hitsneeded = int(round(orgttl / prefetchhitrate)) or 1
                        rcode = str(RCODE[record[0].header.rcode])
                        numrrs = len(record[0].rr)
                        if numrrs == 0:
                            if rcode == 'NOERROR':
                                rcode = 'NODATA'
                            log_info('CACHE-MAINT-EXPIRED: Purged {0} for {1} (TTL-EXPIRED:{2})'.format(rcode, record[2], orgttl))
                        else:
                            log_info('CACHE-MAINT-EXPIRED: Purged {0} RRs for {1} {2} [{3}/{4} hits] (TTL-EXPIRED:{5}/{6})'.format(numrrs, record[2], rcode, record[3], hitsneeded, ttlleft, orgttl))
                            totalrrs += numrrs

                        del_cache_entry(queryhash)

    # Prune cache back to cachesize, removing lowest TTLs first
    size = len(cache)
    if size > cachesize:
        expire = dict()
        for queryhash in list(cache.keys()):
            now = int(time.time())
            expire[queryhash] = cache.get(queryhash, defaultlist)[1] - now

        for queryhash in list(sorted(expire, key=expire.get))[0:size-cachesize]:
            log_info('CACHE-MAINT-EXPULSION: {0} (TTL-LEFT:{1})'.format(cache.get(queryhash, defaultlist)[2], expire[queryhash]))
            del_cache_entry(queryhash)

    after = len(cache)

    if before != after:
        if totalrrs == 0:
            log_info('CACHE-STATS: purged {0} entries, {1} left in cache'.format(before - after, after))
        else:
            log_info('CACHE-STATS: purged {0} entries ({1} RRs), {2} left in cache'.format(before - after, totalrrs, after))

        save_cache(cachefile)

    if debug: log_info('CACHE-MAINT: FINISH')

    gc.collect()

    cache_maintenance_busy = False

    return True


# Query-hash for cache entries
def query_hash(qname, qclass, qtype):
    return hash(qname + '/' + qclass + '/' + qtype)


# Add entry to cache
def add_cache_entry(qname, qclass, qtype, expire, ttl, reply):
    hashname = qname + '/' + qclass + '/' + qtype
    rcode = str(RCODE[reply.header.rcode])
    queryhash = query_hash(qname, qclass, qtype)

    cache[queryhash] = list([reply, expire, hashname, 1, ttl]) # reply - expire - qname/class/type - hits - orgttl

    numrrs = len(cache.get(queryhash, defaultlist)[0].rr)
    if numrrs == 0:
        if rcode == 'NOERROR':
            rcode = 'NODATA'
        log_info('CACHE-UPDATE (' + str(len(cache)) + ' entries): Cached ' + rcode + ' for ' + hashname + ' (TTL:' + str(ttl) + ')')
    else:
        log_info('CACHE-UPDATE (' + str(len(cache)) + ' entries): Cached ' + str(numrrs) + ' RRs for ' + hashname + ' ' + rcode + ' (TTL:' + str(ttl) + ')')

    return queryhash


# Remove entry from cache
def del_cache_entry(queryhash):
    _ = cache.pop(queryhash, None)
    return True


# Round-Robin cycle list
def round_robin(l):
    return l[1:] + l[:1]


# Padd id to 5 positions
def id_str(number):
    return str(number).zfill(5)


# Collapse CNAME's into Address-Records (A/AAAA)
def collapse_cname(request, reply, rid):
    if filtering and reply.rr:
        firstqtype = QTYPE[reply.rr[0].rtype].upper()
        if firstqtype == 'CNAME':
            qname = normalize_dom(reply.rr[0].rname)
            ttl = reply.rr[0].ttl
            addr = list()
            for record in reply.rr[1:]:
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
                        rrtype = 'A'
                        answer = RR(qname, QTYPE.A, ttl=ttl, rdata=A(ip))
                    else:
                        rrtype = 'AAAA'
                        answer = RR(qname, QTYPE.AAAA, ttl=ttl, rdata=AAAA(ip))

                    log_info('REPLY [' + id_str(rid) + ':' + str(count) + '-' + total + ']: COLLAPSE ' + qname + '/IN/CNAME -> ' + str(ip) + '/' + rrtype)

                    reply.add_answer(answer)
            else:
                reply = request.reply()
                reply.header.rcode = getattr(RCODE, 'NXDOMAIN')

    return reply


# Execute commands
def execute_command(qname, log):
    global filtering

    qname = regex.sub('\.' + command + '$', '', qname).upper()

    if log: log_info('COMMAND: \"' + qname + '\"')

    flush = True

    if qname in ('LIST', 'SHOW'):
        if log: log_info('COMMAND: Show CACHE entries')
        flush = False
        now = int(time.time())
        count = 0
        total = str(len(cache))
        for i in list(cache.keys()):
            count += 1
            record = cache.get(i, defaultlist)
            if record[0] is not None:
                rcode = str(RCODE[record[0].header.rcode])
                numrrs = len(record[0].rr)
                orgttl = record[4]
                hitsneeded = int(round(orgttl / prefetchhitrate)) or 1
                if rcode == 'NOERROR' and numrrs == 0:
                    rcode = 'NODATA'
                    log_info('CACHE-INFO (' + str(count) + '/' + total + '): ' + cache[i][2] + ' NODATA [' + str(record[3]) + '/' + str(hitsneeded) + ' Hits] (TTL-LEFT:' + str(record[1] - now) + '/' + str(record[4]) + ')')
                else:
                    if numrrs != 0:
                        log_info('CACHE-INFO (' + str(count) + '/' + total + '): ' + str(numrrs) + ' RRs for ' + cache[i][2] + ' ' + rcode + ' [' + str(record[3]) + '/' + str(hitsneeded) + ' Hits] (TTL-LEFT:' + str(record[1] - now) + '/' + str(record[4]) + ')')
                    else:
                        log_info('CACHE-INFO (' + str(count) + '/' + total + '): ' + cache[i][2] + ' ' + rcode + ' [' + str(record[3]) + '/' + str(hitsneeded) + ' Hits] (TTL-LEFT:' + str(record[1] - now) + '/' + str(record[4]) + ')')

    elif qname in ('CONTINUE', 'RESUME'):
        if filtering:
            log_info('COMMAND: Filtering already ENABLED')
            flush = False
        else:
            log_info('COMMAND: Filtering ENABLED')
            filtering = True

    elif qname in ('PAUSE', 'STOP'):
        if filtering:
            log_info('COMMAND: Filtering DISABLED')
            filtering = False
        else:
            log_info('COMMAND: Filtering already DISABLED')
            flush = False

    elif qname in ('CLEAR', 'FLUSH', 'PURGE', 'WIPE'):
        log_info('COMMAND: Flush CACHE')

    else:
        log_err('COMMAND: Unknown/Failed command \"' + qname + '\"')
        return False

    if flush:
        cache_purge(True, False, False, False)

    return True


# Track if name already seen
def seen_it(name, seen):
    if name not in seen:
        seen.add(name)
    else:
        return True

    return False


# Main DNS resolution function
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

    reply = None

    # Check ACL
    if (cip != 'PREFETCHER') and (cip not in allow_query4) and (cip not in allow_query6):
        log_info('ACL-HIT: Request from ' + cip + ' for ' + queryname + ' ' + aclrcode)
        reply = request.reply()
        reply.header.rcode = getattr(RCODE, aclrcode)

    if command and qname.endswith('.' + command):
        reply = request.reply()
        if cip in ('127.0.0.1', '::1'):
            if execute_command(qname, True):
                reply.header.rcode = getattr(RCODE, 'NOERROR')
            else:
                reply.header.rcode = getattr(RCODE, 'NOTIMP')
                #reply.add_ar(EDNS0())
        else:
            reply.header.rcode = getattr(RCODE, 'REFUSED')


    # Quick response when in cache
    if reply is None and force is False:
        reply = from_cache(qname, qclass, qtype, rid)


    # Check if parent is in cache as NXDOMAIN
    if reply is None and force is False and blocksub and (in_domain(qname, wl_dom) is False):
        dom = in_domain(qname, cache_dom_list(qclass, qtype))
        if dom and dom != qname:
            queryhash = query_hash(dom, qclass, qtype)
            cacheentry = cache.get(queryhash, None)
            if cacheentry is not None:
                rcode = str(RCODE[cacheentry[0].header.rcode])
                if len(cacheentry[0].rr) == 0 and rcode in ('NODATA', 'NOERROR', 'NXDOMAIN', 'REFUSED', 'SERVFAIL'):
                    reply = request.reply()
                    if rcode == 'NOERROR':
                        reply.header.rcode = getattr(RCODE, 'NOERROR')
                        rcode = 'NODATA'
                    else:
                        reply.header.rcode = getattr(RCODE, rcode)

                    log_info('CACHE-PARENT-MATCH: \"' + qname + '\" matches parent \"' + dom + '\" ' + rcode)
                    log_info('REPLY [' + id_str(rid) + ']: ' + queryname + ' = ' + rcode)
                    now = int(time.time())
                    expire = cacheentry[1]
                    parentttlleft = expire - now
                    to_cache(qname, qclass, qtype, reply, force, parentttlleft) # cache it

    # More eleborated filtering on query
    if reply is None:
        queryfiltered = True

        # Filter if qtype = ANY, QCLASS is something else then "IN" and query-type is not supported
        if qtype == 'ANY' or qclass != 'IN' or (qtype not in ('A', 'AAAA', 'CNAME', 'MX', 'NS', 'PTR', 'SOA', 'SRV', 'TXT')):
            log_info('BLOCK-UNSUPPORTED-RRTYPE [' + id_str(rid) + '] from ' + cip + ': ' + queryname + ' NOTIMP')
            reply = request.reply()
            reply.header.rcode = getattr(RCODE, 'NOTIMP')

        # Filter when domain-name is not compliant
        elif filtering and blockillegal and isdomain.search(qname) is False:
            log_err('BLOCK-INVALID-NAME [' + id_str(rid) + '] from ' + cip + ': ' + queryname + ' SERVFAIL - INVALID SYNTAX')
            reply = request.reply()
            reply.header.rcode = getattr(RCODE, 'SERVFAIL')

        # Filter if domain-name is dot-less
        elif filtering and blockundotted and qname.count('.') < mindots:
            log_info('BLOCK-MINDOTS-HIT [' + id_str(rid) + ']: ' + queryname)
            reply = generate_response(request, qname, qtype, redirect_addrs, force)

        # Filter if FQDN is too long
        elif filtering and blockillegal and len(qname) > 252:
            log_err('BLOCK-ILLEGAL-LENGTH-HIT [' + id_str(rid) + ']: ' + queryname)
            reply = request.reply()
            reply.header.rcode = getattr(RCODE, 'REFUSED')

        # Filter if more domain-name contains more then 63 labels
        elif filtering and blockillegal and all(len(x) < 64 for x in qname.split('.')) is False:
            log_err('ILLEGAL-LABEL-LENGTH-HIT [' + id_str(rid) + ']: ' + queryname)
            reply = request.reply()
            reply.header.rcode = getattr(RCODE, 'REFUSED')

        # Filter if PTR records do not compy with IP-Addresses
        elif filtering and blockweird and qtype == 'PTR' and (not ip4arpa.search(qname) and not ip6arpa.search(qname)):
            log_info('BLOCK-WEIRD-HIT [' + id_str(rid) + ']: ' + queryname)
            reply = request.reply()
            reply.header.rcode = getattr(RCODE, 'SERVFAIL')

        # Filter if reverse-lookups are not PTR records
        elif filtering and blockweird and qtype != 'PTR' and (ip4arpa.search(qname) or ip6arpa.search(qname)):
            log_info('BLOCK-WEIRD-HIT [' + id_str(rid) + ']: ' + queryname)
            reply = request.reply()
            reply.header.rcode = getattr(RCODE, 'SERVFAIL')

        # Block IPv4 record-types
        elif filtering and blockv4 and (qtype == 'A' or (qtype == 'PTR' and ip4arpa.search(qname))):
            log_info('BLOCK-IPV4-HIT [' + id_str(rid) + ']: ' + queryname)
            reply = generate_response(request, qname, qtype, redirect_addrs, force)

        # Block IPv6 record-types
        elif filtering and blockv6 and (qtype == 'AAAA' or (qtype == 'PTR' and ip6arpa.search(qname))):
            log_info('BLOCK-IPV6-HIT [' + id_str(rid) + ']: ' + queryname)
            reply = generate_response(request, qname, qtype, redirect_addrs, force)

        # Generate ALIAS response when hit
        #elif filtering and qtype in ('A', 'AAAA', 'CNAME') and in_domain(qname, aliases):
        elif filtering and in_domain(qname, aliases):
            reply = generate_alias(request, qname, qtype, use_tcp, force)

        # Get response and process filtering
        else:
            if filtering and blocksearchdom and searchdom:
                for sdom in searchdom:
                    if qname.endswith('.' + sdom):
                        dname = qname.rstrip('.' + sdom)
                        if in_cache(dname, 'IN', qtype):
                            log_info('SEARCH-HIT [' + id_str(rid) + ']: \"' + qname + '\" matched \"' + dname + ' . ' + sdom + '\"')
                            reply = request.reply()
                            reply.header.rcode = getattr(RCODE, 'NOERROR') # Empty response, NXDOMAIN provides other search-requests
                            break
            
            if reply is None:
                queryfiltered = False
                if filtering:
                    # Make query anyway and check it after response instead of before sending query, response will be checked/filtered
                    # Note: makes filtering based on DNSBL or other services responses possible
                    if forcequery:
                        log_info('FORCE-QUERY: ' + queryname)
                        reply = dns_query(request, qname, qtype, use_tcp, rid, cip, True, True, force)
                    else:
                        # Check against lists
                        ismatch = match_blacklist(rid, 'REQUEST', qtype, qname, True)
                        if ismatch is True: # Blacklisted
                            reply = generate_response(request, qname, qtype, redirect_addrs, force)
                        else:
                            if ismatch is None and checkresponse: # Not listed
                                reply = dns_query(request, qname, qtype, use_tcp, rid, cip, True, True, force)
                            else: # Whitelisted
                                reply = dns_query(request, qname, qtype, use_tcp, rid, cip, False, True, force)
                else: # Non-filtering
                    reply = dns_query(request, qname, qtype, use_tcp, rid, cip, False, False, force)

        # Cache if REQUEST/Query is filtered
        if queryfiltered:
            #ttl = normalize_ttl(qname, reply.rr)
            to_cache(qname, 'IN', qtype, reply, force, filterttl)

    # Cleanup NOTIMP responses
    if str(RCODE[reply.header.rcode]) == 'NOTIMP':
        reply.add_ar(EDNS0())

    log_info('FINISHED [' + id_str(rid) + '] from ' + cip + ' for ' + queryname)

    return reply


# DNS request/reply processing, main beef
class DNS_Instigator(BaseResolver):

    def resolve(self, request, handler):
        return do_query(request, handler, False)


# Read Config - USE WITH CAUTION DIRECTLY MODIFIES VARIABLES!!!
# THIS IS A HACK AND NEEDS TO BE BEAUTIFIED!!!!
# Basically every global variable used can be altered/configured:
# String: <varname> = '<value>'
# Number: <varname> = <value>
# Boolean: <varname> = <True|False>
# List: <varname> = <value1>,<value2>,<value3>, ...
# Dictionary (with list values): <varname> = <key> > <value1>,<value2>,<value3>, ...
def read_config(file):
    if file and file_exist(file, False):
        log_info('CONFIG: Loading config from config-file \"' + file + '\"')
        try:
            f = open(file, 'r')
            for line in f:
                entry = line.strip()
                if (not entry.startswith('#')) and len(entry) > 0:
                    elements = regex.split('\s*=\s*', entry)
                    if len(elements) > 1:
                        var = str(elements[0])
                        val = elements[1].strip()
                        if len(val) > 0:
                            if val.find('>') != -1:
                                dictelements = regex.split('\s*>\s*', val)
                                key = dictelements[0]
                                val = dictelements[1]
                                log_info('CONFIG-SETTING-DICT: ' + var + '[' + key + '] = ' + val)
                                globals()[var] = {key : regex.split('\s*,\s*', val)}
                            elif val.startswith('\'') and val.endswith('\''):
                                log_info('CONFIG-SETTING-STR: ' + var + ' = ' + val)
                                globals()[var] = str(regex.split('\'', val)[1].strip())
                            elif val.lower() in ('false', 'none', 'true'):
                                log_info('CONFIG-SETTING-BOOL: ' + var + ' = ' + val)
                                if val.lower() == 'true':
                                    globals()[var] = bool(1)
                                else:
                                    globals()[var] = bool(0)
                            elif regex.match('^[0-9]+$', val):
                                log_info('CONFIG-SETTING-INT: ' + var + ' = ' + val)
                                globals()[var] = int(val)
                            else:
                                log_info('CONFIG-SETTING-LIST: ' + var + ' = ' + val)
                                globals()[var] = regex.split('\s*,\s*', val)

            f.close()

        except BaseException as err:
            log_err('ERROR: Unable to open/read/process file \"' + file + '\" - ' + str(err))

    else:
        log_info('CONFIG: Skipping config from file, config-file \"' + file + '\" does not exist')

    if blocksearchdom and file_exist('/etc/resolv.conf', False):
        log_info('CONFIG: Loading domains from \"/etc/resolv.conf\"')
        try:
            f = open('/etc/resolv.conf')
            for line in f:
                entry = regex.split('#', line)[0].strip().lower()
                if len(entry) > 0:
                    elements = regex.split('\s+', entry)
                    if elements[0] == 'domain' or elements[0] == 'search':
                        for dom in elements[1:]:
                            if dom not in searchdom:
                                log_info('CONFIG: Fetched ' + elements[0] + ' \"' + dom + '\"')
                                searchdom.add(dom)

            f.close()

        except BaseException as err:
            log_err('ERROR: Unable to open/read/process file \"/etc/resolv.conf\" - ' + str(err))
       
    else:
        log_info('CONFIG: Skipping getting domains from \"/etc/resolv.conf\", file does not exist')

    return


# Add addresses from DICT/LIST to Whitelist
def white_list(alist, desc):
    if type(alist) == type(list()):
        ilist = alist
    elif type(alist) == type(dict()):
        ilist = set()
        for key in alist.keys():
            for val in alist[key]:
                ilist.add(val)
    else:
        return false

    for addr in ilist:
        address = addr.split('@')[0]
        if ipregex.search(address):
            log_info('WHITELISTED IP: ' + desc + ' ' + address)
            if ipregex4.search(addr):
                wl_ip4[address] = desc
            elif ipregex6.search(addr):
                wl_ip6[address] = desc

    return True

# Main beef
if __name__ == '__main__':
    log_info('-----------------------')
    log_info('Initializing INSTIGATOR')

    if debug: log_info('RUNNING INSTIGATOR IN *DEBUG* MODE')

    read_config(configfile)

    # Load/Read lists
    loadcache = False
    if not load_lists(savefile):
        for lst in sorted(lists.keys()):
            if lst in whitelist:
                wl_dom, wl_ip4, wl_ip6, wl_rx, aliases, forward_servers, ttls = read_list(lists[lst], lst, 'Whitelist', wl_dom, wl_ip4, wl_ip6, wl_rx, aliases, forward_servers, ttls)
            else:
                bl_dom, bl_ip4, bl_ip6, bl_rx, _, _, _ = read_list(lists[lst], lst, 'Blacklist', bl_dom, bl_ip4, bl_ip6, bl_rx, dict(), dict(), dict())

        save_lists(savefile)
    else:
        loadcache = True # Only load cache if savefile didn't change

    white_list(redirect_addrs, 'Redirect Address')
    white_list(forward_servers, 'Forward Server')

    # Add command-tld to whitelist
    wl_dom[command] = 'Command-TLD'

    # Load persistent cache
    if loadcache:
        load_cache(cachefile)
    else:
        # Do not load if lists have changed to avoid conflicts between lists and previous cached
        log_info('CACHE-LOAD: Not retrieving persistent CACHE, lists have changed')

    # Show totals in log
    log_totals()

    # DNS-Server/Resolver
    logger = DNSLogger(log='-recv,-send,-request,-reply,+error,+truncated,-data', prefix=False)
    udp_dns_server = dict()
    tcp_dns_server = dict()
    handler = DNSHandler
    for listen in listen_on:
        elements = listen.split('@')
        listen_address = elements[0].upper()
        if ipregex.search(listen_address) or listen_address == '':
            if len(elements) > 1:
                listen_port = int(elements[1])
            else:
                listen_port = 53

            if listen_address == '':
                log_info('Starting DNS Service at port ' + str(listen_port) + ' ...')
            else:
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
                    if listen_address == '':
                        log_info('DNS Service ready at port ' + str(listen_port))
                        break
                    else:
                        log_info('DNS Service ready on ' + listen_address + ' at port ' + str(listen_port))
                else:
                    log_err('DNS Service did not start, aborting ...')
                    sys.exit(1)

    log_info('INSTIGATOR running and ready')

    # Keep things running
    try:
        while True:
            time.sleep(1) # Seconds
            if cache_maintenance_busy is False and prefetching_busy is False:
                cachelist = cache_expired_list()
                prefetchlist = cache_prefetch_list()

                if cache_maintenance_now or cachelist or prefetchlist:
                    cache_purge(False, False, cachelist, prefetchlist)

    except (KeyboardInterrupt, SystemExit):
        log_info('INSTIGATOR SHUTTING DOWN')


    # Shutdown ports
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

    # Save persistent cache
    save_cache(cachefile)

    log_info('INSTIGATOR EXIT')
    log_info('---------------')
    sys.exit(0)

# <EOF>
