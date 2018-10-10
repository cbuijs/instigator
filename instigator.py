#!/usr/bin/env python3
# Needs Python 3.5 or newer!
'''
=========================================================================================
 instigator.py: v5.15-20181010 Copyright (C) 2018 Chris Buijs <cbuijs@chrisbuijs.com>
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
- DNSSEC support (validation only), like DNSMasq. Status: Backburner, see dnspython.
- Itterative resolution besides only forwarding (as is today). Status: Backburner.
- Add more security-features against hammering, dns-drip, ddos, etc. Status: Backburner.
- Fix SYSLOG on MacOS. Status: To-be-done.
- Convert all concatenated strings into .format ones. Status: In Progress

=========================================================================================
'''

# sys module and path, adapt for your system. Below if for Debian 9.5 Stable
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

# Ordered Dictionaries
from collections import OrderedDict

# DNSLib module
from dnslib import *
from dnslib.server import *

# Regex module
import regex

# Use module PyTricia for CIDR/Subnet stuff
import pytricia

# Use cymruwhois for SafeDNS ASN lookups
from cymruwhois import Client

###################

# Debugging
debug = False
if len(sys.argv) > 1: # Any argument on command-line will put debug-mode on, printing all messages to TTY.
    debug = True

# Base/Work dirs
basedir = '/'.join(os.path.realpath(__file__).split('/')[0:-1]) + '/'

# Config
configfile = basedir + 'instigator.conf'

# Resolv.conf file
resolvfile = '/etc/resolv.conf'

# Listen for queries
#listen_on = list(['192.168.1.251@53', '127.0.0.1@53']) # IPv4 only for now.
#listen_on = list(['172.16.1.251@53', '127.0.0.1@53']) # IPv4 only for now.
listen_on = list(['@53']) # Listen on all interfaces/ip's
#listen_on = list(['127.0.0.1@53']) # IPv4 only for now.

# Forwarding queries to
forward_timeout = 5 # Seconds, keep on 5 seconds or higher
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
#forward_servers['.'] = list(['127.0.0.1@53001', '127.0.0.1@53002', '127.0.0.1@53003', '127.0.0.1@53004']) # DEFAULT Stubby
#forward_servers['.'] = list(['172.16.1.1@53053']) # Stubby on router

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
hitrcode = 'NODATA'
#hitrcode = 'NXDOMAIN'
#hitrcode = 'REFUSED'

# Only load cached/fast files when not older then maxfileage
maxfileage = 43200 # Seconds

# Files / Lists
savefile = basedir + 'save.shelve'
defaultlist = list([None, 0, '', 0, 0]) # reply - expire - qname/class/type - hits - orgttl
lists = OrderedDict()

lists['blacklist'] = basedir + 'black.list' # Blacklist
lists['whitelist'] = basedir + 'white.list' # Whitelist
lists['aliases'] = basedir + 'aliases.list' # Aliases/Forwards/TTLS/etc
lists['malicious-ip'] = basedir + 'malicious-ip.list' # Bad IP's
lists['tlds'] = basedir + 'tlds.list' # Allowed TLD's, negated regex-list, generates NXDOMAIN for none IANA TLD's

#lists['shalla-ads'] = '/opt/instigator/shallalist/adv/domains'
#lists['shalla-banking'] = '/opt/instigator/shallalist/finance/banking/domains'
#lists['shalla-costtraps'] = '/opt/instigator/shallalist/costtraps/domains'
#lists['shalla-porn'] = '/opt/instigator/shallalist/porn/domains'
#lists['shalla-gamble'] = '/opt/instigator/shallalist/gamble/domains'
#lists['shalla-spyware'] = '/opt/instigator/shallalist/spyware/domains'
#lists['shalla-trackers'] = '/opt/instigator/shallalist/tracker/domains'
#lists['shalla-updatesites'] = '/opt/instigator/shallalist/updatesites/domains'
#lists['shalla-warez'] = '/opt/instigator/shallalist/warez/domains'

blacklist = list(['blacklist', 'shalla-ads', 'shalla-costtraps', 'shalla-porn', 'shalla-gamble', 'shalla-spyware', 'shalla-warez', 'malicious-ip'])
whitelist = list(['whitelist', 'aliases', 'shalla-banking', 'shalla-updatesites', 'tlds'])
searchdom = set()

# Root servers # !!! WIP
#root_servers = list(['198.41.0.4', '2001:503:ba3e::2:30', '199.9.14.201', '2001:500:200::b', '192.33.4.12', '2001:500:2::c', '199.7.91.13', '2001:500:2d::d', '192.203.230.10', '2001:500:a8::e', '192.5.5.241', '2001:500:2f::f', '192.112.36.4', '2001:500:12::d0d', '198.97.190.53', '2001:500:1::53', '192.36.148.17', '2001:7fe::53', '192.58.128.30', '2001:503:c27::2:30', '193.0.14.129', '2001:7fd::1', '199.7.83.42', '2001:500:9f::42', '202.12.27.33', '2001:dc3::35'])

# Cache Settings
nocache = False # Don't change this
cachefile = basedir + 'cache.shelve'
cachesize = 2048 # Entries
cache_maintenance_now = False
cache_maintenance_busy = False
persistentcache = True
fastcache = False # If True, have the maintenance-loop take care of cache-expiry instead of per query. This could NOT honor TTL's to the second though! No round-robin of RR-Sets!

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

# Check requests/queries
checkrequest = True

# Check responses/answers
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
blockv6 = False

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

# SafeDNS
safedns = False
safednsmononly = True
safednsratio = 50 # Percent
ipasnfile = basedir + 'ipasn.list'
#ipasnfile = False # To disable loading of IPASN and rely on whois
ipasn4 = pytricia.PyTricia(32)
ipasn6 = pytricia.PyTricia(128)

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

# Lists
wl_dom = dict() # Domain whitelist
bl_dom = dict() # Domain blacklist
wl_ip4 = pytricia.PyTricia(32) # IPv4 Whitelist
bl_ip4 = pytricia.PyTricia(32) # IPv4 Blacklist
wl_ip6 = pytricia.PyTricia(128) # IPv6 Whitelist
bl_ip6 = pytricia.PyTricia(128) # IPv6 Blacklist
wl_rx = OrderedDict() # Regex Whitelist
bl_rx = OrderedDict() # Regex Blacklist
wl_asn = dict() # ASN Whitelist
bl_asn = dict() # ASN Blacklist
aliases = OrderedDict() # Aliases
aliases_rx = OrderedDict() # Alias generators/regexes
ttls = OrderedDict() # TTL aliases

# Work caches
indom_cache = dict() # Cache results of domain hits
inrx_cache = dict() # Cache result of regex hits

# Cache
cache = dict() # DNS cache

# Pending IDs
pending = dict() # Pending queries

# Broken forwarders flag
broken_exist = False

## Regexes

# Use fast (less precisie, sometimes faster) versions of regexes
fastregex = False # Leave False unless really slow system or (very) large datasets

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
isdomain = regex.compile('(?=^.{1,253}$)(^((?!-)[a-z0-9_-]{0,62}[a-z0-9]\.)*(xn--[a-z0-9-]{5,63}|[a-z]{2,63})$)', regex.I)

# Regex to filter regexes out
isregex = regex.compile('^/.*/$')

# Regex for AS(N) Numbers
isasn = regex.compile('^AS[0-9]+$', regex.I)

# Regex for numbers
isnum = regex.compile('^[0-9]+$')

##############################################################

def log_info(message):
    '''Log INFO messages to syslog'''
    if debug:
        #print('{0} {1}'.format(time.strftime('%a %d-%b-%Y %H:%M:%S'), message))
        print('{0} {1}'.format(time.strftime('%Y-%m-%d %H:%M:%S'), message)[:256])
        sys.stdout.flush()
    syslog.syslog(syslog.LOG_INFO, message[:256]) # !!! Fix SYSLOG on MacOS
    return True


def log_err(message):
    '''Log ERR messages to syslog'''
    message = '!!! STRESS: {0}'.format(message)
    if debug:
        #print('{0} {1}'.format(time.strftime('%a %d-%b-%Y %H:%M:%S'), message))
        print('{0} {1}'.format(time.strftime('%Y-%m-%d %H:%M:%S'), message)[:256])
        sys.stdout.flush()
    syslog.syslog(syslog.LOG_ERR, message[:256]) # !!! Fix SYSLOG on MacOS
    return True


def file_exist(file, isdb):
    '''Check if file exists and return age (in seconds) if so'''
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
                else:
                    if debug: log_info('FILE-EXIST: ' + file + ' is zero size')

        except BaseException as err:
            log_err('FILE-EXIST-ERROR: ' + str(err))
            return False

    return False


def match_blacklist(rid, rtype, rrtype, value, log):
    '''
    Check if entry matches a list
    Returns:
      True = Black-listed
      False = White-listed
      None = None-listed
    '''
    if filtering is False:
        return None

    tid = id_str(rid)
    testvalue = value
    itisanip = False

    # Check if an IP
    if rtype == 'REQUEST' and rrtype == 'PTR' and (not in_regex(testvalue, aliases_rx, True, 'Generator')):
        if (not in_domain(testvalue, wl_dom, 'Whitelist')) and (not in_domain(testvalue, bl_dom, 'Blacklist')):
            ip = False
            if ip4arpa.search(testvalue):
                ip = '.'.join(testvalue.split('.')[0:4][::-1])
            elif ip6arpa.search(testvalue):
                ip = ':'.join(filter(None, regex.split('(.{4,4})', ''.join(testvalue.split('.')[0:32][::-1]))))

            if ipregex.search(ip):
                log_info('MATCHING: Matching against IP \"' + ip + '\" instead of domain \"' + testvalue + '\"')
                itisanip = True
                testvalue = ip

    elif rtype == 'REPLY':
        #if rrtype in ('A', 'AAAA') and ipregex.search(testvalue):
        if rrtype in ('A', 'AAAA'):
            itisanip = True


    # Check domain-name validity
    if not itisanip:
        testvalue = normalize_dom(regex.split('\s+', testvalue)[-1])
        if blockundotted and testvalue.count('.') < mindots:
            log_info('BLOCK-MINDOTS-HIT [' + tid + ']: ' + value)
            return True
        elif is_illegal(testvalue):
            log_err('BLOCK-ILLEGAL-HIT [' + tid + ']: ' + value)
            return True
        elif is_weird(testvalue, rrtype):
            log_info('BLOCK-WEIRD-HIT [' + tid + ']: ' + value)
            return True


    # Block IP-Family
    if blockv4 and (rrtype == 'A' or (rrtype == 'PTR' and itisanip and ipregex4.search(testvalue))):
        log_info('BLOCK-IPV4-HIT [' + tid + ']: ' + rtype + ' \"' + value + '/' + rrtype + '\"')
        return True

    if blockv6 and (rrtype == 'AAAA' or (rrtype == 'PTR' and itisanip and ipregex6.search(testvalue))):
        log_info('BLOCK-IPV6-HIT [' + tid + ']: ' + rtype + ' \"' + value + '/' + rrtype + '\"')
        return True


    # Check against IP-Lists
    if itisanip:
        asn, prefix, owner = who_is(testvalue, '[' + tid + '] ' + rtype)
        if asn != '0':
            if asn in wl_asn: # Whitelist
                if log: log_info('WHITELIST-ASN-HIT [' + tid + ']: ' + rtype + ' ' + value + '/' + testvalue + ' matched against \"AS' + asn + '\" (' + wl_asn[asn] + '/' + prefix + ') - ' + owner)
                return False
            elif asn in bl_asn: # Blacklist
                if log: log_info('BLACKLIST-ASN-HIT [' + tid + ']: ' + rtype + ' ' + value + '/' + testvalue + ' matched against \"AS' + asn + '\" (' + bl_asn[asn] + '/' + prefix + ') - ' + owner)
                return True

        if testvalue.find(':') == -1:
            wip = wl_ip4
            bip = bl_ip4
        else:
            wip = wl_ip6
            bip = bl_ip6

        found = False
        prefix = False

        if not testvalue in wip: # Whitelist
            if testvalue in bip: # Blacklist
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
        wl_found = in_domain(testvalue, wl_dom, 'Whitelist') # Whitelist
        if wl_found is not False:
            if log: log_info('WHITELIST-HIT [' + tid + ']: ' + rtype + ' \"' + value + '\" matched against \"' + wl_found + '\" (' + wl_dom[wl_found] + ')')
            return False
        else:
            bl_found = in_domain(testvalue, bl_dom, 'Blacklist') # Blacklist
            if bl_found is not False:
                if log: log_info('BLACKLIST-HIT [' + tid + ']: ' + rtype + ' \"' + value + '\" matched against \"' + bl_found + '\" (' + bl_dom[bl_found] + ')')
                return True


    # If it is not an IP, check validity and against regex
    if not itisanip:
        # Catchall: Check agains Regex-Lists
        rxfound = in_regex(value, wl_rx, False, 'Whitelist') # Whitelist
        if rxfound:
            if log: log_info('WHITELIST-REGEX-HIT [' + tid + ']: ' + rtype + ' \"' + value + '\" matched against ' + rxfound)
            return False

        rxfound = in_regex(value, bl_rx, False, 'Blacklist') # Blacklist
        if rxfound:
            if log: log_info('BLACKLIST-REGEX-HIT [' + tid + ']: ' + rtype + ' \"' + value + '\" matched against ' + rxfound)
            return True

    # No hits
    if debug and log: log_info('NONE-HIT [' + tid + ']: ' + rtype + ' \"' + value + '\" does not match against any lists')

    return None


def in_domain(name, domlist, domid):
    '''Check if name is domain or sub-domain'''
    domidname = domid + ':' + name
    if domidname in indom_cache:
        indom = indom_cache.get(domidname, False)
        if indom:
            if debug: log_info('INDOM-CACHE [' + domid + ']: \"' + name + '\" in \"' + indom + '\"')
        else:
            if debug: log_info('INDOM-CACHE [' + domid + ']: \"' + name + '\" is NOMATCH')
        return indom

    testname = name
    while testname:
        if testname in domlist:
            indom_cache[domidname] = testname
            return testname
        elif testname.find('.') == -1:
            break
        else:
            testname = testname[testname.find('.') + 1:]

    indom_cache[domidname] = False
    return False


def in_regex(name, rxlist, isalias, rxid):
    '''Check if name is matching regex'''
    rxidname = rxid + ':' + name
    if rxidname in inrx_cache:
        inrx = inrx_cache.get(rxidname, False)
        if inrx:
            if isalias:
                if debug: log_info('INRX-CACHE [' + rxid +']: \"' + name + '\" -> \"' + inrx + '\"')
            else:
                if debug: log_info('INRX-CACHE [' + rxid +']: \"' + name + '\" matched with \"' + inrx + '\"')
        else:
            if debug: log_info('INRX-CACHE [' + rxid +']: \"' + name + '\" is NOMATCH')
        return inrx

    if name and name != '.':
        for i in rxlist.keys():
            rx = rxlist.get(i, False)
            if rx and rx.search(name) and (not in_domain(name, forward_servers, 'Forward')):
                elements = regex.split(':\s+', i)
                lst = elements[0]
                rx2 = ' '.join(elements[1:])
                result = False
                if isalias:
                    rx3 = regex.split('\s+', rx2)[0]
                    result = regex.sub(rx, rx3, name)
                    if debug: log_info('GENERATOR-MATCH [' + lst + ']: ' + name + ' matches \"' + rx.pattern + '\" = \"' + rx3 + '\" -> \"' + result + '\"')
                else:
                    result = '\"' + rx2 + '\" (' + lst + ')'
                    if debug: log_info('REGEX-MATCH [' + lst + ']: ' + name + ' matches ' + result)

                inrx_cache[rxidname] = result

                return result

    inrx_cache[rxidname] = False
    return False


def who_is(ip, desc):
    '''Whois lookup'''
    asn = '0'
    owner = 'UNKNOWN'

    if ip.find(':') == -1:
        ipasn = ipasn4
        prefix = ip + '/32'
    else:
        ipasn = ipasn6
        prefix = ip + '/128'

    if ip in ipasn:
         prefix = ipasn.get_key(ip)
         elements = regex.split('\s+', ipasn.get(prefix, asn + ' ' + owner))
         if elements:
             asn = elements[0]
             owner = ' '.join(elements[1:])
             if debug: log_info('WHOIS-CACHE-HIT: ' + desc + ' ' + ip + ' AS' + asn + ' (' + prefix + ') - ' + owner)

    else:
        log_info('WHOIS-LOOKUP: ' + desc + ' ' + ip)
        try:
            whois = Client()
            lookup = whois.lookup(ip)
            asn = str(lookup.asn)
        except BaseException as err:
            log_err('WHOIS-ERROR: ' + desc + ' ' + ip + ' - ' + str(err))
            asn = 'NONE'

        if asn != 'NONE' and asn != '' and asn != 'NA' and asn is not None:
            prefix = str(lookup.prefix)
            owner = str(lookup.owner).upper()
            log_info('WHOIS-RESULT: ' + desc + ' ' + ip + ' AS' + asn + ' (' + prefix + ') - ' + owner)
        else:
            asn = '0'
            log_info('WHOIS-UNKNOWN: ' + ip)

        ipasn[prefix] = asn + ' ' + owner

    return asn, prefix, owner


def dns_query(request, qname, qtype, use_tcp, tid, cip, checkbl, checkalias, force):
    '''Do query'''
    global broken_exist

    queryname = qname + '/IN/' + qtype
    hid = id_str(tid)

    #if debug and checkbl: queryname = 'BL:' + queryname
    #if debug and checkalias: queryname = 'AL:' + queryname
    #if debug and force: queryname = 'F:' + queryname

    # Process already pending/same query
    uid = hash(qname + '/' + qtype + '/' + cip + '/' + str(tid))
    count = 0
    while uid in pending:
        count += 1
        if count > 2: # Disembark after 3 seconds
            log_info('DNS-QUERY [' + hid + ']: Skipping query for ' + queryname + ' - ID (' + hid + ') already processing, takes more then 3 secs')
            reply = request.reply()
            reply.header.rcode = getattr(RCODE, 'SERVFAIL')
            return reply

        log_info('DNS-QUERY [' + hid + ']: delaying (' + str(count) + ') query for ' + queryname + ' - ID (' + hid + ') already in progress, waiting to finish')
        time.sleep(1) # Seconds

    # Get from cache if any
    if not force:
        reply = from_cache(qname, 'IN', qtype, tid)
        if reply is not None:
            return reply

    # SafeDNS stuff
    firstreply = None
    asnstack = set()
    ipstack = set()

    reply = None
    rcttl = False

    pending[uid] = int(time.time())

    server = in_domain(qname, forward_servers, 'Forward')
    if server:
        servername = 'FORWARD-HIT: ' + server
    else:
        server = '.'
        servername = 'DEFAULT'

    query = DNSRecord(q=DNSQuestion(qname, getattr(QTYPE, qtype)))

    forward_server = forward_servers.get(server, False)
    if forward_server:

        if forwardroundrobin and len(forward_server) > 1 and safedns is False:
            addrs = round_robin(forward_server)
            forward_servers[server] = list(addrs)
        else:
            addrs = forward_server

        if safedns:
            log_info('SAFEDNS-QUERY [' + hid + ']: forwarding query from ' + cip + ' to all forwarders for ' + queryname)

        for addr in addrs:
            forward_address = addr.split('@')[0]
            if addr.find('@') > 0:
                forward_port = int(addr.split('@')[1])
            else:
                forward_port = 53

            if not in_cache(forward_address, 'BROKEN-FORWARDER', str(forward_port)):
                if not safedns:
                    log_info('DNS-QUERY [' + hid + ']: forwarding query from ' + cip + ' to ' + forward_address + '@' + str(forward_port) + ' (' + servername + ') for ' + queryname)

                useip6 = False
                if forward_address.find(':') > 0:
                    useip6 = True

                error = 'UNKNOWN-ERROR'
                success = True

                reply = None

                try:
                    q = query.send(forward_address, forward_port, tcp=use_tcp, timeout=forward_timeout, ipv6=useip6)
                    reply = DNSRecord.parse(q)

                except BaseException as error:
                    success = False

                if success is True:
                    rcode = str(RCODE[reply.header.rcode])
                    error = rcode
                    if rcode != 'SERVFAIL':
                        if reply.auth and rcode != 'NOERROR' and firstreply is None and QTYPE[reply.auth[0].rtype] == 'SOA':
                            soadom = regex.split('\s+', str(reply.auth[0]))[0].strip('.') or '.'
                            if soadom != ".":
                                rcttl = normalize_ttl(qname, reply.auth)
                                if rcttl:
                                    log_info('SOA-TTL: Taking TTL={1} of SOA \"{0}\" for {2} {3}'.format(soadom, rcttl, queryname, rcode))
                        else:
                            if firstreply is None:
                                _ = normalize_ttl(qname, reply.rr)

                        if safedns:
                            if firstreply is None:
                                firstreply = reply

                            if len(reply.rr) > 0:
                                for record in reply.rr:
                                    rqtype = QTYPE[record.rtype]
                                    if rqtype in ('A', 'AAAA'):
                                        ip = str(record.rdata)
                                        if ip not in ipstack:
                                            ipstack.add(ip)
                                            asn, prefix, owner = who_is(ip, queryname)
                                            if asnstack and asn in asnstack:
                                                if debug: log_info('SAFEDNS: ' + queryname + ' Found same ASN (' + str(len(asnstack)) + ') \"' + asn + '\" (' + owner + ') for ' + ip + ' (' + prefix + ') from ' + forward_address)
                                            elif asn != '0':
                                                asnstack.add(asn)
                                                if debug: log_info('SAFEDNS: ' + queryname + ' Found new ASN (' + str(len(asnstack)) + ') \"' + asn + '\" (' + owner + ') for ' + ip + ' (' + prefix + ') from ' + forward_address)
                                            else:
                                                if debug: log_info('SAFEDNS: ' + queryname + ' UNKNOWN ASN for ' + ip + ' from ' + forward_address)

                        else:
                            break

                    else:
                        success = False

                if success is False or reply is None:
                    log_err('DNS-QUERY [' + hid + ']: ERROR Resolving ' + queryname + ' using ' + forward_address + '@' + str(forward_port) + ' - ' + str(error))
                    if error != 'SERVFAIL':
                        broken_exist = True
                        to_cache(forward_address, 'BROKEN-FORWARDER', str(forward_port), request.reply(), force, retryttl)

            if debug and safedns is False: log_info('DNS-QUERY [' + hid + ']: Skipped broken/invalid forwarder ' + forward_address + '@' + str(forward_port))

    else:
        log_err('DNS-QUERY [' + hid + ']: ERROR Resolving ' + queryname + ' (' + servername + ') - NO DNS SERVERS AVAILBLE!')


    if safedns and firstreply is not None and asnstack:
        reply = firstreply
        astack = ', '.join(sorted(asnstack, key=int))
        if len(asnstack) > 1:
            ratio = int(100 / len(asnstack))
            if ratio < safednsratio:
                if not safednsmononly:
                    reply = False

                log_info('SAFEDNS: ' + queryname + ' UNSAFE! Multiple ASNs (Ratio: ' + str(ratio) + '% < ' + str(safednsratio) + '%) ASNs (' + str(len(asnstack)) + '): ' + astack)
        else:
            log_info('SAFEDNS: ' + queryname + ' is SAFE (Ratio: 100% >= ' + str(safednsratio) + '%) ASN: ' + astack)


    # No response or SafeDNS interception
    if reply is None or reply is False:
        #cache.clear()
        reply = query.reply()
        reply.header.id = tid
        if reply is False:
            log_err('DNS-QUERY [' + hid + ']: SafeDNS Block ' + queryname + ' ' + str(hitrcode))
            if hitrcode == 'NODATA':
                reply.header.rcode = getattr(RCODE, 'NOERROR')
            else:
                reply.header.rcode = getattr(RCODE, hitrcode)
        else:
            log_err('DNS-QUERY [' + hid + ']: ERROR Resolving ' + queryname + ' ' + str(hitrcode))
            reply.header.rcode = getattr(RCODE, 'SERVFAIL')

        _ = pending.pop(uid, None)
        return reply

    # Clear broken-forwarder cache entries
    elif broken_exist:
        broken_exist = False
        for queryhash in no_noerror_list():
            record = cache.get(queryhash, None)
            if record is not None:
                rcode = str(RCODE[record[0].header.rcode])
                log_info('CACHE-MAINT-PURGE: ' + record[2] + ' ' + rcode + ' (Unbroken DNS Servers)')
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

                if replycount > 1: # Query-part of first RR in RRSET set already checked
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
                    log_info('REPLY [' + hid + ':' + str(replycount) + '-' + str(replynum) + ']: ' + rqname + '/IN/' + rqtype + ' = ' + data + ' BLACKLIST-HIT')
                    reply = generate_response(request, qname, qtype, redirect_addrs, force)
                    break

                else:
                    log_info('REPLY [' + hid + ':' + str(replycount) + '-' + str(replynum) + ']: ' + rqname + '/IN/' + rqtype + ' = ' + data + ' NOERROR')

    else:
        reply = request.reply()
        reply.header.rcode = getattr(RCODE, rcode)
        log_info('RCODE-REPLY [' + hid + ']: ' + queryname + ' = ' + rcode)


    # Match up ID
    reply.header.id = tid

    # Collapse CNAME
    if collapse:
        reply = collapse_cname(request, reply, tid)

    # Minimum responses
    if minresp:
        reply.auth = list()
        reply.ar = list()
        #reply.add_ar(EDNS0())

    # Stash in cache
    if blockit:
        ttl = filterttl
    elif rcttl:
        ttl = rcttl
    else:
        ttl = False

    to_cache(qname, 'IN', qtype, reply, force, ttl)

    # Pop from pending
    _ = pending.pop(uid, None)

    return reply


def generate_response(request, qname, qtype, redirect_addrs, force):
    '''Generate response when blocking'''
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
        addanswer = set()
        for addr in redirect_addrs:
            answer = None
            if qtype == 'A' and ipregex4.search(addr):
                answer = RR(qname, QTYPE.A, ttl=filterttl, rdata=A(addr))
            elif qtype == 'AAAA' and ipregex6.search(addr):
                answer = RR(qname, QTYPE.AAAA, ttl=filterttl, rdata=AAAA(addr))
            elif qtype == 'PTR' and (not ipregex.search(addr)):
                answer = RR(qname, QTYPE.PTR, ttl=filterttl, rdata=PTR(addr))
            elif (qtype in ('A', 'AAAA', 'CNAME')) and (not ipregex.search(addr)):
                answer = RR(qname, QTYPE.CNAME, ttl=filterttl, rdata=CNAME(addr))

            if answer is not None:
                addanswer.add(addr)
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


def generate_alias(request, qname, qtype, use_tcp, force):
    '''Generate alias response'''
    queryname = qname + '/IN/' + qtype

    realqname = normalize_dom(request.q.qname)

    reply = request.reply()
    reply.header.id = request.header.id
    reply.header.rcode = getattr(RCODE, 'NOERROR')

    if qname in aliases:
        alias = aliases[qname]
    else:
        aqname = in_domain(qname, aliases, 'Alias')
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
    if alias.upper() in ('NODATA', 'NOTAUTH', 'NXDOMAIN', 'RANDOM', 'REFUSED'):
        reply = request.reply()
        if alias.upper() == 'RANDOM':
            log_info('ALIAS-HIT: ' + queryname + ' = RANDOM-NXDOMAIN')
            reply.header.rcode = getattr(RCODE, 'NXDOMAIN')
        else:
            log_info('ALIAS-HIT: ' + queryname + ' = ' + alias.upper())
            if alias.upper() == 'NODATA':
                reply.header.rcode = getattr(RCODE, 'NOERROR')
            else:
                reply.header.rcode = getattr(RCODE, alias.upper())

    elif ipregex.search(alias) and qtype in ('A', 'AAAA', 'CNAME'):
        log_info('ALIAS-HIT: ' + queryname + ' = REDIRECT-TO-IP -> ' + alias)
        if alias.find(':') == -1:
            answer = RR(realqname, QTYPE.A, ttl=filterttl, rdata=A(alias))
        else:
            answer = RR(realqname, QTYPE.AAAA, ttl=filterttl, rdata=AAAA(alias))

        reply.add_answer(answer)

    elif qtype in ('A', 'AAAA', 'CNAME', 'PTR'):
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
        log_info('ALIAS-HIT: ' + qname + ' -> ' + alias + ' NOERROR')
        if collapse and aliasqname:
            log_info('ALIAS-HIT: COLLAPSE ' + qname + '/IN/CNAME')
    else:
        log_info('ALIAS-HIT: ' + queryname + ' Unsupported RR-Type -> ' + str(RCODE[reply.header.rcode]))

    to_cache(qname, 'IN', qtype, reply, force, False)

    return reply


def save_cache(file):
    '''Save Cache'''
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
    '''Load Cache'''
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
    '''iplist is a Pytricia dict'''
    newdict = dict()
    for i in iplist.keys():
        newdict[i] = iplist[i]
    return newdict

def from_dict(fromlist, tolist):
    '''toist is a Pytricia dict.'''
    for i in fromlist.keys():
        tolist[i] = fromlist[i]
    return tolist


def save_lists(file):
    '''Save Lists'''
    log_info('LIST-SAVE: Saving to \"' + file + '\"')

    try:
        s = shelve.DbfilenameShelf(file, flag='n', protocol=4)

        s['wl_dom'] = wl_dom
        s['wl_ip4'] = to_dict(wl_ip4)
        s['wl_ip6'] = to_dict(wl_ip6)
        s['wl_rx'] = wl_rx
        s['wl_asn'] = wl_asn
        s['aliases'] = aliases
        s['aliases_rx'] = aliases_rx
        s['forward_servers'] = forward_servers
        s['ttls'] = ttls

        s['ipasn4'] = to_dict(ipasn4)
        s['ipasn6'] = to_dict(ipasn6)

        s['bl_dom'] = bl_dom
        s['bl_ip4'] = to_dict(bl_ip4)
        s['bl_ip6'] = to_dict(bl_ip6)
        s['bl_rx'] = bl_rx
        s['bl_asn'] = bl_asn

        s.close()

    except BaseException as err:
        log_err('ERROR: Unable to open/write file \"' + file + '\" - ' + str(err))
        return False


    return True


def load_asn(file, asn4, asn6):
    '''Load IPASN'''
    log_info('ASN: Loading IPASN from \"' + file + '\"')

    if file_exist(file, False):
        try:
            f = open(file, 'r')
            lines = f.readlines()
            f.close()

        except BaseException as err:
            log_err('ERROR: Unable to open/read/process ASN file \"' + file + '\" - ' + str(err))
            return False

        count = 0
        for line in lines:
            count += 1

            elements = regex.split('\s+', line.strip())
            if len(elements) > 1:
                prefix = elements[0]
                if ipregex.search(prefix):
                    asn = elements[1].upper().lstrip('AS')
                    if isasn.search('AS' + asn):
                        if len(elements) > 2:
                           owner = ' '.join(elements[2:]).upper()
                        else:
                           owner = 'IPASN'

                        if prefix.find(':') == -1:
                           asnd = asn4
                        else:
                           asnd = asn6

                        asnd[prefix] = asn + ' ' + owner
                    else:
                        log_err('ASN-ERROR [' + str(count) + ']: Invalid ASN - ' + line)

                else:
                    log_err('ASN-ERROR [' + str(count) + ']: Invalid IP - ' + line)

    else:
        log_err('ERROR: Unable to open/read/process ASN file \"' + file + '\" - File does not exists')

    log_info('ASN: Fetched ' + str(len(asn4)) + ' IPv4 and ' + str(len(asn6)) + ' IPv6 ASNs')

    return asn4, asn6


def load_lists(file):
    '''Load Lists'''
    global wl_dom
    global wl_ip4
    global wl_ip6
    global wl_rx
    global wl_asn
    global aliases
    global aliases_rx
    global forward_servers
    global ttls

    global ipasn4
    global ipasn6

    global bl_dom
    global bl_ip4
    global bl_ip6
    global bl_rx
    global bl_asn

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
            wl_asn = s['wl_asn']
            aliases = s['aliases']
            aliases_rx = s['aliases_rx']
            forward_servers = s['forward_servers']
            ttls = s['ttls']

            from_dict(s['ipasn4'], ipasn4)
            from_dict(s['ipasn6'], ipasn6)

            bl_dom = s['bl_dom']
            bl_ip4 = pytricia.PyTricia(32)
            from_dict(s['bl_ip4'], bl_ip4)
            bl_ip6 = pytricia.PyTricia(128)
            from_dict(s['bl_ip6'], bl_ip6)

            bl_rx = s['bl_rx']
            bl_asn = s['bl_asn']

            s.close()

        except BaseException as err:
            log_err('ERROR: Unable to open/read file \"' + file + '\" - ' + str(err))
            return False

    else:
        log_info('LIST-LOAD: Skip loading lists from \"' + file + '\" - non-existant or older then ' + str(maxfileage) + ' seconds')
        return False

    return True


def log_totals():
    '''Log List Totals'''
    log_info('WHITELIST-TOTALS: ' + str(len(wl_rx)) + ' REGEXes, ' + str(len(wl_ip4)) + ' IPv4 CIDRs, ' + str(len(wl_ip6)) + ' IPv6 CIDRs, ' + str(len(wl_dom)) + ' DOMAINs, ' + str(len(aliases)) + ' ALIASes, ' + str(len(forward_servers)) + ' FORWARDs, ' + str(len(ttls)) + ' TTLs and ' + str(len(wl_asn)) + ' ASNs')
    log_info('BLACKLIST-TOTALS: ' + str(len(bl_rx)) + ' REGEXes, ' + str(len(bl_ip4)) + ' IPv4 CIDRs, ' + str(len(bl_ip6)) + ' IPv6 CIDRs, ' + str(len(bl_dom)) + ' DOMAINs and ' + str(len(bl_asn)) + ' ASNs')
    log_info('CACHE-TOTALS: ' + str(len(cache)) + ' Cache Entries')

    return True


def normalize_dom(dom):
    '''Normalize Domain Names'''
    sdom = str(dom)
    if sdom.find('.') == -1 and sdom.upper() in ('NODATA', 'NXDOMAIN', 'REFUSED', 'RANDOM'):
        return sdom.strip().strip('.').upper()
    else:
        return sdom.strip().strip('.').lower() or '.'

    return dom


# Read filter lists, see "accomplist" to provide ready-2-use lists:
# https://github.com/cbuijs/accomplist
def read_list(file, listname, bw, domlist, iplist4, iplist6, rxlist, arxlist, alist, flist, tlist, asnlist):
    '''Read/Load lists'''
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
            log_err('ERROR: Unable to open/read/process list-file \"' + file + '\" - ' + str(err))

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
                    try:
                        rxlist[name + ': ' + rx] = regex.compile(rx, regex.I)
                    except BaseException as err:
                        log_err(listname + ' INVALID REGEX [' + str(count) + ']: ' + entry + ' - ' + str(err))

                # ASN
                elif isasn.search(entry):
                    fetched += 1
                    asnlist[entry.upper().lstrip('AS')] = name

                # DOMAIN
                elif isdomain.search(entry):
                    entry = normalize_dom(entry)
                    entrytype = 'ANY'
                    if ip4arpa.search(entry) or ip6arpa.search(entry):
                        entrytype = 'PTR'
                    if is_illegal(entry) or is_weird(entry, entrytype):
                        log_err(listname + ' ILLEGAL/FAULTY/WEIRD Entry [' + str(count) + ']: ' + entry)
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
                        if entry[0] == '/':
                            elements = regex.split('/\s*=\s*', entry)
                            if len(elements) > 1:
                                if isregex.search(elements[0] + '/'):
                                    fetched += 1
                                    rx = elements[0].strip('/')
                                    alias = elements[1].strip()

                                    try:
                                        arxlist[name + ': ' + alias + ' ' + rx] = regex.compile(rx, regex.I)
                                    except BaseException as err:
                                        log_err(listname + ' INVALID REGEX [' + str(count) + ']: ' + entry + ' - ' + str(err))

                                    log_info('ALIAS-GENERATOR: \"' + rx + '\" = \"' + alias + '\"')
                                else:
                                    log_err(listname + ' INVALID ALIAS [' + str(count) + ']: ' + entry)

                        else:
                            elements = regex.split('\s*=\s*', entry)
                            if len(elements) > 1:
                                domain = normalize_dom(elements[0])
                                alias = normalize_dom(elements[1])
                                if isdomain.search(domain) and (isdomain.search(alias) or ipregex.search(alias)):
                                    fetched += 1
                                    alist[domain] = alias
                                    if alias.upper() != 'RANDOM':
                                        domlist[domain] = 'Alias-Domain' # Whitelist it
                                    log_info('ALIAS-ALIAS: \"' + domain + '\" = \"' + alias + '\"')
                                else:
                                    log_err(listname + ' INVALID ALIAS [' + str(count) + ']: ' + entry)
                            else:
                                log_err(listname + ' INVALID ALIAS [' + str(count) + ']: ' + entry)

                    # FORWARD - domain.com>ip
                    elif entry.find('>') > 0:
                        #elements = entry.split('>')
                        elements = regex.split('\s*>\s*', entry)
                        if len(elements) > 1:
                            domain = normalize_dom(elements[0])
                            ips = elements[1].strip().lower().strip('.')
                            if isdomain.search(domain):
                                domlist[domain] = 'Forward-Domain' # Whitelist it
                                addrs = list()
                                #for addr in ips.split(','):
                                for addr in regex.split('\s*,\s*', ips):
                                    if ipportregex.search(addr):
                                        addrs.append(addr)
                                        log_info('ALIAS-FORWARDER: \"' + domain + '\" to ' + addr)
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
                        #elements = entry.split('!')
                        elements = regex.split('\s*!\s*', entry)
                        if len(elements) > 1:
                            domain = normalize_dom(elements[0])
                            ttl = elements[1].strip()
                            if isdomain.search(domain) and isnum.search(ttl):
                                fetched += 1
                                tlist[domain] = int(ttl)
                                domlist[domain] = 'TTL-Override' # Whitelist it
                                log_info('ALIAS-TTL: \"' + domain + '\" = ' + ttl)
                            else:
                                log_err(listname + ' INVALID TTL [' + str(count) + ']: ' + entry)
                        else:
                            log_err(listname + ' INVALID TTL [' + str(count) + ']: ' + entry)

                    # Search Domains
                    elif entry.endswith('*'):
                        sdom = normalize_dom(entry.rstrip('*').strip())
                        if isdomain.search(sdom):
                            if sdom not in searchdom:
                                if sdom not in wl_dom:
                                    domlist[sdom] = 'Search-Domain'
                                fetched += 1
                                searchdom.add(sdom)
                                log_info('ALIAS-SEARCH-DOMAIN: \"' + sdom + '\"')
                        else:
                            log_err(listname + ' INVALID SEARCH-DOMAIN [' + str(count) + ']: ' + entry)

                # Invalid/Unknown Syntax or BOGUS entry
                else:
                    log_err(listname + ' INVALID/BOGUS LINE [' + str(count) + ']: ' + entry)

    else:
        log_err('ERROR: Cannot open \"' + file + '\" - Does not exist')

    log_info(listname + ' Processed ' + str(count) + ' lines and used ' + str(fetched))

    return domlist, iplist4, iplist6, rxlist, arxlist, alist, flist, tlist, asnlist


def normalize_ttl(qname, rr):
    '''Normalize TTL's, all RR's in a RRSET will get the same TTL based on strategy (see below)'''
    if filtering:
        newttl = in_domain(qname, ttls, 'TTL')
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


def update_ttl(rr, ttl):
    '''Update all TTL's in RRSET'''
    for x in rr:
        x.ttl = ttl

    return None


def prefetch_it(queryhash):
    '''Prefetch/Update cache on almost expired items with enough hits'''
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


def from_cache(qname, qclass, qtype, tid):
    '''Retrieve from cache'''
    if nocache:
        return None

    queryhash = query_hash(qname, qclass, qtype)
    cacheentry = cache.get(queryhash, None)
    if cacheentry is None:
        return None
    elif fastcache: # Have maintenance loop take care of expiry stuff
        log_info('FASTCACHE-HIT [' + id_str(tid) + ']: ' + cacheentry[2])
        cache[queryhash][3] += 1
        reply = cacheentry[0]
        reply.header.id = tid
        return reply

    expire = cacheentry[1]
    queryname = cacheentry[2]
    now = int(time.time())
    ttl = expire - now
    orgttl = cacheentry[4]
    hits = cacheentry[3]
    hitsneeded = int(round(orgttl / prefetchhitrate)) or 1
    numrrs = len(cacheentry[0].rr)
    rcode = str(RCODE[cacheentry[0].header.rcode])

    # If expired, remove from cache
    if ttl < 1:
        if numrrs > 0 or (numrrs == 0 and rcode != 'NOERROR'):
            log_info('CACHE-EXPIRED: ' + queryname + ' ' + rcode + ' [' + str(hits) + '/' + str(hitsneeded) + ' hits]' + ' (TTL-EXPIRED:' + str(ttl) + '/' + str(orgttl) + ')')
        else:
            log_info('CACHE-EXPIRED: ' + queryname+ ' NODATA ' + ' (TTL-EXPIRED:' + str(orgttl) + ')')
        del_cache_entry(queryhash)
        return None

    # Pull/Fetch from cache
    else:
        reply = cacheentry[0]
        reply.header.id = tid

        # Update hits
        hits += 1
        cache[queryhash][3] = hits 
        
        # Gather address and non-address records and do round-robin
        if roundrobin and numrrs > 1:
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

        if numrrs == 0 and rcode == 'NOERROR':
            log_info('CACHE-HIT (' + str(hits) + '/' + str(hitsneeded) + ' hits) : Retrieved NODATA for ' + queryname + ' (TTL-LEFT:' + str(ttl) + '/' + str(orgttl) + ')')
        else:
            log_info('CACHE-HIT (' + str(hits) + '/' + str(hitsneeded) + ' hits) : Retrieved ' + str(numrrs) + ' RRs for ' + queryname + ' ' + rcode + ' (TTL-LEFT:' + str(ttl) + '/' + str(orgttl) + ')')

        log_replies(reply, 'CACHE-REPLY')

        return reply

    return None


def log_replies(reply, title):
    '''Log replies'''
    hid = id_str(reply.header.id)
    replycount = 0
    replynum = len(reply.rr)
    if replynum > 0:
        for record in reply.rr:
            replycount += 1
            rqname = normalize_dom(record.rname)
            rqtype = QTYPE[record.rtype].upper()
            data = normalize_dom(record.rdata)
            log_info(title + ' [' + hid + ':' + str(replycount) + '-' + str(replynum) + ']: ' + rqname + '/IN/' + rqtype + ' = ' + data)
    else:
        rqname = normalize_dom(reply.q.qname)
        rqtype = QTYPE[reply.q.qtype].upper()
        rcode = str(RCODE[reply.header.rcode])
        if rcode == 'NOERROR':
            rcode = 'NODATA'
        log_info(title + ' [' + hid + ']: ' + rqname + '/IN/' + rqtype + ' ' + rcode)

    return True


def in_cache(qname, qclass, qtype):
    '''Check if in cache'''
    if query_hash(qname, qclass, qtype) in cache:
        if debug: log_info('IN-CACHE-HIT: ' + qname + '/' + qclass + '/' + qtype)
        return True

    return False


def to_cache(qname, qclass, qtype, reply, force, newttl):
    '''Store into cache'''
    global cache_maintenance_now

    if nocache or reply == defaultlist or reply is None:
        return False

    if force is False and in_cache(qname, qclass, qtype):
        return True

    queryname = qname + '/' + qclass + '/' + qtype
    rcode = str(RCODE[reply.header.rcode])
    ttl = nottl

    if not newttl:
        newttl = in_domain(qname, ttls, 'TTL')
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


def cache_expired_list():
    '''get list of purgable items'''
    now = int(time.time())
    return list(dict((k, v) for k, v in cache.items() if v[1] - now < 1).keys()) or False


#def broken_exist():
#    '''Check if we have broken forwarders'''
#    if len(list(dict((k, v) for k, v in cache.items() if v[2].find('/BROKEN-FORWARDER/') > 0).keys())) > 0:
#        return True
#    return False


def no_noerror_list():
    '''Return all no-noerror list'''
    return list(dict((k, v) for k, v in cache.items() if v[0].header.rcode != 0).keys())


def cache_prefetch_list():
    '''Get list of prefetchable items'''
    now = int(time.time())
    # Formula: At least 2 cache-hits, hitrate > 0 and hits are above/equal hitrate
    # value list entries: 0:reply - 1:expire - 2:qname/class/type - 3:hits - 4:orgttl - 5:domainname
    return list(dict((k, v) for k, v in cache.items() if v[3] > 1 and int(round(v[4] / prefetchhitrate)) > 0 and v[1] - now <= int(round(v[4] / prefetchgettime)) and v[3] >= int((round(v[4] / prefetchhitrate)) - (round((v[1] - now) / prefetchhitrate)))).keys()) or False


def cache_dom_list(qclass, qtype):
    '''Get list of domains in cache'''
    newlist = set()
    for dom in list(cache.values()):
        cqname, cqclass, cqtype = dom[2].split('/')
        if cqclass == qclass and cqtype == qtype:
            newlist.add(cqname)

    return newlist


def cache_purge(flushall, olderthen, clist, plist):
    '''Purge cache'''
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
    elist = set()
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


def query_hash(qname, qclass, qtype):
    '''Query-hash for cache entries'''
    return hash(qname + '/' + qclass + '/' + qtype)


def add_cache_entry(qname, qclass, qtype, expire, ttl, reply):
    '''Add entry to cache'''
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


def del_cache_entry(queryhash):
    '''Remove entry from cache'''
    _ = cache.pop(queryhash, None)
    return True


def round_robin(l):
    '''Round-Robin cycle list'''
    return l[1:] + l[:1]


def id_str(number):
    '''Pad id/number to 5 positions'''
    return str(number).zfill(5)


def collapse_cname(request, reply, rid):
    '''Collapse CNAME's into Address-Records (A/AAAA)'''
    if filtering and reply.rr:
        firstqtype = QTYPE[reply.rr[0].rtype].upper()
        if firstqtype == 'CNAME':
            qname = normalize_dom(reply.rr[0].rname)
            ttl = reply.rr[0].ttl
            addr = set()
            for record in reply.rr[1:]:
                qtype = QTYPE[record.rtype].upper()
                if qtype in ('A', 'AAAA'):
                    ip = str(record.rdata).lower()
                    addr.add(ip)

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


def execute_command(qname, log):
    '''Execute commands'''
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


def seen_it(name, seen):
    '''Track if name already seen'''
    if name not in seen:
        seen.add(name)
    else:
        return True

    return False


def is_illegal(qname):
    '''Check if Illegal'''
    if blockillegal:
        # Filter when domain-name is not compliant
        if not isdomain.search(qname):
            return True

        # !!! Below length and label stuff already in isdomain regex

        # Filter if FQDN is too long
        #elif len(qname) > 252:
        #    return True

        # Filter if more domain-name contains more then 63 labels
        #elif all(len(x) < 64 for x in qname.split('.')) is False:
        #    return True

    return False


def is_weird(qname, qtype):
    '''Check if weird'''
    if blockweird:
        # PTR records do not comply with IP-Addresses
        if qtype == 'PTR' and (not ip4arpa.search(qname) and not ip6arpa.search(qname)):
            return True

        # Reverse-lookups are not PTR records
        elif qtype != 'PTR' and (ip4arpa.search(qname) or ip6arpa.search(qname)):
            return True

    return False


def do_query(request, handler, force):
    '''Main DNS resolution function'''
    rid = request.header.id
    tid = id_str(rid)

    cip = str(handler.client_address).split('\'')[1]

    use_tcp = False
    if handler.protocol == 'tcp':
        use_tcp = True

    qname = normalize_dom(request.q.qname)
    qclass = CLASS[request.q.qclass].upper()
    qtype = QTYPE[request.q.qtype].upper()

    queryname = qname + '/' + qclass + '/' + qtype

    log_info('REQUEST [' + tid + '] from ' + cip + ' for ' + queryname + ' (' + handler.protocol.upper() + ')')

    reply = None

    # Check ACL
    if ipregex.search(cip) and (cip not in allow_query4) and (cip not in allow_query6):
        log_info('ACL-HIT [' + tid + ']: Request from ' + cip + ' for ' + queryname + ' ' + aclrcode)
        reply = request.reply()
        reply.header.rcode = getattr(RCODE, aclrcode)

    # Execute Command
    if command and qname.endswith('.' + command):
        reply = request.reply()
        if cip in ('127.0.0.1', '::1'):
            if execute_command(qname, True):
                reply.header.rcode = getattr(RCODE, 'NOERROR')
            else:
                reply.header.rcode = getattr(RCODE, 'NOTIMP')
        else:
            reply.header.rcode = getattr(RCODE, 'REFUSED')


    # Quick response when in cache
    if reply is None and force is False:
        reply = from_cache(qname, qclass, qtype, rid)


    # Check if parent is in cache as NXDOMAIN
    if reply is None and force is False and blocksub and (in_domain(qname, wl_dom, 'Whitelist') is False):
        dom = in_domain(qname, cache_dom_list(qclass, qtype), 'Cache')
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

                    log_info('CACHE-PARENT-MATCH [' + tid + ']: \"' + qname + '\" matches parent \"' + dom + '\" ' + rcode)
                    log_info('REPLY [' + tid + ']: ' + queryname + ' = ' + rcode)
                    now = int(time.time())
                    expire = cacheentry[1]
                    parentttlleft = expire - now
                    to_cache(qname, qclass, qtype, reply, force, parentttlleft) # Cache it

    # More eleborated filtering on query
    if reply is None:
        queryfiltered = True

        # Filter if qtype = ANY, QCLASS is something else then "IN" and query-type is not supported
        if qtype == 'ANY' or qclass != 'IN' or (qtype not in ('A', 'AAAA', 'CNAME', 'MX', 'NS', 'PTR', 'SOA', 'SRV', 'TXT')):
            log_info('BLOCK-UNSUPPORTED-RRTYPE [' + tid + '] from ' + cip + ': ' + queryname + ' NOTIMP')
            reply = request.reply()
            reply.header.rcode = getattr(RCODE, 'NOTIMP')

        # Generate ALIAS response when hit
        elif filtering and in_domain(qname, aliases, 'Alias') and (not in_regex(qname, aliases_rx, True, 'Generator')) and (not in_domain(qname, forward_servers, 'Forward')):
            reply = generate_alias(request, qname, qtype, use_tcp, force)

        # Search-Domain blocker
        elif blocksearchdom and searchdom:
            for sdom in searchdom:
                if qname.endswith('.' + sdom):
                    dname = qname.rstrip('.' + sdom)
                    if in_cache(dname, 'IN', qtype):
                        log_info('SEARCH-HIT [' + tid + ']: \"' + qname + '\" matched \"' + dname + ' . ' + sdom + '\"')
                        reply = request.reply()
                        reply.header.rcode = getattr(RCODE, 'NOERROR') # Empty response, NXDOMAIN provides other search-requests
                        break

        # Get response and process filtering
        if reply is None:
            queryfiltered = False
            if filtering:
                # Make query anyway and check it after response instead of before sending query, response will be checked/filtered
                # Note: makes filtering based on DNSBL or other services responses possible
                if checkrequest is False:
                    log_info('UNFILTERED-QUERY [' + tid + ']: ' + queryname)
                    reply = dns_query(request, qname, qtype, use_tcp, rid, cip, True, True, force)
                else:
                    # Check against lists
                    generated = False
                    if not in_domain(qname, forward_servers, 'Forward'):
                        generated = in_regex(qname, aliases_rx, True, 'Generator')

                    if generated is False:
                        ismatch = match_blacklist(rid, 'REQUEST', qtype, qname, True)
                        if ismatch is True: # Blacklisted
                            reply = generate_response(request, qname, qtype, redirect_addrs, force)
                        elif ismatch is None and checkresponse: # Not listed
                            reply = dns_query(request, qname, qtype, use_tcp, rid, cip, True, True, force)
                        else: # Whitelisted
                            reply = dns_query(request, qname, qtype, use_tcp, rid, cip, False, True, force)
                    else: # Generated-Alias
                        queryfiltered = True
                        answer = False
                        rcode = generated.upper()
                        if rcode in ('NODATA','NXDOMAIN','REFUSED'):
                            log_info('GENERATED-HIT [' + tid + ']: \"' + qname + '/' + qtype + '\" -> \"' + rcode + '\"')
                            reply = request.reply()
                            if rcode == 'NODATA':
                                rcode = 'NOERROR'
                            reply.header.rcode = getattr(RCODE, rcode)

                        else:
                            if ipregex.search(generated):
                                if qtype == 'A' and ipregex4.search(generated):
                                    answer = RR(qname, QTYPE.A, ttl=filterttl, rdata=A(generated))
                                elif qtype == 'AAAA' and ipregex6.search(generated):
                                    answer = RR(qname, QTYPE.AAAA, ttl=filterttl, rdata=AAAA(generated))
                            elif isdomain.search(generated):
                                if qtype in ('A', 'AAAA', 'CNAME'):
                                    answer = RR(qname, QTYPE.CNAME, ttl=filterttl, rdata=CNAME(generated))
                                elif qtype == 'NS':
                                    answer = RR(qname, QTYPE.NS, ttl=filterttl, rdata=NS(generated))
                                elif qtype == 'PTR':
                                    answer = RR(qname, QTYPE.PTR, ttl=filterttl, rdata=PTR(generated))

                            if answer:
                                log_info('GENERATED-HIT [' + tid + ']: \"' + qname + '/' + qtype + '\" -> \"' + generated + '\"')
                                reply = request.reply()
                                reply.header.rcode = getattr(RCODE, 'NOERROR')
                                reply.add_answer(answer)

                            else:
                                log_err('GENERATED-ERROR [' + tid + ']: INVALID/UNSUPPORTED TYPE/DATA \"' + qname + '/' + qtype + '\" -> \"' + generated + '\"')
                                reply = request.reply()
                                reply.header.rcode = getattr(RCODE, 'NXDOMAIN')

            else: # Non-filtering
                reply = dns_query(request, qname, qtype, use_tcp, rid, cip, False, False, force)

        # Cache if REQUEST/Query is filtered
        if queryfiltered:
            #ttl = normalize_ttl(qname, reply.rr)
            to_cache(qname, 'IN', qtype, reply, force, filterttl)

    # Cleanup NOTIMP responses
    if reply and str(RCODE[reply.header.rcode]) == 'NOTIMP':
        reply.add_ar(EDNS0())

    if reply is None:
        log_err('REPLY-NONE [' + tid + '] from ' + cip + ' for ' + queryname)

    log_info('FINISHED [' + tid + '] from ' + cip + ' for ' + queryname)

    return reply


class DNS_Instigator(BaseResolver):
    '''DNS request/reply processing, main beef'''

    def resolve(self, request, handler):
        return do_query(request, handler, False)


def read_config(file):
    '''
    Read Config - USE WITH CAUTION DIRECTLY MODIFIES VARIABLES!!!
    THIS IS A HACK AND NEEDS TO BE BEAUTIFIED!!!!
    Basically every global variable used can be altered/configured:
    String: <varname> = '<value>'
    Number: <varname> = <value>
    Boolean: <varname> = <True|False>
    List: <varname> = <value1>,<value2>,<value3>, ...
    Dictionary (with list values): <varname> = <key> > <value1>,<value2>,<value3>, ...
    '''
    if file and file_exist(file, False):
        log_info('CONFIG: Loading config from config-file \"' + file + '\"')
        try:
            f = open(file, 'r')
            lines = f.readlines()
            f.close()

        except BaseException as err:
            log_err('ERROR: Unable to open/read/process file \"' + file + '\" - ' + str(err))

        for line in lines:
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

    else:
        log_info('CONFIG: Skipping config from file, config-file \"' + file + '\" does not exist')


    if blocksearchdom and file_exist(resolvfile, False):
        log_info('CONFIG: Loading domains from \"' + resolvfile + '\"')
        try:
            f = open(resolvfile)
            lines = f.readlines()
            f.close()

        except BaseException as err:
            log_err('ERROR: Unable to open/read/process file \"' + resolvfile + '\" - ' + str(err))

        for line in lines:
            entry = regex.split('#', line)[0].strip().lower()
            if len(entry) > 0:
                elements = regex.split('\s+', entry)
                if elements[0] == 'domain' or elements[0] == 'search':
                    for dom in elements[1:]:
                        if dom not in searchdom:
                            log_info('CONFIG: Fetched ' + elements[0] + ' \"' + dom + '\" from \"' + resolvfile + '\"')
                            searchdom.add(dom)

    return True


if __name__ == '__main__':
    '''Main beef'''
    log_info('-----------------------')
    log_info('Initializing INSTIGATOR')

    if debug: log_info('RUNNING INSTIGATOR IN *DEBUG* MODE')

    log_info('BASE-DIR: ' + basedir)

    read_config(configfile)

    # Load/Read lists
    loadcache = False
    if not load_lists(savefile):
        for lst in lists.keys():
            if lst in whitelist:
                wl_dom, wl_ip4, wl_ip6, wl_rx, aliases_rx, aliases, forward_servers, ttls, wl_asn = read_list(lists[lst], lst, 'Whitelist', wl_dom, wl_ip4, wl_ip6, wl_rx, aliases_rx, aliases, forward_servers, ttls, wl_asn)
            else:
                bl_dom, bl_ip4, bl_ip6, bl_rx, _, _, _, _, bl_asn = read_list(lists[lst], lst, 'Blacklist', bl_dom, bl_ip4, bl_ip6, bl_rx, dict(), dict(), dict(), dict(), bl_asn)

        # Load IPASN
        if ipasnfile:
            ipasn4, ipasn6 = load_asn(ipasnfile, ipasn4, ipasn6)

        # Whitelist used addresses to unbreak services
        for ip in redirect_addrs:
            ip = ip.split('@')[0]
            if ipregex.search(ip) and (ip not in wl_ip4) and (ip not in wl_ip6):
                log_info('WHITELIST: Added Redirect-Address \"' + ip + '\"')
                if ip.find(':') == -1:
                    wl_ip4[ip] = 'Redirect-Address'
                else:
                    wl_ip6[ip] = 'Redirect-Address'

        for dom in forward_servers.keys():
            if not in_domain(dom, wl_dom, 'Whitelist') and (dom != '.'):
                log_info('WHITELIST: Added Forward-Domain \"' + dom + '\"')
                wl_dom[dom] = 'Forward-Domain'
            for ip in forward_servers[dom]:
                if ipregex.search(ip) and (ip not in wl_ip4) and (ip not in wl_ip6):
                    log_info('WHITELIST: Added Forward-Address \"' + ip + '\"')
                    if ip.find(':') == -1:
                        wl_ip4[ip] = 'Forward-Address'
                    else:
                        wl_ip6[ip] = 'Forward-Address'

        for dom in aliases.keys():
            if not in_domain(dom, wl_dom, 'Whitelist') and (dom != '.'):
                log_info('WHITELIST: Added Alias-Domain \"' + dom + '\"')
                wl_dom[dom] = 'Alias-Domain'

        for dom in searchdom:
            if not in_domain(dom, wl_dom, 'Whitelist') and (dom != '.'):
                log_info('WHITELIST: Added Search-Domain \"' + dom + '\"')
                wl_dom[dom] = 'Search-Domain'

        save_lists(savefile)

    else:
        loadcache = True # Only load cache if savefile didn't change


    # Add command-tld to whitelist
    log_info('WHITELIST: Added Command-Domain \"' + command + '\"')
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
    if debug:
        logger = DNSLogger(log='-recv,-send,+request,+reply,+error,+truncated,+data', prefix=True)
    else:
        logger = DNSLogger(log='-recv,-send,-request,-reply,+error,+truncated,-data', prefix=True)

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

    # Save persistent cache
    save_cache(cachefile)

    log_info('INSTIGATOR EXIT')
    log_info('---------------')
    sys.exit(0)

# <EOF>
