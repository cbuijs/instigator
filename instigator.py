#!/usr/bin/env python3
# Needs Python 3.5 or newer!
'''
=========================================================================================
 instigator.py: v6.44-20181107 Copyright (C) 2018 Chris Buijs <cbuijs@chrisbuijs.com>
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
- Better Documentation / Remarks / Comments. Status: Ongoing.
- Optimize code for better cache/resolution performance. Status: Ongoing.
- Cleanup code and optimize. Some of it is hacky-quick-code. Status: Ongoing.
- Switch to dnspython or more modern lib as DNS 'engine'. Status: Backburner.
- DNSSEC support (validation only), like DNSMasq. Status: Backburner, see dnspython.
- Itterative resolution besides only forwarding (as is today). Status: Backburner.
- Add more security-features against hammering, dns-drip, ddos, etc. Status: Backburner.
- Fix SYSLOG on MacOS. Status: To-be-done.
- Redo randomness blocking

=========================================================================================
'''

# Standard modules
import os, time, shelve, dbm, gc # DBM used for Shelve
gc.enable() # Enable garbage collection

# sys module and path, adapt for your system. Below if for Debian 9.5 Stable
import sys
sys.path.append('/usr/local/lib/python3.5/dist-packages/')

# Random
import random
random.seed(os.urandom(256))

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

# Use cymruwhois for SafeDNS ASN lookups
from cymruwhois import Client

# Use zxcvbn to determine guessability. The harder, it probably is more random. To catch DGA.
#from zxcvbn import zxcvbn
#from zxcvbn.matching import add_frequency_lists

# Simple caches
from cachetools import TTLCache

# Use module PyTricia for CIDR/Subnet stuff
import pytricia

###################

# Debugging
debug = False
if sys.argv[1:]: # Any argument on command-line will put debug-mode on, printing all messages to TTY.
    debug = True

# Logging Message-length
msglength = 1024

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
# See list of servers here: https://www.lifewire.com/free-and-public-dns-servers-2626062
forward_timeout = 5 # Seconds, keep on 5 seconds or higher
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
defaultlist = list([None, 0, '', 0, 0, '']) # reply - expire - qname/class/type - hits - orgttl - comment
lists = OrderedDict()

lists['blacklist'] = basedir + 'black.list' # Blacklist
lists['whitelist'] = basedir + 'white.list' # Whitelist
lists['aliases'] = basedir + 'aliases.list' # Aliases/Forwards/TTLS/etc
lists['malicious-ip'] = basedir + 'malicious-ip.list' # Bad IP's
lists['tlds'] = basedir + 'tlds.list' # Allowed TLD's, negated regex-list, generates NXDOMAIN for none IANA TLD's
lists['nat'] = basedir + 'nat-reflect.list' # Handout local IP's for public names hosted locally

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
whitelist = list(['whitelist', 'aliases', 'shalla-banking', 'shalla-updatesites', 'tlds', 'nat'])
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

# Always load/process lists fully
alwaysfresh = False

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
checkrequest = True # When False, only responses are checked and queries are ignored (passthru)

# Check responses/answers
checkresponse = True # When False, only queries are checked and responses are ignored (passthru)

# Logging
logreplies = True # Improves response times a little bit when False

# Minimal Responses
minresp = True

# Minimum/Maximum number of dots in a domain-name
mindots = 1
maxdots = 32

# Roundrobin of address/forward-records
roundrobin = True
forwardroundrobin = True

# Collapse/Flatten CNAME Chains
collapse = True

# Block IPV4 or IPv6 based queries, True = Block, False = NotBlock and None = Based on transport
blockv4 = False
blockv6 = None

# Block illegal names
blockillegal = True

# Block weird
blockweird = True

# Block subdomains for NODATA, NXDOMAIN, REFUSED and SERVFAIL rcodes received for parent
blocksub = True

# Block queries in search-domains (from /etc/resolv.conf) if entry already exist in cache without searchdomain
blocksearchdom = True

# Block randomized domains
#blockrandom = True
#blockrandommononly = True
#random_threshhold = 42

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
prefetching_busy = False # Gobal Flag, don't change!
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
#indom_cache = dict() # Cache results of domain hits
#inrx_cache = dict() # Cache result of regex hits
#match_cache = dict() # Cache results of match_blacklist
#random_cache = dict() # cache results of randomness-calculations
indom_cache = TTLCache(cachesize * 4, filterttl)
inrx_cache = TTLCache(cachesize * 4, filterttl)
match_cache = TTLCache(cachesize * 4, filterttl)
notlisted = TTLCache(cachesize * 4, filterttl)
#random_cache = TTLCache(cachesize * 4, filterttl)

# List status match_cache
list_status = dict()
list_status[True] = 'BLACKLISTED'
list_status[False] = 'WHITELISTED'
list_status[None] = 'NOTLISTED'
list_status['NOTCACHED'] = 'NOTCACHED'

# Cache
cache = dict() # DNS cache

# Pending IDs
pending = dict() # Pending queries

# Broken forwarders flag
broken_exist = False # Global flag, don't change!

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
ip4arpa_text = '([0-9]{1,3}\.){4}in-addr'
ip6arpa_text = '([0-9a-f]\.){32}ip6'
ip4arpa = regex.compile('^' + ip4arpa_text + '\.arpa$', regex.I)
ip6arpa = regex.compile('^' + ip6arpa_text + '\.arpa$', regex.I)
iparpa = regex.compile('^(' + ip4arpa_text + '|' + ip6arpa_text + ')\.arpa$', regex.I)

# Regex to match domains/hosts in lists
isdomain = regex.compile('(?=^.{1,252}[a-z]$)(^((?!-)[a-z0-9_-]{0,62}[a-z0-9]\.)*(xn--[a-z0-9-]{1,59}|[a-z]{2,63})$)', regex.I)

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
        print('{0} {1}'.format(time.strftime('%Y-%m-%d %H:%M:%S'), message)[:msglength])
        sys.stdout.flush()
    syslog.syslog(syslog.LOG_INFO, message[:msglength]) # !!! Fix SYSLOG on MacOS
    return True


def log_err(message):
    '''Log ERR messages to syslog'''
    message = '!!! STRESS: {0}'.format(message)
    if debug:
        #print('{0} {1}'.format(time.strftime('%a %d-%b-%Y %H:%M:%S'), message))
        print('{0} {1}'.format(time.strftime('%Y-%m-%d %H:%M:%S'), message)[:msglength])
        sys.stdout.flush()
    syslog.syslog(syslog.LOG_ERR, message[:msglength]) # !!! Fix SYSLOG on MacOS
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
                    if debug: log_info('FILE-EXIST: {0} = {1} seconds old'.format(file, age))
                    return age
                else:
                    if debug: log_info('FILE-EXIST: {0} is zero size'.format(file))

        except BaseException as err:
            log_err('FILE-EXIST-ERROR: {0}'.format(err))
            return False

    return False


def make_dirs(subdir):
    '''Make directory-structures'''
    try:
        os.makedirs(subdir)
    except BaseException:
        pass

    return True


def match_blacklist(rid, rtype, rrtype, value):
    '''Check lists/cache'''
    # When reply, only check Requests or RRTypes that have a data-field ending in an IP or Domain-name
    if value != '.' and (rtype == 'REQUEST' or (rtype == 'REPLY' and rrtype in ('A', 'AAAA', 'CNAME', 'MX', 'NS', 'PTR', 'SRV'))):
        tag = 'MATCH-FROM-CACHE'
        cachekey = hash(value + '/' + rrtype)
        result = match_cache.get(cachekey, 'NOTCACHED')
        if result == 'NOTCACHED':
            result = check_blacklist(rid, rtype, rrtype, value)
            if nocache is False:
                tag = 'MATCH-TO-CACHE'
                match_cache[cachekey] = result
            else:
                tag = 'MATCH-NO-CACHE'

    else:
        tag = 'MATCH-NO-CACHE'
        result = None

    #if debug:
    log_info('{0} [{1}]: {2} {3}/{4} = {5}'.format(tag, id_str(rid), rtype, value, rrtype, list_status.get(result, 'NOTLISTED')))

    return result


def check_blacklist(rid, rtype, rrtype, value):
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


    # Block IP-Family
    if blockv4 is not False and (rrtype == 'A' or (rtype == 'REQUEST' and rrtype == 'PTR' and ip4arpa.search(testvalue))):
        log_info('BLOCK-IPV4-HIT [{0}]: {1} \"{2}/{3}\"'.format(tid, rtype, value, rrtype))
        return True

    if blockv6 is not False and (rrtype == 'AAAA' or (rtype == 'REQUEST' and rrtype == 'PTR' and ip6arpa.search(testvalue))):
        log_info('BLOCK-IPV6-HIT [{0}]: {1} \"{2}/{3}\"'.format(tid, rtype, value, rrtype))
        return True


    # Check if an REVDOM/IP
    if rtype == 'REQUEST' and rrtype == 'PTR' and iparpa.search(testvalue):
        if not in_domain(testvalue, wl_dom, 'Whitelist', False):
            if not in_domain(testvalue, bl_dom, 'Blacklist', False):
                ip = False
                if ip4arpa.search(testvalue):
                    ip = '.'.join(testvalue.split('.')[0:4][::-1]) # IPv4
                elif ip6arpa.search(testvalue):
                    ip = ':'.join(filter(None, regex.split('(.{4,4})', ''.join(testvalue.split('.')[0:32][::-1])))) # IPv6

                if ip:
                    # Test IP further on as revdom is not listed
                    log_info('MATCHING [{0}]: Matching against IP \"{1}\" instead of domain \"{2}\"'.format(tid, ip, testvalue))
                    itisanip = True
                    testvalue = ip

            else:
                return True # Blacklisted
        else:
            return False # Whitelisted

    elif rtype == 'REPLY':
        if rrtype in ('A', 'AAAA'):
            itisanip = True
        elif testvalue.count(' ') > 0:
            testvalue = regex.split('\s+', testvalue)[-1] # Take last field as domain-name
            log_info('MATCHING [{0}]: Matching against \"{1}\" of \"{2}\" ({3})'.format(tid, testvalue, value, rrtype))


    # Check domain-name validity
    if not itisanip:
        testvalue = normalize_dom(regex.split('\s+', testvalue)[-1]) # If RRType has multiple values in data, take last one
        if testvalue.count('.') < mindots:
            log_info('BLOCK-MINDOTS-HIT [{0}]: {1} ({2}<{3})'.format(tid, value, testvalue.count('.'), mindots))
            return True
        elif testvalue.count('.') > maxdots:
            log_info('BLOCK-MAXDOTS-HIT [{0}]: {1} ({2}>{3})'.format(tid, value, testvalue.count('.'), maxdots))
            return True
        elif is_illegal(rtype, testvalue, rrtype):
            log_err('BLOCK-ILLEGAL-HIT [{0}]: {1}'.format(tid, value))
            return True
        elif is_weird(rtype, testvalue, rrtype):
            log_info('BLOCK-WEIRD-HIT [{0}]: {1}/{2}'.format(tid, value, rrtype))
            return True
        #elif blockrandom and (not in_domain(testvalue, wl_dom, 'Whitelist', False)):
        #    score = randomness(testvalue)
        #    if blockrandommononly is False and score > random_threshhold: # !!! TEST VALUE BASED ON AVERAGE USE, CHECK THIS !!!
        #        log_info('BLOCK-RANDOMNESS-HIT [{0}]: {1} ({2}>{3})'.format(tid, value, score, random_threshold))
        #        return True


    # Check against IP-Lists
    if itisanip:
        asn, prefix, owner = who_is(testvalue, '[' + tid + '] ' + rtype)
        if asn != '0':
            if asn in wl_asn: # Whitelist
                log_info('WHITELIST-ASN-HIT [{0}]: {1} {2}/{3} matched against \"AS{4}\" ({5}/{6}) - {7}'.format(tid, rtype, value, testvalue, asn, wl_asn[asn], prefix, owner))
                return False
            elif asn in bl_asn: # Blacklist
                log_info('BLACKLIST-ASN-HIT [{0}]: {1} {2}/{3} matched against \"AS{4}\" ({5}/{6}) - {7}'.format(tid, rtype, value, testvalue, asn, wl_asn[asn], prefix, owner))
                return True

        if is_v6(testvalue):
            wip = wl_ip6
            bip = bl_ip6
        else:
            wip = wl_ip4
            bip = bl_ip4

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
            log_info('BLACKLIST-IP-HIT [{0}]: {1} {2} matched against {3} ({4})'.format(tid, rtype, testvalue, prefix, bip[prefix]))
            return True
        elif prefix:
            log_info('WHITELIST-IP-HIT [{0}]: {1} {2} matched against {3} ({4})'.format(tid, rtype, testvalue, prefix, wip[prefix]))
            return False


    # Check against Sub-Domain-Lists
    elif itisanip is False and testvalue.find('.') > 0 and isdomain.search(testvalue):
        for testvalue in (value + '!', value):
            if testvalue.endswith('!'):
                tag = 'FORCED-HIT'
                listname = 'list!'
            else:
                tag = 'HIT'
                listname = 'list'

            wl_found = in_domain(testvalue, wl_dom, 'White' + listname, False) # Whitelist
            if wl_found is not False:
                log_info('WHITELIST-{0} [{1}]: {2} \"{3}\" matched against \"{4}\" ({5})'.format(tag, tid, rtype, value, wl_found, wl_dom[wl_found]))
                return False
            else:
                bl_found = in_domain(testvalue, bl_dom, 'Black' + listname, False) # Blacklist
                if bl_found is not False:
                    log_info('BLACKLIST-{0} [{1}]: {2} \"{3}\" matched against \"{4}\" ({5})'.format(tag, tid, rtype, value, bl_found, bl_dom[bl_found]))
                    return True


    # If it is not an IP, check validity and against regex
    if itisanip is False:
        # Catchall: Check agains Regex-Lists
        rxfound = in_regex(value, wl_rx, False, 'Whitelist') # Whitelist
        if rxfound:
            log_info('WHITELIST-REGEX-HIT [{0}]: {1} \"{2}\" matched against {3}'.format(tid, rtype, value, rxfound))
            return False

        rxfound = in_regex(value, bl_rx, False, 'Blacklist') # Blacklist
        if rxfound:
            log_info('BLACKLIST-REGEX-HIT [{0}]: {1} \"{2}\" matched against {3}'.format(tid, rtype, value, rxfound))
            return True

    # No hits
    if debug: log_info('NONE-HIT [{0}]: {1} \"{2}\" does not match against any lists'.format(tid, rtype, value))

    return None


#def randomness(testvalue):
#    '''Calculates the Shannon entropy of a string'''
#    if testvalue and (not ipregex.search(testvalue)) and (not iparpa.search(testvalue)):
#        score = random_cache.get(testvalue, False)
#        if score is False:
#            prob = [ float(testvalue.count(c)) / len(testvalue) for c in dict.fromkeys(list(testvalue)) ]
#            score = - sum([ p * math.log(p) / math.log(2.0) for p in prob ])
#
#            random_cache[testvalue] = score
#
#            if debug: log_info('RANDOMNESS-TO-CACHE: {0} = {1}'.format(testvalue, score))
#        else:
#            if debug: log_info('RANDOMNESS-FROM-CACHE: {0} = {1}'.format(testvalue, score))
#
#    else:
#        score = 0
#
#    return score


#def randomness(testvalue):
#    '''Calculate randomness'''
#    if testvalue and (not ipregex.search(testvalue)) and (not iparpa.search(testvalue)):
#        score = random_cache.get(testvalue, False)
#        if score is False:
#            words = regex.split('[\._-]', testvalue)
#            totscore = 0
#            for word in words:
#                if word[2:] and (not isnum.search(word)):
#                    randomnessscore = zxcvbn(testvalue)
#                    totscore += int(round(randomnessscore['guesses_log10'])) # The higher, the more random
#            score = int(round(totscore / len(words)))
#            random_cache[testvalue] = score
#            if debug: log_info('RANDOMNESS-TO-CACHE: {0} = {1}'.format(testvalue, score))
#        else:
#            if debug: log_info('RANDOMNESS-FROM-CACHE: {0} = {1}'.format(testvalue, score))
#    else:
#        score = 0
#
#    return score


def in_domain(name, domlist, domid, checksub):
    '''Check if name is domain or sub-domain'''
    domidname = domid + ':' + name
    if nocache is False:
        indom = indom_cache.get(domidname, None)
        if indom is not None:
            if indom is True:
                if debug: log_info('INDOM-CACHE [{0}]: \"{1}\" in \"{2}\"'.format(domid, name, indom))
            else:
                if debug: log_info('INDOM-CACHE [{0}]: \"{1}\" is NOMATCH'.format(domid, name))
            return indom

    if checksub:
        testname = name[name.find('.') + 1:]
    else:
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
    if nocache is False:
        inrx = inrx_cache.get(rxidname, None)
        if inrx is not None:
            if inrx:
                if isalias:
                    if debug: log_info('INRX-CACHE [{0}]: \"{1}\" -> \"{2}\"'.format(rxid, name, inrx))
                else:
                    if debug: log_info('INRX-CACHE [{0}]: \"{1}\" matched with \"{2}\"'.format(rxid, name, inrx))

            return inrx

    #if any(rx.search(name) for rx in rxlist.values()):
    #    return '!!!TEST!!! FOUND IT !!!TEST!!!'
    #else:
    #    return False

    if name and name != '.':
        #for i in rxlist.keys():
        for i in rxlist:
            rx = rxlist.get(i, False)
            if rx and rx.search(name): # and (not in_domain(name, forward_servers, 'Forward', False)):
                elements = regex.split(':\s+', i)
                lst = elements[0]
                rx2 = ' '.join(elements[1:])
                result = False
                if isalias:
                    rx3 = regex.split('\s+', rx2)[0]
                    result = regex.sub(rx, rx3, name)
                    log_info('GENERATOR-MATCH [{0}]: {1} matches \"{2}\" = \"{3}\" -> \"{4}\"'.format(lst, name, rx.pattern, rx3, result))
                else:
                    result = '\"' + rx2 + '\" (' + lst + ')'
                    if debug: log_info('REGEX-MATCH [{0}]: {1} matches {2}'.format(lst, name, result))

                inrx_cache[rxidname] = result

                return result

    inrx_cache[rxidname] = False
    return False


def who_is(ip, desc):
    '''Whois lookup'''
    asn = '0'
    owner = 'UNKNOWN'

    if is_v6(ip):
        ipasn = ipasn6
        prefix = ip + '/128'
    else:
        ipasn = ipasn4
        prefix = ip + '/32'

    if ip in ipasn:
        prefix = ipasn.get_key(ip)
        elements = regex.split('\s+', ipasn.get(prefix, asn + ' ' + owner))
        if elements:
            asn = elements[0]
            owner = ' '.join(elements[1:])
            if debug: log_info('WHOIS-CACHE-HIT: {0} {1} AS{2} ({3}) - {4}'.format(desc, ip, asn, prefix, owner))

    else:
        log_info('WHOIS-LOOKUP: {0} {1}'.format(desc, ip))
        try:
            whois = Client()
            lookup = whois.lookup(ip)
            asn = str(lookup.asn)
        except BaseException as err:
            log_err('WHOIS-ERROR: {0} {1} - {2}'.format(desc, ip, err))
            asn = 'NONE'

        if asn != 'NONE' and asn != '' and asn != 'NA' and asn is not None:
            prefix = str(lookup.prefix)
            owner = str(lookup.owner).upper()
            log_info('WHOIS-RESULT: {0} {1} AS{2} ({3}) - {4}'.format(desc, ip, asn, prefix, owner))
        else:
            asn = '0'
            log_info('WHOIS-UNKNOWN: {0}'.format(ip))

        ipasn[prefix] = asn + ' ' + owner

    return asn, prefix, owner


def dns_query(request, qname, qtype, use_tcp, tid, cip, checkbl, force):
    '''Do query'''
    global broken_exist

    queryname = qname + '/IN/' + qtype
    hid = id_str(tid)

    tag = ''
    if not ipregex.search(cip):
        tag = ' (' + cip + ')'

    #if debug and checkbl: queryname = 'BL:' + queryname
    #if debug and force: queryname = 'F:' + queryname

    # Process already pending/same query
    uid = hash(qname + '/' + qtype + '/' + cip + '/' + str(tid))
    count = 0
    while uid in pending:
        count += 1
        if count > 2: # Disembark after 3 seconds
            log_info('DNS-QUERY [{0}]: Skipping query for {1} - ID \"{2}\" already processing, takes more then 3 seconds{3}'.format(hid, queryname, hid, tag))
            return rc_reply(request, 'SERVFAIL')

        log_info('DNS-QUERY [{0}]: Delaying ({1}) query for {2} - ID \"{3}\" already in progress, waiting to finish{4}'.format(hid, count, queryname, hid, tag))
        time.sleep(1) # Seconds

    # Get from cache if any, only hit when doing internal/alias queries
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

    server = in_domain(qname, forward_servers, 'Forward', False)
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
            log_info('SAFEDNS-QUERY [{0}]: Forwarding query from {1} to all forwarders for {2}{3}'.format(hid, cip, queryname, tag))

        for addr in addrs:
            forward_address = addr.split('@')[0]
            if addr.find('@') > 0:
                forward_port = int(addr.split('@')[1])
            else:
                forward_port = 53

            if forward_port != 53:
                if debug: log_info('DNS-TCP: Using TCP because port is not 53 ({0})'.format(forward_port))
                tcp_use = True
            else:
                tcp_use = use_tcp

            if not in_cache(forward_address, 'BROKEN-FORWARDER', str(forward_port)):
                if not safedns:
                    log_info('DNS-QUERY [{0}]: Forwarding query from {1} to {2}@{3} ({4}) for {5}{6}'.format(hid, cip, forward_address, forward_port, servername, queryname, tag))

                useip6 = is_v6(forward_address)

                error = 'UNKNOWN-ERROR'
                success = True

                reply = None

                try:
                    #qstart = time.time()
                    q = query.send(forward_address, forward_port, tcp=tcp_use, timeout=forward_timeout, ipv6=useip6)
                    reply = DNSRecord.parse(q)
                    #qend = time.time()
                    #if debug: log_info('DNS-RTT [' + hid + ']: ' + str(qend - qstart) + ' seconds' + tag)

                except BaseException as err:
                    error = err
                    success = False

                if success is True:
                    rcode = str(RCODE[reply.header.rcode])
                    error = rcode
                    if rcode != 'SERVFAIL':
                        if rcode != 'NOERROR' and firstreply is None and reply.auth:
                            for record in reply.auth:
                                if QTYPE[record.rtype] == 'SOA':
                                    soadom = regex.split('\s+', str(record))[0].strip('.') or '.'
                                    if soadom != '.':
                                        rcttl = normalize_ttl(qname, reply.auth)
                                        if rcttl:
                                            log_info('SOA-TTL [{0}]: Taking TTL={1} of SOA \"{2}\" for {3} {4}{5}'.format(hid, rcttl, soadom, queryname, rcode, tag))
                                    break

                        else:
                            if firstreply is None:
                                _ = normalize_ttl(qname, reply.rr)

                        if safedns:
                            if firstreply is None:
                                firstreply = reply

                            if reply.rr:
                                for record in reply.rr:
                                    rqtype = QTYPE[record.rtype]
                                    if rqtype in ('A', 'AAAA'):
                                        ip = str(record.rdata)
                                        if ip not in ipstack:
                                            ipstack.add(ip)
                                            asn, prefix, owner = who_is(ip, queryname)
                                            if asnstack and asn in asnstack:
                                                if debug: log_info('SAFEDNS [{0}]: {1} found same ASN ({2}) \"{3}\" ({4}) for {5} ({6}) from {7}{8}'.format(hid, queryname, len(asnstack), asn, owner, ip, prefix, forward_address, tag))
                                            elif asn != '0':
                                                asnstack.add(asn)
                                                if debug: log_info('SAFEDNS [{0}]: {1} found new ASN ({2}) \"{3}\" ({4}) for {5} ({6}) from {7}{8}'.format(hid, queryname, len(asnstack), asn, owner, ip, prefix, forward_address, tag))
                                            else:
                                                if debug: log_info('SAFEDNS [{0}]: {1} UNKNOWN ASN for {2} from {3}{4}'.format(hid, queryname, ip, forward_address, tag))

                        else:
                            break

                    else:
                        success = False

                if success is False or reply is None:
                    log_err('DNS-QUERY [{0}]: ERROR Resolving {1} using {2}@{3} - {4}{5}'.format(hid, queryname, forward_address, forward_port, error, tag))
                    if error != 'SERVFAIL':
                        broken_exist = True
                        to_cache(forward_address, 'BROKEN-FORWARDER', str(forward_port), request.reply(), force, retryttl, 'ERROR' + tag)

            #if debug and safedns is False: log_info('DNS-QUERY [' + hid + ']: Skipped broken/invalid forwarder ' + forward_address + '@' + str(forward_port) + tag)
            if debug and safedns is False: log_info('DNS-QUERY [{0}]: Skipped broken/invalid forwarder {1}@{2}{3}'.format(hid, forward_address, forward_port, tag))

    else:
        log_err('DNS-QUERY [{0}]: ERROR Resolving {1} ({2}) - NO DNS SERVERS AVAILBLE!{3}'.format(hid, queryname, servername, tag))


    if safedns and firstreply is not None and asnstack:
        reply = firstreply
        astack = ', '.join(sorted(asnstack, key=int))
        alen = len(asnstack)
        if alen > 1:
            ratio = int(100 / alen)
            if ratio < safednsratio:
                if not safednsmononly:
                    reply = False

                log_info('SAFEDNS [{0}]: {1} UNSAFE! Multiple ASNs (Ratio {2}% < {3}%) ASNs ({4}): {5}{6}'.format(hid, queryname, ratio, safednsratio, alen, astack, tag))
        else:
            log_info('SAFEDNS [{0}]: {1} is SAFE (Ratio: 100% >= {2}%) ASN: {3}{4}'.format(hid, queryname, safednsratio, astack, tag))


    # No response or SafeDNS interception
    if reply is None or reply is False:
        #cache.clear()
        if reply is False: # SafeDNS catch
            log_err('DNS-QUERY [{0}]: SAFEDNS Block {1} {2}{3}'.format(hid, queryname, hitrcode, tag))
            reply = rc_reply(query, hitrcode)
        else: # Regurlar error
            log_err('DNS-QUERY [{0}]: ERROR Resolving {1} SERVFAIL{2}'.format(hid, queryname, tag))
            reply = rc_reply(query, 'SERVFAIL')

        reply.header.id = tid

        _ = pending.pop(uid, None)

        return reply

    # Clear broken-forwarder cache entries
    elif broken_exist:
        broken_exist = False
        for queryhash in no_noerror_list():
            record = cache.get(queryhash, None)
            if record is not None:
                rcode = str(RCODE[record[0].header.rcode])
                log_info('CACHE-MAINT-PURGE: {0} {1} (Unbroken DNS Servers){2}'.format(record[2], rcode, tag))
                del_cache_entry(queryhash)

    blockit = False

    # Lets process response
    rcode = str(RCODE[reply.header.rcode])
    if rcode == 'NOERROR':
        if checkbl and reply.rr:
            replycount = 0
            replynum = len(reply.rr)
            matched = set()

            for record in reply.rr:
                replycount += 1

                rqname = normalize_dom(record.rname)
                rqtype = QTYPE[record.rtype].upper()
                data = normalize_dom(record.rdata)

                nid = hid + ':' + str(replycount) + '-' + str(replynum)

                if replycount > 1: # Query-part of first RR in RRSET set already checked
                    if rqname not in matched:
                        matchreq = match_blacklist(tid, 'CHAIN', rqtype, rqname)
                        if matchreq is False:
                            break
                        elif matchreq is True:
                            blockit = True
                        else:
                            matched.add(rqname)
                    else:
                        if debug: log_info('REPLY-MATCHED-QNAME-SKIP [{0}]: {1}/IN/{2}{3}'.format(nid, rqname, rqtype, tag))
                else:
                    if debug: log_info('REPLY-FIRST-QNAME-SKIP [{0}]: {1}/IN/{2}{3}'.format(nid, rqname, rqtype, tag))
                    matched.add(rqname)

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
                            log_info('REBIND-BLOCK [{0}]: {1}/IN/{2} = {3} matches {4} ({5}){6}'.format(nid, rqname, rqtype, data, prefix, desc, tag))
                        else:
                            log_info('REBIND-ALLOW [{0}]: {1}/IN/{2} = {3} (DNS Server in REBIND ranges){4}'.format(nid, rqname, rqtype, data, tag))

                    if blockit is False:
                        matchrep = match_blacklist(tid, 'REPLY', rqtype, data)
                        if matchrep is False:
                            break
                        elif matchrep is True:
                            blockit = True

                if blockit:
                    log_info('REPLY [{0}]: {1}/IN/{2} = {3} BLACKLIST-HIT{4}'.format(nid, rqname, rqtype, data, tag))
                    reply = generate_response(request, qname, qtype, redirect_addrs, force, 'REPLY-BLACKLISTED' + tag)
                    break

                #else:
                #    log_info('REPLY [{0}]: {1}/IN/{2} = {3} NOERROR{4}'.format(nid, rqname, rqtype, data, tag))


    else:
        reply = rc_reply(request, rcode)
        log_info('RCODE-REPLY [{0}]: {1} = {2}{3}'.format(hid, queryname, rcode, tag))


    # Match up ID
    reply.header.id = tid

    # Log replies
    log_replies(reply, 'FETCHED-REPLY')

    # Collapse CNAME
    if collapse:
        reply = collapse_cname(request, reply, tid)

    # Minimum responses
    if minresp:
        reply.auth = list()
        reply.ar = list()

    # Stash in cache
    if blockit:
        ttl = filterttl
    elif rcttl:
        ttl = rcttl
    else:
        ttl = False

    if blockit is False:
        to_cache(qname, 'IN', qtype, reply, force, ttl, 'OK' + tag)

    # Pop from pending
    _ = pending.pop(uid, None)

    return reply


def num_rrs(reply):
    '''Count number of RR's'''
    numrrs = len(reply.rr) + len(reply.auth) + len(reply.ar) or 0
    return numrrs


def generate_response(request, qname, qtype, redirect_addrs, force, comment):
    '''Generate response when blocking'''
    queryname = qname + '/IN/' + qtype

    hid = id_str(request.header.id)

    if redirect_addrs and (qtype not in ('ANY', 'TXT')) and any(x.upper() in ('NODATA', 'NXDOMAIN', 'REFUSED') for x in redirect_addrs):
        for addr in redirect_addrs:
            if addr.upper() in ('NODATA', 'NXDOMAIN', 'REFUSED'):
                log_info('GENERATE [{0}]: {1} for {2}'.format(hid, addr, queryname))
                reply = rc_reply(request, addr.upper())
                break

    elif (not redirect_addrs) or (qtype not in ('ANY', 'A', 'AAAA', 'CNAME', 'MX', 'NS', 'SRV', 'TXT')):
        log_info('GENERATE [{0}]: {1} for {2}'.format(hid, hitrcode, queryname))
        reply = rc_reply(request, hitrcode)

    else:
        reply = rc_reply(request, 'NOERROR')
        addanswer = set()
        if qtype in ('ANY', 'TXT'):
            answer = RR(qname, QTYPE.TXT, ttl=filterttl, rdata=TXT('BLACKLISTED'))
            addanswer.add('BLACKLISTED!')
            answer.set_rname(request.q.qname)
            reply.add_answer(answer)

        for addr in redirect_addrs:
            answer = None
            if addr.count('.') > 0 or addr.count(':') > 0:
                if qtype in ('ANY', 'A', 'CNAME') and ipregex4.search(addr):
                    answer = RR(qname, QTYPE.A, ttl=filterttl, rdata=A(addr))
                elif qtype in ('ANY', 'AAAA', 'CNAME') and ipregex6.search(addr):
                    answer = RR(qname, QTYPE.AAAA, ttl=filterttl, rdata=AAAA(addr))
                elif not ipregex.search(addr):
                    if qtype == 'PTR':
                        answer = RR(qname, QTYPE.PTR, ttl=filterttl, rdata=PTR(addr))
                    elif qtype == 'MX':
                        answer = RR(qname, QTYPE.MX, ttl=filterttl, rdata=MX(addr, 10))
                    elif qtype == 'NS':
                        answer = RR(qname, QTYPE.NS, ttl=filterttl, rdata=NS(addr))
                    elif qtype == 'SRV':
                        answer = RR(qname, QTYPE.SRV, ttl=filterttl, rdata=SRV(0, 0, 80, addr))
                    elif qtype in ('ANY', 'A', 'AAAA', 'CNAME'):
                        answer = RR(qname, QTYPE.CNAME, ttl=filterttl, rdata=CNAME(addr))

                if answer is not None:
                    addanswer.add(addr)
                    answer.set_rname(request.q.qname)
                    reply.add_answer(answer)

        log_replies(reply, 'GENERATE-REPLY')

        if addanswer:
            log_info('GENERATE [{0}]: REDIRECT/NOERROR for {1} -> {2}'.format(hid, queryname, ', '.join(addanswer)))
        else:
            reply = rc_reply(request, hitrcode)
            log_info('GENERATE [{0}]: {1} for {2}'.format(hid, hitrcode, queryname))

    to_cache(qname, 'IN', qtype, reply, force, filterttl, comment)

    return reply


def generate_alias(request, qname, qtype, use_tcp, force, newalias):
    '''Generate alias response'''
    queryname = qname + '/IN/' + qtype

    realqname = normalize_dom(request.q.qname)

    reply = rc_reply(request, 'NOERROR')

    reply.header.id = request.header.id

    hid = id_str(reply.header.id)

    if newalias is False:
        tag = 'ALIAS-HIT'
        if qname in aliases:
            alias = aliases[qname]
        else:
            aqname = in_domain(qname, aliases, 'Alias', False)
            if aqname:
                log_info('{0} [{1}]: {2} subdomain of alias \"{3}\"'.format(tag, hid, qname, aqname))
                alias = aliases[aqname]
            else:
                #alias = 'NXDOMAIN'
                return None
    else:
        tag = 'GENERATED-ALIAS-HIT'
        alias = newalias

    israndom = False

    if alias.upper() == 'PASSTHRU':
        log_info('{0} [{1}]: {2} = PASSTHRU'.format(tag, hid, queryname))
        alias = qname

    elif alias.upper() == 'RANDOM':
        if (collapse and qtype == 'CNAME') or qtype == 'A':
            alias = str(random.randint(0, 255)) + '.' + str(random.randint(0, 255)) + '.' + str(random.randint(0, 255)) + '.' + str(random.randint(0, 255))
        elif qtype == 'AAAA':
            alias = ':'.join(filter(None, regex.split('(.{4,4})', ''.join([random.choice('0123456789abcdef') for _ in range(32)]))))
        elif not collapse and qtype == 'CNAME':
            alias = regex.sub('\.+', '.', ''.join([random.choice('0123456789abcdefghijklmnopqrstuvwxyz.') for _ in range(random.randint(4,32))]).strip('.')) + '.' + aqname
        else:
            alias = 'NXDOMAIN'

        if alias != 'NXDOMAIN':
            israndom = True
            log_info('{0} [{1}]: {2} = RANDOM: \"{3}\"'.format(tag, hid, queryname, alias))

    aliasqname = False

    if alias.upper() in ('NODATA', 'NOTAUTH', 'NXDOMAIN', 'REFUSED'):
        log_info('{0} [{1}]: {2} = REDIRECT-TO-RCODE -> {3}'.format(tag, hid, queryname, alias.upper()))
        reply = rc_reply(request, alias.upper())

    elif ipregex.search(alias) and qtype in ('A', 'AAAA', 'CNAME'):
        log_info('{0} [{1}]: {2} = REDIRECT-TO-IP -> {3}'.format(tag, hid, queryname, alias))
        if is_v6(alias):
            answer = RR(realqname, QTYPE.AAAA, ttl=filterttl, rdata=AAAA(alias))
        else:
            answer = RR(realqname, QTYPE.A, ttl=filterttl, rdata=A(alias))

        reply.add_answer(answer)

    elif qtype in ('A', 'AAAA', 'CNAME', 'PTR'):
        log_info('{0} [{1}]: {2} = REDIRECT-TO-NAME -> {3}'.format(tag, hid, queryname, alias))

        if israndom and qtype == 'CNAME':
            rcode = 'NODATA'
        else:
            subreply = dns_query(request, alias, qtype, use_tcp, request.header.id, 'ALIAS-RESOLVER', False, False)
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

            log_replies(reply, tag + '-REPLY')
        else:
            reply = rc_reply(request, rcode)

    else:
        reply = rc_reply(request, 'NXDOMAIN')

    if collapse and aliasqname:
        log_info('{0} [{1}]: COLLAPSE {2}/IN/CNAME'.format(tag, hid, qname))

    if newalias:
        to_cache(qname, 'IN', qtype, reply, force, False, 'GENERATED-ALIAS')
    else:
        to_cache(qname, 'IN', qtype, reply, force, False, 'ALIAS')

    return reply


def to_dict(iplist):
    '''iplist is a Pytricia dict'''
    newdict = dict()
    #for i in iplist.keys():
    for i in iplist:
        newdict[i] = iplist[i]
    return newdict


def from_dict(fromlist, tolist):
    '''toist is a Pytricia dict.'''
    #for i in fromlist.keys():
    for i in fromlist:
        tolist[i] = fromlist[i]
    return tolist


def save_cache(file):
    '''Save Cache'''
    if not persistentcache:
        return False

    log_info('CACHE-SAVE: Saving to \"{0}\"'.format(file))

    try:
        s = shelve.DbfilenameShelf(file, flag='n', protocol=4)
        s.clear()
        s['cache'] = cache
        s.close()

    except BaseException as err:
        log_err('ERROR: Unable to open/write file \"{0}\" - {1}'.format(file, err))
        return False

    return True


def load_cache(file):
    '''Load Cache'''
    if not persistentcache:
        return False

    global cache

    age = file_exist(file, True)
    if age and age < maxfileage:
        log_info('CACHE-LOAD: Loading from \"{0}\"'.format(file))
        try:
            s = shelve.DbfilenameShelf(file, flag='r', protocol=4)
            cache = s['cache']
            s.close()

        except BaseException as err:
            log_err('ERROR: Unable to open/read file \"{0}\" - {1}'.format(file, err))
            return False

        cache_maintenance(False, maxttl, False, False) # Purge everything with has a ttl higher then 60 seconds left

    else:
        log_info('CACHE-LOAD: Skip loading cache from \"{0}\" - non-existant or older then {1} seconds'.format(file, maxfileage))
        return False

    if debug: execute_command('show.' + command, False)

    return True


def save_lists(file):
    '''Save Lists'''
    log_info('LIST-SAVE: Saving to \"{0}\"'.format(file))

    try:
        s = shelve.DbfilenameShelf(file, flag='n', protocol=4)

        s.clear()

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
        log_err('ERROR: Unable to open/write file \"{0}\" - {1}'.format(file, err))
        return False


    return True


def load_asn(file, asn4, asn6):
    '''Load IPASN'''
    log_info('ASN: Loading IPASN from \"{0}\"'.format(file))

    if file_exist(file, False):
        try:
            f = open(file, 'r')
            #lines = f.readlines()
            lines = f.read().splitlines()
            f.close()

        except BaseException as err:
            log_err('ERROR: Unable to open/read/process ASN file \"{0}\" - {1}'.format(file, err))
            return False

        count = 0
        for line in lines:
            count += 1

            elements = regex.split('\s+', line.strip())
            if elements[1:]:
                prefix = elements[0]
                if ipregex.search(prefix):
                    asn = elements[1].upper().lstrip('AS')
                    if isasn.search('AS' + asn):
                        if elements[2:]:
                            owner = ' '.join(elements[2:]).upper()
                        else:
                            owner = 'IPASN'

                        if is_v6(prefix):
                            asnd = asn6
                        else:
                            asnd = asn4

                        asnd[prefix] = asn + ' ' + owner
                    else:
                        log_err('ASN-ERROR [{0}]: Invalid ASN - {1}'.format(count, line))

                else:
                    log_err('ASN-ERROR [{0}]: Invalid IP - {1}'.format(count, line))

    else:
        log_err('ERROR: Unable to open/read/process ASN file \"{0}\" - File does not exist'.format(file))

    log_info('ASN: Fetched {0} IPv4 and {1} IPv6 ASNs'.format(len(asn4), len(asn6)))

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
        log_info('LIST-LOAD: Loading from \"{0}\"'.format(file))
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
            log_err('ERROR: Unable to open/read file \"{0}\" - {1}'.format(file, err))
            return False

    else:
        log_info('LIST-LOAD: Skip loading lists from \"{0}\" - non-existant or older then {1} seconds'.format(file, maxfileage))
        return False

    return True


def log_totals():
    '''Log List Totals'''
    log_info('WHITELIST-TOTALS: {0} REGEXes, {1} IPv4 CIDRs, {2} IPv6 CIDRs, {3} DOMAINs, {4} ALIASes, {5} FORWARDs, {6} TTLs and {7} ASNs'.format(len(wl_rx), len(wl_ip4), len(wl_ip6), len(wl_dom), len(aliases), len(forward_servers), len(ttls), len(wl_asn)))
    log_info('BLACKLIST-TOTALS: {0} REGEXes, {1} IPv4 CIDRs, {2} IPv6 CIDRs, {3} DOMAINs and {4} ASNs'.format(len(bl_rx), len(bl_ip4), len(bl_ip6), len(bl_dom), len(bl_asn)))
    log_info('CACHE-TOTALS: {0} Cache Entries'.format(len(cache)))
    return True


# Read filter lists, see "accomplist" to provide ready-2-use lists:
# https://github.com/cbuijs/accomplist
def read_list(file, listname, bw, domlist, iplist4, iplist6, rxlist, arxlist, alist, flist, tlist, asnlist):
    '''Read/Load lists'''
    listname = listname.upper()
    log_info('Fetching {0} \"{1}\" entries from \"{2}\"'.format(bw, listname, file))

    count = 0
    fetched = 0

    if file_exist(file, False):
        try:
            f = open(file, 'r')
            #lines = f.readlines()
            lines = f.read().splitlines()
            f.close()

        except BaseException as err:
            log_err('ERROR: Unable to open/read/process list-file \"{0}\" - {1}'.format(file, err))

        for line in lines:
            count += 1

            entry = regex.sub('\s*#[^#]*$', '', line.replace('\r', '').replace('\n', '')) # Strip comments and line-feeds

            if entry.startswith('/'):
                name = ' '.join(regex.split('\t+', entry)[1:]).strip() or listname
                entry = regex.sub('/\t+[^/]+$', '/', entry).strip()
            else:
                name = ' '.join(regex.split('\s+', entry)[1:]).strip() or listname
                entry = regex.split('\s+', entry)[0].strip()

            # Accomplist specific clean-up

            # If entry ends in exclaimation, it is a "forced" entry, blacklisted will overrule whitelisted.
            # !!! Note: Accomplist already did the logic and clean whitelist. If using other cleanup yourself, no code for that here.
            forced = False
            if entry.endswith('!'):
                entry = entry.rstrip('!')
                if isdomain.search(entry):
                    forced = True

            # If entry ends in ampersand, it is a "safelisted" entry. Not supported.
            if entry.endswith('&'):
                entry = False

            # Process entry
            if entry and (not entry.startswith('#')):
                # REGEX
                if isregex.search(entry):
                    rx = entry.strip('/')
                    try:
                        rxlist[name + ': ' + rx] = regex.compile(rx, regex.I)
                        fetched += 1
                    except BaseException as err:
                        log_err('{0} INVALID REGEX [{1}]: {2} - {3}'.format(listname, count, entry, err))

                # ASN
                elif isasn.search(entry):
                    fetched += 1
                    asn = entry.upper().lstrip('AS')
                    asnlist[asn] = name

                # DOMAIN
                elif isdomain.search(entry):
                    entry = normalize_dom(entry)
                    entrytype = 'ANY'
                    if iparpa.search(entry):
                        entrytype = 'PTR'

                    dots = entry.count('.')
                    if is_illegal('LIST-ENTRY', entry, entrytype) or is_weird('LIST-ENTRY', entry, entrytype):
                        log_err('{0} ILLEGAL/FAULTY/WEIRD Entry [{1}]: {2}'.format(listname, count, entry))
                    elif entry != '.' and (entry not in domlist):
                        fetched += 1
                        domlist[entry] = name
                        if forced:
                            log_info('{0} FORCED [{1}]: {2}'.format(listname, count, entry))
                            domlist[entry + '!'] = name

                # IPV4
                elif ipregex4.search(entry):
                    fetched += 1
                    iplist4[entry] = name

                # IPV6
                elif ipregex6.search(entry):
                    fetched += 1
                    iplist6[expand_ip(entry)] = name

                #### !!! From here on there are functional entries, which are always condidered "whitelist"
                # ALIAS - domain.com=ip or domain.com=otherdomain.com
                elif bw == 'Whitelist':
                    if entry.find('=') > 0:
                        if entry.startswith('/'):
                            elements = regex.split('/\s*=\s*', entry)
                            if elements[1:]:
                                if isregex.search(elements[0] + '/'):
                                    fetched += 1
                                    rx = elements[0].strip('/')
                                    alias = elements[1].strip()
                                    aliaskey = name + ': ' + alias + ' ' + rx
                                    try:
                                        arxlist[aliaskey] = regex.compile(rx, regex.I)
                                    except BaseException as err:
                                        log_err('{0} INVALID REGEX [{1}]: {2} - {3}'.format(listname, count, entry, err))

                                    log_info('{0} ALIAS-GENERATOR [{1}]: \"{2}\" -> \"{3}\"'.format(listname, count, rx, alias))

                                else:
                                    log_err('{0} INVALID ALIAS [{1}]: {2}'.format(listname, count, entry))

                        else:
                            elements = regex.split('\s*=\s*', entry)
                            if elements[1:]:
                                domain = normalize_dom(elements[0])
                                alias = normalize_dom(elements[1])
                                if isdomain.search(domain) and (isdomain.search(alias) or ipregex.search(alias)):
                                    fetched += 1
                                    alist[domain] = alias
                                    if alias.upper() != 'RANDOM':
                                        domlist[domain] = 'Alias-Domain' # Whitelist it
                                    log_info('{0} ALIAS-ALIAS [{1}]: \"{2}\" -> \"{3}\"'.format(listname, count, domain, alias))
                                else:
                                    log_err('{0} INVALID ALIAS [{1}]: {2}'.format(listname, count, entry))
                            else:
                                log_err('{0} INVALID ALIAS [{1}]: {2}'.format(listname, count, entry))

                    # FORWARD - domain.com>ip
                    elif entry.find('>') > 0:
                        #elements = entry.split('>')
                        elements = regex.split('\s*>\s*', entry)
                        if elements[1:]:
                            domain = normalize_dom(elements[0])
                            ips = elements[1].strip().lower().strip('.')
                            if isdomain.search(domain):
                                domlist[domain] = 'Forward-Domain' # Whitelist it
                                addrs = list()
                                for addr in regex.split('\s*,\s*', ips):
                                    if ipportregex.search(addr):
                                        addrs.append(addr)
                                        log_info('{0} ALIAS-FORWARDER [{1}]: \"{2}\" to {3}'.format(listname, count, domain, addr))
                                    else:
                                        log_err('{0} INVALID FORWARD-ADDRESS [{1}]: {2}'.format(listname, count, addr))

                                if addrs:
                                    fetched += 1
                                    flist[domain] = addrs
                            else:
                                log_err('{0} INVALID FORWARD [{1}]: {2}'.format(listname, count, entry))
                        else:
                            log_err('{0} INVALID FORWARD [{1}]: {2}'.format(listname, count, entry))

                    # TTLS - domain.com!ttl (TTL = integer)
                    elif entry.find('!') > 0:
                        #elements = entry.split('!')
                        elements = regex.split('\s*!\s*', entry)
                        if elements[1:]:
                            domain = normalize_dom(elements[0])
                            ttl = elements[1].strip()
                            if isdomain.search(domain) and isnum.search(ttl):
                                fetched += 1
                                tlist[domain] = int(ttl)
                                domlist[domain] = 'TTL-Override' # Whitelist it
                                log_info('{0} ALIAS-TTL [{1}]: \"{2}\" = {3}'.format(listname, count, domain, ttl))
                            else:
                                log_err('{0} INVALID TTL [{1}]: {2}'.format(listname, count, entry))
                        else:
                            log_err('{0} INVALID TTL [{1}]: {2}'.format(listname, count, entry))

                    # Search Domains
                    elif entry.endswith('*'):
                        sdom = normalize_dom(entry.rstrip('*').strip())
                        if isdomain.search(sdom):
                            if sdom not in searchdom:
                                if sdom not in wl_dom:
                                    domlist[sdom] = 'Search-Domain'
                                fetched += 1
                                searchdom.add(sdom)
                                log_info('{0} ALIAS-SEARCH-DOMAIN [{1}]: \"{2}\"'.format(listname, count, sdom))
                        else:
                            log_err('{0} INVALID SEARCH-DOMAIN [{1}]: {2}'.format(listname, count, entry))

                # Invalid/Unknown Syntax or BOGUS entry
                else:
                    log_err('{0} INVALID/BOGUS LINE [{1}]: {2}'.format(listname, count, entry))

    else:
        log_err('ERROR: Cannot open \"{0}\" - Does not exist'.format(file))

    log_info('{0} Processed {1} lines and used {2}'.format(listname, count, fetched))

    return domlist, iplist4, iplist6, rxlist, arxlist, alist, flist, tlist, asnlist


def reduce_ip(iplist, listname):
    '''Strip all subnets and keep only parents'''
    before = len(iplist)
    kids = dict()
    #for kid in iplist.keys():
    for kid in iplist:
        parent = iplist.parent(kid)
        if parent:
            kids[kid] = parent

    #for kid in kids.keys():
    for kid in kids:
        if debug: log_info('IPLIST-REDUCE [{0}]: Removed subnet {1} ({2}), already covered by {3} ({4})'.format(listname, kid, iplist[kids[kid]], kids[kid], iplist[kid]))
        del iplist[kid]

    after = len(iplist)
    count = before - after
    log_info('IPLIST-REDUCE [{0}]: Removed {1} parent subnets, total went from {2} to {3}'.format(listname, count, before, after))

    return iplist


def reduce_dom(domlist, listname):
    '''Strip all subdomains and keep only parents'''
    before = len(domlist)
    subs = dict()
    #for sub in domlist.keys():
    for sub in domlist:
        parent = in_domain(sub, domlist, 'Reduce-DOM ' + listname, True)
        if parent and parent != sub:
            subs[sub] = parent

    #for sub in subs.keys():
    for sub in subs:
        if debug: log_info('DOMLIST-REDUCE [{0}]: Removing subdomain {1} ({2}), already covered by {3} ({4})'.format(listname, sub, domlist[subs[sub]], subs[sub], domlist[sub]))
        del domlist[sub]

    after = len(domlist)
    count = before - after
    log_info('DOMLIST-REDUCE [{0}]: Removed {1} parented subdomains, total went from {2} to {3}'.format(listname, count, before, after))

    return domlist


def unwhite_ip(wiplist, biplist, listname):
    '''Remove blacklist entries that are whitelisted'''
    before = len(biplist)
    cidrs = dict()
    #for cidr in biplist.keys():
    for cidr in biplist:
        if cidr in wiplist:
            cidrs[cidr] = wiplist.get_key(cidr)

    #for cidr in cidrs.keys():
    for cidr in cidrs:
        if debug: log_info('IPLIST-UNWHITE [{0}]: Removing CIDR {1} ({2}), whitelisted by {3} ({4})'.format(listname, cidr, biplist[cidr], cidrs[cidr], wiplist[cidr]))
        del biplist[cidr]

    after = len(biplist)
    count = before - after
    log_info('IPLIST-UNWHITE [{0}]: Removed {1} whitelisted CIDRs, total went from {2} to {3}'.format(listname, count, before, after))

    return biplist


def unwhite_dom(wdomlist, bdomlist, listname):
    '''Remove blacklist entries that are whitelisted'''
    before = len(bdomlist)
    domains = dict()
    #for domain in bdomlist.keys():
    for domain in bdomlist:
        whitedomain = in_domain(domain, wdomlist, 'Unwhite-DOM ' + listname, False)
        if whitedomain:
            domains[domain] = whitedomain

    #for domain in domains.keys():
    for domain in domains:
        if debug: log_info('DOMLIST-UNWHITE [{0}]: Removing subdomain {1} ({2}), whitelisted by {3} ({4})'.format(listname, domain, bdomlist[domain], domains[domain], wdomlist[domain]))
        del bdomlist[domain]

    after = len(bdomlist)
    count = before - after
    log_info('DOMLIST-UNWHITE [{0}]: Removed {1} whitelisted Domains, total went from {2} to {3}'.format(listname, count, before, after))

    return bdomlist


def unblack_dom(bdomlist, wdomlist, listname):
    '''Remove whitelist entries that are forced blacklisted'''
    before = len(wdomlist)
    domains = dict()
    #for domain in wdomlist.keys():
    for domain in wdomlist:
        blackdomain = in_domain(domain + '!', bdomlist, 'Unblack-DOM ' + listname, False)
        if blackdomain:
            forcedwhite = in_domain(domain + '!', wdomlist, 'Forcedwhite-DOM ' + listname, False)
            if forcedwhite:
                log_info('DOMLIST-UNBLACK [{0}]: Skipped subdomain {1} ({2}), forced whitelisted by {3} ({4})'.format(listname, domain, wdomlist[domain], forcedwhite, wdomlist[forcedwhite]))
            else:
                domains[domain] = blackdomain

    #for domain in domains.keys():
    for domain in domains:
        if debug: log_info('DOMLIST-UNBLACK [{0}]: Removing subdomain {1} ({2}), forced blacklisted by {3} ({4})'.format(listname, domain, wdomlist[domain], domains[domain], bdomlist[domains[domain]]))
        del wdomlist[domain]

    after = len(wdomlist)
    count = before - after
    log_info('DOMLIST-UNBLACK [{0}]: Removed {1} whitelisted Domains, total went from {2} to {3}'. format(listname, count, before, after))

    return wdomlist


def unwhite_asn(awlist, ablist, listname):
    '''Remove blacklist entries that are whitelisted'''
    before = len(ablist)
    asns = dict()
    #for asn in awlist.keys():
    for asn in awlist:
        if asn in ablist:
            asns[asn] = awlist[asn]

    #for asn in asns.keys():
    for asn in asns:
        if debug: log_info('ASNLIST-UNWHITE [{0}]: Removing whitelisted ASN AS{1} ({2})'.format(listname, asn, ablist[asn]))
        del ablist[asn]

    after = len(ablist)
    count = before - after
    log_info('ASNLIST-UNWHITE [{0}]: Removed {1} whitelisted ASNs, total went from {2} to {3}'.format(listname, count, before, after))

    return ablist


def unreg_dom(rxlist, domlist, listname):
    '''Remove entries that are regex matched'''
    before = len(domlist)
    domains = dict()
    #for domain in domlist.keys():
    for domain in domlist:
        if not domain.endswith('!'):
            rx = in_regex(domain, rxlist, False, 'Unreg-DOM ' + listname)
            if rx:
                domains[domain] = rx

    #for domain in domains.keys():
    for domain in domains:
        if debug: log_info('DOMLIST-UNREG [{0}]: Removing domain {1} ({2}), already covered by {3}'.format(listname, domain, domlist[domain], domains[domain]))
        del domlist[domain]

    after = len(domlist)
    count = before - after
    log_info('DOMLIST-UNREG [{0}]: Removed {1} regexed Domains, total went from {2} to {3}'.format(listname, count, before, after))

    return domlist


def normalize_dom(dom):
    '''Normalize Domain Names'''
    return str(dom).strip().strip('.').lower() or '.'


def normalize_ttl(qname, rr):
    '''Normalize TTL's, all RR's in a RRSET will get the same TTL based on strategy (see below)'''
    if filtering:
        newttl = in_domain(qname, ttls, 'TTL', False)
        if newttl:
            ttl = ttls.get(newttl, nottl)
            log_info('TTL-HIT: Setting TTL for {0} ({1}) to {2} seconds'.format(qname, newttl, ttl))
            update_ttl(rr, ttl)
            return ttl

    #if rr and (rr) > 0:
    if rr:
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
        comment = record[5]

        log_info('CACHE-PREFETCH: {0} {1} [{2}/{3} hits] (TTL-LEFT: {4}/{5}) - {6}'.format(queryname, rcode, hits, hitsneeded, ttlleft, orgttl, comment))

        #del_cache_entry(queryhash)

        qname, qclass, qtype = queryname.split('/')
        request = DNSRecord.question(qname, qtype, qclass)
        request.header.id = random.randint(1, 65535)
        #handler = DNSHandler
        #handler.protocol = 'udp'
        #handler.client_address = '\'PREFETCHER\''

        #reply = do_query(request, handler, True) # Query and update cache

        _ = dns_query(request, qname, qtype, False, request.header.id, 'PREFETCHER', True, True) # Fetch and Cache

        prefetching_busy = False

        return True

    prefetching_busy = False
    return False


def from_cache(qname, qclass, qtype, tid):
    '''Retrieve from cache'''
    global cache_maintenance_busy

    if nocache:
        return None

    queryhash = query_hash(qname, qclass, qtype)
    cacheentry = cache.get(queryhash, None)
    if cacheentry is None:
        return None

    cache_maintenance_busy = True

    expire = cacheentry[1]
    queryname = cacheentry[2]
    now = int(time.time())
    ttl = expire - now
    orgttl = cacheentry[4]
    hits = cacheentry[3]
    hitsneeded = int(round(orgttl / prefetchhitrate)) or 1
    numrrs = len(cacheentry[0].rr)
    rcode = str(RCODE[cacheentry[0].header.rcode])
    comment = cacheentry[5]

    # If expired, remove from cache
    if ttl < 1:
        if numrrs > 0 or (numrrs == 0 and rcode != 'NOERROR'):
            log_info('CACHE-EXPIRED: {0} {1} [{2}/{3} hits] (TTL-EXPIRED:{4}/{5}) - {6}'.format(queryname, rcode, hits, hitsneeded, ttl, orgttl, comment))
        else:
            log_info('CACHE-EXPIRED: {0} NODATA (TTL-EXPIRED:{1}) - {2}'.format(queryname, orgttl, comment))
        del_cache_entry(queryhash)
        cache_maintenance_busy = False
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

            if addr[1:]:
                reply.rr = nonaddr + round_robin(addr)

        else:
            for record in reply.rr:
                record.ttl = ttl

        if numrrs == 0 and rcode == 'NOERROR':
            log_info('CACHE-HIT ({0}/{1} hits): Retrieved NODATA for {2} (TTL-LEFT:{3}/{4}) - {5}'.format(hits, hitsneeded, queryname, ttl, orgttl, comment))
        else:
            if numrrs == 0:
                log_info('CACHE-HIT ({0}/{1}): Retrieved {2} for {3} (TTL-LEFT:{4}/{5}) - {6}'.format(hits, hitsneeded, rcode, queryname, ttl, orgttl, comment))
            else:
                log_info('CACHE-HIT ({0}/{1}): Retrieved {2} RRs for {3} {4} (TTL-LEFT:{5}/{6}) - {7}'.format(hits, hitsneeded, numrrs, queryname, rcode, ttl, orgttl, comment))

        log_replies(reply, 'CACHE-REPLY')

        cache_maintenance_busy = False
        return reply

    return None


def log_replies(reply, title):
    '''Log replies'''
    if not logreplies:
        return False

    hid = id_str(reply.header.id)
    replycount = 0
    replynum = len(reply.rr)
    rcode = str(RCODE[reply.header.rcode])
    if replynum > 0:
        for record in reply.rr:
            replycount += 1
            log_info('{0} [{1}:{2}-{3}]: {4}/IN/{5} = {6} {7}'.format(title, hid, replycount, replynum, str(record.rname).rstrip('.') or '.', QTYPE[record.rtype], str(record.rdata).rstrip('.') or '.', rcode))
    else:
        if rcode == 'NOERROR':
            rcode = 'NODATA'
        log_info('{0} [{1}]: {2}/IN/{3} {4}'.format(title, hid, reply.q.qname, QTYPE[reply.q.qtype], rcode))

    return True


def in_cache(qname, qclass, qtype):
    '''Check if in cache'''
    if query_hash(qname, qclass, qtype) in cache:
        if debug: log_info('IN-CACHE-HIT: {0}/{1}/{2}'.format(qname, qclass, qtype))
        return True

    return False


def to_cache(qname, qclass, qtype, reply, force, newttl, comment):
    '''Store into cache'''
    global cache_maintenance_now

    # No caching
    if nocache or reply == defaultlist or reply is None:
        return False

    # Already in cache
    if force is False and in_cache(qname, qclass, qtype):
        return True

    queryname = qname + '/' + qclass + '/' + qtype
    rcode = str(RCODE[reply.header.rcode])
    ttl = nottl

    # Override TTL
    if not newttl:
        newttl = in_domain(qname, ttls, 'TTL', False)
        if newttl:
            newttl = ttls.get(newttl, False)

    # Cache return-codes
    if rcode in ('NOTAUTH', 'NOTIMP', 'NXDOMAIN', 'REFUSED'):
        ttl = newttl or rcodettl
    elif rcode == 'NOERROR' and (not reply.rr): # NODATA
        ttl = newttl or rcodettl
    elif rcode == 'SERVFAIL':
        ttl = newttl or failttl
    elif rcode != 'NOERROR':
        log_info('CACHE-SKIPPED: {0} {1}'.format(queryname, rcode))
        return False
    else: # Regular/NOERROR record
        ttl = newttl or reply.rr[0].ttl

    if ttl > 0: # cache it if not expired yet
        expire = int(time.time()) + ttl
        _ = add_cache_entry(qname, qclass, qtype, expire, ttl, reply, comment)

    if len(cache) > cachesize: # Cache changed, do maintenance
        cache_maintenance_now = True

    return True


def cache_expired_list():
    '''get list of purgable items'''
    now = int(time.time())
    #return list(dict((k, v) for k, v in cache.items() if v[1] - now < 1).keys()) or False
    return list(dict((k, v) for k, v in cache.items() if v[1] - now < 2).keys()) or False


def no_noerror_list():
    '''Return all no-noerror list'''
    return list(dict((k, v) for k, v in cache.items() if v[0].header.rcode != 0).keys())


def cache_prefetch_list():
    '''Get list of prefetchable items'''
    now = int(time.time())
    # Formula: At least one RR-Record, at least 2 cache-hits, hitrate > 0 and hits are above/equal hitrate
    # value list entries: 0:reply - 1:expire - 2:qname/class/type - 3:hits - 4:orgttl - 5:domainname - 6:comment
    return list(dict((k, v) for k, v in cache.items() if len(v[0].rr) > 0 and v[3] > 1 and int(round(v[4] / prefetchhitrate)) > 0 and v[1] - now <= int(round(v[4] / prefetchgettime)) and v[3] >= int((round(v[4] / prefetchhitrate)) - (round((v[1] - now) / prefetchhitrate)))).keys()) or False


def cache_dom_list(qclass, qtype):
    '''Get list of domains in cache'''
    newlist = set()
    for dom in list(cache.values()):
        cqname, cqclass, cqtype = dom[2].split('/')
        if cqclass == qclass and cqtype == qtype:
            newlist.add(cqname)

    return newlist


def cache_maintenance(flushall, olderthen, clist, plist):
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
    # !!! TODO: Entries with lowest hit-rate and lowest TTLs
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

    if flushall:
        indom_cache.clear()
        inrx_cache.clear()
        match_cache.clear()
        #random_cache.clear()

    if before != after:
        if totalrrs == 0:
            log_info('CACHE-STATS: purged {0} entries, {1} left in cache'.format(before - after, after))
        else:
            log_info('CACHE-STATS: purged {0} entries ({1} RRs), {2} left in cache'.format(before - after, totalrrs, after))

        log_info('CACHE-STATS: INRX={0} INDOM={1} MATCH={2} entries'.format(len(inrx_cache), len(indom_cache), len(match_cache)))

        save_cache(cachefile)

    if debug: log_info('CACHE-MAINT: FINISH')

    gc.collect()

    cache_maintenance_busy = False

    return True


def query_hash(qname, qclass, qtype):
    '''Query-hash for cache entries'''
    return hash(qname + '/' + qclass + '/' + qtype)


def add_cache_entry(qname, qclass, qtype, expire, ttl, reply, comment):
    '''Add entry to cache'''
    global cache_maintenance_busy

    cache_maintenance_busy = True

    hashname = qname + '/' + qclass + '/' + qtype
    rcode = str(RCODE[reply.header.rcode])
    queryhash = query_hash(qname, qclass, qtype)

    cache[queryhash] = list([reply, expire, hashname, 1, ttl, comment]) # reply - expire - qname/class/type - hits - orgttl - comment

    numrrs = len(cache.get(queryhash, defaultlist)[0].rr)
    if numrrs == 0:
        if rcode == 'NOERROR':
            rcode = 'NODATA'
        log_info('CACHE-UPDATE ({0} entries): Cached {1} for {2} (TTL:{3}) - {4}'.format(len(cache), rcode, hashname, ttl, comment))
    else:
        log_info('CACHE-UPDATE ({0} entries): Cached {1} RRs for {2} {3} (TTL:{4}) - {5}'.format(len(cache), numrrs, hashname, rcode, ttl, comment))

    cache_maintenance_busy = False

    return queryhash


def del_cache_entry(queryhash):
    '''Remove entry from cache'''
    global cache_maintenance_busy
    cache_maintenance_busy = True
    _ = cache.pop(queryhash, None)
    cache_maintenance_busy = False
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

            zid = id_str(rid)
            if addr:
                reply = rc_reply(request, 'NOERROR')
                count = 0
                total = str(len(addr))
                for ip in addr:
                    count += 1
                    if is_v6(ip):
                        rrtype = 'AAAA'
                        answer = RR(qname, QTYPE.AAAA, ttl=ttl, rdata=AAAA(ip))
                    else:
                        rrtype = 'A'
                        answer = RR(qname, QTYPE.A, ttl=ttl, rdata=A(ip))

                    if logreplies:
                        log_info('REPLY [{0}:{1}-{2}]: COLLAPSE {3}/IN/CNAME -> {4}/{5}'.format(zid, count, total, qname, ip, rrtype))

                    reply.add_answer(answer)

                if not logreplies:
                    log_info('REPLY [{0}]: {1}/IN/CNAME has been COLLAPSED to {2} address-records'.format(zid, qname, len(addr)))

            else:
                reply = rc_reply(request, 'NXDOMAIN')

    return reply


def execute_command(qname, log):
    '''Execute commands'''
    global filtering

    qname = regex.sub('\.' + command + '$', '', qname).upper()

    if log: log_info('COMMAND: \"{0}\"'.format(qname))

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
                    log_info('CACHE-INFO ({0}/{1}): {2} NODATA [{3}/{4} Hits] (TTL-LEFT:{5}/{6})'.format(count, total, cache[i][2], record[3], hitsneeded, record[1] - now, record[4]))
                else:
                    if numrrs != 0:
                        log_info('CACHE-INFO ({0}/{1}): {2} RRs for {3} {4} [{5}/{6} Hits] (TTL-LEFT:{7}/{8})'.format(count, total, numrrs, cache[i][2], rcode, record[3], hitsneeded, record[1] - now, record[4]))
                    else:
                        log_info('CACHE-INFO ({0}/{1}: {2} {3} [{4}/{5} Hits] (TTL-LEFT:{6}/{7})'.format(count, total, cache[i][2], rcode, record[3], hitsneeded, record[1] - now, record[4]))

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
        log_err('COMMAND: Unknown/Failed command \"{0}\"'.format(qname))
        return False

    if flush:
        cache_maintenance(True, False, False, False)

    return True


def is_v6(ipaddress):
    '''Check if IPv6 Address'''
    if ':' in ipaddress:
        return True
    return False


def is_illegal(rtype, value, qtype):
    '''Check if Illegal'''
    if blockillegal:
        if rtype in ('LIST-ENTRY', 'REQUEST'):
            # Filter when domain-name is not compliant
            if (not isdomain.search(value)) and (not iparpa.search(value)):
                log_info('ILLEGAL-{0}: {1}/{2} - QNAME Invalid domain-name'.format(rtype, value, qtype))
                return True
        elif rtype == 'REPLY':
            # A or AAAA record but data is not an IP
            if qtype in ('A', 'AAAA') and (not ipregex.search(value)):
                log_info('ILLEGAL-{0}: {1}/{2} - DATA not an IP-Address'.format(rtype, value, qtype))
                return True
            # Data not a domain
            elif qtype in ('CNAME', 'MX', 'NS', 'PTR', 'SRV') and (not isdomain.search(value)):
                log_info('ILLEGAL-{0}: {1}/{2} - DATA not a domainname'.format(rtype, value, qtype))
                return True

    return False


def is_weird(rtype, value, qtype):
    '''Check if weird'''
    if blockweird:
        # Request qname
        if rtype in ('LIST-ENTRY', 'REQUEST'):
            # PTR records that do not comply with IP-Addresses
            if qtype == 'PTR' and (not iparpa.search(value)):
                log_info('WEIRD-{0}: {1}/{2} - QNAME not ip-arpa syntax'.format(rtype, value, qtype))
                return True

            # Reverse-lookups are not PTR records
            elif qtype != 'PTR' and (iparpa.search(value)):
                log_info('WEIRD-{0}: {1}/{2} - Non-PTR with ip-arpa request'.format(rtype, value, qtype))
                return True

            # SRV records where qname has more then two underscores
            elif qtype == 'SRV' and value.count('_') > 2:
                log_info('WEIRD-{0}: {1}/{2} - Too many underscores (>2)'.format(rtype, value, qtype))
                return True

            # Non-SRV records with underscores in qname
            #elif qtype != 'SRV' and value.count('_') > 0:
            #    log_info('WEIRD-{0}: {1}/{2} - Non-SRV Underscore'.format(rtype, value, qtype))
            #    return True

        # Response Data
        elif rtype == 'REPLY':
            # PTR record pointing to an IP or Arpa
            if qtype == 'PTR' and ipregex.search(value):
                log_info('WEIRD-{0}: {1}/{2} - PTR data not a domain-name'.format(rtype, value, qtype))
                return True

            # Data of response is an arpa domain, technically not wrong, just weird
            elif iparpa.search(value):
                log_info('WEIRD-{0}: {1}/{2} - Data is ip-arpa syntax'.format(rtype, value, qtype))
                return True

            # Underscores
            #elif value.count('_') > 0:
            #    log_info('WEIRD-{0}: {1}/{2} - Underscore'.format(rtype, value, qtype))
            #    return True

    return False


def rc_reply(request, rcode):
    '''Generate empty reply with rcode'''
    reply = request.reply()
    rcode = rcode.upper()
    if debug: log_info('RCODE: {0}/{1} = {2}'.format(str(request.q.qname).rstrip('.'), QTYPE[request.q.qtype], rcode))
    if rcode == 'NODATA':
        reply.header.rcode = getattr(RCODE, 'NOERROR')
    else:
        reply.header.rcode = getattr(RCODE, rcode)
    return reply


def expand_ip(ip):
    '''Expand IPv6 address'''
    if not ipregex6.search(ip):
        return ip

    new_ip = ip

    prefix = False
    if '/' in new_ip:
        new_ip, prefix = new_ip.split('/')[0:2]
        if new_ip.endswith(':'):
            new_ip = new_ip + '0'

    if '::' in new_ip:
        padding = 9 - new_ip.count(':')
        new_ip = new_ip.replace(('::'), ':' * padding)

    parts = new_ip.split(':')
    for part in range(8):
        parts[part] = str(parts[part]).zfill(4)

    new_ip = ':'.join(parts)

    if prefix:
        new_ip = new_ip + '/' + prefix

    if debug: log_info('IPV6-EXPANDER: {0} -> {1}'.format(ip, new_ip))

    return new_ip


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

    log_info('REQUEST [{0}]: from {1} for {2} ({3})'.format(tid, cip, queryname, handler.protocol.upper()))

    reply = None

    # Check ACL
    if ipregex.search(cip):
        if cip + '/32' in allow_query4 or cip + '/128' in allow_query6:
            if debug: log_info('ALLOW-ACL-HIT [{0}]: Request from {1} for {2}'.format(tid, cip, queryname))
        else:
            log_info('REFUSE-ACL-HIT [{0}]: Request from {1} for {2} {3}'.format(tid, cip, queryname, aclrcode))
            reply = rc_reply(request, aclrcode)


    # For caching
    queryfiltered = True


    # Execute Command
    if reply is None:
        if command and qname.endswith('.' + command):
            if cip in ('127.0.0.1', '::1'):
                if execute_command(qname, True):
                    reply = rc_reply(request, 'NOERROR')
                else:
                    reply = rc_reply(request, 'NOTIMP')
            else:
                reply = rc_reply(request, 'REFUSED')

        # Quick response when in cache
        elif force is False:
            reply = from_cache(qname, qclass, qtype, rid)


    # Process query/request
    if reply is None:
        if qclass != 'IN':
            log_info('BLOCK-UNSUPPORTED-CLASS [{0}]: Request from {1} for {2} {3}=NOTIMP'.format(tid, cip, queryname, qclass))
            reply = rc_reply(request, 'NOTIMP')

        # Filter if query-type is not supported
        elif qtype not in ('ANY', 'A', 'AAAA', 'AFSDB', 'ANY', 'APL', 'CAA', 'CERT', 'CNAME', 'DHCID', 'DLV', 'DNAME', 'DNSKEY', 'DS', 'HIP', 'IPSECKEY', 'KEY', 'KX', 'LOC', 'MX', 'NAPTR', 'NS', 'NSEC', 'NSEC3', 'NSEC3PARAM', 'PTR', 'RP', 'RRSIG', 'SIG', 'SOA', 'SRV', 'SSHFP', 'TA', 'TKEY', 'TLSA', 'TSIG', 'TXT'):
            log_info('BLOCK-UNSUPPORTED-RRTYPE [{0}]: Request from {1} for {2}, {3}=NOTIMP'.format(tid, cip, queryname, qtype))
            reply = rc_reply(request, 'NOTIMP')

        # Check if parent is in cache as NXDOMAIN
        elif force is False and blocksub and qname.count('.') > 0 and (not in_domain(qname, wl_dom, 'Whitelist', False)):
            dom = in_domain(qname, cache_dom_list(qclass, qtype), 'Cache', False)
            if dom and dom != qname:
                queryhash = query_hash(dom, qclass, qtype)
                cacheentry = cache.get(queryhash, None)
                if cacheentry is not None:
                    rcode = str(RCODE[cacheentry[0].header.rcode])
                    if (not cacheentry[0].rr) and rcode in ('NODATA', 'NOERROR', 'NOTIMP', 'NXDOMAIN', 'REFUSED', 'SERVFAIL'):
                        reply = rc_reply(request, rcode)
                        if rcode == 'NOERROR':
                            rcode = 'NODATA'
                        log_info('CACHE-PARENT-MATCH [{0}]: \"{1}\" matches parent \"{2}\" {3}'.format(tid, qname, dom, rcode))
                        log_info('REPLY [{0}]: {1} = {2}'.format(tid, queryname, rcode))
                        now = int(time.time())
                        expire = cacheentry[1]
                        parentttlleft = expire - now
                        to_cache(qname, qclass, qtype, reply, force, parentttlleft, 'PARENT-MATCH-' + rcode) # Cache it

        if reply is None:
            # Block IPv4 based queries when client request comes in on IPv6
            if blockv4 is None and ipregex6.search(cip) and (qtype == 'A' or (qtype == 'PTR' and ip4arpa.search(qname))):
                log_info('AUTOBLOCK-IPV4-HIT [{0}]: Request from {1} for {2} {3}'.format(tid, cip, queryname, hitrcode))
                reply = rc_reply(request, hitrcode)

            # Block IPv6 based queries when client request comes in on IPv4
            elif blockv6 is None and ipregex4.search(cip) and (qtype == 'AAAA' or (qtype == 'PTR' and ip6arpa.search(qname))):
                log_info('AUTOBLOCK-IPV6-HIT [{0}]: Request from {1} for {2} {3}'.format(tid, cip, queryname, hitrcode))
                reply = rc_reply(request, hitrcode)

            # Search-Domain blocker
            elif blocksearchdom and searchdom:
                for sdom in searchdom:
                    if qname.endswith('.' + sdom):
                        dname = qname.rstrip('.' + sdom)
                        if in_cache(dname, 'IN', qtype):
                            log_info('SEARCH-HIT [{0}]: \"{1}\" matched \"{2} . {3}\"'.format(tid, qname, dname, sdom))
                            reply = rc_reply(request, 'NOERROR') # Empty response, NXDOMAIN provides other search-requests
                            break

        # Generate ALIAS response when hit !!! Needs to be last in if-elif chain
        if reply is None:
            generated = in_regex(qname, aliases_rx, True, 'Generator') or False
            reply = generate_alias(request, qname, qtype, use_tcp, force, generated)

        # Check query/response against lists
        if reply is None:
            queryfiltered = False
            if filtering:
                if checkrequest is False:
                    log_info('UNFILTERED-QUERY [{0}]: {1}'.format(tid, queryname))
                    reply = dns_query(request, qname, qtype, use_tcp, rid, cip, True, force)
                else:
                    # Check against lists
                    ismatch = match_blacklist(rid, 'REQUEST', qtype, qname)
                    if ismatch is True: # Blacklisted
                        reply = generate_response(request, qname, qtype, redirect_addrs, force, 'REQUEST-BLACKLISTED')
                    elif ismatch is None and checkresponse: # Not listed
                        reply = dns_query(request, qname, qtype, use_tcp, rid, cip, True, force)
                    else: # Whitelisted
                        reply = dns_query(request, qname, qtype, use_tcp, rid, cip, False, force)

            else: # Non-filtering
                reply = dns_query(request, qname, qtype, use_tcp, rid, cip, False, force)

    else:
        queryfiltered = False

    # Cache if REQUEST/Query is filtered
    if reply:
        if queryfiltered:
            #ttl = normalize_ttl(qname, reply.rr)
            to_cache(qname, 'IN', qtype, reply, force, filterttl, 'REQUEST-BLACKLISTED')

        # Cleanup NOTIMP responses
        if str(RCODE[reply.header.rcode]) == 'NOTIMP':
            reply.add_ar(EDNS0())

    # Catch-all
    else:
        reply = rc_reply(request, 'SERVFAIL')
        log_err('REPLY-NONE [{0}]: Request from {1} for {2} = SERVFAIL'.format(tid, cip, queryname))

    log_info('FINISHED [{0}]: Request from {1} for {2}'.format(tid, cip, queryname))

    return reply


'''
### START OF MODIFIED DNSLIB CODE ###
Next classes/defs are taken/copied/tweaked from dnslib and modified to
allow listening on IPv6 sockets.
'''
class UDPServer4(socketserver.ThreadingMixIn,socketserver.UDPServer):
    '''IPv4 UDP Socket'''
    allow_reuse_address = True
    address_family = socket.AF_INET


class TCPServer4(socketserver.ThreadingMixIn,socketserver.TCPServer):
    '''IPv4 TCP Socket'''
    allow_reuse_address = True
    address_family = socket.AF_INET


class UDPServer6(socketserver.ThreadingMixIn,socketserver.UDPServer):
    '''IPv6 UDP Socket'''
    allow_reuse_address = True
    address_family = socket.AF_INET6


class TCPServer6(socketserver.ThreadingMixIn,socketserver.TCPServer):
    '''IPv6 TCP Socket'''
    allow_reuse_address = True
    address_family = socket.AF_INET6


class DNSServer(object):
    '''DNS Server'''
    def __init__(self,resolver,
                      address='',
                      port=53,
                      tcp=False,
                      logger=None,
                      handler=DNSHandler,
                      server=None):
        '''
            resolver:   resolver instance
            address:    listen address (default: '')
            port:       listen port (default: 53)
            tcp:        UDP (false) / TCP (true) (default: False)
            logger:     logger instance (default: DNSLogger)
            handler:    handler class (default: DNSHandler)
            server:     socketserver class (default: UDPServer/TCPServer)
        '''
        if not server:
            if tcp:
                if ':' in address:
                    server = TCPServer6
                else:
                    server = TCPServer4
            else:
                if ':' in address:
                    server = UDPServer6
                else:
                    server = UDPServer4

        self.server = server((address,port),handler)
        self.server.resolver = resolver
        self.server.logger = logger or DNSLogger()

    def start(self):
        '''Start DNS Server'''
        self.server.serve_forever()

    def start_thread(self):
        '''Start DNS Server thread'''
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.daemon = True
        self.thread.start()

    def stop(self):
        '''Stop DNS Server'''
        self.server.shutdown()

    def isAlive(self):
        '''Check if server is running'''
        return self.thread.isAlive()

'''
### END OF MODIFIED DNSLIB CODE ###
'''


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
    Number: <varname> = <integer>
    Boolean: <varname> = <True|False|None>
    List: <varname> = <value1>,<value2>,<value3>, ...
    Dictionary (with list values): <varname> = <key> > <value1>,<value2>,<value3>, ...
    '''
    if file and file_exist(file, False):
        log_info('CONFIG: Loading config from config-file \"{0}\"'.format(file))
        try:
            f = open(file, 'r')
            #lines = f.readlines()
            lines = f.read().splitlines()
            f.close()

        except BaseException as err:
            log_err('ERROR: Unable to open/read/process file \"{0}\" - {1}'.format(file, err))

        for line in lines:
            entry = line.strip()
            if entry and (not entry.startswith('#')):
                elements = regex.split('\s*=\s*', entry)
                if elements[1:]:
                    var = str(elements[0])
                    val = elements[1].strip()
                    if val and val.upper() != 'DEFAULT':
                        if val.find('>') != -1:
                            dictelements = regex.split('\s*>\s*', val)
                            key = dictelements[0]
                            val = dictelements[1]
                            log_info('CONFIG-SETTING-DICT: {0}[{1}] = {2}'.format(var, key, val))
                            globals()[var] = {key : regex.split('\s*,\s*', val)}
                        elif val.startswith('\'') and val.endswith('\''):
                            log_info('CONFIG-SETTING-STR: {0} = {1}'.format(var, val))
                            globals()[var] = str(regex.split('\'', val)[1].strip())
                        elif val.lower() in ('false', 'none', 'true'):
                            log_info('CONFIG-SETTING-BOOL: {0} = {1}'.format(var, val))
                            if val.lower() == 'true':
                                globals()[var] = bool(1)
                            else:
                                globals()[var] = bool(0)
                        elif regex.match('^[0-9]+$', val):
                            log_info('CONFIG-SETTING-INT: {0} = {1}'.format(var, val))
                            globals()[var] = int(val)
                        else:
                            log_info('CONFIG-SETTING-LIST: {0} = {1}'.format(var, val))
                            globals()[var] = regex.split('\s*,\s*', val)

    else:
        log_info('CONFIG: Skipping config from file, config-file \"{0}\" does not exist'.format(file))


    if blocksearchdom and file_exist(resolvfile, False):
        log_info('CONFIG: Loading domains from \"{0}\"'.format(resolvfile))
        try:
            f = open(resolvfile, 'r')
            #lines = f.readlines()
            lines = f.read().splitlines()
            f.close()

        except BaseException as err:
            log_err('ERROR: Unable to open/read/process file \"{0}\" - {1}'.format(resolvfile, err))

        for line in lines:
            entry = regex.split('#', line)[0].strip().lower()
            if entry:
                elements = regex.split('\s+', entry)
                if elements[0] == 'domain' or elements[0] == 'search':
                    for dom in elements[1:]:
                        if dom not in searchdom:
                            log_info('CONFIG: Fetched {0} \"{1}\" from \"{2}\"'. format(elements[0], dom, resolvfile))
                            searchdom.add(dom)

    return True


def get_dns_servers(file, fservers):
    log_info('CONFIG: Loading nameservers from \"{0}\"'.format(file))
    try:
        f = open(file, 'r')
        #lines = f.readlines()
        lines = f.read().splitlines()
        f.close()

    except BaseException as err:
        log_err('ERROR: Unable to open/read/process file \"{0}\" - {1}'.format(file, err))

    ns = list()
    for line in lines:
        entry = regex.split('#', line)[0].strip().lower()
        if entry:
            elements = regex.split('\s+', entry)
            if elements[0] == 'nameserver':
                for ip in elements[1:]:
                    if ip not in ns and ipregex.search(ip):
                        log_info('CONFIG: Fetched {0} \"{1}\" from \"{2}\"'.format(elements[0], ip, file))
                        ns.append(ip)

    if ns:
        if '.' in fservers:
            fservers['.'] += ns
        else:
            fservers['.'] = ns

    return fservers


#def white_label(domlist):
#    '''Add all labels of whitelisted domains to freqency list'''
#    wordlist = set()
#    worddict = dict()
#    for dom in domlist:
#        if (not ipregex.search(dom)) and (not iparpa.search(dom)):
#            for label in regex.split('[\._-]', dom):
#                if label[2:] and (label not in wordlist) and (not isnum.search(label)):
#                    wordlist.add(label)
#
#    # Add some static words !!! ADD this as config option !!!
#    wordlist.add('amazon')
#    wordlist.add('amazonaws')
#    wordlist.add('apple')
#    wordlist.add('facebook')
#    wordlist.add('google')
#    wordlist.add('youtube')
#
#    worddict['whitelist'] = list(wordlist)
#    add_frequency_lists(worddict)
#    log_info('WHITELIST: Added {0} labels to randomness-guesser'.format(len(wordlist)))
#
#    return True


if __name__ == '__main__':
    '''Main beef'''

    log_info('-----------------------')
    log_info('Initializing INSTIGATOR')

    if debug: log_info('RUNNING INSTIGATOR IN *DEBUG* MODE')

    log_info('BASE-DIR: {0}'.format(basedir))

    read_config(configfile)

    # Load/Read lists
    loadcache = False
    if alwaysfresh or (not load_lists(savefile)):
        #for lst in lists.keys():
        for lst in lists:
            if lst in whitelist:
                wl_dom, wl_ip4, wl_ip6, wl_rx, aliases_rx, aliases, forward_servers, ttls, wl_asn = read_list(lists[lst], lst, 'Whitelist', wl_dom, wl_ip4, wl_ip6, wl_rx, aliases_rx, aliases, forward_servers, ttls, wl_asn)
            else:
                bl_dom, bl_ip4, bl_ip6, bl_rx, _, _, _, _, bl_asn = read_list(lists[lst], lst, 'Blacklist', bl_dom, bl_ip4, bl_ip6, bl_rx, dict(), dict(), dict(), dict(), bl_asn)

        # Load IPASN
        if ipasnfile:
            ipasn4, ipasn6 = load_asn(ipasnfile, ipasn4, ipasn6)

        # Get DNS servers from resolv.conf
        if '.' not in forward_servers:
            forward_servers = get_dns_servers(resolvfile, forward_servers)

        # Whitelist used addresses to unbreak services
        for ip in redirect_addrs:
            ip = expand_ip(ip.split('@')[0])
            if ipregex.search(ip) and (ip not in wl_ip4) and (ip not in wl_ip6):
                log_info('WHITELIST: Added Redirect-Address \"{0}\"'.format(ip))
                if is_v6(ip):
                    wl_ip6[ip] = 'Redirect-Address'
                else:
                    wl_ip4[ip] = 'Redirect-Address'

        # Whitelist forward domains/servers
        #for dom in forward_servers.keys():
        for dom in forward_servers:
            if not in_domain(dom, wl_dom, 'Whitelist', False) and (dom != '.'):
                log_info('WHITELIST: Added Forward-Domain \"{0}\"'.format(dom))
                wl_dom[dom] = 'Forward-Domain'
            for ip in forward_servers[dom]:
                if ipregex.search(ip) and (ip not in wl_ip4) and (ip not in wl_ip6):
                    log_info('WHITELIST: Added Forward-Address \"{0}\"'.format(expand_ip(ip)))
                    if is_v6(ip):
                        wl_ip6[expand_ip(ip)] = 'Forward-Address'
                    else:
                        wl_ip4[ip] = 'Forward-Address'

        # Whitelist alias domains
        #for dom in aliases.keys():
        for dom in aliases:
            if not in_domain(dom, wl_dom, 'Whitelist', False) and (dom != '.'):
                log_info('WHITELIST: Added Alias-Domain \"{0}\"'.format(dom))
                wl_dom[dom] = 'Alias-Domain'

        # Whitelist search domains
        for dom in searchdom:
            if not in_domain(dom, wl_dom, 'Whitelist', False) and (dom != '.'):
                log_info('WHITELIST: Added Search-Domain \"{0}\"'.format(dom))
                wl_dom[dom] = 'Search-Domain'

        # Add command-tld to whitelist
        log_info('WHITELIST: Added Command-Domain \"{0}\"'.format(command))
        wl_dom[command] = 'Command-TLD'

        # Optimize lists
        wl_ip4 = reduce_ip(wl_ip4, 'IPv4 Whitelist')
        bl_ip4 = reduce_ip(bl_ip4, 'IPv4 Blacklist')
        bl_ip4 = unwhite_ip(wl_ip4, bl_ip4, 'IPv4 Blacklist')

        wl_ip6 = reduce_ip(wl_ip6, 'IPv6 Whitelist')
        bl_ip6 = reduce_ip(bl_ip6, 'IPv6 Blacklist')
        bl_ip6 = unwhite_ip(wl_ip6, bl_ip6, 'IPv6 Blacklist')

        wl_dom = reduce_dom(wl_dom, 'Domain Whitelist')
        bl_dom = reduce_dom(bl_dom, 'Domain Blacklist')

        wl_dom = unblack_dom(bl_dom, wl_dom, 'Domain Forced Black/Whitelist') # Remove forced blacklist entries from whitelist

        bl_dom = unwhite_dom(wl_dom, bl_dom, 'Domain White/Blacklist')

        wl_dom = unreg_dom(wl_rx, wl_dom, 'Domains Whitelist')
        bl_dom = unreg_dom(bl_rx, bl_dom, 'Domain Blacklist')
        bl_dom = unreg_dom(wl_rx, bl_dom, 'Domain White/Blacklist')

        bl_asn = unwhite_asn(wl_asn, bl_asn, 'ASN White/Blacklist')

        save_lists(savefile)

    else:
        loadcache = True # Only load cache if savefile didn't change


    ## Add all labels of whitelisted domains to freqency list for DGA/Randomness detection
    #white_label(wl_dom)

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
            if elements[1:]:
                listen_port = int(elements[1])
            else:
                listen_port = 53

            if listen_address == '':
                log_info('Starting DNS Service at port {0} ...'.format(listen_port))
            else:
                log_info('Starting DNS Service on {0} at port {1} ...'.format(listen_address, listen_port))

            # Define Service
            #handler = DNSHandler
            #if ipregex6.search(listen_address):
            #    log_info('LISTENING on IPv6 ({0}@{1}) not supported yet!'.format(listen_address, listen_port))
            #    serverhash = False
            #    #serverhash = hash(listen_address + '@' + str(listen_port))
            #    #udp_dns_server[serverhash] = DNSServer(DNS_Instigator(), address=listen_address, port=listen_port, logger=logger, tcp=False, handler=handler) # UDP
            #    #tcp_dns_server[serverhash] = DNSServer(DNS_Instigator(), address=listen_address, port=listen_port, logger=logger, tcp=True, handler=handler) # TCP
            #else:
            serverhash = hash(listen_address + '@' + str(listen_port))
            udp_dns_server[serverhash] = DNSServer(DNS_Instigator(), address=listen_address, port=listen_port, logger=logger, tcp=False, handler=handler) # UDP
            tcp_dns_server[serverhash] = DNSServer(DNS_Instigator(), address=listen_address, port=listen_port, logger=logger, tcp=True, handler=handler) # TCP

            # Start Service as threads
            if serverhash:
                try:
                    udp_dns_server[serverhash].start_thread() # UDP
                    tcp_dns_server[serverhash].start_thread() # TCP
                except BaseException as err:
                    log_err('ERROR: Unable to start service on {0} at port {1} - {2}, ABORTING'.format(listen_address, listen_port, err))
                    sys.exit(1)

                time.sleep(0.5)

                if udp_dns_server[serverhash].isAlive() and tcp_dns_server[serverhash].isAlive():
                    if listen_address == '':
                        log_info('DNS Service ready at port {0}'.format(listen_port))
                        break
                    else:
                        log_info('DNS Service ready on {0} at port {1}'.format(listen_address, listen_port))
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
                    cache_maintenance(False, False, cachelist, prefetchlist)

    except (KeyboardInterrupt, SystemExit):
        log_info('INSTIGATOR SHUTTING DOWN')


    # Shutdown ports
    for listen in listen_on:
        if ipportregex.search(listen):
            elements = listen.split('@')
            listen_address = elements[0]

            if elements[1:]:
                listen_port = int(elements[1])
            else:
                listen_port = 53

            serverhash = hash(listen_address + '@' + str(listen_port))

            log_info('DNS Service shutdown on {0} at port {1} ...'.format(listen_address, listen_port))

            try:
                udp_dns_server[serverhash].stop() # UDP
                tcp_dns_server[serverhash].stop() # TCP

            except BaseException as err:
                log_err('ERROR: Unable to stop service on {0} at port {1} - {2}'.format(listen_address, listen_port, err))

    # Save persistent cache
    save_cache(cachefile)

    log_info('INSTIGATOR EXIT')
    log_info('---------------')
    sys.exit(0)

# <EOF>
