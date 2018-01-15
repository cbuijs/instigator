#!/usr/bin/env python
'''
=========================================================================================
 instigator.py: v0.3-20180115 Copyright (C) 2017 Chris Buijs <cbuijs@chrisbuijs.com>
=========================================================================================

 Python DNS Server with security and filtering features

- Better Documentation / Remarks / Comments

=========================================================================================
'''

# Standard modules
import sys, time

# make sure modules can be found
sys.path.append("/usr/local/lib/python2.7/dist-packages/")

# DNSLib module
from dnslib import RR, A, CNAME, MX, PTR, SRV, RCODE
from dnslib.proxy import ProxyResolver
from dnslib.server import DNSServer

# Blacklist
blacklist = dict()
blacklist['doubleclick.net'] = True
blacklist['google-analytics.com'] = True
blacklist['google-analytics.com'] = True

# Listen for queries
listen_address = '127.0.0.1'
listen_port = 5053

# Forwarding queries to
forward_address = '9.9.9.9' # Quad9
forward_port = 53
forward_timeout = 20 # Seconds

# Redirect when blacklisted, leave empty for "Refused"
redirect_address = '192.168.1.250'
#redirect_address = ''
redirect_host = 'sinkhole' # For CNAME, MX, PTR, SRV


# Check if entry matches a list
def in_list(type, name):
    name = str(name).rstrip('.').lower()
    testname = name
    blacklisted = False
    while True:
        if testname in blacklist:
            blacklisted = True
            print ('HIT: \"' + name + '\" matched against \"' + testname + '\"')
            break
        elif testname.find('.') == -1:
            break
        else:
            testname = testname[testname.find('.') + 1:]
            print ('Checking \"' + name + '\" against \"' + testname + '\"')

    if blacklisted:
        return testname
    else:
        return False
       

class DNS_Instigator(ProxyResolver):
    def __init__(self, forward_address, forward_port, forward_timeout, redirect_host, redirect_address):
        ProxyResolver.__init__(self, forward_address, forward_port, forward_timeout)
        self.redirect_host = redirect_host
        self.redirect_address = redirect_address

    def resolve(self, request, handler):
        if in_list('black', request.q.qname):
            reply = request.reply()

            if len(self.redirect_address) == 0:
                reply.header.rcode = getattr(RCODE,'REFUSED')
            else:
                answer = RR(ttl=1800, rdata=A(self.redirect_address))
                answer.set_rname(request.q.qname)
                reply.add_answer(answer)
                reply.header.rcode = getattr(RCODE,'NOERROR')

            return reply
        else:
            return ProxyResolver.resolve(self, request, handler)


# The main beef
if __name__ == '__main__':

    # Resolver
    dns_resolver = DNS_Instigator(forward_address=forward_address, forward_port=forward_port, forward_timeout=forward_timeout, redirect_host=redirect_host, redirect_address=redirect_address) 

    # Server
    dns_server = DNSServer(dns_resolver, address=listen_address, port=listen_port)

    # Start server
    dns_server.start_thread()

    # Keep things running
    while dns_server.isAlive():
        time.sleep(1)

