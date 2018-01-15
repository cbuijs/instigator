#!/usr/bin/env python
'''
=========================================================================================
 instigator.py: v0.2-20180115 Copyright (C) 2017 Chris Buijs <cbuijs@chrisbuijs.com>
=========================================================================================

 Python DNS Server with security and filtering features

- Better Documentation / Remarks / Comments

=========================================================================================
'''

# Standard modules
import sys

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

# Timeout on forwarding
timeout = 20

# Listen on
listen = '127.0.0.1'
listen_port = 5053

# Forwarding queries to
forward_dns = '9.9.9.9' # Quad9
forward_port = 53

# Redirect when blacklisted, leave empty for "Refused"
#redirect_address = '192.168.1.250'
redirect_address = ''
redirect_host = 'dummy'

class SubProxy(ProxyResolver):
    def __init__(self, address, port, timeout, answer, host):
        ProxyResolver.__init__(self, address, port, timeout)
        self.answer = answer
        self.host = host

    def resolve(self, request, handler):
        if in_list('black', request.q.qname):
            reply = request.reply()

            if len(self.host) == 0:
                reply.header.rcode = getattr(RCODE,'REFUSED')
            else:
                answer = RR(rdata=A(self.host))
                answer.set_rname(request.q.qname)
                reply.add_answer(answer)
                reply.header.rcode = getattr(RCODE,'NOERROR')

            return reply
        else:
            return ProxyResolver.resolve(self, request, handler)

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
       

if __name__ == '__main__':
    import time

    resolver = SubProxy(address=forward_dns, port=forward_port, timeout=timeout, answer=redirect_host, host=redirect_address) 

    server = DNSServer(resolver, address=listen, port=listen_port)
    
    server.start_thread()

    while server.isAlive():
        time.sleep(1)
