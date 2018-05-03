# DNS Instigator
Testbed to build a filtering DNS server based on dnslib

See <a href="https://github.com/cbuijs/instigator/blob/master/instigator.py">instigator.py</a> for variables and settings.

Black/White/Alias-list syntax:

IP-Addresses can be either just an IP-Address or a CIDR subnet, example:

	192.168.1.1		Will give a hit on address 192.168.1.1
	10.1.2.0/25		Will give a hit on all addresses in 10.1.2.0/25 including network and broadcast address
	194.188.1.128/32	Same as a single address
	2001::1/128		Single IPv6 address
	1234:aa:bb:cdef::/64	All addresses in a IPv6 /64 subnet including network and broadcast address

Domains are just domains, will also apply to sub-domains, example:

	company.com		Will give a hit on domain company.com and all domains ending om .company.com
	ad.doubleclick.net	Will give a hit on domain doubleclick.net and all domains ending in .ad.doubleclick.net
	blah.test.invalid	Will give a hit on domain blah.test.invalid and all domains ending in .bla.test.invalid
	info			Will give a hit on domain info and all domains ending in .info

Regexes need to be secluded in forward slashes at begin and end of the line, example:

	/^ad[sz]*[0-9]*\..*$/	Will give a hit on domains starting with ad, ads or adz and have an optional number after it.
	/^.*click\..*$/		Will give a hit on domain-labels ending in click
	/.*porn.*/              Will give a hit on domain-labels with the word porn in it

Aliases need to be divided by an equals-sign (=), example:

	www.google.com=retricted.google.com	# Redirect
	www.company.com=10.1.2.3		# Hosts-file equivelant
	www.badguys.com=REFUSED			# Return-code refused
	www.whatisthis.com=NXDOMAIN		# Return-code NXDOMAIN
	www.goodguys.com=PASSTHRU		# Passthru/whitelist
	
Note: Aliases are concidered "whitelisted". Cannot point to other aliases.
