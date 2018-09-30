# DNS Instigator
Testbed to build a filtering DNS server based on dnslib.

<b>Note/Disclaimer:</b> This code is as-is, changes frequently, sometimes well tested, sometimes not and is badly documented. Use at own risk!

<a href="https://www.dwheeler.com/sloccount/">SLOC-Count:</a> $ 952,364.-

Use the <a href="https://github.com/cbuijs/instigator/issues">Issues</a> tab to report anything I could/should help on or should include as feature/fix, and I will try my best.

See <a href="https://github.com/cbuijs/instigator/blob/master/instigator.py">instigator.py</a> for variables and settings.

Black/White/Alias-list syntax:

IP-Addresses can be either just an IP-Address or a CIDR subnet, example:

	192.168.1.1		Will give a hit on address 192.168.1.1
	10.1.2.0/25		Will give a hit on all addresses in 10.1.2.0/25 including network and broadcast address
	194.188.1.128/32	Same as a single address
	2001::1/128		Single IPv6 address
	1234:aa:bb:cdef::/64	All addresses in a IPv6 /64 subnet including network and broadcast address

Domains are just domains, but include sub-domains as well, example:

	company.com		Will give a hit on domain company.com and all domains ending in .company.com
	ad.doubleclick.net	Will give a hit on domain ad.doubleclick.net and all domains ending in .ad.doubleclick.net
	blah.test.invalid	Will give a hit on domain blah.test.invalid and all domains ending in .bla.test.invalid
	info			Will give a hit on domain info and all domains ending in .info

Regexes need to be secluded in forward slashes at begin and end of the line, example:

	/^ad[sz]*[0-9]*\..*$/	Will give a hit on domains starting with ad, ads or adz and have an optional number after it.
	/^.*click\..*$/		Will give a hit on domain-labels ending in click
	/.*porn.*/              Will give a hit on domain-labels with the word porn in it

Aliases need to be divided by an equals-symbol (=), example (domains include sub-domains):

	www.google.com=retricted.google.com	# Redirect
	www.company.com=10.1.2.3		# Hosts-file equivelant, but includes sub-domains as well
	www.badguys.com=REFUSED			# Return-code REFUSED for domain and sub-domains
	www.whatisthis.com=NXDOMAIN		# Return-code NXDOMAIN for domain and sub-domains
	www.goodguys.com=PASSTHRU		# Passthru/whitelist domain and sub-domains
	blahblah.com=RANDOM			# Generate random answers (A, AAAA and CNAME) for domain and sub-domains

	Note: Aliases only work on queries/requests.

Forwarders need to be divided by a greater-then-symbol (>), port numbers can be used using the at-sign (@), example:

	google.com>8.8.8.8@53,8.8.4.4@53		# Use google dns for all domains ending in google.com
	chrisbuijs.com>9.9.9.9@53,149.112.112.112@53	# Use Quad9 dns servers for all domains ending in chrisbuijs.com

TTL overrides can be done by using an exclamation (!), example (TTL in seconds):

	google.com!666		# Use TTL of 666 for domain google.com and all sub-domains ending in .google.com
	chrisbuijs.com!120	# Use a TTL of 120 for domain chrisbuijs.com and all sub-domains ending in .chrisbuijs.com

Defining search-domains can be doe using an asterix (*) and the end of the domain-name, example:

	lan*		# .lan search-domain
	company.com*	# .company.com search-domain

	Note: When search-domains are defined, domains that are already in cache (example: www.blah.com), will not be
	      forwarded when ending in a search-domain (example: www.blah.com.company.com).

	
<b>Note:</b> Aliases/Forwarders/TTL-Overrides/Search-Domains are automatically "whitelisted", and cannot point to other aliases. For forwarders port-number is optional (default of 53 is assumed).
