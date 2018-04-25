# DNS Instigator
Testbed to build a filtering DNS server based on dnslib

See 'instigator.py' for variables and settings.

Black/White.list syntax:

IP-Addresses can be either just an IP-Address or a CIDR subnet, example:

	192.168.1.1
	10.1.2.0/25
	194.188.1.128/25

Domains are just domains, will also apply to sub-domains, example:

	company.com
	ad.doubleclick.ney
	blah.test.invalid
	info

Regexes need to be secluded in forward slashes at begin and end of the line, example:

	/^ad[sz]*[0-9]*\..*$/
	/^.*click\..*$/
	/.*porn.*/
