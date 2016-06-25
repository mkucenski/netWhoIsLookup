# netWhoIsLookup
Python-based "Smart" Whois client and libraries for identifying large numbers of IP addresses (out-of-date, untested)


## Client Installation

* Debian packages needed:
* libclass-dbi-mysql-perl
* libnet-ip-perl
* libnet-netmask-perl
* libnet-telnet-perl

* cp SmartXMLDBWhoisClient.pl /usr/local/bin/
* mkdir -p /usr/local/lib/site_perl/mkucenski
* cp mkucenski/SQLWhois.pm /usr/local/lib/site_perl/mkucenski/
* cp mkucenski/SmarXMLDBWhois.pm /usr/local/lib/site_perl/mkucenski/
* cp mkucenski/Debug.pm /usr/local/lib/site_perl/mkucenski/

## Client Usage

SmartXMLDBWhoisClient.pl <case-identifier> <ip-address>

-or-

cat <ip-address-list-file.txt> | xargs -L 1000 | SmartXMLDBWhoisClient.pl <case-identifier> 

## Server Installation

* Install MySQL (v5) on a Windows/FreeBSD/Linux server.
* Create a new database (schema) named 'SQLWhois'.
* Create tables found in 'tableCreate.sql'.
* Create a user named 'smartxmldb'.
* Grant 'smartxmldb' SELECT, INSERT, UPDATE, DELETE privileges on 'SQLWhois'.
* Modify SmartXMLDBWhoisClient.pl with the password assigned to 'smartxmldb'.
