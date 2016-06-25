#!/usr/bin/perl

# Copyright 2009 Matthew A. Kucenski
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

use strict;
use warnings;

use mkucenski::SQLWhois;
use mkucenski::SmartXMLDBWhois;
use XML::Simple;
use Data::Dumper;

my $db = mkucenski::SQLWhois->new("SQLWhois", "localhost", "root", "");
$db->debug(4);
my $whois = mkucenski::SmartXMLDBWhois->new("<server>", "43", "SQLWhois", "localhost", "root", "");
$whois->debug(4);

my $query = "SELECT * FROM tbl_NetmaskRaw WHERE Netmask REGEXP '^189'";
foreach ($db->_querySQLMany($query)) {
	print "------------------------------\n" . $_->{Netmask} . "\n------------------------------\n";
	my $xml;
	eval { $xml = XMLin($_->{XML}) };
	#$whois->processXML($_->{XML});
	$whois->processRaw($_->{Raw}, undef, $xml->{QueryResult}->{ServerName});
	#last;
}