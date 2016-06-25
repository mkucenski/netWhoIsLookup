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

use mkucenski::SmartXMLDBWhois;
use Data::Dumper;

my $whois = mkucenski::SmartXMLDBWhois->new("<server>", "<port>", "<user>", "<server>", "<user>", "<password>");
if ($whois) {
	$whois->debug(2);
	
	my $caseNum = shift;
	#print STDERR "Case: $caseNum\n";
	print $whois->csvHeaders() . "\n";
	foreach (@ARGV) {
		#print STDERR "IP: $_\n";
		my $rv = $whois->whoisCSV($_);
		if ($rv) {
			$whois->addToCase($caseNum, $_);
			print $rv . "\n";
		} else {
			print "\"$_\",\"Error\"\n";
		}
	}
} else {
	print STDERR "SmartXMLDBWhoisClient: Invalid SmartXMLDBWhois object\n";
}
print STDERR "SmartXMLDBWhoisClient.pl Exiting...\n";

