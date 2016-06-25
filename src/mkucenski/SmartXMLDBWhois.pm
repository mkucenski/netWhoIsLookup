package mkucenski::SmartXMLDBWhois;

use strict;
use warnings;

use mkucenski::SQLWhois;
use Net::IP;
use Net::Netmask;
use Net::Telnet;
use XML::Simple;
use Data::Dumper;

sub new {
	my $class = shift;
	if (@_ && ($#_ + 1) == 6) {
		my ($whoisServer, $whoisPort, $dbName, $dbServer, $dbUser, $dbPassword) = @_;
		
		my $self  = {	DB			=> undef,
						WHOISSERVER	=> $whoisServer,
						WHOISPORT	=> $whoisPort,
						_DEBUG		=> 0
		};
		
		# Setup the database object
		$self->{DB} = mkucenski::SQLWhois->new($dbName, $dbServer, $dbUser, $dbPassword);
		if ($self->{DB}) {
			bless ($self, $class);
			return $self;
		} else {
			print STDERR "SmartXMLDBWhois:new() Error creating SQLWhois object.\n";
		}
	} else {
		print STDERR "SmartXMLDBWhois:new() Incorrect number of parameters (" . ($#_ + 1) . ") sent to new().\n";
	}
	return undef;
}

sub debug {
	my $self = shift;
	if (@_) {
		my ($level) = @_;
		$self->{_DEBUG} = new mkucenski::Debug($level);
		$self->{DB}->debug($level);
		return "true";
	} else {
		print STDERR "SmartXMLDBWhois:debug() No parameters\n";
	}
	return undef;
}

sub whois {
	my $self = shift;
	if (@_) {
		my ($ipStr, $briefOutput, $csvOutput, $xmlOutput) = @_;
		
		# Build an IP object to ensure the IP requested is valid.
		my $ip = new Net::IP ($ipStr);
		if ($ip) {
			# First check to see if this IP is already stored as a failed IP.
			if (!$self->{DB}->checkForFailedIP($ip->ip())) {
				if ($self->{DB}) {
					# Try to query the database for an answer first.		
					my $dbAnswer = $self->{DB}->query($ip->ip(), $briefOutput, $csvOutput, $xmlOutput);
					if ($dbAnswer) {
						return $dbAnswer;
					} else {
						# Ask the whois server to retrieve the requested data.
						$self->{_DEBUG}->debug(3, "SmartXMLDBWhois", "whois", "Querying network whois for: " . $ip->ip());
						# Query attempt #1
						my $xmlStr = $self->_queryWhoisServer($ip->ip());
						if ($xmlStr) {
							my $rv = $self->processXML($xmlStr, $ip->ip());
							if ($rv && $rv eq "waitRetry") {
								# Query attempt #2
								print STDERR "Whois proxy reached rate limit.  Sleeping 10 seconds...\n";
								sleep 10;
								my $xmlStr = $self->_queryWhoisServer($ip->ip());
								if ($xmlStr) {
									$rv = $self->processXML($xmlStr, $ip->ip());
									if ($rv && $rv eq "waitRetry") {
										# Query attempt #3
										print STDERR "Whois proxy reached rate limit.  Sleeping 60 seconds...\n";
										sleep 60;
										my $xmlStr = $self->_queryWhoisServer($ip->ip());
										if ($xmlStr) {
											$rv = $self->processXML($xmlStr, $ip->ip());
										} else {
											$self->{_DEBUG}->debug(1, "SmartXMLDBWhois", "whois", "No response from whois server for <" . $ip->ip() . "> on third attempt.");
										}
									}
								} else {
									$self->{_DEBUG}->debug(1, "SmartXMLDBWhois", "whois", "No response from whois server for <" . $ip->ip() . "> on second attempt.");
								}
							}

							# Check if any of the above processing attempts succeeded.							
							if ($rv && $rv eq "true") {
								# Query the database for the newly added data.
								$dbAnswer = $self->{DB}->query($ip->ip(), $briefOutput, $csvOutput, $xmlOutput);
								if ($dbAnswer) {
									return $dbAnswer;
								} else {
									$self->{_DEBUG}->debug(1, "SmartXMLDBWhois", "whois", "Unexpectedly received no data from database");
								}
							} else {
								$self->{_DEBUG}->debug(1, "SmartXMLDBWhois", "whois", "XML processing failed");
							} # if ($rv && $rv eq "true")
						} else {
							$self->{_DEBUG}->debug(1, "SmartXMLDBWhois", "whois", "No response from whois server for <" . $ip->ip() . "> on first attempt.");
						}
					}
				} else {
					$self->{_DEBUG}->debug(1, "SmartXMLDBWhois", "whois", "Invalid database handle");
				}		
			} else {
				$self->{_DEBUG}->debug(1, "SmartXMLDBWhois", "whois", "Ignoring <" . $ipStr . ">, already stored as failed IP");
			}
		} else {
			$self->{_DEBUG}->debug(1, "SmartXMLDBWhois", "whois", "Net::IP returned invalid object");
		}
	} else {
		$self->{_DEBUG}->debug(1, "SmartXMLDBWhois", "whois", "No parameters sent to query()");
	}
	return undef;
}

sub whoisBrief {
	my $self = shift;
	return $self->whois(@_, 1, 0, 0);
}

sub whoisCSV {
	my $self = shift;
	return $self->whois(@_, 0, 1, 0);
}

sub whoisXML {
	my $self = shift;
	return $self->whois(@_, 0, 0, 1);
}

sub csvHeaders {
	my $self = shift;
	return $self->{DB}->csvHeaders();
}

sub briefHeaders {
	my $self = shift;
	return $self->{DB}->briefHeaders();	
}

sub addToCase {
	my $self = shift;
	if (@_) {
		my ($caseNum, $ipStr) = @_;
		return $self->{DB}->addIPToCase($caseNum, $ipStr);
	} else {
		$self->{_DEBUG}->debug(1, "SmartXMLDBWhois", "addToCase", "Invalid parameter(s).");
	}
	return undef;
}

sub processXML {
	my $self = shift;
	if (@_) {
		my ($xmlStr, $ipStr) = @_;
		my $rawStr;

		# TODO ...
		#	1: Check for valid proxy parsing.
		#		1a: Store in the database
		#	2: If that fails, parse manually.
		#		2a: Store in the database
		#	3: If that fails, store in DB for manual review.

		my $xml;
		$xml = $self->_stringToXML($xmlStr);
		if ($xml) {
			if ($xml->{ErrorCode} eq "Success") {
				$self->{_DEBUG}->debug(3, "SmartXMLDBWhois", "processXML", "Attempting to parse primary result for <$ipStr>...");
				if ($self->_processQueryResult($xml->{QueryResult}, $ipStr)) {
					return "true";
				} else {
					#MAK if ($xml->{QueryResult}->{QueryResult}) {
					#MAK 	$self->{_DEBUG}->debug(3, "SmartXMLDBWhois", "processXML", "Attempting to parse secondary result for <$ipStr>...");
					#MAK 	if ($self->_processQueryResult($xml->{QueryResult}->{QueryResult}, $ipStr)) {
					#MAK 		return "true";
					#MAK 	} else {
					#MAK 		$self->{_DEBUG}->debug(1, "SmartXMLDBWhois", "processXML", "Failure parsing primary and secondary results for <$ipStr>.");
					#MAK 	}
					#MAK } else {
					#MAK 	$self->{_DEBUG}->debug(2, "SmartXMLDBWhois", "processXML", "No secondary result found for <$ipStr>.");
					#MAK }
				}
			} else {
				my $proxyError = $xml->{ErrorCode};
				$self->{_DEBUG}->debug(1, "SmartXMLDBWhois", "processXML", "Whois proxy failure <$proxyError>");
				
				if ($proxyError eq "RequestsTooFast") {
					return "waitRetry";
				} elsif ($proxyError eq "RequestLimitReached") {
					return "waitRetry";
				} else {
				}
			} # if ($xml->{ErrorCode} eq "Success")
		} else {
			$self->{_DEBUG}->debug(1, "SmartXMLDBWhois", "processXML", "Invalid XML data");
		} # if ($xml)
		
		# Store as failed IP for manual review and to prevent future lookups
		$self->{_DEBUG}->debug(2, "SmartXMLDBWhois", "processXML", "Storing <" . $ipStr . "> as failed IP");
		$self->{DB}->addFailedIP($ipStr, $xmlStr, $rawStr);
	} else {
		$self->{_DEBUG}->debug(1, "SmartXMLDBWhois", "processXML", "No parameters sent to processXML()");
	}
	return undef;
}

sub _processQueryResult {
	my $self = shift;
	if (@_) {
		my ($xmlQueryResult, $ipStr) = @_;
		
		if ($xmlQueryResult) {
			my $rawStr = $xmlQueryResult->{WhoisRecord}->{RawText};
		
			my @netmasks;
			if ($xmlQueryResult->{ErrorCode} eq "Success") {
				if ($xmlQueryResult->{FoundMatch} ne "No") {
					my $netmaskStr = $xmlQueryResult->{WhoisRecord}->{Network}->{CIDR};
					my $ipRangeStr = $xmlQueryResult->{WhoisRecord}->{Network}->{IPRange};
					if ($netmaskStr) {
						push(@netmasks, $self->_netmasksFromNetmasks($netmaskStr));
					} elsif ($ipRangeStr) {
						push(@netmasks, $self->_netmasksFromIPRanges($ipRangeStr));
					} else {
						push(@netmasks, $self->_searchForNetmasks($rawStr));
					}
					
					# Retrieve all values that will be stored in the database for each Netmask
					my $id 		= $xmlQueryResult->{WhoisRecord}->{Registrant}->{ID};
					my $name	= $xmlQueryResult->{WhoisRecord}->{Registrant}->{Name};
					my $desc	= $self->_flatten($xmlQueryResult->{WhoisRecord}->{Registrant}->{Description});
					my $addr	= $self->_flatten($xmlQueryResult->{WhoisRecord}->{Registrant}->{Address});
					my $city	= $self->_flatten($xmlQueryResult->{WhoisRecord}->{Registrant}->{City});
					my $state	= $self->_flatten($xmlQueryResult->{WhoisRecord}->{Registrant}->{StateProvince});
					my $zip		= $xmlQueryResult->{WhoisRecord}->{Registrant}->{PostalCode};
					my $country	= $xmlQueryResult->{WhoisRecord}->{Registrant}->{Country};
					my $whois	= $xmlQueryResult->{ServerName};
					
					# Search raw text for an ID if missing
					if (!$id) {
						$id = $self->_searchForID($rawStr);
					}

					# Search raw text for a name if missing
					if (!$name) {
						$name = $self->_searchForName($rawStr);
					}
					
					# Search raw text for a description if missing
					if (!$desc) {
						$desc = $self->_searchForDescription($rawStr);
					}
					
					# Search raw text for an address if missing
					if (!$addr) {
						$addr = $self->_searchForAddress($rawStr);
					}

					# Search raw text for a country if missing
					if (!$country) {
						$name = $self->_searchForCountry($rawStr);
					}
					
					# Search raw text for a whois server if missing
					if (!$whois) {
						$whois = $self->_searchForWhois($rawStr);
					}
					
					if (@netmasks) {
						my $rv = undef;
						foreach (@netmasks) { # Add an entry for each netmask found
							if ($self->{DB}->add(	$_->desc(),
													$id,
													$name,
													$desc,
													$addr,
													$city,
													$state,
													$zip,
													$country,
													$whois,
													$self->_xmlToString($xmlQueryResult),
													$rawStr)) {
								$rv = "true";	# At least one netmask record has to succeed before returning true;
								$self->{_DEBUG}->debug(3, "SmartXMLDBWhois", "_processQueryResult", "Added netmask record for <" . $_->desc() . ">");
							} else {
								$self->{_DEBUG}->debug(1, "SmartXMLDBWhois", "_processQueryResult", "Failure adding netmask record for <" . $ipStr . ">.");
							}
						}
						if ($rv) { # At least one netmask record has to succeed before returning true;
							return $rv;
						}
					} else {
						$self->{_DEBUG}->debug(1, "SmartXMLDBWhois", "_processQueryResult", "No netmask values found.");
					}
				} else {
					$self->{_DEBUG}->debug(1, "SmartXMLDBWhois", "_processQueryResult", "Network WHOIS server found no record for: <" . $ipStr . ">");
				} #if ($xmlQueryResult->{FoundMatch} ne "No")
			} else {
				$self->{_DEBUG}->debug(2, "SmartXMLDBWhois", "_processQueryResult", "Whois proxy parsing failure <" . $xmlQueryResult->{ErrorCode} . ">");
				# If the connection is refused by the whois server, there is no data to be parsed.
				if ($xmlQueryResult->{ErrorCode} ne "ConnectionRefused") { 
					return $self->processRaw(	$rawStr, 
												$ipStr, 
												$xmlQueryResult->{ServerName}, 
												$self->_xmlToString($xmlQueryResult));
				} # if ($xmlQueryResult->{ErrorCode} ne "ConnectionRefused")
			} # if ($xmlQueryResult->{ErrorCode} eq "Success")
		} else {
			$self->{_DEBUG}->debug(1, "SmartXMLDBWhois", "_processQueryResult", "Invalid query result value.");
		}
	} else {
		$self->{_DEBUG}->debug(1, "SmartXMLDBWhois", "_processQueryResult", "No parameters.");
	}
	return undef;
}

sub processRaw {
	my $self = shift;
	if (@_) {
		my ($raw, $ipStr, $whoisServer, $xmlStr) = @_;

		if ($raw) {
			if ($ipStr) {
				my $name	= $self->_searchForName($raw);
				my $id		= $self->_searchForID($raw);
				my $desc	= $self->_searchForDescription($raw);
				my $addr	= $self->_searchForAddress($raw);
				my $country	= $self->_searchForCountry($raw);
				my $whois 	= $self->_searchForWhois($raw);
				my @netmasks= $self->_searchForNetmasks($raw);
		
				if (@netmasks) {		
					# Add an entry for each netmask found
					foreach (@netmasks) { # $_ references each netmask in the @netmasks array
						if ($_) {
							if ($self->{DB}->add(	$_->desc(),
													$id,
													$name,
													$desc,
													$addr,
													undef,
													undef,
													undef,
													$country,
													($whois?$whois:$whoisServer),
													$xmlStr,
													$raw)) {
								$self->{_DEBUG}->debug(3, "SmartXMLDBWhois", "processRaw", "Added netmask record for <" . $_->desc() . ">");
								return "true";
							} else {
								$self->{_DEBUG}->debug(1, "SmartXMLDBWhois", "processRaw", "Failure adding netmask record.");
							}
						} else {
							$self->{_DEBUG}->debug(1, "SmartXMLDBWhois", "processRaw", "Invalid netmask record.");
						}
					}
				} else {
					$self->{_DEBUG}->debug(1, "SmartXMLDBWhois", "processRaw", "No netmask values found.");
				}
			} else {
				$self->{_DEBUG}->debug(1, "SmartXMLDBWhois", "processRaw", "No IP address given.");
			} # if ($ipStr)
		} else {
			$self->{_DEBUG}->debug(1, "SmartXMLDBWhois", "processRaw", "No raw data available to process.");
		} # if ($raw)

		# Store as failed IP for manual review and to prevent future lookups
		$self->{_DEBUG}->debug(2, "SmartXMLDBWhois", "processRaw", "Storing <" . $ipStr . "> as failed IP");
		$self->{DB}->addFailedIP($ipStr, $xmlStr, $raw);
	} else {
		$self->{_DEBUG}->debug(1, "SmartXMLDBWhois", "processRaw", "No parameters sent to processRaw()");
	}
	return undef;
}
sub _searchForNetmasks {
	my $self = shift;
	if (@_) {
		my ($raw) = @_;
		
		if ($raw =~ /inetnum:\s+(.+)/m) {
			return $self->_netmasksFromNetmasks(_trim($1)); 
		} else {
			$self->{_DEBUG}->debug(1, "SmartXMLDBWhois", "_searchForNetmasks", "Netmasks not found.");
		}
	} else {
		$self->{_DEBUG}->debug(1, "SmartXMLDBWhois", "_searchForNetmasks", "No raw data given for parsing.");
	}
	return undef;
}

sub _searchForName {
	my $self = shift;
	if (@_) {
		my ($raw) = @_;

		if ($raw =~ /owner:\s+(.+)/m) {
			$self->{_DEBUG}->debug(3, "SmartXMLDBWhois", "_searchForName", "Found name: " . _trim($1)); 
			return _trim($1);
		} elsif ($raw =~ /responsible:\s+(.+)/m) { 
			$self->{_DEBUG}->debug(3, "SmartXMLDBWhois", "_searchForName", "Found name: " . _trim($1));
			return _trim($1);
		} elsif ($raw =~ /netname:\s+(.+)/m) { 
			$self->{_DEBUG}->debug(3, "SmartXMLDBWhois", "_searchForName", "Found name: " . _trim($1));
			return _trim($1);
		} elsif ($raw =~ /role:\s+(.+)/m) { 
			$self->{_DEBUG}->debug(3, "SmartXMLDBWhois", "_searchForName", "Found name: " . _trim($1));
			return _trim($1);
		} else {
			$self->{_DEBUG}->debug(1, "SmartXMLDBWhois", "_searchForName", "Name not found.");
		}
	} else {
		$self->{_DEBUG}->debug(1, "SmartXMLDBWhois", "_searchForName", "No raw data given for parsing.");
	}
	return undef;
}

sub _searchForID {
	my $self = shift;
	if (@_) {
		my ($raw) = @_;

		if ($raw =~ /ownerid:\s+(.+)/m) {
			$self->{_DEBUG}->debug(3, "SmartXMLDBWhois", "_searchForID", "Found ID: " . _trim($1));
			return _trim($1);
		} else {
			$self->{_DEBUG}->debug(2, "SmartXMLDBWhois", "_searchForID", "ID not found.");
		}
	} else {
		$self->{_DEBUG}->debug(1, "SmartXMLDBWhois", "_searchForID", "No raw data given for parsing.");
	}
	return undef;
}

sub _searchForDescription {
	my $self = shift;
	if (@_) {
		my ($raw) = @_;

		my $desc;
		while ($raw =~ /remarks:\s+(.+)/g) {
			$desc .= _trim($1) . "\n";
		}
		if ($desc) {
			$self->{_DEBUG}->debug(3, "SmartXMLDBWhois", "_searchForDescription", "Found description.");
		}
		return $desc;
	} else {
		$self->{_DEBUG}->debug(2, "SmartXMLDBWhois", "_searchForDescription", "No raw data given for parsing.");
	}
	return undef;
}

sub _searchForAddress {
	my $self = shift;
	if (@_) {
		my ($raw) = @_;

		my $addr;
		while ($raw =~ /address:\s+(.+)/g) {
			$addr .= _trim($1) . "\n";
		}
		if ($addr) {
			$self->{_DEBUG}->debug(3, "SmartXMLDBWhois", "_searchForID", "Found address: " . $addr);
		}
		return $addr;
	} else {
		$self->{_DEBUG}->debug(1, "SmartXMLDBWhois", "_searchForAddress", "No raw data given for parsing.");
	}
	return undef;
}

sub _searchForCountry {
	my $self = shift;
	if (@_) {
		my ($raw) = @_;

		my $country;
		if ($raw =~ /country:\s+(.+)/m) {
			$country = _trim($1);
		} elsif ($raw =~ /Brazilian resource:/m) {
			$country = "BR";
		} elsif ($raw =~ /Nic.br/m) {
			$country = "BR";
		} else {			
			$self->{_DEBUG}->debug(2, "SmartXMLDBWhois", "_searchForCountry", "Country not found.");
		} 
		if ($country) {
			$self->{_DEBUG}->debug(3, "SmartXMLDBWhois", "_searchForID", "Found country: " . $country);
		}
		return $country;
	} else {
		$self->{_DEBUG}->debug(1, "SmartXMLDBWhois", "_searchForCountry", "No raw data given for parsing.");
	}
	return undef;
}

# Although we typically know which whois server provided the raw data, the data is actually from a "sub"
# whois server and that fact is noted in the raw text.
sub _searchForWhois {
	my $self = shift;
	if (@_) {
		my ($raw) = @_;

		if ($raw =~ /Brazilian resource:\s+(.+)/m) {
			$self->{_DEBUG}->debug(3, "SmartXMLDBWhois", "_searchForID", "Found whois: " . _trim($1));
			return _trim($1);
		} else {
			$self->{_DEBUG}->debug(3, "SmartXMLDBWhois", "_searchForWhois", "Whois not found.");
		} 
	} else {
		$self->{_DEBUG}->debug(1, "SmartXMLDBWhois", "_searchForWhois", "No raw data given for parsing.");
	}
	return undef;
}

sub _queryWhoisServer {
	my $self = shift;
	if (@_) {
		my ($ip) = @_;
		
		$self->{_DEBUG}->debug(3, "SmartXMLDBWhois", "_queryWhoisServer", "Opening network connection to " . $self->{WHOISSERVER} . ":" . $self->{WHOISPORT});
		my $client = new Net::Telnet(	Host		=> $self->{WHOISSERVER},
										Port 		=> $self->{WHOISPORT},
										Timeout		=> 60,
										Telnetmode	=> 0);
		if ($client) {
			my $resp = "";
			$client->put($ip);
			my $rv; 
			while ($client->eof() eq "") {
				$rv = $client->get();
				if ($rv) { $resp .= $rv; }
			}
			$client->close();
			return $resp;
		} else {
			$self->{_DEBUG}->debug(1, "SmartXMLDBWhois", "_queryWhoisServer", "Invalid network handle");
		}
	} else {
		$self->{_DEBUG}->debug(1, "SmartXMLDBWhois", "_queryWhoisServer", "No parameters sent to _queryWhoisServer()");
	}
	return undef;
}

sub _netmasksFromNetmasks {
	my $self = shift;
	if (@_) {
		my ($netmaskStr) = @_;

		my @netmasks;
		# Split the Netmask string in case multiple are listed.
		foreach (split(',', $netmaskStr)) {
			my $netmask = new2 Net::Netmask(_trim($_));
			if ($netmask) {
				$self->{_DEBUG}->debug(3, "SmartXMLDBWhois", "_netmasksFromNetmasks", "Found Netmask: " . $netmask);
				push(@netmasks, $netmask);
			} else {
				$self->{_DEBUG}->debug(2, "SmartXMLDBWhois", "_netmasksFromNetmasks", "Error converting <" . _trim($_) . "> to a Net::Netmask object");
			}
		}
		return @netmasks;
	} else {
		$self->{_DEBUG}->debug(1, "SmartXMLDBWhois", "_netmasksFromNetmasks", "No parameters sent to _netmasksFromNetmasks()");
	}
	return undef;
}

sub _netmasksFromIPRanges {
	my $self = shift;
	if (@_) {
		my ($ipRangeStr) = @_;

		my @netmasks;
		# Split the IP Range in case multiple are listed.
		foreach (split(',', $ipRangeStr)) {
			my $netmask = new2 Net::Netmask(_trim($_));
			if ($netmask) {
				$self->{_DEBUG}->debug(3, "SmartXMLDBWhois", "_netmasksFromIPRanges", "Found Netmask: " . $netmask);
				push(@netmasks, $netmask);
			} else {
				# Split the range into start/end IPs and generate a list of Netmasks that will cover the range
				my @ips = split('-', _trim($_));
				my @tmp = range2cidrlist(_trim($ips[0]), _trim($ips[1]));
				foreach $netmask (@tmp) {
					$self->{_DEBUG}->debug(3, "SmartXMLDBWhois", "_netmasksFromIPRanges", "Found Netmask: " . $netmask);
					push(@netmasks, $netmask);
				}
			} #if ($netmask)
		} #foreach (split(',', $ipRangeStr))
		return @netmasks;
	} else {
		$self->{_DEBUG}->debug(1, "SmartXMLDBWhois", "_netmasksFromIPRanges", "No parameters sent to _netmasksFromIPRange()");
	}
	return undef;
}

# Perl trim function to remove whitespace from the start and end of the string
sub _trim($) {
	my $string = shift;
	$string =~ s/^\s+//;
	$string =~ s/\s+$//;
	return $string;
}

sub _flatten {
	my $self = shift;
	if (@_) {
		my ($var) = @_;
		my $ref = ref($var);
		
		if ($ref eq "") {
			return $var;
		} elsif ($ref eq "SCALAR") {
			return @$var;
		} elsif ($ref eq "ARRAY") {
			my $flat = "";
			foreach (@$var) {
				$flat .= $_ . "\n";
			}
			return $flat;
		} elsif ($ref eq "HASH") {
			$self->{_DEBUG}->debug(4, "SmartXMLDBWhois", "_flatten", "HASH:" . Dumper($var));
		} else {
			$self->{_DEBUG}->debug(4, "SmartXMLDBWhois", "_flatten", "UNK:" . Dumper($var));
		}
	}
	return undef;
}

sub _stringToXML {
	my $self = shift;
	if (@_) {
		my ($xmlStr) = @_;
		
		my $xml;
		eval { $xml = XMLin($xmlStr) };
		if ($@) {
			$self->{_DEBUG}->debug(1, "SmartXMLDBWhois", "_stringToXML", "XMLout failed with <" . $@ . ">.");
		} else {
			return $xml;
		}
	} else {
		$self->{_DEBUG}->debug(1, "SmartXMLDBWhois", "_stringToXML", "Invalid parameter(s).");
	}
	return undef
}

sub _xmlToString {
	my $self = shift;
	if (@_) {
		my ($xml) = @_;
		
		my $xmlStr;
		eval { $xmlStr = XMLout($xml) };
		if ($@) {
			$self->{_DEBUG}->debug(1, "SmartXMLDBWhois", "_xmlToString", "XMLout failed with <" . $@ . ">.");
		} else {
			return $xmlStr;
		}
	} else {
		$self->{_DEBUG}->debug(1, "SmartXMLDBWhois", "_xmlToString", "Invalid parameter(s).");
	}
	return undef
}

1;

=head1 NAME

mkucenski::SmartXMLDBWhois - Custom perl module for querying an XML whois
proxy and storying the results in an SQL database (via mkucenski::SQLWhois).

=head1 SYNOPSIS

  use mkucenski::SmartXMLDBWhois;

  my $whois = mkucenski::SmartXMLDBWhois->new("localhost", "43", "SQLWhois", "localhost", "root", "");
  if ($whois) {
    $whois->debug(2);
    print $whois->csvHeaders() . "\n";
    foreach (@ARGV) {
      my $rv = $whois->whoisCSV($_);
      if ($rv) { 
        print $rv . "\n";
      } else {
        print "\"$_\",\"Error\"\n";
      }
    }
  }

=head1 DESCRIPTION

This module is used to build "smart" whois clients that can
drastically cut down the time and network communications
required to identify large numbers of IP addresses.  This
module uses XML whois proxy software from Hexillion
(www.hexillion.com) for easier parsing of queried whois data.

The whois data is parsed for an IP range or network mask which will
be stored in a SQL database.  All queries for IP addresses first
check to see if a corresponding network mask is already stored in the
database.  If a network mask is already stored, the results are
displayed instead of again querying the whois server.

=head2 Methods

=over 4

=item * $object->new($dbName, $dbServer, $dbUser, $dbPassword)

Create a new SQLWhois object connected to a MySQL database with the
given parameters.

=item * $object->debug($level)

Set the debug level of this object.

See mkucenski::Debug

=item * $object->query($ipAddress)

Query the database for the given IP address and return the raw whois
data (e.g. similar to executing: whois <ipAddress>).

=item * $object->queryBrief($ipAddress)

Query the database for the given IP address and return a brief
summary.

=item * $object->queryCSV($ipAddress)

Query the database for the given IP address and return a comma-
separated string.

=item * $object->queryXML($ipAddress)

Query the database for the given IP address and return the XML whois
data from the whois proxy server by Hexillion (www.hexillion.com).

=item * $object->csvHeaders()

Returns a string of commas separated headers corresponding to the
output from queryCSV().

=item * $object->briefHeaders()

Returns a string of headers corresponding to the output from
queryBrief().

=item * $object->add($netmask,$id,$name,$description,$address,$city,$state,$zip,$country,$whois,$xml,$raw)
						
Add the given netmask and associated data to the database for future
queries.

=item * $object->addFailedIP($ipAddress, $xml, $raw)

Save the data associated with a failed IP address into the database
for manual review and bug fixes to the parsing engine.

=item * $object->addToCase($caseNumber, $ipAddress)

Associate the IP address with a case number so that queries against
the database can be made for a particular case only.

See mkucenski:SmartXMLDBWhois

=item * $object->checkForFailedIP($ipAddress)

Check to see if the given IP address has already been stored as a failed
address.

=back

 =head1 AUTHOR
 
 Matthew A. Kucenski
 
 =head1 COPYRIGHT
 
 Copyright 2009 Matthew A. Kucenski
 
 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at
 
 http://www.apache.org/licenses/LICENSE-2.0
 
 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 
=head1 SEE ALSO

 mkucenski::SmartXMLDBWhois, mkucenski::Debug

=cut
