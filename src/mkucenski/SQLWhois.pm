package mkucenski::SQLWhois;

use strict;
use warnings;

use DBI;
use Net::IP;
use Net::Netmask;
use Data::Dumper;
use mkucenski::Debug;

# Class constructor: Takes the neccessary database parameters and sets up the connection for future queries.
sub new {
	my $class = shift;
	if (@_ && ($#_ + 1) == 4) {
		my ($dbName, $dbServer, $dbUser, $dbPassword) = @_;
		
		my $self  = {	DB				=> undef,	# Database handle
						_ageThreshold	=> -30,		# Threshold to expire netmask entries and refresh from a network whois server
						_DEBUG			=> undef	# Debug object handle
		};
		
		# Connect to the database using the given parameters and store the database handle.
		$self->{DB} = DBI->connect(	"DBI:mysql:database=" . $dbName . ";host=" . $dbServer,
									$dbUser, 
									$dbPassword,
									{'RaiseError' => 0, 'PrintError' => 0});
		if ($self->{DB}) {
			bless ($self, $class);
			return $self;
		} else {
			print STDERR "SQLWhois:new() Database connection failed ($DBI::err - $DBI::errstr).\n";
		}
	} else {
		print STDERR "SQLWhois:new() Incorrect number of parameters (" . ($#_ + 1) . ").\n";
	}
	return undef;
}

# Enable debugging for this object
sub debug {
	my $self = shift;
	if (@_) {
		my ($level) = @_;
		$self->{_DEBUG} = new mkucenski::Debug($level);
		return "true";
	} else {
		print STDERR "SQLWhois:debug() Invalid parameter(s).\n";
	}
	return undef;
}

# Query the database for the given IP address.  Additional options (brief,csv,xml) are automatically set by
#	additional whoisXXX functions below.  By default, this function returns the raw whois data.
sub query {
	my $self = shift;
	if (@_) {
		my ($ipStr, $briefOutput, $csvOutput, $xmlOutput) = @_;
		
		# Normalize and check all IP addresses using the Net::IP package
		my $ip = new Net::IP ($ipStr);
		if ($ip) {
			# First check to see if a link from IP to Netmask has been stored.
			my $rec = $self->_queryNetmaskFromIP($ip);
			if (!$rec) {
				$self->{_DEBUG}->debug(3, "SQLWhois", "query",  $ip->ip() . " not found in IP table");

				# Next check if any Netmask in the DB matches this IP.
				$rec = $self->_findNetmask($ip);
				if ($rec) {
					# Add an IP to Netmask mapping for quicker queries in the future.
					if ($self->_insertSQL("INSERT INTO tbl_IP VALUES ('" . $ip->ip() . "', '" . $rec->{Netmask} . "')")) {
						$self->{_DEBUG}->debug(3, "SQLWhois", "query", "<" . $ip->ip() . "> saved to IP table with netmask <" . $rec->{Netmask} . ">.");
					} else {
						$self->{_DEBUG}->debug(2, "SQLWhois", "query",  "query(): Failed to save <" . $ip->ip() . "> into IP table with netmask <" . $rec->{Netmask} . ">.");
					}
				}
			}
			# If a record was found in either scenario above, display the results.
			if ($rec) {
				# Check the age of the record and expire if greater than the threshold value specified above.
				if ($rec->{Age} > $self->{_ageThreshold}) {
					if ($briefOutput == 1) {
						my $rec_name = $rec->{Name}?$rec->{Name}:"";
						my $rec_city = $rec->{City}?$rec->{City}:"";
						my $rec_state = $rec->{State}?$rec->{State}:"";
						my $rec_country = $rec->{Country}?$rec->{Country}:"";
						my $rec_whois = $rec->{WhoisServer}?$rec->{WhoisServer}:"";
						my $rec_age = $rec->{Age};
	
						return	$ip->ip() . " (" . 
								$rec->{Netmask} . "): \"" .
								$rec_name . "\" " .
								$rec_city . ", " . 
								$rec_state . ", " . 
								$rec_country . " [" . 
								$rec_whois . ", " .
								$rec_age . "]";
					} elsif ($csvOutput == 1) {
						# These values are split into their own variables prior to printing because
						# some may be undef and Perl gets upset about concatenating undef to strings.
						# Also, the Perl ternary operator (xx?yy:zz) does not operate correctly
						# inline with string concatenation.
						my $rec_id = $rec->{ID}?$rec->{ID}:"";
						my $rec_name = $rec->{Name}?$rec->{Name}:"";
						my $rec_city = $rec->{City}?$rec->{City}:"";
						my $rec_state = $rec->{State}?$rec->{State}:"";
						my $rec_zip = $rec->{Zip}?$rec->{Zip}:"";
						my $rec_country = $rec->{Country}?$rec->{Country}:"";
						my $rec_whois = $rec->{WhoisServer}?$rec->{WhoisServer}:"";
						my $rec_age = $rec->{Age};
							
						return	"\"" . 	$ip->ip() . "\",\"" . 
										$rec->{Netmask} . "\",\"" . 
										$rec_id . "\",\"" . 
										$rec_name . "\",\"" . 
										$rec_city . "\",\"" . 
										$rec_state . "\",\"" . 
										$rec_zip . "\",\"" . 
										$rec_country . "\",\"" . 
										$rec_whois . "\",\"" .
										$rec_age . "\"";
					} elsif ($xmlOutput == 1) {
						return $self->_queryNetmaskXML($rec->{Netmask});
					} else {
						return $self->_queryNetmaskRaw($rec->{Netmask});
					}
				} else {
					$self->{_DEBUG}->debug(2, "SQLWhois", "query", "Data found for <" . $rec->{Netmask} . "> is expired and will be deleted.");
					if (!$self->_deleteNetmask($rec->{Netmask})) {
						$self->{_DEBUG}->debug(1, "SQLWhois", "query", "Error deleting records for <" . $rec->{Netmask} . ">.");
					}
				} # if ($rec->{Age} > $self->{_ageThreshold})
			} else {
				$self->{_DEBUG}->debug(3, "SQLWhois", "query", "No data found for " . $ip->ip());
			} # if ($rec)
		} else { #if ($ip)
			$self->{_DEBUG}->debug(1, "SQLWhois", "query", "Net::IP returned invalid object");
		} #if ($ip)
	} else {
		$self->{_DEBUG}->debug(1, "SQLWhois", "query", "Invalid parameter(s).");
	}
	return undef;
}

sub csvHeaders {
	return "\"IP Address\",\"Netmask\",\"ID\",\"Name\",\"City\",\"State\",\"Zip\",\"Country\",\"Whois Server\",\"Age\"";
}

sub briefHeaders {
	return "IP Address (Netmask): \"Name\" City, State, Country [Whois Server, Age]";
}
	
# Query the database and return a brief summary
sub queryBrief {
	my $self = shift;
	return $self->query(@_, 1, 0, 0);
}

# Query the database and return a CSV formatted summary
sub queryCSV {
	my $self = shift;
	return $self->query(@_, 0, 1, 0);
}

# Query the database and return an XML string
sub queryXML {
	my $self = shift;
	return $self->query(@_, 0, 0, 1);
}

# Add a netmask and associated metadata to the database.
sub add {
	my $self = shift;
	if (@_) {
		my ($netmaskStr, $id, $name, $desc, $addr, $city, $state, $zip, $country, $whois, $xml, $raw) = @_;

		# Normalize and check the given netmask string.		
		my $netmask = new2 Net::Netmask($netmaskStr);
		if ($netmask) {
			if ($self->{DB}) {
				my $query = "INSERT INTO tbl_Netmask VALUES ('" 	. $netmask->desc() . "',"
																	. $self->{DB}->quote($id) . ","
																	. $self->{DB}->quote($name) . ","
																	. $self->{DB}->quote($desc) . ","
																	. $self->{DB}->quote($addr) . ","
																	. $self->{DB}->quote($city) . ","
																	. $self->{DB}->quote($state) . ","
																	. $self->{DB}->quote($zip) . ","
																	. $self->{DB}->quote($country) . ","
																	. $self->{DB}->quote($whois) . ","
																	. "NULL" . ")";
				# Insert record into tbl_Netmask
				$self->{_DEBUG}->debug(3, "SQLWhois", "add", "Executing INSERT query: \"$query\"");
				if ($self->_insertSQL($query)) {
					$self->{_DEBUG}->debug(3, "SQLWhois", "add", $netmask->desc() . " saved to Netmask table");
	
					# Save the Raw/XML data into tbl_NetmaskRaw
					if ($self->_addXMLRaw($netmask, $xml, $raw)) {
						$self->{_DEBUG}->debug(3, "SQLWhois", "add", "Saved raw/XML data for <" . $netmask->desc() . ">");
					} else {
						$self->{_DEBUG}->debug(2, "SQLWhois", "add", "Failed to save raw/XML data for <" . $netmask->desc() . ">");
					} 
					
					return "true";
				} else {
					$self->{_DEBUG}->debug(1, "SQLWhois", "add", "Failed to add data for netmask: " . $netmask->desc());
					$self->{_DEBUG}->debug(3, "SQLWhois", "add", "Failed on \"" . $query . "\"");
				}
			} else {
				$self->{_DEBUG}->debug(1, "SQLWhois", "add", "Invalid database handle");
			}
		} else {
			$self->{_DEBUG}->debug(1, "SQLWhois", "add", "Invalid netmask value <" . $netmask->desc() . ">.");
		}
	} else {
		$self->{_DEBUG}->debug(1, "SQLWhois", "add", "Invalid parameter(s).");
	}
	return undef;
}

# Add a failed IP to the database along with its raw/xml data.  This is done so that future parsing
# enhancements can be run against this stored data rather than refetching.
sub addFailedIP {
	my $self = shift;
	if (@_) {
		my ($ip, $xml, $raw) = @_;
		
		if ($self->{DB}) {
			my $query = "INSERT INTO tbl_IPFail VALUES ('". $ip . "',"
															. $self->{DB}->quote($raw) . ","
															. $self->{DB}->quote($xml) . ","
															. "NULL" . ")";
			if (!$self->_insertSQL($query)) {
				$self->{_DEBUG}->debug(1, "SQLWhois", "addFailedIP", "Failed to add IP failure data for: " . $ip);
			} else {
				$self->{_DEBUG}->debug(3, "SQLWhois", "addFailedIP", $ip . " saved to IP failure table");
				return "true";
			}
		} else {
			$self->{_DEBUG}->debug(1, "SQLWhois", "addFailedIP", "Invalid database handle");
		}
	} else {
		$self->{_DEBUG}->debug(1, "SQLWhois", "addFailedIP", "Invalid parameter(s).");
	}
	return undef;
}

# Supports ignoring IPs that are known to fail parsing.
sub checkForFailedIP {
	my $self = shift;
	if (@_) {
		my ($ip) = @_;
		
		my $query = "SELECT IP FROM tbl_IPFail WHERE IP='" . $ip . "'";
		my $rec = $self->_querySQL($query);
		if ($rec) {
			return $rec->{IP};
		}			
	} else {
		$self->{_DEBUG}->debug(1, "SQLWhois", "checkForFailedIP", "Invalid parameter(s).");
	}
	return undef;
}

sub addIPToCase {
	my $self = shift;
	if (@_) {
		my ($caseNum, $ipStr) = @_;
		
		if ($self->{DB}) {
			my $query = "INSERT INTO tbl_Case VALUES ('". $caseNum . "','"
														. $ipStr . "')";
			if (!$self->_insertSQL($query)) {
				$self->{_DEBUG}->debug(2, "SQLWhois", "addIPToCase", "Failed to add IP to case: " . $caseNum . ", " . $ipStr);
			} else {
				$self->{_DEBUG}->debug(3, "SQLWhois", "addIPToCase", "<" . $ipStr . "> saved to case: " . $caseNum);
				return "true";
			}
		} else {
			$self->{_DEBUG}->debug(1, "SQLWhois", "addIPToCase", "Invalid database handle");
		}
	} else {
		$self->{_DEBUG}->debug(1, "SQLWhois", "addIPToCase", "Invalid parameter(s).");
	}
	return undef;
}

# Class Destructor
sub DESTROY {
	my $self = shift;
	if ($self->{DB}) {
		$self->{DB}->disconnect();
	} else {
		$self->{_DEBUG}->debug(1, "SQLWhois", "DESTROY", "Invalid database handle");
	}	
}

# INTERNAL ONLY: Delete netmask record and IP/Raw records linking to this netmask
sub _deleteNetmask {
	my $self = shift;
	if (@_) {
		my ($netmaskStr) = @_;
		
		my $delete = "DELETE FROM tbl_Netmask WHERE Netmask='" . $netmaskStr . "'";
		$self->{_DEBUG}->debug(3, "SQLWhois", "_deleteNetmask", "Executing delete query: <" . $delete . ">.");
		my $rv = $self->_deleteSQL($delete);
		if ($rv) {
			$delete = "DELETE FROM tbl_IP WHERE Netmask='" . $netmaskStr . "'";
			$self->{_DEBUG}->debug(3, "SQLWhois", "_deleteNetmask", "Executing delete query: <" . $delete . ">.");
			$rv = $self->_deleteSQL($delete);
			if (!$rv) {
				$self->{_DEBUG}->debug(2, "SQLWhois", "_deleteNetmask", "Database returned: \"" . $self->{DB}->errstr() . "\" (" . $self->{DB}->err() .") on tbl_IP delete.");
			}
			
			$delete = "DELETE FROM tbl_NetmaskRaw WHERE Netmask='" . $netmaskStr . "'";
			$self->{_DEBUG}->debug(3, "SQLWhois", "_deleteNetmask", "Executing delete query: <" . $delete . ">.");
			$rv = $self->_deleteSQL($delete);
			if (!$rv) {
				$self->{_DEBUG}->debug(2, "SQLWhois", "_deleteNetmask", "Database returned: \"" . $self->{DB}->errstr() . "\" (" . $self->{DB}->err() .") on tbl_NetmaskRaw delete.");
			}
			return "true";
		} else {
			$self->{_DEBUG}->debug(1, "SQLWhois", "_deleteNetmask", "Database returned: \"" . $self->{DB}->errstr() . "\" (" . $self->{DB}->err() .") on tbl_Netmask delete.");
		}
	} else {
		$self->{_DEBUG}->debug(1, "SQLWhois", "_deleteNetmask", "Invalid parameter(s).");
	}
	return undef;
}

# INTERNAL ONLY: Insert the raw and xml strings into the database
sub _addXMLRaw {
	my $self = shift;
	if (@_) {
		my ($netmask, $xml, $raw) = @_;
		
		if ($self->{DB}) {
			my $query = "INSERT INTO tbl_NetmaskRaw VALUES ('". $netmask->desc() . "',"
																. $self->{DB}->quote($raw) . ","
																. $self->{DB}->quote($xml) . ")";
			if (!$self->_insertSQL($query)) {
				$self->{_DEBUG}->debug(2, "SQLWhois", "_addXMLRaw", "Failed to add XMLRaw data for netmask: " . $netmask->desc());
			} else {
				$self->{_DEBUG}->debug(3, "SQLWhois", "_addXMLRaw", $netmask->desc() . " saved to NetmaskRaw table");
				return "true";
			}
		} else {
			$self->{_DEBUG}->debug(1, "SQLWhois", "_addXMLRaw", "Invalid database handle");
		}
	} else {
		$self->{_DEBUG}->debug(1, "SQLWhois", "_addXMLRaw", "Invalid parameter(s).");
	}
	return undef;
}

# INTERNAL ONLY: Retrieve the raw data for the requested netmask.
sub _queryNetmaskRaw {
	my $self = shift;
	if (@_) {
		my ($netmask) = @_;
		
		my $query = "SELECT Raw FROM tbl_NetmaskRaw WHERE Netmask='" . $netmask . "'";
		my $rec = $self->_querySQL($query);
		if ($rec) {
			return $rec->{Raw};
		}			
	} else {
		$self->{_DEBUG}->debug(1, "SQLWhois", "_queryNetmaskRaw", "Invalid parameter(s).");
	}
	return undef;
}

# INTERNAL ONLY: Retrieve the XML data for the requested netmask.
sub _queryNetmaskXML {
	my $self = shift;
	if (@_) {
		my ($netmask) = @_;
		
		my $query = "SELECT XML FROM tbl_NetmaskRaw WHERE Netmask='" . $netmask . "'";
		my $rec = $self->_querySQL($query);
		if ($rec) {
			return $rec->{XML};
		}			
	} else {
		$self->{_DEBUG}->debug(1, "SQLWhois", "_queryNetmaskXML", "Invalid parameter(s).");
	}
	return undef;
}

# INTERNAL ONLY: Execute an SQL query that returns a single record.  (See also _querySQLMany)
sub _querySQL {
	my $self = shift;
	if (@_) {
		my ($query) = @_;
		
		if ($self->{DB}) {
			return $self->{DB}->selectrow_hashref($query);
		} else {
			$self->{_DEBUG}->debug(1, "SQLWhois", "_querySQL", "Invalid database handle");
		}
	} else {
		$self->{_DEBUG}->debug(1, "SQLWhois", "_querySQL", "Invalid parameter(s).");
	}
	return undef;
}

# INTERNAL ONLY: Execute a DELETE on the database.
sub _deleteSQL {
	my $self = shift;
	if (@_) {
		my ($delete) = @_;
		
		if ($self->{DB}) {
			my $rv = $self->{DB}->do($delete);
			if ($rv) {
				return $rv;
			} else {
				$self->{_DEBUG}->debug(2, "SQLWhois", "_deleteSQL", "Database returned: \"" . $self->{DB}->errstr() . "\" (" . $self->{DB}->err() .") on <" . $delete . ">");
			}
			return $rv;
		} else {
			$self->{_DEBUG}->debug(1, "SQLWhois", "_deleteSQL", "Invalid database handle");
		}
	} else {
		$self->{_DEBUG}->debug(1, "SQLWhois", "_deleteSQL", "Invalid parameter(s).");
	}
	return undef;
}

# INTERNAL ONLY: Execute an INSERT on the database.
sub _insertSQL {
	my $self = shift;
	if (@_) {
		my ($insert) = @_;
		
		if ($self->{DB}) {
			my $rv = $self->{DB}->do($insert);
			if ($rv) {
				return $rv;
			} else {
				my $err = $self->{DB}->err();
				if ($err == 1062) {
					$self->{_DEBUG}->debug(3, "SQLWhois", "_insertSQL", "Database returned: \"" . $self->{DB}->errstr() . "\" (" . $self->{DB}->err() .") on <" . $insert . ">");
					return "duplicate";
				} else {
					$self->{_DEBUG}->debug(2, "SQLWhois", "_insertSQL", "Database returned: \"" . $self->{DB}->errstr() . "\" (" . $self->{DB}->err() .") on <" . $insert . ">");
				}
			}
			return $rv;
		} else {
			$self->{_DEBUG}->debug(1, "SQLWhois", "_insertSQL", "Invalid database handle");
		}
	} else {
		$self->{_DEBUG}->debug(1, "SQLWhois", "_insertSQL", "Invalid parameter(s).");
	}
	return undef;
}

# INTERNAL ONLY: Execute an SQL query that returns multiple records.  (See also _querySQL)
sub _querySQLMany {
	my $self = shift;
	if (@_) {
		my ($query) = @_;
		
		if ($self->{DB}) {
			my @records;
			my $qh = $self->{DB}->prepare($query);	
			if ($qh->execute()) {
				while (my $rec = $qh->fetchrow_hashref()) {
					push(@records, $rec);
				}
				return @records;
			} else {
				$self->{_DEBUG}->debug(1, "SQLWhois", "_querySQLMany", "\"$query\" failed to execute");
			}
		} else {
			$self->{_DEBUG}->debug(1, "SQLWhois", "_querySQLMany", "Invalid database handle");
		}
	} else {
		$self->{_DEBUG}->debug(1, "SQLWhois", "_querySQLMany", "Invalid parameter(s).");
	}
	return undef;
}

# INTERNAL ONLY: Given an IP address, search all stored Netmasks for the first that would include
#	the IP address.
sub _findNetmask {
	my $self = shift;
	if (@_) {
		my ($ip) = @_;
		
		if ($self->{DB}) {
			# Speed up the search for a matching netmask by searching only those that match the first octet of the IP address.
			my @ipOctets = split('\.', $ip->ip());
			my $query = "SELECT *, TO_DAYS(Timestamp)-TO_DAYS(NOW()) AS Age FROM tbl_Netmask WHERE Netmask REGEXP '^" . $ipOctets[0] . "'";
			my @records = $self->_querySQLMany($query);
			my $netBlockTable = {};
			foreach (@records) {
				my $netmask = new2 Net::Netmask($_->{Netmask});
				if ($netmask) {
					if ($netmask->match($ip->ip())) {
						# For each match, add the matching block to a table.  See below where the table is searched for the smallest matching block.
						$netmask->storeNetblock($netBlockTable);
					}
				} else {
					$self->{_DEBUG}->debug(1, "SQLWhois", "_findNetmask", "Invalid netmask string stored in database: $_->{Netmask}");
				}
			}
			# <findNetblock> returns the smallest matching network block
			my $matchedNetmask = Net::Netmask::findNetblock($ip->ip(), $netBlockTable);
			if ($matchedNetmask) {
				my $query2 = "SELECT *, TO_DAYS(Timestamp)-TO_DAYS(NOW()) AS Age FROM tbl_Netmask WHERE Netmask='" . $matchedNetmask->desc() . "'";
				return $self->_querySQL($query2);
			} else {
				$self->{_DEBUG}->debug(4, "SQLWhois", "_findNetmask", $ip . " not found in netmask table.");
			}
		} else {
			$self->{_DEBUG}->debug(1, "SQLWhois", "_findNetmask", "Invalid database handle");
		}
	} else {
		$self->{_DEBUG}->debug(1, "SQLWhois", "_findNetmask", "Invalid parameter(s).");
	}
	return undef;
}

sub _queryNetmaskFromIP {
	my $self = shift;
	if (@_) {
		my ($ip) = @_;
		
		my $query = "SELECT tbl_Netmask.*, TO_DAYS(tbl_Netmask.Timestamp)-TO_DAYS(NOW()) AS Age FROM tbl_IP JOIN tbl_Netmask ON tbl_IP.Netmask=tbl_Netmask.Netmask WHERE tbl_IP.IP='" . $ip->ip() . "'";
		return $self->_querySQL($query);
	} else {
		$self->{_DEBUG}->debug(1, "SQLWhois", "_queryIP", "Invalid parameter(s).");
	}
	return undef;
}

1;

=head1 NAME

mkucenski::SQLWhois - Custom perl module for storing XML whois data into an SQL database

=head1 SYNOPSIS

  use mkucenski::SQLWhois;
  
  my $dbName = "SQLWhois";
  my $dbServer = "localhost";
  my $dbUser = "root";
  my $dbPassword = "********";
  my $sqlWhois = mkucenski::SQLWhois->new($dbName, $dbServer, $dbUser, $dbPassword);
  $sqlWhois->debug(2);
  
  print $sqlWhois->query("10.1.1.23") . "\n";
  print $sqlWhois->queryCSV("10.1.1.23") . "\n";

=head1 DESCRIPTION

This module is not meant to be used directly.  It is used as part of
mkucenski::SmartXMLDBWhois and should be used by clients through that
interface.  

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

See mkucenski:SmartXMLDBWhois

=item * $object->checkForFailedIP($ipAddress)

Check to see if the given IP address has already been stored as a failed
address.

=item * $object->addIPToCase($caseNumber, $ipAddress)

Associate the IP address with a case number so that queries against
the database can be made for a particular case only.

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
