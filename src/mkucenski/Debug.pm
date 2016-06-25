package mkucenski::Debug;

use strict;
use warnings;

# Error Levels:    1         2      3       4
my @errStr = ('', 'ERROR', 'WARN', 'INFO', 'TEST');

sub new {
	my $class = shift;
	my $level = shift;
	my $self  = { _DEBUG => ($level?$level:0) };
	bless ($self, $class);
	return $self;
}

sub debug {
	my $self = shift;
	if (@_) {
		my ($level, $module, $routine, $msg) = @_;
		
		if ($level <= $self->{_DEBUG}) {
			print STDERR $errStr[$level] . ": $module:$routine() $msg\n";
			return "true";
		}
	} else {
		print STDERR "Debug::debug() No values given\n";
	}
	return undef;
}

1;

=head1 NAME

=head1 SYNOPSIS
 
=head1 DESCRIPTION
 
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
 
=cut