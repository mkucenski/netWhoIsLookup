#!/bin/sh

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

# This script is a basic way to search for .gov and .mil IP addresses.  

# The query is slightly more complex than you would initially think
# necessary.  The reason is that sometimes an IP addresses will get
# listed as registered to a commercial entity, but then "leased"
# out to a government/military entity.  In those cases, I found that
# There was usually a .mil/.gov reference somewhere in the raw whois
# data.

# This script searches the raw whois data for various indicators of
# .mil/.gov status.  It searches by CaseID (entered when you initially)
# ran your IP addresses through this system.

DBUSER="$1"
CASEID="$2"

QUERY="SELECT tbl_Case.CaseID, tbl_Case.IP, tbl_Netmask.Netmask, tbl_Netmask.Name \
	FROM tbl_Case, tbl_IP, tbl_Netmask, tbl_NetmaskRaw \
	WHERE tbl_Case.CaseID='$CASEID' AND tbl_Case.IP=tbl_IP.IP AND \
		tbl_IP.Netmask=tbl_Netmask.Netmask AND \
		tbl_IP.Netmask=tbl_NetmaskRaw.Netmask AND \
		tbl_Netmask.Country='US' AND \
		(tbl_NetmaskRaw.Raw REGEXP '\\.mil[^[:alnum:]]' OR \
			tbl_NetmaskRaw.Raw REGEXP 'AAFES' OR \
			tbl_NetmaskRaw.Raw REGEXP '\\.gov[^[:alnum:]]')"

echo "$QUERY" | mysql --host=<server> --user=$DBUSER --password <password>

