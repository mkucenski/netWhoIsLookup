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

DBUSER="$1"

echo -n "Total IPs stored: "
mysql --host=<server> --user=$DBUSER --password --database=<password> -e "SELECT COUNT(IP) FROM tbl_IP;"

echo -n "Total Failed IPs stored: "
mysql --host=<server> --user=$DBUSER --password --database=<password> -e "SELECT COUNT(IP) FROM tbl_IPFail;"

echo -n "Top IPs per Netmask stored: "
mysql --host=<server> --user=$DBUSER --password --database=<password> -e "SELECT COUNT(IP), Netmask FROM tbl_IP GROUP BY Netmask ORDER BY COUNT(IP) DESC;" | head -n 15

echo -n "Total Netmasks stored: "
mysql --host=<server> --user=$DBUSER --password --database=<password> -e "SELECT COUNT(Netmask) FROM tbl_Netmask;"

