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

# This script can be used to find large, stored netmasks.  Occasionally,
# the perl scripts will not be able to find a small netmask for a particular
# IP address.  When that happens, a large (> /8) gets added to the database
# and subsequent queries for IPs in that range no longer even request a more
# narrow response.  They find the large netmask and return it as the answer.

# Use this script to list all large, stored netmasks.  Then use 
# <deleteNetmask.sh> to delete them from the database.  Re-run your IP
# addresses and hopefully you will get more narrow results.

DBUSER="$1"

QUERY="SELECT Netmask, Name, Country FROM tbl_Netmask WHERE Netmask REGEXP '.+\/(8|7|6|5|4|3|2|1|0)$';"

echo "$QUERY" | mysql --host=<server> --user=$DBUSER --password <password>

