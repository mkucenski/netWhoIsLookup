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

# The nature of the whois system causes errors, primarily due to timeouts.
# IPs for which a whois response cannot be found are entered into a failure
# table.  The reason for this is so that subsequent requests for the same
# or similar IP addresses don't continue querying a server that doesn't know
# or refuses to give an answer.  You can review the table to determine why
# the failure occurred.  Or, you can manually delete the failures using this
# script and re-run your IPs.

DBUSER="$1"

QUERY="DELETE FROM tbl_IPFail;"

echo "$QUERY" | mysql --host=<server> --user=$DBUSER --password <password>

