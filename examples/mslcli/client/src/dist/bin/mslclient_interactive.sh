#!/bin/bash

# find directory of this script
DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

$DIR/mslclient.sh -int true -url http://localhost:8080/msl -cfg "$DIR/mslcli.cfg" -eid client1 -uid user1 -eas PSK -uas EMAIL_PASSWORD "$@"
exit $?
