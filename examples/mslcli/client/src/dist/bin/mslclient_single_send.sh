#!/bin/bash

# find directory of this script
DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

$DIR/mslclient.sh -url http://localhost:8080/msl -cfg "$DIR/mslcli.cfg" -kx DIFFIE_HELLMAN -eid client1 -uid user1 -if request.dat -eas PSK -uas EMAIL_PASSWORD "$@"
exit $?
