#!/bin/sh

./mslclient.sh -int true -url http://localhost:8080/msl -cfg mslcli.cfg -eid client1 -uid user1 -eas PSK -uas EMAIL_PASSWORD "$@"
exit $?
