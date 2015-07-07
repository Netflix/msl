#!/bin/sh

./mslclient.sh -url http://localhost:8080/msl -cfg mslcli.cfg -kx DIFFIE_HELLMAN -eid simpleMslClient -uid simpleMslClientUserId -if request.dat "$@"
exit $?
