#!/bin/sh

./mslclient.sh -url http://localhost:8080/msl -cfg mslcli.cfg -kx dh -eid simpleMslClient -uid simpleMslClientUserId -if request.dat "$@"
exit $?
