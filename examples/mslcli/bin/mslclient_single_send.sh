#!/bin/bash

./mslclient.sh -url http://localhost:8080/msl -cfg mslcli.cfg -kx DIFFIE_HELLMAN -eid client1 -uid user1 -if request.dat -eas PSK -uas EMAIL_PASSWORD "$@"
exit $?
