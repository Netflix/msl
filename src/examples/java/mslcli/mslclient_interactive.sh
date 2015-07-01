#!/bin/sh

./mslclient.sh -int true -url http://localhost:8080/msl -cfg mslcli.cfg -eid simpleMslClient -uid simpleMslClientUserId "$@"
