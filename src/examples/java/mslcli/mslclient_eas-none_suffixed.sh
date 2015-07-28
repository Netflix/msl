#!/bin/sh

./mslclient.sh -int true -cfg mslcli.cfg -url http://localhost:8080/msl -eid client4 -uid user1 -uas EMAIL_PASSWORD -eas NONE_SUFFIXED -kx ASYMMETRIC_WRAPPED -kxm JWE_RSA "$@"
exit $?
