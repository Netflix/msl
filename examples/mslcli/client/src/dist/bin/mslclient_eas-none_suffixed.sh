#!/bin/bash

# find directory of this script
DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

$DIR/mslclient.sh -int true -cfg "$DIR/mslcli.cfg" -url http://localhost:8080/msl -eid client4 -uid user1 -uas EMAIL_PASSWORD -eas NONE_SUFFIXED -kx ASYMMETRIC_WRAPPED -kxm JWE_RSA "$@"
exit $?
