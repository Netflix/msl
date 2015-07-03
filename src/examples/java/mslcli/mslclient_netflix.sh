#!/bin/sh

./mslclient.sh -cfg mslcli.cfg -int true -url http://us.noss.test.netflix.com/nccp/controller/3.1/license -kx jwe -uid anyuserid -eid MY_ESN "$@"

exit $?
