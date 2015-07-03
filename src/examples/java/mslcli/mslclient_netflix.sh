#!/bin/sh

./mslclient.sh -cfg mslcli.cfg -int true -url http://us.noss.test.netflix.com/nccp/controller/3.1/license -kx aw -kxm JWE_RSA -uid anyuserid -eid MY_ESN "$@"

exit $?
