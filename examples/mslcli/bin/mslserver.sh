#!/bin/sh

java -cp ./build/mslcli-core.jar:lib/msl-0.1.0-SNAPSHOT.jar:lib/bcprov-jdk15on-150.jar:lib/servlet-api-2.5.jar mslcli.server.SimpleHttpServer -cfg mslsrv.cfg -eid server1 -eas RSA "$@"
