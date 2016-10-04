#!/bin/bash

# find directory of this script
DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

# path to where all JARs are stored
JAR_HOME="$DIR/../lib"

CLASSPATH="$JAR_HOME/*"

java -cp "$CLASSPATH" mslcli.server.SimpleHttpServer -cfg "$DIR/mslsrv.cfg" -eid server1 -eas RSA "$@"

exit $?
