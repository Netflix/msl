#!/bin/bash

# find directory of thsi script
DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

# path to where all JARs are stored
JAR_HOME="$DIR/msl-cli-0.1.0-SNAPSHOT/lib"

CLASSPATH="$JAR_HOME/mslcli-core-0.1.0-SNAPSHOT.jar:$JAR_HOME/servlet-api-2.5.jar:$JAR_HOME/msl-core-0.1.0-SNAPSHOT.jar:$JAR_HOME/bcprov-jdk15on-1.46.jar:$JAR_HOME/json-20140107.jar"

java -cp $CLASSPATH mslcli.server.SimpleHttpServer -cfg mslsrv.cfg -eid server1 -eas RSA "$@"

exit $?

