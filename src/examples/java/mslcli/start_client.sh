#!/bin/sh

java -cp ./build:lib/msl-0.1.0-SNAPSHOT.jar:lib/bcprov-jdk15on-150.jar:lib/servlet-api-2.5.jar mslcli.client.ClientApp http://localhost:8080/msl
