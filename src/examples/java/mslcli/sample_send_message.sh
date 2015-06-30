#!/bin/sh

java -cp ./build:lib/msl-0.1.0-SNAPSHOT.jar:lib/bcprov-jdk15on-150.jar:lib/servlet-api-2.5.jar mslcli.client.ClientApp -url http://localhost:8080/msl -cfg mslcli.cfg -kx dh -eid simpleMslClient -uid simpleMslClientUserId -if request.dat -of response.dat
