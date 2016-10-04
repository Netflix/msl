MSL Command Line Interface.

This implementation is very basic by intent.
MSL server is a simple ECHO server accepting arbitrary inputs.
Passing JSON-formatted payloads and implementing data abstraction layer
for payload marshalling/unmarshalling was not viewed as an essential goal,
because it does not help in understanding of MSL core; MSL messages in
general can carry arbitrary payload data.

MSL CLI should be built from the top level directory where the gradlew binary
is located:

Contents:
========

 * client:
   Client code example, and MSLCLI common library.

 * server:
   Server code example - depends upon client MSLCLI.


First build the client/lib and distribution:

% ./gradlew -p examples/mslcli/client compileJava
% ./gradlew -p examples/mslcli/client distZip

Next, build the Server

% ./gradlew -p examples/mslcli/server compileJava
% ./gradlew -p examples/mslcli/server distZip

Extract the client and server distributions into their respective build
directories:

% cd examples/mslcli/client/build
% unzip distributions/*.zip
% cd ../../../../examples/mslcli/server/build
% unzip distributions/*.zip

From the new client directory, open a new terminal session to run the MSL CLI client

From one, start the client
% ./client/build/distributions/*/bin/mslclient.sh [options]
% ./client/build/distributions/*/bin/mslclient.sh help

From another terminal start the server
% ./server/build/distributions/*/bin/mslserver.sh

The server is terminated by pressing Ctrl-C.
