MSL Command Line Interface.

This implementation is very basic by intent.
MSL server is a simple ECHO server accepting arbitrary inputs.
Passing JSON-formatted payloads and implementing data abstraction
layer for payload marshalling/unmarshalling was not viewed as an
essential goal, because it does not help in understanding of MSL
core; MSL messages in general can carry arbitrary payload data.

MSL CLI should be built from the top level directory where the gradlew binary
is located:
% ./gradlew -p examples/mslcli compileJava

Build distribution, so all dependencies can be picked up easily:
% ./gradlew -p examples/mslcli distZip

Then go to the mslcli build directory:
% cd examples/mslcli/build

Unzip the distribution ZIP into the build directory:
% unzip distributions/*.zip

From the new directory, open two terminal sessions to run the MSL CLI client
and server.

From one, start the client
% ./bin/mslclient.sh [options]
% ./bin/mslclient.sh help

From another start the server
% ./bin/mslserver.sh

The server is terminated by pressing Ctrl-C.