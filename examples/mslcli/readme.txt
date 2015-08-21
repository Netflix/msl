MSL Command Line Interface.

This implementation is very basic by intent.
MSL server is a simple ECHO server accepting arbitrary inputs.
Passing JSON-formatted payloads and implementing data abstraction
layer for payload marshalling/unmarshalling was not viewed as an
essential goal, because it does not help in understanding of MSL
core; MSL messages in general can carry arbitrary payload data.

MSL CLI should be built from the top level, as one of the msl sub-projects, e.g.:
% cd ~/Git/msl
% ./gradlew build

Build distribution, so all dependencies can be picked up easily:
% ./gradlew distZip

Then go to the mslcli bin directory:
% cd examples/mslcli/bin

Unzip the distribution ZIP, to access all jar files:
./mslcli_unzip.sh

Have two terminals, for running MSL CLI client and server.
From one, start the client
% ./mslclient.sh [options]

From another start the server
% ./mslserver.sh

Please, read mslclient_manual.txt for the detailed information on how to run mslclient.sh.

The server is terminated by pressing Ctrl-C.

Comments / suggestions are welcome to decide in which direction this project needs
to go and what additional features would be the most beneficial.
