Initial implementation of MSL Command Line Interface.

This implementation is very basic by intent.
Comments / suggestions are welcome to decide in which
direction this project needs to go and which additional
features will be most beneficial.

MSL server is a simple ECHO server. Passing JSON-formatted
payloads and implementing data abstraction layer for
marshalling/unmarshalling payload was not viewed as essential
goal, because it does not help in understanding of MSL core,
and MSL messages can carry arbitrary data.

To run MSL CLI:
% cd mslcli
% ./build.sh

Open two terminals. From one, type
% ./start_client.sh

From another
% ./start_server.sh

The client will enter the infinite prompt loop, asking for text message to be sent to the server.
The response will be printed to stdout, and it's supposed to be the same.

Both client and server must be terminated by Ctrl-C.

Note: mslcli.cli package contains the code that is not being used so far and can be ignored.
It is meant to be used for command-line options parsing, for a future support of flexible
client/server configurations.
