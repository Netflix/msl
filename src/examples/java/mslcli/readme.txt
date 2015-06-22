MSL Command Line Interface.

This implementation is very basic by intent.
MSL server is a simple ECHO server accepting arbitrary inputs.
Passing JSON-formatted payloads and implementing data abstraction
layer for payload marshalling/unmarshalling was not viewed as an
essential goal, because it does not help in understanding of MSL
core; MSL messages in general can carry arbitrary payload data.

To build MSL CLI:
% cd mslcli
% ./build.sh

Open two terminals. From one, type
% ./start_client.sh

From another
% ./start_server.sh

The client program will first present the command selection. Entering "help" prints help information
explaining each command and command options.

Message responses will be printed to stdout, and it's supposed to be the same as the request.

The server is terminated by pressing Ctrl-C.

Comments / suggestions are welcome to decide in which direction this project needs
to go and what additional features would be the most beneficial.
