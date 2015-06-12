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
