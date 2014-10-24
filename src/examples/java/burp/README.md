# MSL Burp Extender

[Burp Suite](http://portswigger.net/burp/) is a platform for security testing of web applications. The MSL Burp Extender allows you to inspect MSL messages that are transmitted through a Burp proxy.

This version has been tested with the free edition of Burp Suite v1.6.

## Getting Started

Since every MSL configuration is different and messages are secured using authentication schemes, key exchange schemes, and crypto keys specific to a configuration, you must first configure the MSL Burp Extender to match your configuration. Generally speaking, this can be accomplished by providing the MSL Burp Extender with the same configuration (i.e. @MslContext@) as your trusted services server.

An example configuration compatible with the integration test server is defined in [msl/util/WiretapMslContext.java](msl/util/WiretapMslContext.java).

Once you have the MSL Burp Extender configured properly, you can use it with Burp Suite.

* Start Burp Suite.
* Create a JAR from the MSL Burp Extender and install it into Burp Suite.
* In Burp Suite the Proxy > Options will display the proxy URL the client should use.
  * on the "Request Handling" tab enable "Support Invisible Proxying"
* In Burp Suite set Options > Connections to the real MSL server.
