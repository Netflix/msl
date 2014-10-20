# Burp Extender for MSL

## What is Brup Suite

Refer to http://portswigger.net/burp/

## Extender

### Changes before creating extender jar

* Modify WiretapMslContext.java with appropriate MSL Server keys
    * MSL_ENCRYPTION_KEY
    * MSL_HMAC_KEY
    * MSL_WRAPPING_KEY

### Steps to setup extender

* Start Burp Suite, this extender was tested with free edition (burpsuite_free_v1.6.jar)
* Create Jar out of the extender code and use it with Extender tool (http://portswigger.net/burp/extender/) in Burp Suite.
* Setup proxy options in the Proxy -> options, these is the endpoint with which client communicates.
    * Make sure to check "Support invisible proxying" in "Request handling" tab of the proxy setting.
* Setup upward proxy server in the options -> connections to talk to actual MSL server.





