# Message Security Layer

Message Security Layer (MSL) is an extensible and flexible secure messaging protocol that can be used to transport data between two or more communicating entities. Data may also be associated with specific users, and treated as confidential or non-replayable if so desired.

## Documentation

The [MSL Protocol](https://github.com/Netflix/msl/wiki/) provides a complete description of the protocol and implementation requirements. The [Configuration Guide](https://github.com/Netflix/msl/wiki/Configuration-Guide) presents some common client and server MSL configurations.

The set of public interfaces and classes an application must implement and use is documented in the [Public Javadoc](http://netflix.github.com/msl/javadoc-public/). Documentation on all of the code, including internal classes and private methods, can be found in the full [Javadoc](http://netflix.github.com/msl/javadoc/).

## Third-Party Libraries

The Java MSL code base requires the [org.json](http://www.json.org/java/) and [Bouncy Castle](http://www.bouncycastle.org) libraries and the unit tests require [JUnit 4](http://junit.org).

The JavaScript MSL code base includes some third-party libraries within the lib/ directory, most notably the [Clarinet](https://github.com/dscape/clarinet) parser. The [jsrsasign](http://kjur.github.io/jsrsasign/) and [crypto-js](https://code.google.com/p/crypto-js/) libraries are currently included but are planned for removal.

All third-party libraries are subject to their respective license agreements.

## Getting Started

To build an application that uses MSL for communication, you must read through and understand the [MSL Protocol](https://github.com/Netflix/msl/wiki/). This is necessary because unlike other security protocols and libraries, you must make choices about how to secure your communication and authenticate your entities and users. The [Configuration Guide](https://github.com/Netflix/msl/wiki/Configuration-Guide) can help you make those decisions.

The application interface to the MSL stack is <code>MslControl</code>. The application configuration for a single MSL network is an instance of <code>MslContext</code>. Your application may participate in multiple MSL networks and therefore have multiple instances of <code>MslContext</code> but only one <code>MslControl</code> should be used. Message-specific configuration, such as the user or security properties of that message, are specified in individual instances of <code>MessageContext</code>.

### Java

The Java MSL code base includes project files for [Eclipse](http://www.eclipse.org) and [IntelliJ IDEA](http://www.jetbrains.com/idea/).

An example server is provided under [src/examples/java/server/](src/examples/java/server/). The Eclipse project is a web project that can be deployed onto a Tomcat server. The example server is a J2EE servlet that will respond to requests from the example JavaScript client. The example server MSL configuration is specific to this server and should not be used to configure your application, but it can be used as the basis for doing so.

You may need to install the [Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files](http://www.oracle.com/technetwork/java/javase/downloads/) to use cryptographic keys above a certain size.

### JavaScript

The JavaScript MSL code base assumes a JavaScript execution environment that supports the latest [Web Crypto API](http://www.w3.org/TR/WebCryptoAPI/) specification. If you are using a web browser you may need to enable experimental features or feature flags to enable Web Crypto.

- Chrome Browser 37\+  
On Linux libnss 3.16.2\+ must be separately installed.  
For earlier versions: <code>chrome://flags/#enable-experimental-web-platform-features</code>
- Firefox 34\+
- Internet Explorer 11\+  
For earlier versions: <code>about:config dom.webcrypto.enabled</code>
- Safari 8\+

Your browser may not support all Web Crypto API algorithms, key sizes, and features. If you encounter a problem with a Web Crypto operation please check the release notes for your browser version to determine if it supports what you are trying to do.

To include the JavaScript MSL stack in your JavaScript application you must include all of the MSL JavaScript source files required by your MSL configuration. You must also specify the version of Web Crypto provided by your JavaScript execution environment by calling <code>MslCrypto$setWebCryptoVersion()</code> after loading the contents of <code>WebCryptoAdapter.js</code>. An example list of the required source files and use of <code>MslCrypto$setWebCryptoVersion()</code> can be found in [src/test/javascript/msltests.html](src/test/javascript/msltests.html).

An example client is provided under [src/examples/javascript/client/](src/examples/javascript/client/). The example client is a web page that will send requests to the example Java server. The example client MSL configuration is specific to this client and should not be used to configure your appplication, but it can be used as the basis for doing so.

## LICENSE

Copyright 2014 Netflix, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

<http://www.apache.org/licenses/LICENSE-2.0>

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
