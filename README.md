[![Build Status](https://travis-ci.org/Netflix/msl.svg?branch=master)](https://travis-ci.org/Netflix/msl)

# Message Security Layer

<img src="https://github.com/Netflix/msl/raw/gh-pages/images/msl-logo.gif" alt="MSL Logo" align="left" hspace="20" vspace="0"/>
Message Security Layer (MSL) is an extensible and flexible secure messaging framework that can be used to transport data between two or more communicating entities. Data may also be associated with specific users, and treated as confidential or non-replayable if so desired.

<br clear="all"/>

## Documentation

The [MSL Framework](https://github.com/Netflix/msl/wiki/) provides a complete description of the framework and its implementation requirements. The [Configuration Guide](https://github.com/Netflix/msl/wiki/Configuration-Guide) presents some common client and server MSL configurations. The framework documentation and configuration guide were reviewed by an external security firm. No issues were identified.

The set of public interfaces and classes an application must implement and use is documented in the [Public Javadoc](http://netflix.github.com/msl/javadoc-public/). Documentation on all of the code, including internal classes and private methods, can be found in the full [Javadoc](http://netflix.github.com/msl/javadoc/).

For questions and support please contact [Wesley Miaw](mailto:wmiaw@netflix.com) directly. Bugs and feature requests should be filed in the [Issue Tracker](https://github.com/Netflix/msl/issues/).

## Third-Party Libraries

The Java MSL code base requires the [org.json](http://www.json.org/java/) and [Bouncy Castle](http://www.bouncycastle.org) libraries. The unit tests require [JUnit 4](http://junit.org) and [Hamcrest](http://hamcrest.org). The integration tests require [TestNG](http://testng.org).

The JavaScript MSL code base includes some third-party libraries within the lib/ directory, most notably the [Clarinet](https://github.com/dscape/clarinet) parser and [jsrsasign](http://kjur.github.io/jsrsasign/).

The C++ MSL code base requires [OpenSSL](https://www.openssl.org) and includes some third-party libraries within the lib/ directory: [Chromium Numerics](https://chromium.googlesource.com/chromium/src/base/+/master/numerics/), [RapidJSON](http://rapidjson.org), [RSA Converter](https://rsaconverter.sourceforge.io), and [UTF-8 with CPP in a Portable Way](https://github.com/nemtrif/utfcpp). The unit tests also include some third-party libraries within the tests lib/ directory: [Google Mock](https://github.com/google/googlemock) and [Google Test](https://github.com/google/googletest).

All third-party libraries are subject to their respective license agreements.

## Getting Started

To build an application that uses MSL for communication, you must read through and understand the [MSL Framework](https://github.com/Netflix/msl/wiki/). This is necessary because unlike other security protocols and libraries, you must make choices about how to secure your communication and authenticate your entities and users. The [Configuration Guide](https://github.com/Netflix/msl/wiki/Configuration-Guide) can help you make those decisions.

The application interface to the MSL stack is <code>MslControl</code>. The application configuration for a single MSL network is an instance of <code>MslContext</code>. Your application may participate in multiple MSL networks and therefore have multiple instances of <code>MslContext</code> but only one <code>MslControl</code> should be used. Message-specific configuration, such as the user or security properties of that message, are specified in individual instances of <code>MessageContext</code>.

### Java

[IntelliJ IDEA](http://www.jetbrains.com/idea/) users should import the Java MSL code as a Gradle project.

[Eclipse](http://www.eclipse.org) users should use the Gradle IDE (available in the Eclipse Marketplace) and Web Tools Platform (included with the Eclipse IDE for Java EE developers) to import the Java MSL code as a Gradle project.

An example server is provided under [examples/simple/src/main/java/server/](examples/simple/src/main/java/server/). The Eclipse Gradle plugin will import this project as a web project that can be deployed onto a Tomcat server. IntelliJ users must manually configure a run configuration to deploy the project artifact into `/msl-example-server`. The example server is a J2EE servlet that will respond to requests from the example JavaScript client. The example server MSL configuration is specific to this server and should not be used to configure your application, but it can be used as the basis for doing so.

Integration tests are provided under [integ-tests/src/main/java/](integ-tests/src/main/java/). These tests can be run using the `integ-tests` Gradle target `test`. The Eclipse Gradle plugin will import this project as a web project that can be deployed onto a Tomcat server. IntelliJ users must manually configure a run configuration to deploy the project artifact into `/msl-test-server`.

A command line client and server is provided under [examples/mslcli/src/main/java/](examples/mslcli/src/main/java/). The command line client can be configured to work with any MSL server. The command line server is an example MSL server that must be run from the command line. See [examples/mslcli/readme.txt](examples/mslcli/readme.txt) for more details.

You may need to install the [Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files](http://www.oracle.com/technetwork/java/javase/downloads/) to use cryptographic keys above a certain size.

### JavaScript

The JavaScript MSL code base assumes a JavaScript execution environment that supports the latest [Web Crypto API](http://www.w3.org/TR/WebCryptoAPI/) specification. If you are using a web browser you may need to enable experimental features or feature flags to enable Web Crypto.

- Chrome Browser 37\+  
For earlier versions: <code>chrome://flags/#enable-experimental-web-platform-features</code>  
On Linux libnss 3.16.2\+ must be separately installed.
- Edge
- Firefox 34\+  
For earlier versions: <code>about:config dom.webcrypto.enabled</code>
- Internet Explorer 11\+  
- Safari 8\+

Your browser may not support all Web Crypto API algorithms, key sizes, and features. If you encounter a problem with a Web Crypto operation please check the release notes for your browser version to determine if it supports what you are trying to do.

To include the JavaScript MSL stack in your JavaScript application you must include all of the MSL JavaScript source files required by your MSL configuration. An example list of the required source files can be found in [src/test/javascript/msltests.html](src/test/javascript/msltests.html).

An example client is provided under [src/examples/simple/src/main/javascript/client/](src/examples/simple/src/main/javascript/client/). The example client is a web page that will send requests to the example Java server. The example client MSL configuration is specific to this client and should not be used to configure your application, but it can be used as the basis for doing so.

### C++

The C++ MSL code base requires C++11 and CMake.

The code base has been built and tested under the following environments:

- Xcode 8 and Homebrew (gcc6, openssl) for Mac OS.  
Compiler flags: <code>\-std=c\+\+0x \-DGTEST_DONT_DEFINE_FAIL=1 \-DRAPIDJSON_HAS_STDSTRING=1</code>.
- Xcode 8 for iOS.  
Compiler flags: <code>\-std=gnu\+\+11 \-DGTEST_DONT_DEFINE_FAIL=1 \-DRAPIDJSON_HAS_STDSTRING=1</code>.

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
