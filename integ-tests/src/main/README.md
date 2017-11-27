# MSL Integration Tests

The integration tests consist of a set of Java servlets and a matching set of TestNG classes. These tests concentrate on executing end-to-end communication between a trusted services client and server.

## Setup

The servlets found in [java/com/netflix/msl/server/](java/com/netflix/msl/server/) must be built and deployed on a Java application server (e.g. Tomcat).

Once the server is running the tests found in [java/com/netflix/msl/client/](java/com/netflix/msl/client/) may be run. The tests assume the server application is available at http://localhost:8080/msl-integ-tests/. The tests must be run sequentially; they will not succeed if run in parallel.