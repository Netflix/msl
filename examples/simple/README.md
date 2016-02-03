# MSL Simple
This project contains a JavaScript client and Java server with compatible MSL configurations. Both client and server can be modified or extended for compatibility with other MSL configurations.

# Server
The server is a web project containing a single Java servlet. It can be run from within an IDE or compiled into a WAR and deployed onto a web server that includes a servlet container.

The following Gradle command, executed from the top-level directory, will use Jetty to run the server on port 8080.

    ./gradlew :msl-example:appRun
    
# Client
Open the _src/main/javascript/client/SimpleClient.html_ web page in your web browser. The web page and its associated files can also be hosted on a web server, including the same server running the Java servlet.
