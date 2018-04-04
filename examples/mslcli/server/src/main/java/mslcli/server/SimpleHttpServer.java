/**
 * Copyright (c) 2014-2018 Netflix, Inc.  All rights reserved.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package mslcli.server;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.util.Date;

import com.netflix.msl.MslException;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import mslcli.common.CmdArguments;
import mslcli.common.util.ConfigurationException;
import mslcli.common.util.ConfigurationRuntimeException;
import mslcli.common.util.MslProperties;
import mslcli.common.util.SharedUtil;

/**
 * <p>Simple HTTP Server using com.sun.net.httpserver.* classes built into Oracle's JVM</p>
 *
 * @author Vadim Spector <vspector@netflix.com>
 */

public class SimpleHttpServer {

    /**
     * HTTP server launcher
     * @param args command line arguments
     */
    public static void main(final String[] args) {
        if (args.length < 1) {
            log("Parameters: config_file");
            System.exit(1);
        }
        try {
            final CmdArguments cmdArgs = new CmdArguments(args);
            final MslProperties prop = MslProperties.getInstance(SharedUtil.loadPropertiesFromFile(cmdArgs.getConfigFilePath()));
            final SimpleMslServer mslServer = new SimpleMslServer(prop, cmdArgs);
            final HttpServer server = HttpServer.create(new InetSocketAddress(prop.getServerPort()), 0);
            server.createContext("/mslcli-server", new MyHandler(mslServer));
            server.setExecutor(null); // creates a default executor
            log(String.format("waiting for requests on http://localhost:%d/mslcli-server ...", prop.getServerPort()));
            server.start();
        } catch (final ConfigurationException e) {
            log("Server Configuration Error: " + e.getMessage());
            System.exit(1);
        } catch (final IOException e) {
            log("Server Initialization Error: " + e.getMessage());
            System.exit(1);
        } catch (final Exception e) {
            log("Server Internal Error: " + e.getMessage());
            SharedUtil.getRootCause(e).printStackTrace(System.err);
            System.exit(1);
        }
    }

    /**
     * callback class for handling to HTTP requests
     */
    static class MyHandler implements HttpHandler {
        /**
         * @param mslServer MSL server to delegate requests to
         */
        MyHandler(final SimpleMslServer mslServer) {
            this.mslServer = mslServer;
        }

        @Override
        public void handle(final HttpExchange t) throws IOException {
            log("Processing request");
            final long t_start = System.currentTimeMillis();

            final ByteArrayOutputStream out = new ByteArrayOutputStream();
            try {
                // Allow requests from anywhere.
                t.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
                mslServer.processRequest(t.getRequestBody(), out);
            } catch (final ConfigurationException e) {
                log("Server Configuration Error: " + e.getMessage());
            } catch (final ConfigurationRuntimeException e) {
                log("Server Configuration Error: " + e.getCause().getMessage());
            } catch (final MslException e) {
                log(SharedUtil.getMslExceptionInfo(e));
            } catch (final IOException e) {
                final Throwable thr = SharedUtil.getRootCause(e);
                log("IO-ERROR: " + e);
                log("ROOT CAUSE:");
                thr.printStackTrace(System.err);
            } catch (final RuntimeException e) {
                log("RT-ERROR: " + e);
                log("ROOT CAUSE:");
                SharedUtil.getRootCause(e).printStackTrace(System.err);
            } finally {
                final byte[] response = out.toByteArray();
                t.sendResponseHeaders(200, response.length);
                final OutputStream os = t.getResponseBody();
                os.write(response);
                os.flush();
                os.close();
            }

            final long t_total = System.currentTimeMillis() - t_start;
            log(String.format("SUCCESS: %1$te/%1$tm/%1$tY %1$tH:%1$tM:%1$tS.%1$tL", new Date()));
            log(String.format("Processing Time %d msec", t_total));
        }

        /** MSL server to delegate requests to */
        private final SimpleMslServer mslServer;
    }

    /**
     * @param msg message to log
     */
    private static void log(final String msg) {
        System.out.println(msg);
    }
}
