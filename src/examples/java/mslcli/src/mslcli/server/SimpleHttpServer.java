/**
 * Copyright (c) 2014 Netflix, Inc.  All rights reserved.
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

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import mslcli.common.util.SharedUtil;

public class SimpleHttpServer {

    public static void main(String[] args) throws Exception {
        final SimpleMslServer mslServer = new SimpleMslServer();
        final HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
        server.createContext("/msl", new MyHandler(mslServer));
        server.setExecutor(null); // creates a default executor
        server.start();
    }

    static class MyHandler implements HttpHandler {
        MyHandler(final SimpleMslServer mslServer) {
            this.mslServer = mslServer;
        }

        @Override
        public void handle(HttpExchange t) throws IOException {
            System.out.println("Processing request");

            try {
                // Allow requests from anywhere.
                t.getResponseHeaders().set("Access-Control-Allow-Origin", "*");

                final ByteArrayOutputStream out = new ByteArrayOutputStream();
                mslServer.processRequest(t.getRequestBody(), out);

                final byte[] response = out.toByteArray();

                t.sendResponseHeaders(200, response.length);
                OutputStream os = t.getResponseBody();
                os.write(response);
                os.close();
            } catch (IOException e) {
               System.err.println("\nIO-ERROR: " + e);
               System.err.println("ROOT CAUSE:");
               SharedUtil.getCause(e).printStackTrace(System.err);
               throw e;
            } catch (RuntimeException e) {
               System.err.println("\nRT-ERROR: " + e);
               System.err.println("ROOT CAUSE:");
               SharedUtil.getCause(e).printStackTrace(System.err);
               throw e;
            }
            System.out.println("\nSUCCESS!!!\n");
        }

        private final SimpleMslServer mslServer;
    }
}
