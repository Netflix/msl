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
package server;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

import javax.xml.bind.DatatypeConverter;

import org.json.JSONObject;

import server.entityauth.SimpleRsaStore;
import server.msg.SimpleReceiveMessageContext;
import server.msg.SimpleRequest;
import server.msg.SimpleRespondMessageContext;
import server.userauth.SimpleEmailPasswordStore;
import server.userauth.SimpleUser;
import server.util.SimpleMslContext;

import com.netflix.msl.entityauth.RsaStore;
import com.netflix.msl.msg.ConsoleFilterStreamFactory;
import com.netflix.msl.msg.ErrorHeader;
import com.netflix.msl.msg.MessageContext;
import com.netflix.msl.msg.MessageInputStream;
import com.netflix.msl.msg.MslControl;
import com.netflix.msl.msg.MslControl.MslChannel;
import com.netflix.msl.userauth.EmailPasswordStore;
import com.netflix.msl.util.MslContext;

/**
 * <p>An example Java MSL server that listens on the specified port (default
 * 8080) for requests from the example JavaScript MSL client.</p> 
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class SimpleServer {
    /** Line separator. */
    private static final String NEWLINE = System.lineSeparator();
    
    /**
     * <p>Start the MSL server listening on the specified port. If no port is
     * specified then default to port 8080.</p>
     * 
     * @param args arguments.
     */
    public static void main(final String[] args) {
        // Try to interpret the first argument (if any) as a port number.
        final int port;
        try {
            port = (args.length > 0)
                ? Integer.parseInt(args[0])
                : SimpleConstants.DEFAULT_PORT;
        } catch (final NumberFormatException e) {
            System.err.println("The port number " + args[0] + " is not an integer.");
            return;
        }
        
        // Create the MSL control.
        //
        // Since this is an example process all requests on the calling thread.
        // Dump all received and sent data to the console.
        final MslControl ctrl = new MslControl(0);
        ctrl.setFilterFactory(new ConsoleFilterStreamFactory());
        
        // Create the RSA key store.
        final RsaStore rsaStore;
        try {
            final byte[] privKeyEncoded = DatatypeConverter.parseBase64Binary(SimpleConstants.RSA_PRIVKEY_B64);
            final PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(privKeyEncoded);
            final KeyFactory rsaKeyFactory = KeyFactory.getInstance("RSA");
            final PrivateKey privKey = rsaKeyFactory.generatePrivate(privKeySpec);
            rsaStore = new SimpleRsaStore(SimpleConstants.SERVER_ID, null, privKey);
        } catch (final NoSuchAlgorithmException e) {
            System.err.println("RSA algorithm not found.");
            e.printStackTrace(System.err);
            return;
        } catch (final InvalidKeySpecException e) {
            System.err.println("Invalid RSA private key.");
            e.printStackTrace(System.err);
            return;
        }
        
        // Create the email/password store.
        final Map<String,String> emailPasswords = new HashMap<String,String>();
        for (final String[] emailPassword : SimpleConstants.EMAIL_PASSWORDS)
            emailPasswords.put(emailPassword[0], emailPassword[1]);
        final EmailPasswordStore emailPasswordStore = new SimpleEmailPasswordStore(emailPasswords);
        
        // Set up the MSL context.
        final MslContext ctx = new SimpleMslContext(SimpleConstants.SERVER_ID, rsaStore, emailPasswordStore);
        
        //  Set up the receive MSL message context.
        final MessageContext rcvMsgCtx = new SimpleReceiveMessageContext();
        
        // Start accepting connections.
        final ServerSocket server;
        try {
            server = new ServerSocket(port);
        } catch (final IOException e) {
            System.err.println("Unable to open server socket on port " + port + ".");
            e.printStackTrace(System.err);
            return;
        }
        
        // Receive and respond to messages.
        while (true) {
            // Wait for a client connection.
            final InputStream in;
            final OutputStream out;
            try {
                final Socket client = server.accept();
                in = new BufferedInputStream(client.getInputStream());
                out = new BufferedOutputStream(client.getOutputStream());
            } catch (final IOException e) {
                try { server.close(); } catch (final IOException ex) {}
                e.printStackTrace(System.err);
                return;
            }
            
            // Receive a request.
            final MessageInputStream request;
            final Future<MessageInputStream> requestFuture = ctrl.receive(ctx, rcvMsgCtx, in, out, SimpleConstants.TIMEOUT_MS);
            try {
                request = requestFuture.get();
                if (request == null)
                    continue;
            } catch (final ExecutionException e) {
                e.printStackTrace(System.err);
                continue;
            } catch (final InterruptedException e) {
                System.err.println("MslControl.receive() interrupted.");
                continue;
            }
            
            // We should not receive error headers but check just in case.
            final ErrorHeader error = request.getErrorHeader();
            if (error != null) {
                System.err.println("Unexpectedly received error message: [" + error.getErrorCode() + "][" + error.getInternalCode() + "][" + error.getErrorMessage() + "]");
                continue;
            }
            
            // Process request.
            final SimpleRequest simpleRequest;
            SimpleRespondMessageContext responseMsgCtx;
            try {
                // Parse request.
                final String identity = request.getIdentity();
                final SimpleUser user = (SimpleUser)request.getUser();
                simpleRequest = SimpleRequest.parse(identity, user, request);
                
                // Output the request.
                final String requestJson = simpleRequest.toJSONString();
                final JSONObject requestJo = new JSONObject(requestJson);
                System.out.println("REQUEST" + NEWLINE +
                                   "======" + NEWLINE +
                                   requestJo.toString(4) + NEWLINE +
                                   "======");
                
                // Execute.
                responseMsgCtx = simpleRequest.execute();
            } catch (final Exception e) {
                e.printStackTrace(System.err);
                // Encryption is required to avoid accidentally leaking
                // information in the error message.
                responseMsgCtx = new SimpleRespondMessageContext(null, true, e.getMessage());
                continue;
            }
            
            // Send response. We don't need the MslChannel because we are not
            // opening a persistent channel.
            final Future<MslChannel> channelFuture = ctrl.respond(ctx, responseMsgCtx, in, out, request, SimpleConstants.TIMEOUT_MS);
            try {
                channelFuture.get();
            } catch (final ExecutionException e) {
                e.printStackTrace(System.err);
                continue;
            } catch (final InterruptedException e) {
                System.err.println("MslControl.receive() interrupted.");
                continue;
            }
            
            // Output the response.
            System.out.println("RESPONSE" + NEWLINE +
                               "========" + NEWLINE +
                               responseMsgCtx.getData() + NEWLINE +
                               "========");
            
            // If the request type was quit then exit.
            if (SimpleRequest.Type.QUIT.equals(simpleRequest.getType()))
                break;
        }
        
        // Close the server socket.
        try { server.close(); } catch (final IOException e) {}
    }
}
