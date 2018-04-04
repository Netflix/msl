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
package server;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.json.JSONObject;

import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.crypto.JcaAlgorithm;
import com.netflix.msl.crypto.SymmetricCryptoContext;
import com.netflix.msl.entityauth.RsaStore;
import com.netflix.msl.msg.ConsoleFilterStreamFactory;
import com.netflix.msl.msg.ErrorHeader;
import com.netflix.msl.msg.MessageContext;
import com.netflix.msl.msg.MessageInputStream;
import com.netflix.msl.msg.MslControl;
import com.netflix.msl.msg.MslControl.MslChannel;
import com.netflix.msl.userauth.EmailPasswordStore;
import com.netflix.msl.util.Base64;
import com.netflix.msl.util.MslContext;

import server.entityauth.SimpleRsaStore;
import server.msg.SimpleReceiveMessageContext;
import server.msg.SimpleRequest;
import server.msg.SimpleRespondMessageContext;
import server.userauth.SimpleEmailPasswordStore;
import server.userauth.SimpleUser;
import server.util.SimpleMslContext;

/**
 * <p>An example Java MSL servlet that listens for requests from the example
 * JavaScript MSL client. Once any authorized client issues a quit operation,
 * this servlet will no longer process additional requests and will instead
 * return HTTP status code {@code 401}. The server must be restarted to re-
 * enable the servlet.</p> 
 * 
 * <p>This class is thread-safe.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class SimpleServlet extends HttpServlet {
    private static final long serialVersionUID = -4593207843035538485L;
    
    /** Line separator. */
    private static final String NEWLINE = System.lineSeparator();
    
    /** Service token key set ID. */
    private static final String ST_KEYSET_ID = "serviceTokenKeySetId";
    /** Service token encryption key. */
    private static final byte[] ST_ENCRYPTION_KEY = new byte[] {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };
    /** Service token HMAC key. */
    private static final byte[] ST_HMAC_KEY = new byte[] {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    };
    
    /** "Quit" state. */
    private static boolean QUIT = false;
    
    // Add BouncyCastle provider.
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    
    /**
     * <p>Create a new servlet instance and initialize its static, immutable
     * state.</p>
     */
    public SimpleServlet() {
        // Create the RSA key store.
        final RsaStore rsaStore;
        try {
            final byte[] privKeyEncoded = Base64.decode(SimpleConstants.RSA_PRIVKEY_B64);
            final PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(privKeyEncoded);
            final KeyFactory rsaKeyFactory = KeyFactory.getInstance("RSA");
            final PrivateKey privKey = rsaKeyFactory.generatePrivate(privKeySpec);
            rsaStore = new SimpleRsaStore(SimpleConstants.SERVER_ID, null, privKey);
        } catch (final NoSuchAlgorithmException e) {
            throw new RuntimeException("RSA algorithm not found.", e);
        } catch (final InvalidKeySpecException e) {
            throw new RuntimeException("Invalid RSA private key.", e);
        }
        
        // Create the email/password store.
        final Map<String,String> emailPasswords = new HashMap<String,String>();
        for (final String[] emailPassword : SimpleConstants.EMAIL_PASSWORDS)
            emailPasswords.put(emailPassword[0], emailPassword[1]);
        final EmailPasswordStore emailPasswordStore = new SimpleEmailPasswordStore(emailPasswords);
        
        // Set up the MSL context.
        this.ctx = new SimpleMslContext(SimpleConstants.SERVER_ID, rsaStore, emailPasswordStore);
        
        // Create the MSL control.
        //
        // Since this is an example process all requests on the calling thread.
        this.ctrl = new MslControl(0);
        ctrl.setFilterFactory(new ConsoleFilterStreamFactory());
        
        // Use one crypto context for all service tokens.
        final SecretKey encryptionKey = new SecretKeySpec(ST_ENCRYPTION_KEY, JcaAlgorithm.AES);
        final SecretKey hmacKey = new SecretKeySpec(ST_HMAC_KEY, JcaAlgorithm.HMAC_SHA256);
        final ICryptoContext stCryptoContext = new SymmetricCryptoContext(this.ctx, ST_KEYSET_ID, encryptionKey, hmacKey, null);
        cryptoContexts.put("", stCryptoContext);
    }
    
    /* (non-Javadoc)
     * @see javax.servlet.http.HttpServlet#doPost(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
     */
    @Override
    protected void doPost(final HttpServletRequest req, final HttpServletResponse resp) throws IOException {
        // Allow requests from anywhere.
        resp.setHeader("Access-Control-Allow-Origin", "*");
        
        // If "quit" then return HTTP status code 401.
        if (QUIT) {
            System.out.println("Returning 401.");
            resp.sendError(HttpServletResponse.SC_GONE, "MSL servlet terminated.");
            return;
        }
        
        //  Set up the receive MSL message context.
        final MessageContext rcvMsgCtx = new SimpleReceiveMessageContext(cryptoContexts);

        // Receive a request.
        final InputStream in = req.getInputStream();
        final OutputStream out = resp.getOutputStream();
        final MessageInputStream request;
        final Future<MessageInputStream> requestFuture = ctrl.receive(ctx, rcvMsgCtx, in, out, SimpleConstants.TIMEOUT_MS);
        try {
            request = requestFuture.get();
            if (request == null)
                return;
        } catch (final ExecutionException e) {
            e.printStackTrace(System.err);
            return;
        } catch (final InterruptedException e) {
            System.err.println("MslControl.receive() interrupted.");
            return;
        }

        // We should not receive error headers but check just in case.
        final ErrorHeader error = request.getErrorHeader();
        if (error != null) {
            System.err.println("Unexpectedly received error message: [" + error.getErrorCode() + "][" + error.getInternalCode() + "][" + error.getErrorMessage() + "]");
            return;
        }

        // Process request.
        final SimpleRequest simpleRequest;
        SimpleRespondMessageContext responseMsgCtx;
        try {
            // Parse request.
            final String identity = request.getIdentity();
            final SimpleUser user = (SimpleUser)request.getUser();
            simpleRequest = SimpleRequest.parse(identity, user, request, cryptoContexts);

            // Output the request.
            final String requestJson = simpleRequest.toJSONString();
            final JSONObject requestJo = new JSONObject(requestJson);
            System.out.println(NEWLINE + "REQUEST" + NEWLINE +
                "======" + NEWLINE +
                requestJo.toString(4) + NEWLINE +
                "======");

            // Execute.
            responseMsgCtx = simpleRequest.execute();

            // If the request type was quit then remember it.
            if (SimpleRequest.Type.QUIT.equals(simpleRequest.getType()))
                QUIT = true;
        } catch (final Exception e) {
            e.printStackTrace(System.err);
            // FIXME: Remove encryption requirement.
            // Encryption is required to avoid accidentally leaking
            // information in the error message.
            responseMsgCtx = new SimpleRespondMessageContext(true, e.getMessage());
        }

        // Send response. We don't need the MslChannel because we are not
        // opening a persistent channel.
        final Future<MslChannel> channelFuture = ctrl.respond(ctx, responseMsgCtx, in, out, request, SimpleConstants.TIMEOUT_MS);
        try {
            channelFuture.get();
        } catch (final ExecutionException e) {
            e.printStackTrace(System.err);
            return;
        } catch (final InterruptedException e) {
            System.err.println("MslControl.receive() interrupted.");
            return;
        }

        // Output the response.
        System.out.println(NEWLINE + "RESPONSE" + NEWLINE +
            "========" + NEWLINE +
            responseMsgCtx.getData() + NEWLINE +
            "========");
    }
    
    /** MSL context. */
    private final MslContext ctx;
    /** MSL control. */
    private final MslControl ctrl;
    /** Service token crypto contexts. */
    private final Map<String,ICryptoContext> cryptoContexts = new HashMap<String,ICryptoContext>();
}
