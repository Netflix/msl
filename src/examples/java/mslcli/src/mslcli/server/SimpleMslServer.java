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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Security;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

import javax.crypto.SecretKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.netflix.msl.MslConstants;
import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.crypto.SymmetricCryptoContext;
import com.netflix.msl.entityauth.PresharedKeyStore;
import com.netflix.msl.entityauth.RsaStore;
import com.netflix.msl.msg.ConsoleFilterStreamFactory;
import com.netflix.msl.msg.ErrorHeader;
import com.netflix.msl.msg.MessageContext;
import com.netflix.msl.msg.MessageInputStream;
import com.netflix.msl.msg.MslControl;
import com.netflix.msl.msg.MslControl.MslChannel;
import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.tokens.MslUser;
import com.netflix.msl.tokens.ServiceToken;
import com.netflix.msl.tokens.UserIdToken;
import com.netflix.msl.userauth.EmailPasswordStore;
import com.netflix.msl.util.MslContext;
import com.netflix.msl.util.MslStore;

import mslcli.common.Pair;
import mslcli.common.util.AppContext;
import mslcli.common.util.ConfigurationException;
import mslcli.common.util.ConfigurationRuntimeException;
import mslcli.common.util.MslProperties;
import mslcli.common.util.MslStoreWrapper;
import mslcli.common.util.SharedUtil;
import mslcli.server.msg.ServerReceiveMessageContext;
import mslcli.server.msg.ServerRespondMessageContext;
import mslcli.server.msg.ServerRespondMessageContext.Token;
import mslcli.server.util.ServerMslContext;

/**
 * <p>An example Java MSL server that listens for requests from the example MSL client.
 * </p> 
 * 
 * <p>This class is thread-safe.</p>
 * 
 * @author Vadim Spector <vspector@netflix.com>
 */

public class SimpleMslServer {
    private static final long serialVersionUID = -4593207843035538485L;

    private static final int TIMEOUT_MS = 120 * 1000;

    // Add BouncyCastle provider.
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    
    /**
     * <p>Create a new server instance and initialize its state.
     * </p>
     */
    public SimpleMslServer(final MslProperties prop) throws ConfigurationException {
        if (prop == null) {
            throw new IllegalArgumentException("NULL MslProperties");
        }

        this.appCtx = AppContext.getInstance(prop, prop.getServerId());
        this.appCtx.setMslStoreWrapper(new AppMslStoreWrapper(appCtx));

        // Create the MSL control.
        this.mslCtrl = appCtx.getMslControl();
        if (prop.isDebugOn()) {
            mslCtrl.setFilterFactory(new ConsoleFilterStreamFactory());
        }

        this.mslCtx = new ServerMslContext(appCtx, prop.getServerId(), new ServerMslConfig(appCtx, prop.getServerId()));

        // Use one crypto context for all service tokens.
        final String stKeySetId = prop.getServiceTokenKeySetId(prop.getServerId());
        final Pair<SecretKey,SecretKey> keys = appCtx.getServiceTokenKeys(stKeySetId);
        final ICryptoContext stCryptoContext = new SymmetricCryptoContext(this.mslCtx, stKeySetId, keys.x, keys.y, null);
        cryptoContexts.put("", stCryptoContext);
    }
    
    /**
     * process incoming request
     */
    public void processRequest(final InputStream in, final OutputStream out) throws ConfigurationException, IOException, MslException {
        if (in == null) {
            throw new IllegalArgumentException("NULL Input Stream");
        }
        if (out == null) {
            throw new IllegalArgumentException("NULL Output Stream");
        }
        //  Set up the receive MSL message context.
        final MessageContext rcvMsgCtx = new ServerReceiveMessageContext(cryptoContexts);

        // Receive a request.
        final MessageInputStream requestInputStream;
        final Future<MessageInputStream> requestFuture = mslCtrl.receive(mslCtx, rcvMsgCtx, in, out, TIMEOUT_MS);
        try {
            requestInputStream = requestFuture.get();
        } catch (ExecutionException e) {
            final Throwable thr = SharedUtil.getRootCause(e);
            if (thr instanceof MslException) {
                throw (MslException)thr;
            } else if (thr instanceof ConfigurationException) {
                throw (ConfigurationException)thr;
            } else if (thr instanceof ConfigurationRuntimeException) {
                throw (ConfigurationException)thr.getCause();
            } else {
                throw new IOException("ExecutionException", e);
            }
        } catch (InterruptedException e) {
            throw new IOException("InterruptedException", e);
        }

        if (requestInputStream == null) {
            System.err.println("NULL Input Stream ?");
            return;
        }

        // We should not receive error headers but check just in case.
        final ErrorHeader error = requestInputStream.getErrorHeader();
        if (error != null) {
            throw new IOException("Unexpectedly received error message: [" + error.getErrorCode() + "][" + error.getInternalCode() + "][" + error.getErrorMessage() + "]");
        }

        // Process request.
        final String clientId = requestInputStream.getIdentity();
        final MslUser user = requestInputStream.getUser();
        final byte[] request = SharedUtil.readIntoArray(requestInputStream);

        //  Set up the respond MSL message context. Echo back the initial request.
        Set<Token> tokens = new HashSet<Token>();
        tokens.addAll(Arrays.asList(
            new Token("st_name1", "st_data1", true, true),
            new Token("st_name2", "st_data2", true, true)
        ));
        final MessageContext responseMsgCtx = new ServerRespondMessageContext(clientId, true, new String(request, MslConstants.DEFAULT_CHARSET), tokens, cryptoContexts);

        // Send response. We don't need the MslChannel because we are not
        // opening a persistent channel.
        final Future<MslChannel> channelFuture = mslCtrl.respond(mslCtx, responseMsgCtx, in, out, requestInputStream, TIMEOUT_MS);
        try {
            channelFuture.get();
        } catch (ExecutionException e) {
            final Throwable thr = SharedUtil.getRootCause(e);
            if (thr instanceof MslException) {
                throw (MslException)thr;
            } else if (thr instanceof ConfigurationException) {
                throw (ConfigurationException)thr;
            } else if (thr instanceof ConfigurationRuntimeException) {
                throw (ConfigurationException)thr.getCause();
            } else {
                throw new IOException("ExecutionException", e);
            }
        } catch (InterruptedException e) {
            throw new IOException("ExecutionException", e);
        }
    }

    /*
     * This is a class to serve as an interceptor to all MslStore calls.
     * It can override only the methods in MslStore the app cares about.
     * This sample implementation just prints out the information about
     * calling some selected MslStore methods.
     */
    private static final class AppMslStoreWrapper extends MslStoreWrapper {
        private AppMslStoreWrapper(final AppContext appCtx) {
            if (appCtx == null) {
                throw new IllegalArgumentException("NULL app context");
            }
            this.appCtx = appCtx;
        }

        @Override
        public void setCryptoContext(final MasterToken masterToken, final ICryptoContext cryptoContext) {
            if (masterToken == null) {
                appCtx.info("MslStore: setting crypto context with NULL MasterToken???");
            } else {
                appCtx.info(String.format("MslStore: %s %s",
                    (cryptoContext != null)? "Adding" : "Removing", SharedUtil.getMasterTokenInfo(masterToken)));
            }
            super.setCryptoContext(masterToken, cryptoContext);
        }

        @Override
        public void removeCryptoContext(final MasterToken masterToken) {
            appCtx.info("MslStore: Removing Crypto Context for " + SharedUtil.getMasterTokenInfo(masterToken));
            super.removeCryptoContext(masterToken);
        }

        @Override
        public void clearCryptoContexts() {
            appCtx.info("MslStore: Clear Crypto Contexts");
            super.clearCryptoContexts();
        }

        @Override
        public void addUserIdToken(final String userId, final UserIdToken userIdToken) throws MslException {
            appCtx.info(String.format("MslStore: Adding %s for userId %s", SharedUtil.getUserIdTokenInfo(userIdToken), userId));
            super.addUserIdToken(userId, userIdToken);
        }
        @Override
        public void removeUserIdToken(final UserIdToken userIdToken) {
            appCtx.info("MslStore: Removing " + SharedUtil.getUserIdTokenInfo(userIdToken));
            super.removeUserIdToken(userIdToken);
        }

        @Override
        public UserIdToken getUserIdToken(final String userId) {
            appCtx.info("MslStore: Getting UserIdToken for user ID " + userId);
            return super.getUserIdToken(userId);
        }

        @Override
        public void addServiceTokens(final Set<ServiceToken> tokens) throws MslException {
            if (tokens != null && !tokens.isEmpty()) {
                final StringBuilder sb = new StringBuilder();
                for (ServiceToken st : tokens) {
                    sb.append(SharedUtil.getServiceTokenInfo(st)).append("\n");
                }
                appCtx.info("MslStore: Adding Service Tokens " + sb.toString());
            }
            super.addServiceTokens(tokens);
        }

        @Override
        public void removeServiceTokens(final String name, final MasterToken masterToken, final UserIdToken userIdToken) throws MslException {
            appCtx.info(String.format("MslStore: Removing Service Tokens %s for %s %s", name,
                SharedUtil.getMasterTokenInfo(masterToken), SharedUtil.getUserIdTokenInfo(userIdToken)));
            super.removeServiceTokens(name, masterToken, userIdToken);
        }

        private final AppContext appCtx;
    }
    
    /** application context. */
    private final AppContext appCtx;

    /** MSL context. */
    private final MslContext mslCtx;

    /** MSL control. */
    private final MslControl mslCtrl;

    /** Service token crypto contexts. */
    private final Map<String,ICryptoContext> cryptoContexts = new HashMap<String,ICryptoContext>();
}
