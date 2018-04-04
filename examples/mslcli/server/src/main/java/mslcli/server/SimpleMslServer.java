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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Security;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

import javax.crypto.SecretKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.netflix.msl.MslException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.crypto.SymmetricCryptoContext;
import com.netflix.msl.msg.ConsoleFilterStreamFactory;
import com.netflix.msl.msg.ErrorHeader;
import com.netflix.msl.msg.MessageContext;
import com.netflix.msl.msg.MessageInputStream;
import com.netflix.msl.msg.MslControl;
import com.netflix.msl.msg.MslControl.MslChannel;
import com.netflix.msl.util.MslContext;

import mslcli.common.CmdArguments;
import mslcli.common.IllegalCmdArgumentException;
import mslcli.common.Pair;
import mslcli.common.util.AppContext;
import mslcli.common.util.ConfigurationException;
import mslcli.common.util.ConfigurationRuntimeException;
import mslcli.common.util.MslProperties;
import mslcli.common.util.SharedUtil;
import mslcli.server.msg.ServerReceiveMessageContext;
import mslcli.server.msg.ServerRespondMessageContext;
import mslcli.server.msg.ServerRespondMessageContext.Token;
import mslcli.server.util.ServerMslContext;

/**
 * <p>
 * An example Java MSL server that listens for requests from the example MSL client.
 * This class is thread-safe.
 * </p> 
 * 
 * @author Vadim Spector <vspector@netflix.com>
 */

public class SimpleMslServer {
    /** timeout for reading request and producing response */
    private static final int TIMEOUT_MS = 120 * 1000;

    // Add BouncyCastle provider.
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    
    /**
     * Create a new server instance and initialize its state.
     *
     * @param prop MslProperties from the configuration file
     * @param args command line arguments
     * @throws ConfigurationException
     * @throws IllegalCmdArgumentException
     */
    public SimpleMslServer(final MslProperties prop, final CmdArguments args) throws ConfigurationException, IllegalCmdArgumentException {
        if (prop == null) {
            throw new IllegalArgumentException("NULL MslProperties");
        }

        this.appCtx = AppContext.getInstance(prop);

        // Create the MSL control.
        this.mslCtrl = appCtx.getMslControl();
        if (args.isVerbose()) {
            mslCtrl.setFilterFactory(new ConsoleFilterStreamFactory());
        }

        this.mslCtx = new ServerMslContext(appCtx, new ServerMslConfig(appCtx, args));

        // Use one crypto context for all service tokens.
        final String stKeySetId = prop.getServiceTokenKeySetId(args.getEntityId());
        final Pair<SecretKey,SecretKey> keys = appCtx.getServiceTokenKeys(stKeySetId);
        final ICryptoContext stCryptoContext = new SymmetricCryptoContext(this.mslCtx, stKeySetId, keys.x, keys.y, null);
        cryptoContexts.put("", stCryptoContext);
    }
    
    /**
     * Process incoming MSL request and produce MSL response.
     *
     * @param in input stream for reading request
     * @param out output stream for writing response
     * @throws ConfigurationException
     * @throws IOException
     * @throws MslException
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
        } catch (final ExecutionException e) {
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
        } catch (final InterruptedException e) {
            throw new IOException("InterruptedException", e);
        }

        if (requestInputStream == null) {
            appCtx.info("NULL Input Stream");
            return;
        }

        // We should not receive error headers but check just in case.
        final ErrorHeader error = requestInputStream.getErrorHeader();
        if (error != null) {
            throw new IOException("Unexpectedly received error message: [" + error.getErrorCode() + "][" + error.getInternalCode() + "][" + error.getErrorMessage() + "]");
        }

        // Process request.
        final byte[] request = SharedUtil.readIntoArray(requestInputStream);

        //  Set up the respond MSL message context. Echo back the initial request.
        final Set<Token> tokens = new HashSet<Token>();
        tokens.addAll(Arrays.asList(
            new Token("st_name1", "st_data1", true, true),
            new Token("st_name2", "st_data2", true, true)
        ));
        final MessageContext responseMsgCtx = new ServerRespondMessageContext(true, request /*echo request*/, tokens, cryptoContexts);

        // Send response. We don't need the MslChannel because we are not
        // opening a persistent channel.
        final Future<MslChannel> channelFuture = mslCtrl.respond(mslCtx, responseMsgCtx, in, out, requestInputStream, TIMEOUT_MS);
        try {
            channelFuture.get();
        } catch (final ExecutionException e) {
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
        } catch (final InterruptedException e) {
            throw new IOException("ExecutionException", e);
        }
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
