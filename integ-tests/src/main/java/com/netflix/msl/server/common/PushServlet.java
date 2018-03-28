/**
 * Copyright (c) 2017 Netflix, Inc.  All rights reserved.
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
package com.netflix.msl.server.common;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslKeyExchangeException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.keyx.KeyExchangeScheme;
import com.netflix.msl.msg.MessageContext;
import com.netflix.msl.msg.MessageDebugContext;
import com.netflix.msl.msg.MessageInputStream;
import com.netflix.msl.msg.MslControl.MslChannel;
import com.netflix.msl.msg.ServerReceiveMessageContext;
import com.netflix.msl.server.configuration.tokens.TokenFactoryType;
import com.netflix.msl.userauth.UserAuthenticationScheme;

/**
 * <p>A servlet that first receives MSL message via POST, but then sends a push
 * response instead of a normal response.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public abstract class PushServlet extends BaseServlet {
    private static final long serialVersionUID = 8620410155638929311L;

    /**
     * @param entityAuthScheme server entity authentication scheme.
     * @param type server token factory type.
     * @param seqno initial master token sequence number.
     * @param unsupportedEntityAuthSchemes unsupported entity authentication
     *        schemes. May be {@code null}.
     * @param unsupportedUserAuthSchemes unsupported user authentication
     *        schemes. May be {@code null}.
     * @param unsupportedKeyxSchemes unsupported key exchange schemes. May be
     *        {@code null}.
     * @param cryptoContexts service token crypto contexts.
     * @param dbgCtx optional message debug context. May be {@code null}.
     * @param nullCryptoContext true if the server MSL crypto context should
     *        not perform encryption or integrity protection.
     * @param console true message data should be written out to the console.
     * @throws MslCryptoException if there is an error signing or creating the
     *         entity authentication data or an error creating a key
     * @throws MslEncodingException if there is an error creating the entity
     *         authentication data.
     * @throws MslKeyExchangeException if there is an error accessing Diffie-
     *         Hellman parameters.
     * @throws NoSuchAlgorithmException if a key generation algorithm is not
     *         found.
     * @throws InvalidAlgorithmParameterException if key generation parameters
     *         are invalid.
     */
    public PushServlet(final EntityAuthenticationScheme entityAuthScheme, final TokenFactoryType type,
        final long seqno,
        final List<EntityAuthenticationScheme> unsupportedEntityAuthSchemes,
        final List<UserAuthenticationScheme> unsupportedUserAuthSchemes,
        final List<KeyExchangeScheme> unsupportedKeyxSchemes,
        final Map<String,ICryptoContext> cryptoContexts, final MessageDebugContext dbgCtx,
        final boolean nullCryptoContext, final boolean console) throws Exception
    {
        super(0, entityAuthScheme, type, seqno, unsupportedEntityAuthSchemes, unsupportedUserAuthSchemes, unsupportedKeyxSchemes, nullCryptoContext, console);
        recvMsgCtx = new ServerReceiveMessageContext(cryptoContexts, dbgCtx);
    }

    /* (non-Javadoc)
     * @see javax.servlet.http.HttpServlet#doPost(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
     */
    @Override
    protected void doPost(final HttpServletRequest req, final HttpServletResponse resp) throws IOException {
        final InputStream in = req.getInputStream();
        final OutputStream out = resp.getOutputStream();
        
        // Receive the message.
        final Future<MessageInputStream> futureRecv = mslCtrl.receive(mslCtx, recvMsgCtx, in, out, TIMEOUT);
        final MessageInputStream mis;
        try {
            mis = futureRecv.get();
        } catch (final ExecutionException | InterruptedException | CancellationException e) {
            if (debug) e.printStackTrace(System.out);
            return;
        }
        
        // If the message input stream is null, clean up and return.
        if (mis == null) {
            try { in.close(); } catch (final IOException e) {}
            try { out.close(); } catch (final IOException e) {}
            return;
        }
        
        // Deliver the message input stream for processing.
        final List<MessageContext> pushMsgCtxs;
        try {
            pushMsgCtxs = process(mis);
        } catch (final Throwable t) {
            try { in.close(); } catch (final IOException e) {}
            try { out.close(); } catch (final IOException e) {}
            return;
        }
        
        // Push responses.
        for (final MessageContext pushMsgCtx : pushMsgCtxs) {
            final Future<MslChannel> futurePush = mslCtrl.push(mslCtx, pushMsgCtx, in, out, mis, TIMEOUT);
            try {
                futurePush.get();
            } catch (final ExecutionException | InterruptedException | CancellationException e) {
                if (debug) e.printStackTrace(System.out);
                return;
            }
        }
        
        // Clean up.
        try { in.close(); } catch (final IOException e) {}
        try { out.close(); } catch (final IOException e) {}
    }
    
    /**
     * Called when a message input stream is received for further processing.
     * 
     * @param mis the message input stream.
     * @return the message contexts used to push replies.
     */
    protected abstract List<MessageContext> process(final MessageInputStream mis) throws Throwable;
    
    /** Receive message context. */
    protected MessageContext recvMsgCtx;
}
