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
import java.io.PrintWriter;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Future;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.netflix.msl.MslConstants;
import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslKeyExchangeException;
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.keyx.KeyExchangeScheme;
import com.netflix.msl.msg.MessageInputStream;
import com.netflix.msl.server.configuration.msg.ServerMessageContext;
import com.netflix.msl.server.configuration.tokens.TokenFactoryType;
import com.netflix.msl.userauth.UserAuthenticationScheme;

/**
 * <p>A servlet that accepts POST requests in order to send a response.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class RespondServlet extends BaseServlet {
    private static final long serialVersionUID = -167726318549015539L;
    
    protected static final String payload = "Hello";
    protected static final String error = "Error";
    
    /**
     * @param numThreads
     * @param entityAuthScheme
     * @param tokenFactoryType
     * @param initialSequenceNum
     * @param isMessageEncrypted
     * @param isIntegrityProtected
     * @param unSupportedEntityAuthFactories
     * @param unSupportedUserAuthFactories
     * @param unSupportedKeyxFactories
     * @param isNullCryptoContext
     * @param setConsoleFilterStreamFactory
     * @throws NoSuchAlgorithmException if a key generation algorithm is not
     *         found.
     * @throws InvalidAlgorithmParameterException if key generation parameters
     *         are invalid.
     * @throws MslKeyExchangeException if there is an error accessing Diffie-
     *         Hellman parameters.
     * @throws MslCryptoException if there is an error signing or creating the
     *         entity authentication data.
     * @throws MslEncodingException if there is an error creating the entity
     *         authentication data.
     * @throws Exception if there is an error configuring the servlet.
     */
    public RespondServlet(final int numThreads, final EntityAuthenticationScheme entityAuthScheme, final TokenFactoryType tokenFactoryType,
        final long initialSequenceNum, final boolean isMessageEncrypted, final boolean isIntegrityProtected,
        final List<EntityAuthenticationScheme> unSupportedEntityAuthFactories,
        final List<UserAuthenticationScheme> unSupportedUserAuthFactories,
        final List<KeyExchangeScheme> unSupportedKeyxFactories,
        final boolean isNullCryptoContext, final boolean setConsoleFilterStreamFactory) throws Exception
    {
        super(numThreads, entityAuthScheme, tokenFactoryType, initialSequenceNum,
            unSupportedEntityAuthFactories, unSupportedUserAuthFactories, unSupportedKeyxFactories,
            isNullCryptoContext, setConsoleFilterStreamFactory);
        this.encrypted = isMessageEncrypted;
        this.integrityProtected = isIntegrityProtected;
    }
    
    /**
     * @throws NoSuchAlgorithmException if a key generation algorithm is not
     *         found.
     * @throws InvalidAlgorithmParameterException if key generation parameters
     *         are invalid.
     * @throws MslKeyExchangeException if there is an error accessing Diffie-
     *         Hellman parameters.
     * @throws MslCryptoException if there is an error signing or creating the
     *         entity authentication data.
     * @throws MslEncodingException if there is an error creating the entity
     *         authentication data.
     * @throws Exception if there is an error configuring the servlet.
     */
    @Override
    protected void configure() throws Exception {
        super.configure();
        
        /**
         * Message Context Configuration
         */
        msgCtx = new ServerMessageContext(mslCtx, payload.getBytes(MslConstants.DEFAULT_CHARSET), encrypted);
        msgCtx.setIntegrityProtected(integrityProtected);
    }

    @Override
    protected void doPost(final HttpServletRequest request, final HttpServletResponse response) throws IOException {
        final InputStream inStream = request.getInputStream();
        final OutputStream outStream = response.getOutputStream();
        InputStream mslInputStream = null;

        final byte[] buffer = new byte[5];

        try {
            final Future<MessageInputStream> msgInputStream = mslCtrl.receive(mslCtx, msgCtx, inStream, outStream, TIMEOUT);

            mslInputStream = msgInputStream.get();
            if (mslInputStream == null) return;

            do {
                final int bytesRead = mslInputStream.read(buffer);
                if (bytesRead == -1) break;
            } while (true);

            //Checking the the received payload is the same as the one the client sent
            if (!Arrays.equals(payload.getBytes(MslConstants.DEFAULT_CHARSET), buffer)) {
                msgCtx.setBuffer(error.getBytes(MslConstants.DEFAULT_CHARSET));
                mslCtrl.respond(mslCtx, msgCtx, inStream, outStream, msgInputStream.get(), TIMEOUT);
                throw new IllegalStateException("PayloadBytes is not as expected: " + Arrays.toString(buffer));
            }
            msgCtx.setBuffer(buffer);
            mslCtrl.respond(mslCtx, msgCtx, inStream, outStream, msgInputStream.get(), TIMEOUT);

        } catch (final Exception ex) {
            if (debug)
                ex.printStackTrace(System.out);
        } finally {
            if (mslInputStream != null) {
                mslInputStream.close();
            }
        }
    }
    
    @Override
    protected void setPrivateVariable(final PrintWriter out, final String key, final String[] values) throws Exception {
        if (key.equals("encrypted")) {
            this.encrypted = Boolean.parseBoolean(values[0]);
            out.println(key + ": " + values[0]);
        } else if (key.equals("intProtected")) {
            this.integrityProtected = Boolean.parseBoolean(values[0]);
            out.println(key + ": " + values[0]);
        } else {
            super.setPrivateVariable(out, key, values);
        }
    }
    
    /** Message context. */
    protected ServerMessageContext msgCtx;
    /** Application data encrypted. */
    protected boolean encrypted;
    /** Application data integrity protected. */
    protected boolean integrityProtected;
}
