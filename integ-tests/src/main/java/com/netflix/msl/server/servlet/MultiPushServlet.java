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
package com.netflix.msl.server.servlet;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslKeyExchangeException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.keyx.KeyRequestData;
import com.netflix.msl.msg.MessageContext;
import com.netflix.msl.msg.MessageDebugContext;
import com.netflix.msl.msg.MessageInputStream;
import com.netflix.msl.msg.MessageOutputStream;
import com.netflix.msl.msg.MessageServiceTokenBuilder;
import com.netflix.msl.msg.PublicMessageContext;
import com.netflix.msl.server.common.PushServlet;
import com.netflix.msl.server.configuration.tokens.TokenFactoryType;
import com.netflix.msl.tokens.MslUser;
import com.netflix.msl.userauth.UserAuthenticationData;

/**
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class MultiPushServlet extends PushServlet {
    private static final long serialVersionUID = -584699388668046804L;

    /**
     * <p>Create a new secret push servlet that will echo any received data in
     * multiple push messages that require secrecy.</p>
     * 
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
    public MultiPushServlet() throws Exception {
        super(EntityAuthenticationScheme.RSA, TokenFactoryType.ACCEPT_NON_REPLAYABLE_ID, 0,
            null, null, null, null, null, false, false);
    }


    /* (non-Javadoc)
     * @see com.netflix.msl.server.common.PushServlet#process(com.netflix.msl.msg.MessageInputStream)
     */
    @Override
    protected List<MessageContext> process(final MessageInputStream mis) throws IOException {
        // Read the request.
        final ByteArrayOutputStream data = new ByteArrayOutputStream();
        do {
            final byte[] cbuf = new byte[1024];
            final int count = mis.read(cbuf);
            if (count == -1) break;
            data.write(cbuf, 0, count);
        } while (true);
        
        final MessageContext msgCtx = new PublicMessageContext() {
            @Override
            public Map<String, ICryptoContext> getCryptoContexts() {
                return Collections.emptyMap();
            }

            @Override
            public String getRemoteEntityIdentity() {
                return null;
            }

            @Override
            public boolean isRequestingTokens() {
                return false;
            }

            @Override
            public String getUserId() {
                return null;
            }

            @Override
            public UserAuthenticationData getUserAuthData(final ReauthCode reauthCode, final boolean renewable, final boolean required) {
                return null;
            }

            @Override
            public MslUser getUser() {
                return null;
            }

            @Override
            public Set<KeyRequestData> getKeyRequestData() throws MslKeyExchangeException {
                return Collections.emptySet();
            }

            @Override
            public void updateServiceTokens(final MessageServiceTokenBuilder builder, final boolean handshake) {
            }

            @Override
            public void write(final MessageOutputStream output) throws IOException {
                output.write(data.toByteArray());
                output.close();
            }

            @Override
            public MessageDebugContext getDebugContext() {
                return null;
            }
        };
        return Arrays.asList(msgCtx, msgCtx, msgCtx);
    }
}
