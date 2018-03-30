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
package server.msg;

import java.io.IOException;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

import com.netflix.msl.MslConstants;
import com.netflix.msl.MslConstants.CompressionAlgorithm;
import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslException;
import com.netflix.msl.MslKeyExchangeException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.keyx.KeyRequestData;
import com.netflix.msl.msg.MessageContext;
import com.netflix.msl.msg.MessageDebugContext;
import com.netflix.msl.msg.MessageOutputStream;
import com.netflix.msl.msg.MessageServiceTokenBuilder;
import com.netflix.msl.tokens.MslUser;
import com.netflix.msl.userauth.UserAuthenticationData;

/**
 * <p>Example server message context for sending response messages.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class SimpleRespondMessageContext implements MessageContext {
    /**
     * <p>Service token container.</p>
     */
    public static class Token {
        /**
         * <p>Define a new service token for inclusion in the response message.
         * If the service token should be entity- or user-bound but cannot be,
         * the maximum binding possible is used but the service token is
         * included in the response.</p>
         * 
         * @param name service token name.
         * @param data service token application data.
         * @param entityBound true if the service token should be entity-bound.
         * @param userBound true if the service token should be user-bound.
         */
        public Token(final String name, final String data, final boolean entityBound, final boolean userBound) {
            this.name = name;
            this.data = data;
            this.entityBound = entityBound;
            this.userBound = userBound;
        }
        
        /** Service token name. */
        public final String name;
        /** Service token application data. */
        public final String data;
        /** Service token should be entity-bound. */
        public final boolean entityBound;
        /** Service token should be user-bound. */
        public final boolean userBound;
    }
    
    /**
     * <p>Create a new response message context with the specified
     * properties.</p>
     * 
     * @param encrypted true if the response data must be encrypted.
     * @param data application response data.
     */
    public SimpleRespondMessageContext(final boolean encrypted, final String data) {
        this.encrypted = encrypted;
        this.data = data;
        this.tokens = Collections.emptySet();
        this.cryptoContexts = Collections.emptyMap();
    }
    
    /**
     * <p>Create a new response message context with the specified
     * properties.</p>
     * 
     * @param encrypted true if the response data must be encrypted.
     * @param data application response data.
     * @param tokens application service tokens.
     * @param cryptoContexts application service token crypto contexts.
     */
    public SimpleRespondMessageContext(final boolean encrypted, final String data, final Set<Token> tokens, final Map<String,ICryptoContext> cryptoContexts) {
        this.encrypted = encrypted;
        this.data = data;
        this.tokens = tokens;
        this.cryptoContexts = Collections.unmodifiableMap(cryptoContexts);
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.msg.MessageContext#getCryptoContexts()
     */
    @Override
    public Map<String, ICryptoContext> getCryptoContexts() {
        return cryptoContexts;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.msg.MessageContext#getRemoteEntityIdentity()
     */
    @Override
    public String getRemoteEntityIdentity() {
        return null;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.msg.MessageContext#isEncrypted()
     */
    @Override
    public boolean isEncrypted() {
        return encrypted;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.msg.MessageContext#isIntegrityProtected()
     */
    @Override
    public boolean isIntegrityProtected() {
        return true;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.msg.MessageContext#isNonReplayable()
     */
    @Override
    public boolean isNonReplayable() {
        return false;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.msg.MessageContext#isRequestingTokens()
     */
    @Override
    public boolean isRequestingTokens() {
        return false;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.msg.MessageContext#getUserId()
     */
    @Override
    public String getUserId() {
        return null;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.msg.MessageContext#getUserAuthData(com.netflix.msl.msg.MessageContext.ReauthCode, boolean, boolean)
     */
    @Override
    public UserAuthenticationData getUserAuthData(final ReauthCode reauthCode, final boolean renewable, final boolean required) {
        return null;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.msg.MessageContext#getUser()
     */
    @Override
    public MslUser getUser() {
        return null;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.msg.MessageContext#getKeyRequestData()
     */
    @Override
    public Set<KeyRequestData> getKeyRequestData() throws MslKeyExchangeException {
        return null;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.msg.MessageContext#updateServiceTokens(com.netflix.msl.msg.MessageServiceTokenBuilder, boolean)
     */
    @Override
    public void updateServiceTokens(final MessageServiceTokenBuilder builder, final boolean handshake) throws MslEncodingException, MslCryptoException, MslException {
        if (handshake)
            return;
        
        for (final Token token : tokens) {
            final String name = token.name;
            final byte[] data = token.data.getBytes(MslConstants.DEFAULT_CHARSET);
            if (token.userBound && builder.isPrimaryUserIdTokenAvailable())
                builder.addUserBoundPrimaryServiceToken(name, data, true, CompressionAlgorithm.GZIP);
            else if (token.entityBound && builder.isPrimaryMasterTokenAvailable())
                builder.addMasterBoundPrimaryServiceToken(name, data, true, CompressionAlgorithm.GZIP);
            else
                builder.addUnboundPrimaryServiceToken(name, data, true, CompressionAlgorithm.GZIP);
        }
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.msg.MessageContext#write(com.netflix.msl.msg.MessageOutputStream)
     */
    @Override
    public void write(final MessageOutputStream output) throws IOException {
        output.write(data.getBytes(MslConstants.DEFAULT_CHARSET));
        output.close();
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.msg.MessageContext#getDebugContext()
     */
    @Override
    public MessageDebugContext getDebugContext() {
        return null;
    }
    
    /**
     * @return the application response data.
     */
    public String getData() {
        return data;
    }

    /** Service token crypto contexts. */
    private final Map<String,ICryptoContext> cryptoContexts;
    /** True if the response data must be encrypted. */
    private final boolean encrypted;
    /** Response data. */
    private final String data;
    /** Service tokens. */
    private final Set<Token> tokens;
}
