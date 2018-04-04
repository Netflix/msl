/**
 * Copyright (c) 2016 Netflix, Inc.  All rights reserved.
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
package oneshot;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslException;
import com.netflix.msl.MslInternalException;
import com.netflix.msl.MslKeyExchangeException;
import com.netflix.msl.MslMessageException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.keyx.AsymmetricWrappedExchange;
import com.netflix.msl.keyx.KeyRequestData;
import com.netflix.msl.msg.MessageDebugContext;
import com.netflix.msl.msg.MessageOutputStream;
import com.netflix.msl.msg.MessageServiceTokenBuilder;
import com.netflix.msl.msg.SecretMessageContext;
import com.netflix.msl.tokens.MslUser;
import com.netflix.msl.userauth.EmailPasswordAuthenticationData;
import com.netflix.msl.userauth.UserAuthenticationData;

/**
 * <p>A simple message context for the oneshot example.</p>
 * 
 * <p>All data must be encrypted and integrity protected. Email/password user
 * authentication is supported.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class OneshotMessageContext extends SecretMessageContext {
    /** MSL local user ID. */
    private static final String USER_ID = "local-userid";
    /** Key exchange key pair ID. */
    private static final String KEY_PAIR_ID = "keyx-keypairid";
    
    /**
     * <p>Crate a new message context with the provided application data. If
     * both email and password are provided then user authentication data will
     * be provided as needed.</p>
     * 
     * @param data application data.
     * @param email user email address. May be {@code null}.
     * @param password user password. May be {@code null}.
     */
    public OneshotMessageContext(final byte[] data, final String email, final String password) {
        this.data = data;
        if (email != null && password != null)
            this.userAuthData = new EmailPasswordAuthenticationData(email, password);
        else
            this.userAuthData = null;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.msg.MessageContext#getCryptoContexts()
     */
    @Override
    public Map<String, ICryptoContext> getCryptoContexts() {
        return null;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.msg.MessageContext#getRemoteEntityIdentity()
     */
    @Override
    public String getRemoteEntityIdentity() {
        return null;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.msg.MessageContext#isRequestingTokens()
     */
    @Override
    public boolean isRequestingTokens() {
        return true;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.msg.MessageContext#getUserId()
     */
    @Override
    public String getUserId() {
        return USER_ID;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.msg.MessageContext#getUserAuthData(com.netflix.msl.msg.MessageContext.ReauthCode, boolean, boolean)
     */
    @Override
    public UserAuthenticationData getUserAuthData(final ReauthCode reauthCode, final boolean renewable, final boolean required) {
        return userAuthData;
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
        // Create key request data on demand; we do not want to reuse RSA keys.
        final KeyPairGenerator generator;
        try {
            generator = KeyPairGenerator.getInstance("RSA");
        } catch (final NoSuchAlgorithmException e) {
            throw new MslInternalException("RSA algorithm not found.", e);
        }
        generator.initialize(2048);
        final KeyPair keypair = generator.generateKeyPair();
        final PrivateKey privateKey = keypair.getPrivate();
        final PublicKey publicKey = keypair.getPublic();
        
        // Return key request data.
        final KeyRequestData keyxRequest = new AsymmetricWrappedExchange.RequestData(KEY_PAIR_ID, AsymmetricWrappedExchange.RequestData.Mechanism.JWK_RSA, publicKey, privateKey);
        return new HashSet<KeyRequestData>(Arrays.asList(keyxRequest));
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.msg.MessageContext#updateServiceTokens(com.netflix.msl.msg.MessageServiceTokenBuilder, boolean)
     */
    @Override
    public void updateServiceTokens(final MessageServiceTokenBuilder builder, final boolean handshake) throws MslMessageException, MslCryptoException, MslEncodingException, MslException {
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.msg.MessageContext#write(com.netflix.msl.msg.MessageOutputStream)
     */
    @Override
    public void write(final MessageOutputStream output) throws IOException {
        output.write(data);
        output.close();
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.msg.MessageContext#getDebugContext()
     */
    @Override
    public MessageDebugContext getDebugContext() {
        return null;
    }

    /** Application data. */
    private final byte[] data;
    /** User authentication data. */
    private final UserAuthenticationData userAuthData;
}
