/**
 * Copyright (c) 2012-2018 Netflix, Inc.  All rights reserved.
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
package com.netflix.msl.msg;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslKeyExchangeException;
import com.netflix.msl.MslMessageException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.crypto.JcaAlgorithm;
import com.netflix.msl.crypto.SymmetricCryptoContext;
import com.netflix.msl.keyx.AsymmetricWrappedExchange;
import com.netflix.msl.keyx.AsymmetricWrappedExchange.RequestData.Mechanism;
import com.netflix.msl.keyx.DiffieHellmanExchange;
import com.netflix.msl.keyx.DiffieHellmanParameters;
import com.netflix.msl.keyx.KeyRequestData;
import com.netflix.msl.keyx.MockDiffieHellmanParameters;
import com.netflix.msl.keyx.SymmetricWrappedExchange;
import com.netflix.msl.keyx.SymmetricWrappedExchange.KeyId;
import com.netflix.msl.tokens.MslUser;
import com.netflix.msl.userauth.EmailPasswordAuthenticationData;
import com.netflix.msl.userauth.MockEmailPasswordAuthenticationFactory;
import com.netflix.msl.userauth.UserAuthenticationData;
import com.netflix.msl.userauth.UserAuthenticationScheme;
import com.netflix.msl.util.MslContext;

/**
 * Test message context.
 * 
 * The {@link #updateServiceTokens(MessageServiceTokenBuilder, boolean)} and
 * {@link #write(MessageOutputStream)} methods do nothing. Unit tests should
 * override those methods for the specific test.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class MockMessageContext implements MessageContext {
    private static final String DH_PARAMETERS_ID = "1";
    private static final String RSA_KEYPAIR_ID = "rsaKeypairId";
    
    /** Service token name for crypto context. */
    public static final String SERVICE_TOKEN_NAME = "serviceToken";
    /** Default service token crypto context name (empty string). */
    public static final String DEFAULT_SERVICE_TOKEN_NAME = "";

    /**
     * @param ctx MSL context.
     * @param bitlength key length in bits.
     * @return a new key of the specified bit length.
     */
    private static SecretKey getSecretKey(final MslContext ctx, final int bitlength, final String algorithm) {
        final byte[] keydata = new byte[bitlength / Byte.SIZE];
        ctx.getRandom().nextBytes(keydata);
        return new SecretKeySpec(keydata, algorithm);
    }
    
    /**
     * Create a new test message context.
     * 
     * The message will not be encrypted or non-replayable.
     * 
     * @param ctx MSL context.
     * @param userId user ID. May be {@code null}.
     * @param scheme user authentication scheme. May be {@code null}.
     * @throws NoSuchAlgorithmException if a key generation algorithm is not
     *         found.
     * @throws InvalidAlgorithmParameterException if key generation parameters
     *         are invalid.
     * @throws MslKeyExchangeException if there is an error accessing Diffie-
     *         Hellman parameters.
     */
    public MockMessageContext(final MslContext ctx, final String userId, final UserAuthenticationScheme scheme) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, MslKeyExchangeException {
        this.remoteEntityIdentity = null;
        this.encrypted = false;
        this.integrityProtected = false;
        this.nonReplayable = false;
        this.requestingTokens = false;
        this.userId = userId;
        this.user = null;
        this.debugContext = null;
        
        if (UserAuthenticationScheme.EMAIL_PASSWORD.equals(scheme)) {
            userAuthData = new EmailPasswordAuthenticationData(MockEmailPasswordAuthenticationFactory.EMAIL, MockEmailPasswordAuthenticationFactory.PASSWORD);
        } else if (scheme != null) {
            throw new IllegalArgumentException("Unsupported authentication type: " + scheme.name());
        }
        
        keyRequestData = new HashSet<KeyRequestData>();
        {
            final DiffieHellmanParameters params = MockDiffieHellmanParameters.getDefaultParameters();
            final DHParameterSpec paramSpec = params.getParameterSpec(MockDiffieHellmanParameters.DEFAULT_ID);
            final KeyPairGenerator generator = KeyPairGenerator.getInstance("DH");
            generator.initialize(paramSpec);
            final KeyPair requestKeyPair = generator.generateKeyPair();
            final BigInteger publicKey = ((DHPublicKey)requestKeyPair.getPublic()).getY();
            final DHPrivateKey privateKey = (DHPrivateKey)requestKeyPair.getPrivate();
            keyRequestData.add(new DiffieHellmanExchange.RequestData(DH_PARAMETERS_ID, publicKey, privateKey));
        }
        {
            final KeyPairGenerator rsaGenerator = KeyPairGenerator.getInstance("RSA");
            final KeyPair rsaKeyPair = rsaGenerator.generateKeyPair();
            final PublicKey publicKey = rsaKeyPair.getPublic();
            final PrivateKey privateKey = rsaKeyPair.getPrivate();
            keyRequestData.add(new AsymmetricWrappedExchange.RequestData(RSA_KEYPAIR_ID, Mechanism.RSA, publicKey, privateKey));
        }
        {
            keyRequestData.add(new SymmetricWrappedExchange.RequestData(KeyId.PSK));
        }
        
        cryptoContexts = new HashMap<String,ICryptoContext>();
        cryptoContexts.put(SERVICE_TOKEN_NAME, new SymmetricCryptoContext(ctx, SERVICE_TOKEN_NAME, getSecretKey(ctx, 128, JcaAlgorithm.AES), getSecretKey(ctx, 256, JcaAlgorithm.HMAC_SHA256), null));
        cryptoContexts.put(DEFAULT_SERVICE_TOKEN_NAME, new SymmetricCryptoContext(ctx, DEFAULT_SERVICE_TOKEN_NAME, getSecretKey(ctx, 128, JcaAlgorithm.AES), getSecretKey(ctx, 256, JcaAlgorithm.HMAC_SHA256), null));
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.msg.MessageContext#getCryptoContexts()
     */
    @Override
    public Map<String,ICryptoContext> getCryptoContexts() {
        return Collections.unmodifiableMap(cryptoContexts);
    }
    
    /**
     * Remove a service token crypto context.
     * 
     * @param name service token name.
     */
    public void removeCryptoContext(final String name) {
        cryptoContexts.remove(name);
    }
    
    /**
     * @param remoteEntityIdentity the message remote entity identity or {@code null} if unknown.
     */
    public void setRemoteEntityIdentity(final String remoteEntityIdentity) {
        this.remoteEntityIdentity = remoteEntityIdentity;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.msg.MessageContext#getRemoteEntityIdentity()
     */
    @Override
    public String getRemoteEntityIdentity() {
        return remoteEntityIdentity;
    }
    
    /**
     * @param encrypted true if the message must be encrypted.
     */
    public void setEncrypted(final boolean encrypted) {
        this.encrypted = encrypted;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.msg.MessageContext#isEncrypted()
     */
    @Override
    public boolean isEncrypted() {
        return encrypted;
    }
    
    /**
     * @param integrityProtected true if the message must be integrity
     *        protected.
     */
    public void setIntegrityProtected(final boolean integrityProtected) {
        this.integrityProtected = integrityProtected;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.msg.MessageContext#isIntegrityProtected()
     */
    @Override
    public boolean isIntegrityProtected() {
        return integrityProtected;
    }
    
    /**
     * @param requestingTokens true if the message is requesting tokens.
     */
    public void setRequestingTokens(final boolean requestingTokens) {
        this.requestingTokens = requestingTokens;
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.msg.MessageContext#isRequestingTokens()
     */
    @Override
    public boolean isRequestingTokens() {
        return requestingTokens;
    }
    
    /**
     * @param nonReplayable true if the message must be non-replayable.
     */
    public void setNonReplayable(final boolean nonReplayable) {
        this.nonReplayable = nonReplayable;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.msg.MessageContext#isNonReplayable()
     */
    @Override
    public boolean isNonReplayable() {
        return nonReplayable;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.msg.MessageContext#getUserId()
     */
    @Override
    public String getUserId() {
        return userId;
    }

    /**
     * @param userAuthData the new user authentication data.
     */
    public void setUserAuthData(final UserAuthenticationData userAuthData) {
        this.userAuthData = userAuthData;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.msg.MessageContext#getUserAuthData(com.netflix.msl.msg.MessageContext.ReauthCode, boolean, boolean)
     */
    @Override
    public UserAuthenticationData getUserAuthData(final ReauthCode reauth, final boolean renewable, final boolean required) {
        // Default implementation just returns the existing user authentication
        // data. Override to implement specific behavior.
        return userAuthData;
    }
    
    /**
     * @param user the remote user. 
     */
    public void setUser(final MslUser user) {
        this.user = user;
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.msg.MessageContext#getUser()
     */
    @Override
    public MslUser getUser() {
        return user;
    }
    
    /**
     * @param keyRequestData the new key request data.
     */
    public void setKeyRequestData(final Set<KeyRequestData> keyRequestData) {
        this.keyRequestData.clear();
        this.keyRequestData.addAll(keyRequestData);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.msg.MessageContext#getKeyRequestData()
     */
    @Override
    public Set<KeyRequestData> getKeyRequestData() {
        return Collections.unmodifiableSet(keyRequestData);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.msg.MessageContext#updateServiceTokens(com.netflix.msl.msg.MessageServiceTokenBuilder, boolean)
     */
    @Override
    public void updateServiceTokens(final MessageServiceTokenBuilder builder, final boolean handshake) throws MslMessageException, MslCryptoException, MslEncodingException {
        // Default implementation does nothing. Override to implement specific
        // behavior.
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.msg.MessageContext#write(com.netflix.msl.msg.MessageOutputStream)
     */
    @Override
    public void write(final MessageOutputStream output) throws IOException {
        // Default implementation does nothing. Override to implement specific
        // behavior.
    }
    
    /**
     * @param debugContext the new message debug context.
     */
    public void setMessageDebugContext(final MessageDebugContext debugContext) {
        this.debugContext = debugContext;
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.msg.MessageContext#getDebugContext()
     */
    @Override
    public MessageDebugContext getDebugContext() {
        return debugContext;
    }

    /** Message remote entity identity. */
    private String remoteEntityIdentity;
    /** Message requires encryption. */
    private boolean encrypted;
    /** Message requires integrity protection. */
    private boolean integrityProtected;
    /** Message must be non-replayable. */
    private boolean nonReplayable;
    /** Message is requesting tokens. */
    private boolean requestingTokens;
    /** Message user ID. */
    private final String userId;
    /** Message user authentication data. */
    private UserAuthenticationData userAuthData;
    /** Message remote user. */
    private MslUser user;
    /** Key request data. */
    private final Set<KeyRequestData> keyRequestData;
    /** Service token crypto contexts. */
    private final Map<String,ICryptoContext> cryptoContexts;
    /** Message debug context. */
    private MessageDebugContext debugContext;
}
