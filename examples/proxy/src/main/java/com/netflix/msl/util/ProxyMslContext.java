/**
 * Copyright (c) 2015-2017 Netflix, Inc.  All rights reserved.
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
package com.netflix.msl.util;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Random;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

import com.netflix.msl.MslConstants.CompressionAlgorithm;
import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslInternalException;
import com.netflix.msl.ProxyMslError;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.entityauth.EntityAuthenticationData;
import com.netflix.msl.entityauth.EntityAuthenticationFactory;
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.entityauth.FailingEntityAuthenticationFactory;
import com.netflix.msl.entityauth.ProxyEntityAuthenticationFactory;
import com.netflix.msl.entityauth.ProxyEntityAuthenticationScheme;
import com.netflix.msl.io.DefaultMslEncoderFactory;
import com.netflix.msl.io.MslEncoderFactory;
import com.netflix.msl.io.MslEncoderFormat;
import com.netflix.msl.keyx.FailingKeyExchange;
import com.netflix.msl.keyx.KeyExchangeFactory;
import com.netflix.msl.keyx.KeyExchangeScheme;
import com.netflix.msl.keyx.ProxyKeyExchangeScheme;
import com.netflix.msl.msg.MessageCapabilities;
import com.netflix.msl.tokens.ProxyTokenFactory;
import com.netflix.msl.tokens.TokenFactory;
import com.netflix.msl.userauth.FailingUserAuthenticationFactory;
import com.netflix.msl.userauth.ProxyUserAuthenticationScheme;
import com.netflix.msl.userauth.UserAuthenticationFactory;
import com.netflix.msl.userauth.UserAuthenticationScheme;

/**
 * <p>A trusted services network MSL context that supports MSL messages that
 * are protected using session keys. Authentication and key exchange are not
 * supported and any attempt to perform those operations will throw an
 * exception.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class ProxyMslContext extends MslContext {
    /**
     * <p>Proxy entity authentication factory.</p>
     * 
     * <p>When used, this factory throws an exception to trigger external
     * processing of the MSL message.</p>
     */
    private static EntityAuthenticationFactory proxyEntityAuthFactory = new FailingEntityAuthenticationFactory(ProxyEntityAuthenticationScheme.PROXY, ProxyMslError.ENTITYAUTH_REQUIRED);
    
    /**
     * <p>Proxy user authentication factory.</p>
     * 
     * <p>When used, this factory throws an exception to trigger external
     * processing of the MSL message.</p>
     */
    private static UserAuthenticationFactory proxyUserAuthFactory = new FailingUserAuthenticationFactory(ProxyUserAuthenticationScheme.PROXY, ProxyMslError.USERAUTH_REQUIRED);
    
    /**
     * <p>Proxy key exchange factory.</p>
     * 
     * <p>When used to generate a response, this factory throws an exception to
     * trigger external processing of the message.</p>
     */
    private static KeyExchangeFactory proxyKeyxFactory = new FailingKeyExchange(ProxyKeyExchangeScheme.PROXY, ProxyMslError.KEYX_REQUIRED);
    
    /**
     * <p>Create a new proxy MSL context.</p>
     * 
     * @param entityAuthData local entity authentication data.
     * @param entityAuthFactory local entity authentication factory.
     * @param cryptoContext MSL token crypto context.
     */
    public ProxyMslContext(final EntityAuthenticationData entityAuthData, final EntityAuthenticationFactory entityAuthFactory, final ICryptoContext cryptoContext) {
        // Message capabilities.
        final Set<CompressionAlgorithm> compressionAlgos = new HashSet<CompressionAlgorithm>(Arrays.asList(CompressionAlgorithm.values()));
        final Set<MslEncoderFormat> encoderFormats = new HashSet<MslEncoderFormat>(MslEncoderFormat.values());
        this.messageCapabilities = new MessageCapabilities(compressionAlgos, null, encoderFormats);
        
        // Entity authentication.
        this.entityAuthData = entityAuthData;
        final String identity;
        try {
            identity = entityAuthData.getIdentity();
        } catch (final MslCryptoException e) {
            throw new MslInternalException("Unable to extract identity from proxy entity authentication data.", e);
        }
        this.entityAuthFactory = new ProxyEntityAuthenticationFactory(identity, entityAuthFactory, ProxyMslError.ENTITYAUTH_REQUIRED);
        
        // MSL token crypto context.
        this.cryptoContext = cryptoContext;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslContext#getTime()
     */
    @Override
    public long getTime() {
        return System.currentTimeMillis();
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslContext#getRandom()
     */
    @Override
    public Random getRandom() {
        return new SecureRandom();
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslContext#isPeerToPeer()
     */
    @Override
    public boolean isPeerToPeer() {
        return false;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslContext#getMessageCapabilities()
     */
    @Override
    public MessageCapabilities getMessageCapabilities() {
        return messageCapabilities;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslContext#getEntityAuthenticationData(com.netflix.msl.util.MslContext.ReauthCode)
     */
    @Override
    public EntityAuthenticationData getEntityAuthenticationData(final ReauthCode reauthCode) {
        return entityAuthData;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslContext#getMslCryptoContext()
     */
    @Override
    public ICryptoContext getMslCryptoContext() throws MslCryptoException {
        return cryptoContext;
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslContext#getEntityAuthenticationScheme(java.lang.String)
     */
    @Override
    public EntityAuthenticationScheme getEntityAuthenticationScheme(final String name) {
        // We must explicitly support the local entity's entity authentication
        // scheme.
        if (entityAuthData.getScheme().name().equals(name))
            return entityAuthData.getScheme();
        
        // Otherwise return the proxy scheme that will trigger external
        // processing of the message.
        return ProxyEntityAuthenticationScheme.PROXY;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslContext#getEntityAuthenticationFactory(com.netflix.msl.entityauth.EntityAuthenticationScheme)
     */
    @Override
    public EntityAuthenticationFactory getEntityAuthenticationFactory(final EntityAuthenticationScheme scheme) {
        // We must explicitly support authentication of the local entity.
        if (entityAuthData.getScheme().equals(scheme))
            return entityAuthFactory;
        
        // Otherwise return the proxy entity authentication factory that will
        // trigger external processing of the message.
        return proxyEntityAuthFactory;
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslContext#getUserAuthenticationScheme(java.lang.String)
     */
    @Override
    public UserAuthenticationScheme getUserAuthenticationScheme(final String name) {
        return ProxyUserAuthenticationScheme.PROXY;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslContext#getUserAuthenticationFactory(com.netflix.msl.userauth.UserAuthenticationScheme)
     */
    @Override
    public UserAuthenticationFactory getUserAuthenticationFactory(final UserAuthenticationScheme scheme) {
        // Return the proxy user authentication factory that will trigger
        // external processing of the message.
        return proxyUserAuthFactory;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslContext#getTokenFactory()
     */
    @Override
    public TokenFactory getTokenFactory() {
        return tokenFactory;
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslContext#getKeyExchangeScheme(java.lang.String)
     */
    @Override
    public KeyExchangeScheme getKeyExchangeScheme(final String name) {
        return ProxyKeyExchangeScheme.PROXY;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslContext#getKeyExchangeFactory(com.netflix.msl.keyx.KeyExchangeScheme)
     */
    @Override
    public KeyExchangeFactory getKeyExchangeFactory(final KeyExchangeScheme scheme) {
        // Return the proxy key exchange factory that will trigger external
        // processing of the message.
        return proxyKeyxFactory;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslContext#getKeyExchangeFactories()
     */
    @Override
    public SortedSet<KeyExchangeFactory> getKeyExchangeFactories() {
        return keyxFactories;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslContext#getMslStore()
     */
    @Override
    public MslStore getMslStore() {
        return store;
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslContext#getMslEncoderFactory()
     */
    @Override
    public MslEncoderFactory getMslEncoderFactory() {
        return encoderFactory;
    }

    /** Message capabilities. */
    private final MessageCapabilities messageCapabilities;
    /** Entity authentication data. */
    private final EntityAuthenticationData entityAuthData;
    /** Entity authentiation factory. */
    private final EntityAuthenticationFactory entityAuthFactory;
    /** MSL crypto context. */
    private final ICryptoContext cryptoContext;
    /** Token factory. */
    private final TokenFactory tokenFactory = new ProxyTokenFactory();
    /** Key exchange factories. */
    private final SortedSet<KeyExchangeFactory> keyxFactories = new TreeSet<KeyExchangeFactory>(Arrays.asList(proxyKeyxFactory));
    /** MSL store. */
    private final MslStore store = new NullMslStore();
    /** MSL encoder factory. */
    private final MslEncoderFactory encoderFactory = new DefaultMslEncoderFactory();
}
