/**
 * Copyright (c) 2015 Netflix, Inc.  All rights reserved.
 */
package com.netflix.msl.util;

import java.util.Arrays;
import java.util.SortedSet;
import java.util.TreeSet;

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
import com.netflix.msl.keyx.FailingKeyExchange;
import com.netflix.msl.keyx.KeyExchangeFactory;
import com.netflix.msl.keyx.KeyExchangeScheme;
import com.netflix.msl.keyx.ProxyKeyExchangeScheme;
import com.netflix.msl.tokens.FailoverTokenFactory;
import com.netflix.msl.tokens.TokenFactory;
import com.netflix.msl.userauth.FailingUserAuthenticationFactory;
import com.netflix.msl.userauth.ProxyUserAuthenticationScheme;
import com.netflix.msl.userauth.UserAuthenticationFactory;
import com.netflix.msl.userauth.UserAuthenticationScheme;

/**
 * <p>A trusted services network MSL context that supports MSL messages that
 * are protected using session keys. FIXME</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class FailoverMslContext extends ProxyMslContext {
    /**
     * <p>Failover entity authentication factory.</p>
     * 
     * <p>When used, this factory throws an exception indicating inability to
     * process the MSL message.</p>
     */
    private static EntityAuthenticationFactory failoverEntityAuthFactory = new FailingEntityAuthenticationFactory(ProxyEntityAuthenticationScheme.PROXY, ProxyMslError.ENTITYAUTH_CANNOT_FAILOVER);
    
    /**
     * <p>Failover user authentication factory.</p>
     * 
     * <p>When used, this factory throws an exception indiating inability to
     * process the MSL message.</p>
     */
    private static UserAuthenticationFactory failoverUserAuthFactory = new FailingUserAuthenticationFactory(ProxyUserAuthenticationScheme.PROXY, ProxyMslError.USERAUTH_CANNOT_FAILOVER);
    
    /**
     * <p>Failover key exchange factory.</p>
     * 
     * <p>When used to generate a response, this factory simply returns
     * {@code null} indicating it does not wish to perform key exchange.</p>
     */
    private static KeyExchangeFactory failoverKeyxFactory = new FailingKeyExchange(ProxyKeyExchangeScheme.PROXY, null);
    
    /**
     * <p>Create a new proxy MSL context.</p>
     * 
     * @param entityAuthData local entity authentication data.
     * @param entityAuthFactory local entity authentication factory.
     * @param cryptoContext MSL token crypto context.
     */
    public FailoverMslContext(final EntityAuthenticationData entityAuthData, final EntityAuthenticationFactory entityAuthFactory, final ICryptoContext cryptoContext) {
        super(entityAuthData, entityAuthFactory, cryptoContext);
        
        // Entity authentication.
        this.entityAuthData = entityAuthData;
        final String identity;
        try {
            identity = entityAuthData.getIdentity();
        } catch (final MslCryptoException e) {
            throw new MslInternalException("Unable to extract identity from proxy entity authentication data.", e);
        }
        this.entityAuthFactory = new ProxyEntityAuthenticationFactory(identity, entityAuthFactory, ProxyMslError.ENTITYAUTH_CANNOT_FAILOVER);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslContext#getEntityAuthenticationFactory(com.netflix.msl.entityauth.EntityAuthenticationScheme)
     */
    @Override
    public EntityAuthenticationFactory getEntityAuthenticationFactory(final EntityAuthenticationScheme scheme) {
        // We must explicitly support authentication of the local entity.
        if (entityAuthData.getScheme().equals(scheme))
            return entityAuthFactory;
        
        // Otherwise return the failover entity authentication factory that
        // will always fail.
        return failoverEntityAuthFactory;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslContext#getUserAuthenticationFactory(com.netflix.msl.userauth.UserAuthenticationScheme)
     */
    @Override
    public UserAuthenticationFactory getUserAuthenticationFactory(final UserAuthenticationScheme scheme) {
        // Return the failover user authentication factory that will always
        // fail.
        return failoverUserAuthFactory;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslContext#getTokenFactory()
     */
    @Override
    public TokenFactory getTokenFactory() {
        return tokenFactory;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslContext#getKeyExchangeFactory(com.netflix.msl.keyx.KeyExchangeScheme)
     */
    @Override
    public KeyExchangeFactory getKeyExchangeFactory(final KeyExchangeScheme scheme) {
        // Return the failover key exchange factory that will simply not
        // perform key exchange.
        return failoverKeyxFactory;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslContext#getKeyExchangeFactories()
     */
    @Override
    public SortedSet<KeyExchangeFactory> getKeyExchangeFactories() {
        return keyxFactories;
    }

    /** Entity authentication data. */
    private final EntityAuthenticationData entityAuthData;
    /** Entity authentiation factory. */
    private final EntityAuthenticationFactory entityAuthFactory;
    /** Token factory. */
    private final TokenFactory tokenFactory = new FailoverTokenFactory();
    /** Key exchange factories. */
    private final SortedSet<KeyExchangeFactory> keyxFactories = new TreeSet<KeyExchangeFactory>(Arrays.asList(failoverKeyxFactory));
}
