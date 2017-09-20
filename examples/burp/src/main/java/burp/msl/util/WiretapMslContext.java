/**
 * Copyright (c) 2014-2017 Netflix, Inc.  All rights reserved.
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
package burp.msl.util;

import java.security.SecureRandom;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import burp.msl.tokens.EchoingTokenFactory;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.crypto.JcaAlgorithm;
import com.netflix.msl.crypto.SymmetricCryptoContext;
import com.netflix.msl.entityauth.EntityAuthenticationData;
import com.netflix.msl.entityauth.EntityAuthenticationFactory;
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.entityauth.MockPresharedAuthenticationFactory;
import com.netflix.msl.entityauth.MockRsaAuthenticationFactory;
import com.netflix.msl.entityauth.MockX509AuthenticationFactory;
import com.netflix.msl.entityauth.PresharedAuthenticationData;
import com.netflix.msl.entityauth.RsaAuthenticationData;
import com.netflix.msl.entityauth.UnauthenticatedAuthenticationData;
import com.netflix.msl.entityauth.X509AuthenticationData;
import com.netflix.msl.io.DefaultMslEncoderFactory;
import com.netflix.msl.io.MslEncoderFactory;
import com.netflix.msl.keyx.AsymmetricWrappedExchange;
import com.netflix.msl.keyx.DiffieHellmanExchange;
import com.netflix.msl.keyx.KeyExchangeFactory;
import com.netflix.msl.keyx.KeyExchangeScheme;
import com.netflix.msl.keyx.MockDiffieHellmanParameters;
import com.netflix.msl.keyx.SymmetricWrappedExchange;
import com.netflix.msl.msg.MessageCapabilities;
import com.netflix.msl.tokens.TokenFactory;
import com.netflix.msl.userauth.UserAuthenticationFactory;
import com.netflix.msl.userauth.UserAuthenticationScheme;
import com.netflix.msl.util.AuthenticationUtils;
import com.netflix.msl.util.MockAuthenticationUtils;
import com.netflix.msl.util.MslContext;
import com.netflix.msl.util.MslStore;
import com.netflix.msl.util.NullMslStore;

/**
 * User: skommidi
 * Date: 9/22/14
 */
public class WiretapMslContext extends MslContext {
    /**
     * Key exchange factory comparator.
     */
    private static class KeyExchangeFactoryComparator implements Comparator<KeyExchangeFactory> {
        /** Scheme priorities. Lower values are higher priority. */
        private final Map<KeyExchangeScheme,Integer> schemePriorities = new HashMap<KeyExchangeScheme,Integer>();

        /**
         * Create a new key exchange factory comparator.
         */
        public KeyExchangeFactoryComparator() {
            schemePriorities.put(KeyExchangeScheme.JWK_LADDER, 0);
            schemePriorities.put(KeyExchangeScheme.JWE_LADDER, 1);
            schemePriorities.put(KeyExchangeScheme.DIFFIE_HELLMAN, 2);
            schemePriorities.put(KeyExchangeScheme.SYMMETRIC_WRAPPED, 3);
            schemePriorities.put(KeyExchangeScheme.ASYMMETRIC_WRAPPED, 4);
        }

        /* (non-Javadoc)
         * @see java.util.Comparator#compare(java.lang.Object, java.lang.Object)
         */
        @Override
        public int compare(final KeyExchangeFactory a, final KeyExchangeFactory b) {
            final KeyExchangeScheme schemeA = a.getScheme();
            final KeyExchangeScheme schemeB = b.getScheme();
            final Integer priorityA = schemePriorities.get(schemeA);
            final Integer priorityB = schemePriorities.get(schemeB);
            return priorityA.compareTo(priorityB);
        }
    }


    /**
     * <p>Create a new wiretap MSL context.</p>
     *
     * @param entityAuthFactories entity authentication factories.
     * @param userAuthFactories user authentication factories.
     */
    public WiretapMslContext(final Set<EntityAuthenticationFactory> entityAuthFactories, final Set<UserAuthenticationFactory> userAuthFactories) {
        final SecretKey mslEncryptionKey = new SecretKeySpec(MSL_ENCRYPTION_KEY, JcaAlgorithm.AES);
        final SecretKey mslHmacKey = new SecretKeySpec(MSL_HMAC_KEY, JcaAlgorithm.HMAC_SHA256);
        final SecretKey mslWrappingKey = new SecretKeySpec(MSL_WRAPPING_KEY, JcaAlgorithm.AESKW);
        this.mslCryptoContext = new SymmetricCryptoContext(this, "TestMslKeys", mslEncryptionKey, mslHmacKey, mslWrappingKey);
        
        // Entity authentication factories are mapped as-is.
        final Map<EntityAuthenticationScheme,EntityAuthenticationFactory> entityAuthFactoriesMap = new HashMap<EntityAuthenticationScheme,EntityAuthenticationFactory>();
        for (final EntityAuthenticationFactory factory : entityAuthFactories) {
            entityAuthFactoriesMap.put(factory.getScheme(), factory);
        }
        this.entityAuthFactories = Collections.unmodifiableMap(entityAuthFactoriesMap);

        // User authentication factories are mapped as-is.
        final Map<UserAuthenticationScheme,UserAuthenticationFactory> userAuthFactoriesMap = new HashMap<UserAuthenticationScheme,UserAuthenticationFactory>();
        for (final UserAuthenticationFactory factory : userAuthFactories) {
            userAuthFactoriesMap.put(factory.getScheme(), factory);
        }
        this.userAuthFactories = Collections.unmodifiableMap(userAuthFactoriesMap);

        final MockDiffieHellmanParameters params = MockDiffieHellmanParameters.getDefaultParameters();
        final AuthenticationUtils authutils = new MockAuthenticationUtils();

        final SortedSet<KeyExchangeFactory> keyExchangeFactoriesSet = new TreeSet<KeyExchangeFactory>(new KeyExchangeFactoryComparator());
        keyExchangeFactoriesSet.add(new AsymmetricWrappedExchange(authutils));
        keyExchangeFactoriesSet.add(new SymmetricWrappedExchange(authutils));
        keyExchangeFactoriesSet.add(new DiffieHellmanExchange(params, authutils));
        this.keyExchangeFactories = Collections.unmodifiableSortedSet(keyExchangeFactoriesSet);
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
        return random;
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
        return capabilities;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslContext#getEntityAuthenticationData(com.netflix.msl.util.MslContext.ReauthCode)
     */
    @Override
    public EntityAuthenticationData getEntityAuthenticationData(final ReauthCode reauthCode) {
        return entityAuthData;
    }

    public void setEntityAuthenticationData(final EntityAuthenticationScheme scheme) throws MslCryptoException {
        if (EntityAuthenticationScheme.PSK.equals(scheme))
            entityAuthData = new PresharedAuthenticationData(MockPresharedAuthenticationFactory.PSK_ESN);
        else if (EntityAuthenticationScheme.X509.equals(scheme))
            entityAuthData = new X509AuthenticationData(MockX509AuthenticationFactory.X509_CERT);
        else if (EntityAuthenticationScheme.RSA.equals(scheme))
            entityAuthData = new RsaAuthenticationData(MockRsaAuthenticationFactory.RSA_ESN, MockRsaAuthenticationFactory.RSA_PUBKEY_ID);
        else if (EntityAuthenticationScheme.NONE.equals(scheme))
            entityAuthData = new UnauthenticatedAuthenticationData("MOCKUNAUTH-ESN");
        else
            throw new IllegalArgumentException("Unsupported authentication type: " + scheme.name());
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslContext#getMslCryptoContext()
     */
    @Override
    public ICryptoContext getMslCryptoContext() {
        return mslCryptoContext;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslContext#getEntityAuthenticationScheme(java.lang.String)
     */
    @Override
    public EntityAuthenticationScheme getEntityAuthenticationScheme(final String name) {
        return EntityAuthenticationScheme.getScheme(name);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslContext#getEntityAuthenticationFactory(com.netflix.msl.entityauth.EntityAuthenticationScheme)
     */
    @Override
    public EntityAuthenticationFactory getEntityAuthenticationFactory(final EntityAuthenticationScheme scheme) {
        return entityAuthFactories.get(scheme);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslContext#getUserAuthenticationScheme(java.lang.String)
     */
    @Override
    public UserAuthenticationScheme getUserAuthenticationScheme(final String name) {
        return UserAuthenticationScheme.getScheme(name);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslContext#getUserAuthenticationFactory(com.netflix.msl.userauth.UserAuthenticationScheme)
     */
    @Override
    public UserAuthenticationFactory getUserAuthenticationFactory(final UserAuthenticationScheme scheme) {
        return userAuthFactories.get(scheme);
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
        return KeyExchangeScheme.getScheme(name);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslContext#getKeyExchangeFactory(com.netflix.msl.keyx.KeyExchangeScheme)
     */
    @Override
    public KeyExchangeFactory getKeyExchangeFactory(final KeyExchangeScheme scheme) {
        for (final KeyExchangeFactory factory : keyExchangeFactories) {
            if (factory.getScheme().equals(scheme))
                return factory;
        }
        return null;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslContext#getKeyExchangeFactories()
     */
    @Override
    public SortedSet<KeyExchangeFactory> getKeyExchangeFactories() {
        return keyExchangeFactories;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslContext#getMslStore()
     */
    @Override
    public MslStore getMslStore() {
        return mslStore;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslContext#getMslEncoderFactory()
     */
    @Override
    public MslEncoderFactory getMslEncoderFactory() {
        return encoderFactory;
    }

    /** MSL encryption key. */
    private static final byte[] MSL_ENCRYPTION_KEY = {
            (byte)0x1d, (byte)0x58, (byte)0xf3, (byte)0xb8, (byte)0xf7, (byte)0x47, (byte)0xd1, (byte)0x6a,
            (byte)0xb1, (byte)0x93, (byte)0xc4, (byte)0xc0, (byte)0xa6, (byte)0x24, (byte)0xea, (byte)0xcf,
    };
    /** MSL HMAC key. */
    private static final byte[] MSL_HMAC_KEY = {
            (byte)0xd7, (byte)0xae, (byte)0xbf, (byte)0xd5, (byte)0x87, (byte)0x9b, (byte)0xb0, (byte)0xe0,
            (byte)0xad, (byte)0x01, (byte)0x6a, (byte)0x4c, (byte)0xf3, (byte)0xcb, (byte)0x39, (byte)0x82,
            (byte)0xf5, (byte)0xba, (byte)0x26, (byte)0x0d, (byte)0xa5, (byte)0x20, (byte)0x24, (byte)0x5b,
            (byte)0xb4, (byte)0x22, (byte)0x75, (byte)0xbd, (byte)0x79, (byte)0x47, (byte)0x37, (byte)0x0c,
    };
    /** MSL wrapping key. */
    private static final byte[] MSL_WRAPPING_KEY = {
            (byte)0x83, (byte)0xb6, (byte)0x9a, (byte)0x15, (byte)0x80, (byte)0xd3, (byte)0x23, (byte)0xa2,
            (byte)0xe7, (byte)0x9d, (byte)0xd9, (byte)0xb2, (byte)0x26, (byte)0x26, (byte)0xb3, (byte)0xf6,
    };
    /** Secure random. */
    private final Random random = new SecureRandom();
    /** Message capabilities. */
    private final MessageCapabilities capabilities = new MessageCapabilities(null, null, null);
    /** Entity authentication data. */
    private EntityAuthenticationData entityAuthData = new UnauthenticatedAuthenticationData("WireTap");
    /** MSL token crypto context. */
    private final ICryptoContext mslCryptoContext;
    /** Map of supported entity authentication schemes onto factories. */
    private final Map<EntityAuthenticationScheme, EntityAuthenticationFactory> entityAuthFactories;
    /** Map of supported user authentication schemes onto factories. */
    private final Map<UserAuthenticationScheme, UserAuthenticationFactory> userAuthFactories;
    /** Token factory. */
    private final TokenFactory tokenFactory = new EchoingTokenFactory();
    /** Supported key exchange factories in preferred order. */
    private final SortedSet<KeyExchangeFactory> keyExchangeFactories;
    /** MSL store. */
    private final MslStore mslStore = new NullMslStore();
    /** MSL encoder factory. */
    private final MslEncoderFactory encoderFactory = new DefaultMslEncoderFactory();
}
