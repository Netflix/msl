/**
 * Copyright (c) 2012-2017 Netflix, Inc.  All rights reserved.
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

import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.netflix.msl.MslConstants.CompressionAlgorithm;
import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.crypto.JcaAlgorithm;
import com.netflix.msl.crypto.SymmetricCryptoContext;
import com.netflix.msl.entityauth.EntityAuthenticationData;
import com.netflix.msl.entityauth.EntityAuthenticationFactory;
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.entityauth.MasterTokenProtectedAuthenticationFactory;
import com.netflix.msl.entityauth.MockIdentityProvisioningService;
import com.netflix.msl.entityauth.MockPresharedAuthenticationFactory;
import com.netflix.msl.entityauth.MockPresharedProfileAuthenticationFactory;
import com.netflix.msl.entityauth.MockRsaAuthenticationFactory;
import com.netflix.msl.entityauth.MockEccAuthenticationFactory;
import com.netflix.msl.entityauth.MockX509AuthenticationFactory;
import com.netflix.msl.entityauth.PresharedAuthenticationData;
import com.netflix.msl.entityauth.PresharedProfileAuthenticationData;
import com.netflix.msl.entityauth.ProvisionedAuthenticationFactory;
import com.netflix.msl.entityauth.RsaAuthenticationData;
import com.netflix.msl.entityauth.EccAuthenticationData;
import com.netflix.msl.entityauth.UnauthenticatedAuthenticationData;
import com.netflix.msl.entityauth.UnauthenticatedAuthenticationFactory;
import com.netflix.msl.entityauth.UnauthenticatedSuffixedAuthenticationData;
import com.netflix.msl.entityauth.UnauthenticatedSuffixedAuthenticationFactory;
import com.netflix.msl.entityauth.X509AuthenticationData;
import com.netflix.msl.io.DefaultMslEncoderFactory;
import com.netflix.msl.io.MslEncoderFactory;
import com.netflix.msl.io.MslEncoderFormat;
import com.netflix.msl.keyx.AsymmetricWrappedExchange;
import com.netflix.msl.keyx.DiffieHellmanExchange;
import com.netflix.msl.keyx.KeyExchangeFactory;
import com.netflix.msl.keyx.KeyExchangeScheme;
import com.netflix.msl.keyx.MockDiffieHellmanParameters;
import com.netflix.msl.keyx.SymmetricWrappedExchange;
import com.netflix.msl.msg.MessageCapabilities;
import com.netflix.msl.tokens.MockTokenFactory;
import com.netflix.msl.tokens.TokenFactory;
import com.netflix.msl.userauth.MockEmailPasswordAuthenticationFactory;
import com.netflix.msl.userauth.MockUserIdTokenAuthenticationFactory;
import com.netflix.msl.userauth.UserAuthenticationFactory;
import com.netflix.msl.userauth.UserAuthenticationScheme;

/**
 * MSL context for unit tests.
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class MockMslContext extends MslContext {
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
     * Create a new test MSL context.
     *
     * @param scheme entity authentication scheme.
     * @param peerToPeer true if the context should operate in peer-to-peer
     *        mode.
     * @throws MslCryptoException if there is an error signing or creating the
     *         entity authentication data.
     * @throws MslEncodingException if there is an error creating the entity
     *         authentication data.
     */
    public MockMslContext(final EntityAuthenticationScheme scheme, final boolean peerToPeer) throws MslEncodingException, MslCryptoException {
        this.peerToPeer = peerToPeer;

        if (EntityAuthenticationScheme.PSK.equals(scheme))
            entityAuthData = new PresharedAuthenticationData(MockPresharedAuthenticationFactory.PSK_ESN);
        else if (EntityAuthenticationScheme.PSK_PROFILE.equals(scheme))
            entityAuthData = new PresharedProfileAuthenticationData(MockPresharedProfileAuthenticationFactory.PSK_ESN, MockPresharedProfileAuthenticationFactory.PROFILE);
        else if (EntityAuthenticationScheme.X509.equals(scheme))
            entityAuthData = new X509AuthenticationData(MockX509AuthenticationFactory.X509_CERT);
        else if (EntityAuthenticationScheme.RSA.equals(scheme))
            entityAuthData = new RsaAuthenticationData(MockRsaAuthenticationFactory.RSA_ESN, MockRsaAuthenticationFactory.RSA_PUBKEY_ID);
        else if (EntityAuthenticationScheme.ECC.equals(scheme))
            entityAuthData = new EccAuthenticationData(MockEccAuthenticationFactory.ECC_ESN, MockEccAuthenticationFactory.ECC_PUBKEY_ID);
        else if (EntityAuthenticationScheme.NONE.equals(scheme))
            entityAuthData = new UnauthenticatedAuthenticationData("MOCKUNAUTH-ESN");
        else if (EntityAuthenticationScheme.NONE_SUFFIXED.equals(scheme))
            entityAuthData = new UnauthenticatedSuffixedAuthenticationData("MOCKUNAUTH-ROOT", "MOCKUNAUTH-SUFFIX");
        else      
            throw new IllegalArgumentException("Unsupported authentication type: " + scheme.name());

        final Set<CompressionAlgorithm> algos = new HashSet<CompressionAlgorithm>();
        algos.add(CompressionAlgorithm.GZIP);
        algos.add(CompressionAlgorithm.LZW);
        final List<String> languages = Arrays.asList(new String[] { "en-US" });
        final Set<MslEncoderFormat> formats = new HashSet<MslEncoderFormat>();
        formats.add(MslEncoderFormat.JSON);
        capabilities = new MessageCapabilities(algos, languages, formats);

        final SecretKey mslEncryptionKey = new SecretKeySpec(MSL_ENCRYPTION_KEY, JcaAlgorithm.AES);
        final SecretKey mslHmacKey = new SecretKeySpec(MSL_HMAC_KEY, JcaAlgorithm.HMAC_SHA256);
        final SecretKey mslWrappingKey = new SecretKeySpec(MSL_WRAPPING_KEY, JcaAlgorithm.AESKW);
        mslCryptoContext = new SymmetricCryptoContext(this, "TestMslKeys", mslEncryptionKey, mslHmacKey, mslWrappingKey);

        tokenFactory = new MockTokenFactory();
        store = new SimpleMslStore();
        encoderFactory = new DefaultMslEncoderFactory();

        final MockDiffieHellmanParameters params = MockDiffieHellmanParameters.getDefaultParameters();
        final AuthenticationUtils authutils = new MockAuthenticationUtils();
        
        entityAuthFactories = new HashMap<EntityAuthenticationScheme,EntityAuthenticationFactory>();
        entityAuthFactories.put(EntityAuthenticationScheme.PSK, new MockPresharedAuthenticationFactory());
        entityAuthFactories.put(EntityAuthenticationScheme.PSK_PROFILE, new MockPresharedProfileAuthenticationFactory());
        entityAuthFactories.put(EntityAuthenticationScheme.RSA, new MockRsaAuthenticationFactory());
        entityAuthFactories.put(EntityAuthenticationScheme.ECC, new MockEccAuthenticationFactory());
        entityAuthFactories.put(EntityAuthenticationScheme.NONE, new UnauthenticatedAuthenticationFactory(authutils));
        entityAuthFactories.put(EntityAuthenticationScheme.X509, new MockX509AuthenticationFactory());
        entityAuthFactories.put(EntityAuthenticationScheme.NONE_SUFFIXED, new UnauthenticatedSuffixedAuthenticationFactory(authutils));
        entityAuthFactories.put(EntityAuthenticationScheme.MT_PROTECTED, new MasterTokenProtectedAuthenticationFactory(authutils));
        entityAuthFactories.put(EntityAuthenticationScheme.PROVISIONED, new ProvisionedAuthenticationFactory(new MockIdentityProvisioningService(this)));

        userAuthFactories = new HashMap<UserAuthenticationScheme,UserAuthenticationFactory>();
        userAuthFactories.put(UserAuthenticationScheme.EMAIL_PASSWORD, new MockEmailPasswordAuthenticationFactory());
        userAuthFactories.put(UserAuthenticationScheme.USER_ID_TOKEN, new MockUserIdTokenAuthenticationFactory());
        
        keyxFactories = new TreeSet<KeyExchangeFactory>(new KeyExchangeFactoryComparator());
        keyxFactories.add(new AsymmetricWrappedExchange(authutils));
        keyxFactories.add(new SymmetricWrappedExchange(authutils));
        keyxFactories.add(new DiffieHellmanExchange(params, authutils));
    }

    @Override
    public long getTime() {
        return System.currentTimeMillis();
    }

    @Override
    public Random getRandom() {
        return new Random();
    }

    @Override
    public boolean isPeerToPeer() {
        return peerToPeer;
    }

    /**
     * Set the message capabilities.
     * 
     * @param capabilities the new message capabilities.
     */
    public void setMessageCapabilities(final MessageCapabilities capabilities) {
        this.capabilities = capabilities;
    }

    @Override
    public MessageCapabilities getMessageCapabilities() {
        return capabilities;
    }

    /**
     * Set the entity authentication data.
     *
     * @param entityAuthData the new entity authentication data.
     */
    public void setEntityAuthenticationData(final EntityAuthenticationData entityAuthData) {
        this.entityAuthData = entityAuthData;
    }

    @Override
    public EntityAuthenticationData getEntityAuthenticationData(final ReauthCode reauthCode) {
        return entityAuthData;
    }

    /**
     * Set the MSL crypto context.
     *
     * @param cryptoContext the new MSL crypto context.
     */
    public void setMslCryptoContext(final ICryptoContext cryptoContext) {
        mslCryptoContext = cryptoContext;
    }

    @Override
    public ICryptoContext getMslCryptoContext() throws MslCryptoException {
        return mslCryptoContext;
    }
    
    @Override
    public EntityAuthenticationScheme getEntityAuthenticationScheme(final String name) {
        return EntityAuthenticationScheme.getScheme(name);
    }

    /**
     * Adds or replaces the entity authentication factory associated with the
     * entity authentication scheme of the provided factory.
     *
     * @param factory entity authentication factory.
     */
    public void addEntityAuthenticationFactory(final EntityAuthenticationFactory factory) {
        entityAuthFactories.put(factory.getScheme(), factory);
    }

    /**
     * Removes the entity authentication factory associated with the specified
     * entity authentication scheme.
     *
     * @param scheme entity authentication scheme.
     */
    public void removeEntityAuthenticationFactory(final EntityAuthenticationScheme scheme) {
        entityAuthFactories.remove(scheme);
    }

    @Override
    public EntityAuthenticationFactory getEntityAuthenticationFactory(final EntityAuthenticationScheme scheme) {
        return entityAuthFactories.get(scheme);
    }
    
    @Override
    public UserAuthenticationScheme getUserAuthenticationScheme(final String name) {
        return UserAuthenticationScheme.getScheme(name);
    }

    /**
     * Adds or replaces the user authentication factory associated with the
     * user authentication scheme of the provided factory.
     *
     * @param factory user authentication factory.
     */
    public void addUserAuthenticationFactory(final UserAuthenticationFactory factory) {
        userAuthFactories.put(factory.getScheme(), factory);
    }

    /**
     * Removes the user authentication factory associated with the specified
     * user authentication scheme.
     *
     * @param scheme user authentication scheme.
     */
    public void removeUserAuthenticationFactory(final UserAuthenticationScheme scheme) {
        userAuthFactories.remove(scheme);
    }

    @Override
    public UserAuthenticationFactory getUserAuthenticationFactory(final UserAuthenticationScheme scheme) {
        return userAuthFactories.get(scheme);
    }

    /**
     * Sets the token factory.
     *
     * @param factory the token factory.
     */
    public void setTokenFactory(final TokenFactory factory) {
        this.tokenFactory = factory;
    }

    @Override
    public TokenFactory getTokenFactory() {
        return tokenFactory;
    }
    
    @Override
    public KeyExchangeScheme getKeyExchangeScheme(final String name) {
        return KeyExchangeScheme.getScheme(name);
    }

    /**
     * Adds a key exchange factory to the end of the preferred set.
     *
     * @param factory key exchange factory.
     */
    public void addKeyExchangeFactory(final KeyExchangeFactory factory) {
        keyxFactories.add(factory);
    }

    /**
     * Removes all key exchange factories associated with the specified key
     * exchange scheme.
     *
     * @param scheme key exchange scheme.
     */
    public void removeKeyExchangeFactories(final KeyExchangeScheme scheme) {
        final Iterator<KeyExchangeFactory> factories = keyxFactories.iterator();
        while (factories.hasNext()) {
            final KeyExchangeFactory factory = factories.next();
            if (factory.getScheme().equals(scheme))
                factories.remove();
        }
    }

    @Override
    public KeyExchangeFactory getKeyExchangeFactory(final KeyExchangeScheme scheme) {
        for (final KeyExchangeFactory factory : keyxFactories) {
            if (factory.getScheme().equals(scheme))
                return factory;
        }
        return null;
    }

    @Override
    public SortedSet<KeyExchangeFactory> getKeyExchangeFactories() {
        return Collections.unmodifiableSortedSet(keyxFactories);
    }

    /**
     * Sets the MSL store.
     *
     * @param store the MSL store.
     */
    public void setMslStore(final MslStore store) {
        this.store = store;
    }

    @Override
    public MslStore getMslStore() {
        return store;
    }
    
    /**
     * Sets the MSL encoder factory.
     * 
     * @param encoderFactory the MSL encoder factory.
     */
    public void setMslEncoderFactory(final MslEncoderFactory encoderFactory) {
        this.encoderFactory = encoderFactory;
    }

    @Override
    public MslEncoderFactory getMslEncoderFactory() {
        return encoderFactory;
    }

    /** Peer-to-peer mode. */
    private final boolean peerToPeer;
    /** Message capabilities. */
    private MessageCapabilities capabilities;
    /** Entity authentication data. */
    private EntityAuthenticationData entityAuthData;
    /** MSL crypto context. */
    private ICryptoContext mslCryptoContext;
    /** Map of supported entity authentication schemes onto factories. */
    private final Map<EntityAuthenticationScheme,EntityAuthenticationFactory> entityAuthFactories;
    /** Map of supported user authentication schemes onto factories. */
    private final Map<UserAuthenticationScheme,UserAuthenticationFactory> userAuthFactories;
    /** Token factory. */
    private TokenFactory tokenFactory;
    /** Supported key exchange factories in preferred order. */
    private final SortedSet<KeyExchangeFactory> keyxFactories;
    /** MSL store. */
    private MslStore store;
    /** MSL encoder factory. */
    private MslEncoderFactory encoderFactory;
}
