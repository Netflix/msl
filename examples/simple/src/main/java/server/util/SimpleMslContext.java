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
package server.util;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import server.userauth.SimpleTokenFactory;

import com.netflix.msl.MslConstants.CompressionAlgorithm;
import com.netflix.msl.MslCryptoException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.crypto.SymmetricCryptoContext;
import com.netflix.msl.entityauth.EntityAuthenticationData;
import com.netflix.msl.entityauth.EntityAuthenticationFactory;
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.entityauth.RsaAuthenticationData;
import com.netflix.msl.entityauth.RsaAuthenticationFactory;
import com.netflix.msl.entityauth.RsaStore;
import com.netflix.msl.entityauth.UnauthenticatedAuthenticationFactory;
import com.netflix.msl.io.DefaultMslEncoderFactory;
import com.netflix.msl.io.MslEncoderFactory;
import com.netflix.msl.io.MslEncoderFormat;
import com.netflix.msl.keyx.AsymmetricWrappedExchange;
import com.netflix.msl.keyx.KeyExchangeFactory;
import com.netflix.msl.keyx.KeyExchangeScheme;
import com.netflix.msl.msg.MessageCapabilities;
import com.netflix.msl.tokens.TokenFactory;
import com.netflix.msl.userauth.EmailPasswordAuthenticationFactory;
import com.netflix.msl.userauth.EmailPasswordStore;
import com.netflix.msl.userauth.UserAuthenticationFactory;
import com.netflix.msl.userauth.UserAuthenticationScheme;
import com.netflix.msl.util.AuthenticationUtils;
import com.netflix.msl.util.MslContext;
import com.netflix.msl.util.MslStore;
import com.netflix.msl.util.NullMslStore;

/**
 * <p>The example server MSL context.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class SimpleMslContext extends MslContext {
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
     * <p>Create a new simple MSL context.</p>
     * 
     * @param serverId local server entity identity.
     * @param rsaStore local server entity RSA store.
     * @param emailPasswords user email/password store.
     */
    public SimpleMslContext(final String serverId, final RsaStore rsaStore, final EmailPasswordStore emailPasswordStore) {
        // Message capabilities.
        final Set<CompressionAlgorithm> compressionAlgos = new HashSet<CompressionAlgorithm>(Arrays.asList(CompressionAlgorithm.GZIP, CompressionAlgorithm.LZW));
        final List<String> languages = Arrays.asList("en-US");
        final Set<MslEncoderFormat> encoderFormats = new HashSet<MslEncoderFormat>(Arrays.asList(MslEncoderFormat.JSON));
        this.messageCaps = new MessageCapabilities(compressionAlgos, languages, encoderFormats);
        
        // MSL crypto context.
        final SecretKey encryptionKey = new SecretKeySpec(MSL_ENCRYPTION_KEY, "AES");
        final SecretKey hmacKey = new SecretKeySpec(MSL_HMAC_KEY, "HmacSHA256");
        final SecretKey wrappingKey = new SecretKeySpec(MSL_WRAPPING_KEY, "AES");
        this.mslCryptoContext = new SymmetricCryptoContext(this, serverId, encryptionKey, hmacKey, wrappingKey);
        
        // Create authentication utils.
        final AuthenticationUtils authutils = new SimpleAuthenticationUtils(serverId);
        
        // Entity authentication.
        //
        // Use the local entity identity for the key pair ID.
        this.entityAuthData = new RsaAuthenticationData(serverId, serverId);
        
        // Entity authentication factories.
        this.entityAuthFactories = new HashSet<EntityAuthenticationFactory>();
        this.entityAuthFactories.add(new RsaAuthenticationFactory(serverId, rsaStore, authutils));
        this.entityAuthFactories.add(new UnauthenticatedAuthenticationFactory(authutils));
        
        // User authentication factories.
        this.userAuthFactory = new EmailPasswordAuthenticationFactory(emailPasswordStore, authutils);
        
        // Key exchange factories.
        this.keyxFactories = new TreeSet<KeyExchangeFactory>(new KeyExchangeFactoryComparator());
        this.keyxFactories.add(new AsymmetricWrappedExchange(authutils));
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
        return messageCaps;
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
        for (final EntityAuthenticationFactory factory : entityAuthFactories) {
            if (factory.getScheme().equals(scheme))
                return factory;
        }
        return null;
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
        if (userAuthFactory.getScheme().equals(scheme))
            return userAuthFactory;
        return null;
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
        for (final KeyExchangeFactory factory : keyxFactories) {
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

    private final MessageCapabilities messageCaps;
    private final EntityAuthenticationData entityAuthData;
    private final ICryptoContext mslCryptoContext;
    private final Set<EntityAuthenticationFactory> entityAuthFactories;
    private final UserAuthenticationFactory userAuthFactory;
    private final TokenFactory tokenFactory = new SimpleTokenFactory();
    private final SortedSet<KeyExchangeFactory> keyxFactories;
    private final MslStore store = new NullMslStore();
    private final MslEncoderFactory encoderFactory = new DefaultMslEncoderFactory();;
}
