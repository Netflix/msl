/**
 * Copyright (c) 2014 Netflix, Inc.  All rights reserved.
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

package mslcli.server.util;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collections;
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

import com.netflix.msl.MslConstants.CompressionAlgorithm;
import com.netflix.msl.MslCryptoException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.crypto.SymmetricCryptoContext;
import com.netflix.msl.entityauth.EntityAuthenticationData;
import com.netflix.msl.entityauth.EntityAuthenticationFactory;
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.entityauth.PresharedAuthenticationData;
import com.netflix.msl.entityauth.PresharedAuthenticationFactory;
import com.netflix.msl.entityauth.PresharedKeyStore;
import com.netflix.msl.entityauth.RsaAuthenticationData;
import com.netflix.msl.entityauth.RsaAuthenticationFactory;
import com.netflix.msl.entityauth.RsaStore;
import com.netflix.msl.entityauth.UnauthenticatedAuthenticationFactory;
import com.netflix.msl.keyx.AsymmetricWrappedExchange;
import com.netflix.msl.keyx.KeyExchangeFactory;
import com.netflix.msl.keyx.KeyExchangeScheme;
import com.netflix.msl.keyx.SymmetricWrappedExchange;
import com.netflix.msl.msg.MessageCapabilities;
import com.netflix.msl.tokens.TokenFactory;
import com.netflix.msl.userauth.EmailPasswordAuthenticationFactory;
import com.netflix.msl.userauth.EmailPasswordStore;
import com.netflix.msl.userauth.UserAuthenticationFactory;
import com.netflix.msl.userauth.UserAuthenticationScheme;
import com.netflix.msl.util.AuthenticationUtils;
import com.netflix.msl.util.MslContext;
import com.netflix.msl.util.MslStore;
import com.netflix.msl.util.SimpleMslStore;

import static mslcli.common.Constants.*;
import mslcli.common.util.SharedUtil;
import mslcli.server.tokens.ServerTokenFactory;
import mslcli.server.util.ServerAuthenticationUtils;

/**
 * <p>The sample server MSL context.</p>
 * 
 * @author Vadim Spector <vspector@netflix.com>
 */

public class ServerMslContext implements MslContext {
    /** MSL encryption key. */
    private static final byte[] MSL_ENCRYPTION_KEY = SharedUtil.hexStringToByteArray("1d58f3b8f747d16ab1093c4ca624eacf");

    /** MSL HMAC key. */
    private static final byte[] MSL_HMAC_KEY = SharedUtil.hexStringToByteArray("d7aebfd5879bb0e0ad016a4cf3cb3982f5ba260da520245bb42275bd7947370c");

    /** MSL wrapping key. */
    private static final byte[] MSL_WRAPPING_KEY = SharedUtil.hexStringToByteArray("0x83b69a1580d323a20xe79dd9b22626b3f6");

    /**
     * <p>Create a new simple MSL context.</p>
     * 
     * @param serverId local server entity identity.
     * @param presharedKeyStore local server entity preshared key store.
     * @param emailPasswords user email/password store.
     */
    public ServerMslContext(final String serverId, final PresharedKeyStore presharedKeyStore, final RsaStore rsaStore, final EmailPasswordStore emailPasswordStore, final MslStore mslStore) {
        // Message capabilities.
        final Set<CompressionAlgorithm> compressionAlgos = new HashSet<CompressionAlgorithm>(Arrays.asList(CompressionAlgorithm.GZIP, CompressionAlgorithm.LZW));
        final List<String> languages = Arrays.asList("en-US");
        this.messageCaps = new MessageCapabilities(compressionAlgos, languages);
        
        // MSL crypto context.
        final SecretKey encryptionKey = new SecretKeySpec(MSL_ENCRYPTION_KEY, "AES");
        final SecretKey hmacKey = new SecretKeySpec(MSL_HMAC_KEY, "HmacSHA256");
        final SecretKey wrappingKey = new SecretKeySpec(MSL_WRAPPING_KEY, "AES");
        this.mslCryptoContext = new SymmetricCryptoContext(this, serverId, encryptionKey, hmacKey, wrappingKey);
        
        // Create authentication utils.
        final AuthenticationUtils authutils = new ServerAuthenticationUtils(serverId);
        
        // Entity authentication.
        //
        // Use the local entity identity for the preshared keys database ID.
        this.entityAuthData = new RsaAuthenticationData(serverId, SERVER_RSA_KEY_ID);
        
        // Entity authentication factories.
        this.entityAuthFactories = new HashSet<EntityAuthenticationFactory>();
        this.entityAuthFactories.add(new PresharedAuthenticationFactory(presharedKeyStore, authutils));
        this.entityAuthFactories.add(new RsaAuthenticationFactory(rsaStore, authutils));
        
        // User authentication factories.
        this.userAuthFactory = new EmailPasswordAuthenticationFactory(emailPasswordStore, authutils);
        
        // Key exchange factories.
        final TreeSet<KeyExchangeFactory> keyxTmpFactories = new TreeSet<KeyExchangeFactory>(SharedUtil.getKeyExchangeFactoryComparator());
        keyxTmpFactories.add(new SymmetricWrappedExchange(authutils));
        this.keyxFactories = Collections.unmodifiableSortedSet(keyxTmpFactories);

        // key token factory
        this.tokenFactory = new ServerTokenFactory();

        this.mslStore = mslStore;
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
        return mslStore;
    }

    private final MessageCapabilities messageCaps;
    private final EntityAuthenticationData entityAuthData;
    private final ICryptoContext mslCryptoContext;
    private final Set<EntityAuthenticationFactory> entityAuthFactories;
    private final UserAuthenticationFactory userAuthFactory;
    private final TokenFactory tokenFactory;
    private final SortedSet<KeyExchangeFactory> keyxFactories;
    private final MslStore mslStore;
}
