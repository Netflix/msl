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

package mslcli.client.util;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Random;
import java.util.Set;
import java.util.SortedSet;

import com.netflix.msl.MslConstants.CompressionAlgorithm;
import com.netflix.msl.MslCryptoException;
import com.netflix.msl.crypto.ClientMslCryptoContext;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.entityauth.EntityAuthenticationData;
import com.netflix.msl.entityauth.EntityAuthenticationFactory;
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.entityauth.PresharedAuthenticationData;
import com.netflix.msl.entityauth.PresharedAuthenticationFactory;
import com.netflix.msl.entityauth.PresharedKeyStore;
import com.netflix.msl.entityauth.RsaAuthenticationFactory;
import com.netflix.msl.entityauth.RsaStore;
import com.netflix.msl.keyx.AsymmetricWrappedExchange;
import com.netflix.msl.keyx.DiffieHellmanExchange;
import com.netflix.msl.keyx.JsonWebEncryptionLadderExchange;
import com.netflix.msl.keyx.JsonWebKeyLadderExchange;
import com.netflix.msl.keyx.KeyExchangeFactory;
import com.netflix.msl.keyx.KeyExchangeScheme;
import com.netflix.msl.keyx.SymmetricWrappedExchange;
import com.netflix.msl.keyx.WrapCryptoContextRepository;
import com.netflix.msl.msg.MessageCapabilities;
import com.netflix.msl.tokens.ClientTokenFactory;
import com.netflix.msl.tokens.TokenFactory;
import com.netflix.msl.userauth.EmailPasswordAuthenticationFactory;
import com.netflix.msl.userauth.EmailPasswordStore;
import com.netflix.msl.userauth.UserAuthenticationFactory;
import com.netflix.msl.userauth.UserAuthenticationScheme;
import com.netflix.msl.util.AuthenticationUtils;
import com.netflix.msl.util.MslContext;
import com.netflix.msl.util.MslStore;

import mslcli.common.util.AppContext;

/**
 * <p>The sample client MSL context for clients talking to trusted network servers.</p>
 * 
 * @author Vadim Spector <vspector@netflix.com>
 */

public final class ClientMslContext implements MslContext {
    
    /**
     * <p>Create a new MSL context.</p>
     * 
     * @param appCtx application context
     * @param clientId local client entity identity.
     */
    public ClientMslContext(final AppContext appCtx,
                            final String clientId)
    {
        if (appCtx == null) {
            throw new IllegalArgumentException("NULL AppContext");
        }
        if (clientId == null) {
            throw new IllegalArgumentException("NULL client ID");
        }

        // MSL store
        this.mslStore = appCtx.getMslStore();

        // Create the preshared keys store.
        final PresharedKeyStore presharedKeyStore = appCtx.getPresharedKeyStore();

        // Create the RSA store.
        final RsaStore rsaStore = appCtx.getRsaStore();

        // Create the email/password store.
        final EmailPasswordStore emailPasswordStore = appCtx.getEmailPasswordStore();

        // Message capabilities.
        final Set<CompressionAlgorithm> compressionAlgos =
            new HashSet<CompressionAlgorithm>(Arrays.asList(CompressionAlgorithm.GZIP, CompressionAlgorithm.LZW));
        final List<String> languages = Arrays.asList("en-US");
        this.messageCaps = new MessageCapabilities(compressionAlgos, languages);
        
        /* MSL crypto context. Since MSL client does not encrypt/decrypt master tokens,
         * ClientMslCryptoContext is used. It has all dummy methods. This class
         * is defined in MSL core.
         */
        this.mslCryptoContext = new ClientMslCryptoContext();

        // WrapCryptoContextRepository
        final WrapCryptoContextRepository wrapCryptoContextRepository = appCtx.getWrapCryptoContextRepository();
        
        // Create authentication utils.
        final AuthenticationUtils authutils = new ClientAuthenticationUtils(clientId, appCtx);
        
        // Entity authentication.
        //
        // Use the local entity identity for the preshared keys database ID.
        this.entityAuthData = new PresharedAuthenticationData(clientId);
        
        // Entity authentication factories.
        this.entityAuthFactories = new HashSet<EntityAuthenticationFactory>();
        this.entityAuthFactories.add(new PresharedAuthenticationFactory(presharedKeyStore, authutils));
        this.entityAuthFactories.add(new RsaAuthenticationFactory(rsaStore, authutils));
        
        // User authentication factories.
        this.userAuthFactory = new EmailPasswordAuthenticationFactory(emailPasswordStore, authutils);
        
        // Key exchange factories. Real-life clients are likely to support subset of key exchange types.
        this.keyxFactories = appCtx.getKeyExchangeFactorySet(
            new AsymmetricWrappedExchange(authutils),
            new SymmetricWrappedExchange(authutils),
            new DiffieHellmanExchange(appCtx.getDiffieHellmanParameters(), authutils),
            new JsonWebEncryptionLadderExchange(wrapCryptoContextRepository, authutils),
            new JsonWebKeyLadderExchange(wrapCryptoContextRepository, authutils)
        );

        // key token factory
        this.tokenFactory = new ClientTokenFactory();
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
