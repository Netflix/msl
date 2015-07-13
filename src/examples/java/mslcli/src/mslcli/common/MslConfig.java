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

package mslcli.common;

import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

import com.netflix.msl.entityauth.EntityAuthenticationData;
import com.netflix.msl.entityauth.EntityAuthenticationFactory;
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
import com.netflix.msl.userauth.EmailPasswordAuthenticationFactory;
import com.netflix.msl.userauth.UserAuthenticationFactory;
import com.netflix.msl.util.AuthenticationUtils;

import mslcli.common.util.AppContext;
import mslcli.common.util.ConfigurationException;
import mslcli.client.util.ClientAuthenticationUtils;

/**
 * <p>The common configuration class for MSl client and server</p>
 * 
 * @author Vadim Spector <vspector@netflix.com>
 */

public abstract class MslConfig {
    protected MslConfig(final AppContext appCtx, final String entityId, final EntityAuthenticationData entityAuthData, final AuthenticationUtils authutils)
        throws ConfigurationException
    {
        // set application context
        this.appCtx = appCtx;

        // set entity ID
        this.entityId = entityId;

        // Entity authentication.
        this.entityAuthData = entityAuthData;

        // Entity authentication factories.
        this.entityAuthFactories = new HashSet<EntityAuthenticationFactory>();
        this.entityAuthFactories.add(new PresharedAuthenticationFactory(appCtx.getPresharedKeyStore(), authutils));
        this.entityAuthFactories.add(new RsaAuthenticationFactory(appCtx.getRsaStore(), authutils));

        // User authentication factories.
        this.userAuthFactories = new HashSet<UserAuthenticationFactory>();
        this.userAuthFactories.add(new EmailPasswordAuthenticationFactory(appCtx.getEmailPasswordStore(), authutils));

        // Key exchange factories.
        this.keyxFactories = getKeyExchangeFactorySet(
            new AsymmetricWrappedExchange(authutils),
            new SymmetricWrappedExchange(authutils),
            new DiffieHellmanExchange(appCtx.getDiffieHellmanParameters(), authutils),
            new JsonWebEncryptionLadderExchange(appCtx.getWrapCryptoContextRepository(), authutils),
            new JsonWebKeyLadderExchange(appCtx.getWrapCryptoContextRepository(), authutils)
        );
    }

    public final EntityAuthenticationData getEntityAuthenticationData() {
        return entityAuthData;
    }

    public final Set<EntityAuthenticationFactory> getEntityAuthenticationFactories() {
        return Collections.<EntityAuthenticationFactory>unmodifiableSet(entityAuthFactories);
    }
 
    public final Set<UserAuthenticationFactory> getUserAuthenticationFactories() {
        return Collections.<UserAuthenticationFactory>unmodifiableSet(userAuthFactories);
    }
 
    public final SortedSet<KeyExchangeFactory> getKeyExchangeFactories() {
        return keyxFactories;
    }

    /**
     * Key exchange factory comparator. The purpose is to list key exchange schemes in order of preference.
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
        public int compare(KeyExchangeFactory a, KeyExchangeFactory b) {
            final KeyExchangeScheme schemeA = a.getScheme();
            final KeyExchangeScheme schemeB = b.getScheme();
            final Integer priorityA = schemePriorities.get(schemeA);
            final Integer priorityB = schemePriorities.get(schemeB);
            return priorityA.compareTo(priorityB);
        }
    }

    /**
     * Convenience method creating SortedSet of multiple key exchange factories,
     * sorted in order of preference of their use.
     */
    protected static SortedSet<KeyExchangeFactory> getKeyExchangeFactorySet(KeyExchangeFactory... factories) {
        final TreeSet<KeyExchangeFactory> keyxFactoriesSet = new TreeSet<KeyExchangeFactory>(keyxFactoryComparator);
        keyxFactoriesSet.addAll(Arrays.asList(factories));
        return  Collections.unmodifiableSortedSet(keyxFactoriesSet);
    }
 
    protected final AppContext appCtx;
    protected final String entityId;
    private final EntityAuthenticationData entityAuthData;
    private final Set<EntityAuthenticationFactory> entityAuthFactories;
    private final Set<UserAuthenticationFactory> userAuthFactories;
    private final SortedSet<KeyExchangeFactory> keyxFactories;

    private static final KeyExchangeFactoryComparator keyxFactoryComparator = new KeyExchangeFactoryComparator();
}
