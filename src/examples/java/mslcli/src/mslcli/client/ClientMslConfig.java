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

package mslcli.client;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.SortedSet;

import com.netflix.msl.keyx.AsymmetricWrappedExchange;
import com.netflix.msl.keyx.DiffieHellmanExchange;
import com.netflix.msl.keyx.JsonWebEncryptionLadderExchange;
import com.netflix.msl.keyx.JsonWebKeyLadderExchange;
import com.netflix.msl.keyx.SymmetricWrappedExchange;
import com.netflix.msl.keyx.WrapCryptoContextRepository;
import com.netflix.msl.userauth.EmailPasswordAuthenticationFactory;
import com.netflix.msl.userauth.UserAuthenticationFactory;
import com.netflix.msl.entityauth.RsaAuthenticationFactory;
import com.netflix.msl.entityauth.RsaStore;
import com.netflix.msl.entityauth.PresharedAuthenticationData;
import com.netflix.msl.entityauth.PresharedAuthenticationFactory;
import com.netflix.msl.entityauth.PresharedKeyStore;
import com.netflix.msl.entityauth.EntityAuthenticationFactory;
import com.netflix.msl.util.AuthenticationUtils;
import com.netflix.msl.keyx.KeyExchangeFactory;
import com.netflix.msl.entityauth.EntityAuthenticationData;

import mslcli.common.util.AppContext;
import mslcli.common.util.ConfigurationException;
import mslcli.client.util.ClientAuthenticationUtils;

/**
 * <p>The configuration class for MSl client</p>
 * 
 * @author Vadim Spector <vspector@netflix.com>
 */

public final class ClientMslConfig {
    public ClientMslConfig(final AppContext appCtx, final String clientId) throws ConfigurationException {
        // Entity authentication.
        this.entityAuthData = new PresharedAuthenticationData(clientId);

        // Create authentication utils.
        final AuthenticationUtils authutils = new ClientAuthenticationUtils(clientId, appCtx);

        // Entity authentication factories.
        this.entityAuthFactories = new HashSet<EntityAuthenticationFactory>();
        this.entityAuthFactories.add(new PresharedAuthenticationFactory(appCtx.getPresharedKeyStore(), authutils));
        this.entityAuthFactories.add(new RsaAuthenticationFactory(appCtx.getRsaStore(), authutils));

        // User authentication factories.
        this.userAuthFactories = new HashSet<UserAuthenticationFactory>();
        this.userAuthFactories.add(new EmailPasswordAuthenticationFactory(appCtx.getEmailPasswordStore(), authutils));

        // Key exchange factories. Real-life clients are likely to support subset of key exchange types.
        this.keyxFactories = appCtx.getKeyExchangeFactorySet(
            new AsymmetricWrappedExchange(authutils),
            new SymmetricWrappedExchange(authutils),
            new DiffieHellmanExchange(appCtx.getDiffieHellmanParameters(), authutils),
            new JsonWebEncryptionLadderExchange(appCtx.getWrapCryptoContextRepository(), authutils),
            new JsonWebKeyLadderExchange(appCtx.getWrapCryptoContextRepository(), authutils)
        );
    }

    public EntityAuthenticationData getEntityAuthenticationData() {
        return entityAuthData;
    }

    public Set<EntityAuthenticationFactory> getEntityAuthenticationFactories() {
        return Collections.<EntityAuthenticationFactory>unmodifiableSet(entityAuthFactories);
    }
 
    public Set<UserAuthenticationFactory> getUserAuthenticationFactories() {
        return Collections.<UserAuthenticationFactory>unmodifiableSet(userAuthFactories);
    }
 
    public SortedSet<KeyExchangeFactory> getKeyExchangeFactories() {
        return keyxFactories;
    }
 
    private final EntityAuthenticationData entityAuthData;
    private final Set<EntityAuthenticationFactory> entityAuthFactories;
    private final Set<UserAuthenticationFactory> userAuthFactories;
    private final SortedSet<KeyExchangeFactory> keyxFactories;
}
