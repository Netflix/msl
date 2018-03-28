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
package com.netflix.msl.server.configuration.util;

import java.util.List;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.crypto.NullCryptoContext;
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.keyx.KeyExchangeScheme;
import com.netflix.msl.server.configuration.tokens.ServerTokenFactory;
import com.netflix.msl.server.configuration.tokens.TokenFactoryType;
import com.netflix.msl.tokens.MockTokenFactory;
import com.netflix.msl.userauth.UserAuthenticationScheme;
import com.netflix.msl.util.MockMslContext;

/**
 * User: skommidi
 * Date: 7/21/14
 */
public class ServerMslContext extends MockMslContext {
    /**
     * Create a new Server MSL context.
     * 
     * @throws MslCryptoException if there is an error signing or creating the
     *         entity authentication data.
     * @throws MslEncodingException if there is an error creating the entity
     *         authentication data.
     */
    public ServerMslContext(final EntityAuthenticationScheme entityAuthScheme, final boolean peerToPeer,
                            final TokenFactoryType tokenFactoryType, final long initialSequenceNum,
                            final List<EntityAuthenticationScheme> unSupportedEntityAuthFactories,
                            final List<UserAuthenticationScheme> unSupportedUserAuthFactories,
                            final List<KeyExchangeScheme> unSupportedKeyxFactories,
                            final boolean isNullCryptoContext) throws MslEncodingException, MslCryptoException {
        super(entityAuthScheme, peerToPeer);
        //Set Server TokenFactory with initialSequenceNumber
        final MockTokenFactory tokenFactory = new ServerTokenFactory(tokenFactoryType);
        tokenFactory.setNewestMasterToken(initialSequenceNum);
        super.setTokenFactory(tokenFactory);

        if (isNullCryptoContext) {
            super.setMslCryptoContext(new NullCryptoContext());
        }

        if (unSupportedEntityAuthFactories != null) {
            for (final EntityAuthenticationScheme scheme : unSupportedEntityAuthFactories) {
                super.removeEntityAuthenticationFactory(scheme);
            }
        }
        if (unSupportedUserAuthFactories != null) {
            for (final UserAuthenticationScheme scheme : unSupportedUserAuthFactories) {
                super.removeUserAuthenticationFactory(scheme);
            }
        }
        if (unSupportedKeyxFactories != null) {
            for (final KeyExchangeScheme scheme : unSupportedKeyxFactories) {
                super.removeKeyExchangeFactories(scheme);
            }
        }
    }
}
