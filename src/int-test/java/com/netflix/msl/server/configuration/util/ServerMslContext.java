package com.netflix.msl.server.configuration.util;

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

import java.util.List;

/**
 * User: skommidi
 * Date: 7/21/14
 */
public class ServerMslContext extends MockMslContext {
    /**
     * Create a new Server MSL context.
     */
    public ServerMslContext(final EntityAuthenticationScheme entityAuthScheme, final boolean peerToPeer,
                            final TokenFactoryType tokenFactoryType, final long initialSequenceNum,
                            final List<EntityAuthenticationScheme> unSupportedEntityAuthFactories,
                            final List<UserAuthenticationScheme> unSupportedUserAuthFactories,
                            final List<KeyExchangeScheme> unSupportedKeyxFactories,
                            final boolean isNullCryptoContext) throws MslEncodingException, MslCryptoException {
        super(entityAuthScheme, peerToPeer);
        //Set Server TokenFactory with initialSequenceNumber
        MockTokenFactory tokenFactory = new ServerTokenFactory(tokenFactoryType);
        tokenFactory.setNewestMasterToken(initialSequenceNum);
        super.setTokenFactory(tokenFactory);

        if (isNullCryptoContext) {
            super.setMslCryptoContext(new NullCryptoContext());
        }

        if (unSupportedEntityAuthFactories != null) {
            for (EntityAuthenticationScheme scheme : unSupportedEntityAuthFactories) {
                super.removeEntityAuthenticationFactory(scheme);
            }
        }
        if (unSupportedUserAuthFactories != null) {
            for (UserAuthenticationScheme scheme : unSupportedUserAuthFactories) {
                super.removeUserAuthenticationFactory(scheme);
            }
        }
        if (unSupportedKeyxFactories != null) {
            for (KeyExchangeScheme scheme : unSupportedKeyxFactories) {
                super.removeKeyExchangeFactories(scheme);
            }
        }
    }
}
