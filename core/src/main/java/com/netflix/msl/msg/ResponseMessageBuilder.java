/**
 * Copyright (c) 2012-2018 Netflix, Inc.  All rights reserved.
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
package com.netflix.msl.msg;

import java.util.Arrays;
import java.util.Iterator;
import java.util.Set;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslEntityAuthException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslException;
import com.netflix.msl.MslInternalException;
import com.netflix.msl.MslKeyExchangeException;
import com.netflix.msl.MslMasterTokenException;
import com.netflix.msl.MslUserAuthException;
import com.netflix.msl.entityauth.EntityAuthenticationData;
import com.netflix.msl.io.MslEncoderFactory;
import com.netflix.msl.io.MslEncoderFormat;
import com.netflix.msl.keyx.KeyExchangeFactory;
import com.netflix.msl.keyx.KeyExchangeFactory.KeyExchangeData;
import com.netflix.msl.keyx.KeyRequestData;
import com.netflix.msl.keyx.KeyResponseData;
import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.tokens.MslUser;
import com.netflix.msl.tokens.ServiceToken;
import com.netflix.msl.tokens.TokenFactory;
import com.netflix.msl.tokens.UserIdToken;
import com.netflix.msl.userauth.UserAuthenticationData;
import com.netflix.msl.userauth.UserAuthenticationFactory;
import com.netflix.msl.userauth.UserAuthenticationScheme;
import com.netflix.msl.util.MslContext;

/**
 * <p>Response message builder.</p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class ResponseMessageBuilder extends MessageBuilder {
    /**
     * Issue a new master token for the specified identity or renew an existing
     * master token.
     *
     * @param ctx MSL context.
     * @param format MSL encoder format.
     * @param keyRequestData available key request data.
     * @param masterToken master token to renew. Null if the identity is
     *        provided.
     * @param entityAuthData entity authentication data. Null if a master token
     *        is provided.
     * @return the new master token and crypto context or {@code} null if the
     *         factory chooses not to perform key exchange.
     * @throws MslCryptoException if the crypto context cannot be created.
     * @throws MslKeyExchangeException if there is an error with the key
     *         request data or the key response data cannot be created or none
     *         of the key exchange schemes are supported.
     * @throws MslMasterTokenException if the master token is not trusted.
     * @throws MslEntityAuthException if there is a problem with the master
     *         token identity or entity identity.
     * @throws MslException if there is an error creating or renewing the
     *         master token.
     */
    private static KeyExchangeData issueMasterToken(final MslContext ctx, final MslEncoderFormat format, final Set<KeyRequestData> keyRequestData, final MasterToken masterToken, final EntityAuthenticationData entityAuthData) throws MslKeyExchangeException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslException {
        // Attempt key exchange in the preferred order.
        MslException keyxException = null;
        final Iterator<KeyExchangeFactory> factories = ctx.getKeyExchangeFactories().iterator();
        while (factories.hasNext()) {
            final KeyExchangeFactory factory = factories.next();
            for (final KeyRequestData request : keyRequestData) {
                if (!factory.getScheme().equals(request.getKeyExchangeScheme()))
                    continue;

                // Attempt the key exchange, but if it fails try with the next
                // combination before giving up.
                try {
                    if (masterToken != null)
                        return factory.generateResponse(ctx, format, request, masterToken);
                    else
                        return factory.generateResponse(ctx, format, request, entityAuthData);
                } catch (final MslCryptoException e) {
                    if (!factories.hasNext()) throw e;
                    keyxException = e;
                } catch (final MslKeyExchangeException e) {
                    if (!factories.hasNext()) throw e;
                    keyxException = e;
                } catch (final MslEncodingException e) {
                    if (!factories.hasNext()) throw e;
                    keyxException = e;
                } catch (final MslMasterTokenException e) {
                    if (!factories.hasNext()) throw e;
                    keyxException = e;
                } catch (final MslEntityAuthException e) {
                    if (!factories.hasNext()) throw e;
                    keyxException = e;
                }
            }
        }

        // We did not perform a successful key exchange. If we caught an
        // exception then throw that exception now.
        if (keyxException != null) {
            if (keyxException instanceof MslCryptoException)
                throw (MslCryptoException)keyxException;
            if (keyxException instanceof MslKeyExchangeException)
                throw (MslKeyExchangeException)keyxException;
            if (keyxException instanceof MslEncodingException)
                throw (MslEncodingException)keyxException;
            if (keyxException instanceof MslMasterTokenException)
                throw (MslMasterTokenException)keyxException;
            if (keyxException instanceof MslEntityAuthException)
                throw (MslEntityAuthException)keyxException;
            throw new MslInternalException("Unexpected exception caught during key exchange.", keyxException);
        }

        // If we didn't find any then we're unable to perform key exchange.
        throw new MslKeyExchangeException(MslError.KEYX_FACTORY_NOT_FOUND, Arrays.toString(keyRequestData.toArray()));
    }

    /**
     * Create a new message builder that will craft a new message in response
     * to another message. The constructed message may be used as a request.
     *
     * @param ctx MSL context.
     * @param requestHeader message header to respond to.
     * @throws MslMasterTokenException if the provided message's master token
     *         is not trusted.
     * @throws MslCryptoException if the crypto context from a key exchange
     *         cannot be created.
     * @throws MslKeyExchangeException if there is an error with the key
     *         request data or the key response data cannot be created.
     * @throws MslUserAuthException if there is an error with the user
     *         authentication data or the user ID token cannot be created.
     * @throws MslException if a user ID token in the message header is not
     *         bound to its corresponding master token or there is an error
     *         creating or renewing the master token.
     */
    public ResponseMessageBuilder(final MslContext ctx, final MessageHeader requestHeader) throws MslKeyExchangeException, MslCryptoException, MslMasterTokenException, MslUserAuthException, MslException {
        super(ctx);
        final MasterToken masterToken = requestHeader.getMasterToken();
        final EntityAuthenticationData entityAuthData = requestHeader.getEntityAuthenticationData();
        UserIdToken userIdToken = requestHeader.getUserIdToken();
        final UserAuthenticationData userAuthData = requestHeader.getUserAuthenticationData();

        // The response message ID must be equal to the request message ID + 1.
        final long requestMessageId = requestHeader.getMessageId();
        final long messageId = incrementMessageId(requestMessageId);

        // Compute the intersection of the request and response message
        // capabilities.
        final MessageCapabilities capabilities = MessageCapabilities.intersection(requestHeader.getMessageCapabilities(), ctx.getMessageCapabilities());

        // Identify the response format.
        final MslEncoderFactory encoder = ctx.getMslEncoderFactory();
        final Set<MslEncoderFormat> formats = (capabilities != null) ? capabilities.getEncoderFormats() : null;
        final MslEncoderFormat format = encoder.getPreferredFormat(formats);

        try {
            // If the message contains key request data and is renewable...
            final KeyExchangeData keyExchangeData;
            final Set<KeyRequestData> keyRequestData = requestHeader.getKeyRequestData();
            if (requestHeader.isRenewable() && !keyRequestData.isEmpty()) {
                // If the message contains a master token...
                if (masterToken != null) {
                    // If the master token is renewable or expired then renew
                    // the master token.
                    if (masterToken.isRenewable(null) || masterToken.isExpired(null))
                        keyExchangeData = issueMasterToken(ctx, format, keyRequestData, masterToken, null);
                    // Otherwise we don't need to do anything special.
                    else
                        keyExchangeData = null;
                }

                // Otherwise use the entity authentication data to issue a
                // master token.
                else {
                    // The message header is already authenticated via the
                    // entity authentication data's crypto context so we can
                    // simply proceed with the master token issuance.
                    keyExchangeData = issueMasterToken(ctx, format, keyRequestData, null, entityAuthData);
                }
            }

            // If the message does not contain key request data there is no key
            // exchange for us to do.
            else {
                keyExchangeData = null;
            }

            // If we successfully performed key exchange, use the new master
            // token for user authentication.
            final MasterToken userAuthMasterToken;
            if (keyExchangeData != null) {
                userAuthMasterToken = keyExchangeData.keyResponseData.getMasterToken();
            } else {
                userAuthMasterToken = masterToken;
            }

            // If the message contains a user ID token issued by the local
            // entity...
            if (userIdToken != null && userIdToken.isVerified()) {
                // If the user ID token is renewable and the message is
                // renewable, or it is expired, or it needs to be rebound
                // to the new master token then renew the user ID token.
                if ((userIdToken.isRenewable(null) && requestHeader.isRenewable()) ||
                    userIdToken.isExpired(null) ||
                    !userIdToken.isBoundTo(userAuthMasterToken))
                {
                    final TokenFactory tokenFactory = ctx.getTokenFactory();
                    userIdToken = tokenFactory.renewUserIdToken(ctx, userIdToken, userAuthMasterToken);
                }
            }

            // If the message is renewable and contains user authentication
            // data and a master token then we need to attempt user
            // authentication and issue a user ID token.
            else if (requestHeader.isRenewable() && userAuthMasterToken != null && userAuthData != null) {
                // If this request was parsed then its user authentication data
                // should have been authenticated and the user will exist. If
                // it was not parsed, then we need to perform user
                // authentication now.
                MslUser user = requestHeader.getUser();
                if (user == null) {
                    final UserAuthenticationScheme scheme = userAuthData.getScheme();
                    final UserAuthenticationFactory factory = ctx.getUserAuthenticationFactory(scheme);
                    if (factory == null) {
                        throw new MslUserAuthException(MslError.USERAUTH_FACTORY_NOT_FOUND, scheme.name())
                        .setMasterToken(masterToken)
                        .setUserAuthenticationData(userAuthData)
                        .setMessageId(requestMessageId);
                    }
                    user = factory.authenticate(ctx, userAuthMasterToken.getIdentity(), userAuthData, null);
                }
                final TokenFactory tokenFactory = ctx.getTokenFactory();
                userIdToken = tokenFactory.createUserIdToken(ctx, user, userAuthMasterToken);
            }

            // Create the message builder.
            //
            // Peer-to-peer responses swap the tokens.
            final KeyResponseData keyResponseData = requestHeader.getKeyResponseData();
            final Set<ServiceToken> serviceTokens = requestHeader.getServiceTokens();
            if (ctx.isPeerToPeer()) {
                final MasterToken peerMasterToken = (keyResponseData != null) ? keyResponseData.getMasterToken() : requestHeader.getPeerMasterToken();
                final UserIdToken peerUserIdToken = requestHeader.getPeerUserIdToken();
                final Set<ServiceToken> peerServiceTokens = requestHeader.getPeerServiceTokens();
                initializeMessageBuilder(ctx, messageId, capabilities, peerMasterToken, peerUserIdToken, peerServiceTokens, masterToken, userIdToken, serviceTokens, keyExchangeData);
            } else {
                final MasterToken localMasterToken = (keyResponseData != null) ? keyResponseData.getMasterToken() : masterToken;
                initializeMessageBuilder(ctx, messageId, capabilities, localMasterToken, userIdToken, serviceTokens, null, null, null, keyExchangeData);
            }
        } catch (final MslException e) {
            e.setMasterToken(masterToken);
            e.setEntityAuthenticationData(entityAuthData);
            e.setUserIdToken(userIdToken);
            e.setUserAuthenticationData(userAuthData);
            e.setMessageId(requestMessageId);
            throw e;
        }
    }

    /**
     * Create a new message builder that will craft a new message in response
     * to another message without issuing or renewing any master tokens or user
     * ID tokens. The constructed message may be used as a request.
     *
     * @param ctx MSL context.
     * @param requestHeader message header to respond to.
     * @throws MslCryptoException if there is an error accessing the remote
     *         entity identity.
     * @throws MslException if any of the request's user ID tokens is not bound
     *         to its master token.
     */
    public void createIdempotentResponse(final MslContext ctx, final MessageHeader requestHeader) throws MslCryptoException, MslException {
        final MasterToken masterToken = requestHeader.getMasterToken();
        final EntityAuthenticationData entityAuthData = requestHeader.getEntityAuthenticationData();
        final UserIdToken userIdToken = requestHeader.getUserIdToken();
        final UserAuthenticationData userAuthData = requestHeader.getUserAuthenticationData();

        // The response message ID must be equal to the request message ID + 1.
        final long requestMessageId = requestHeader.getMessageId();
        final long messageId = incrementMessageId(requestMessageId);

        // Compute the intersection of the request and response message
        // capabilities.
        final MessageCapabilities capabilities = MessageCapabilities.intersection(requestHeader.getMessageCapabilities(), ctx.getMessageCapabilities());

        // Create the message builder.
        //
        // Peer-to-peer responses swap the tokens.
        try {
            final KeyResponseData keyResponseData = requestHeader.getKeyResponseData();
            final Set<ServiceToken> serviceTokens = requestHeader.getServiceTokens();
            if (ctx.isPeerToPeer()) {
                final MasterToken peerMasterToken = (keyResponseData != null) ? keyResponseData.getMasterToken() : requestHeader.getPeerMasterToken();
                final UserIdToken peerUserIdToken = requestHeader.getPeerUserIdToken();
                final Set<ServiceToken> peerServiceTokens = requestHeader.getPeerServiceTokens();
                initializeMessageBuilder(ctx, messageId, capabilities, peerMasterToken, peerUserIdToken, peerServiceTokens, masterToken, userIdToken, serviceTokens, null);
            } else {
                final MasterToken localMasterToken = (keyResponseData != null) ? keyResponseData.getMasterToken() : masterToken;
                initializeMessageBuilder(ctx, messageId, capabilities, localMasterToken, userIdToken, serviceTokens, null, null, null, null);
            }
        } catch (final MslException e) {
            e.setMasterToken(masterToken);
            e.setEntityAuthenticationData(entityAuthData);
            e.setUserIdToken(userIdToken);
            e.setUserAuthenticationData(userAuthData);
            e.setMessageId(requestMessageId);
            throw e;
        }
    }
}
