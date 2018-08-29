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
package com.netflix.msl.msg;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

import com.netflix.msl.MslConstants;
import com.netflix.msl.MslConstants.ResponseCode;
import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslEntityAuthException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslException;
import com.netflix.msl.MslInternalException;
import com.netflix.msl.MslKeyExchangeException;
import com.netflix.msl.MslMasterTokenException;
import com.netflix.msl.MslMessageException;
import com.netflix.msl.MslUserAuthException;
import com.netflix.msl.crypto.NullCryptoContext;
import com.netflix.msl.entityauth.EntityAuthenticationData;
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.io.MslEncoderFactory;
import com.netflix.msl.io.MslEncoderFormat;
import com.netflix.msl.keyx.KeyExchangeFactory;
import com.netflix.msl.keyx.KeyExchangeFactory.KeyExchangeData;
import com.netflix.msl.keyx.KeyRequestData;
import com.netflix.msl.keyx.KeyResponseData;
import com.netflix.msl.msg.MessageHeader.HeaderData;
import com.netflix.msl.msg.MessageHeader.HeaderPeerData;
import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.tokens.MslUser;
import com.netflix.msl.tokens.ServiceToken;
import com.netflix.msl.tokens.TokenFactory;
import com.netflix.msl.tokens.UserIdToken;
import com.netflix.msl.userauth.UserAuthenticationData;
import com.netflix.msl.userauth.UserAuthenticationFactory;
import com.netflix.msl.userauth.UserAuthenticationScheme;
import com.netflix.msl.util.MslContext;
import com.netflix.msl.util.MslUtils;

/**
 * <p>A message builder provides methods for building messages.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class MessageBuilder {
    /** Empty service token data. */
    private static final byte[] EMPTY_DATA = new byte[0];
    
    /**
     * Increments the provided message ID by 1, wrapping around to zero if
     * the provided value is equal to {@link MslConstants#MAX_LONG_VALUE}.
     * 
     * @param messageId the message ID to increment.
     * @return the message ID + 1.
     * @throws MslInternalException if the provided message ID is out of range.
     */
    public static long incrementMessageId(final long messageId) {
        if (messageId < 0 || messageId > MslConstants.MAX_LONG_VALUE)
            throw new MslInternalException("Message ID " + messageId + " is outside the valid range.");
        return (messageId == MslConstants.MAX_LONG_VALUE) ? 0 : messageId + 1;
    }
    
    /**
     * Decrements the provided message ID by 1, wrapping around to
     * {@link MslConstants#MAX_LONG_VALUE} if the provided value is equal to 0.
     * 
     * @param messageId the message ID to decrement.
     * @return the message ID - 1.
     * @throws MslInternalException if the provided message ID is out of range.
     */
    public static long decrementMessageId(final long messageId) {
        if (messageId < 0 || messageId > MslConstants.MAX_LONG_VALUE)
            throw new MslInternalException("Message ID " + messageId + " is outside the valid range.");
        return (messageId == 0) ? MslConstants.MAX_LONG_VALUE : messageId - 1;
    }
    
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
     * <p>Construct a new MessageBuilder</p>
     */
    public MessageBuilder() {}

    /**
     * <p>Create a new message builder that will craft a new message with the
     * specified message ID.</p>
     * 
     * @param ctx MSL context.
     * @param masterToken master token. May be null unless a user ID token is
     *        provided.
     * @param userIdToken user ID token. May be null.
     * @param messageId the message ID to use. Must be within range.
     * @return void
     * @throws MslException if a user ID token is not bound to its
     *         corresponding master token.
     */
    public void createRequest(final MslContext ctx, final MasterToken masterToken, final UserIdToken userIdToken, final long messageId) throws MslException {
        if (messageId < 0 || messageId > MslConstants.MAX_LONG_VALUE)
            throw new MslInternalException("Message ID " + messageId + " is outside the valid range.");
        final MessageCapabilities capabilities = ctx.getMessageCapabilities();
        initializeMessageBuilder(ctx, messageId, capabilities, masterToken, userIdToken, null, null, null, null, null);
    }
    
    /**
     * <p>Create a new message builder that will craft a new message.</p>
     * 
     * @param ctx MSL context.
     * @param masterToken master token. May be null unless a user ID token is
     *        provided.
     * @param userIdToken user ID token. May be null.
     * @return void
     * @throws MslException if a user ID token is not bound to its
     *         corresponding master token.
     */
    public void createRequest(final MslContext ctx, final MasterToken masterToken, final UserIdToken userIdToken) throws MslException {
        final long messageId = MslUtils.getRandomLong(ctx);
        final MessageCapabilities capabilities = ctx.getMessageCapabilities();
        initializeMessageBuilder(ctx, messageId, capabilities, masterToken, userIdToken, null, null, null, null, null);
    }
    
    /**
     * Create a new message builder that will craft a new message in response
     * to another message. The constructed message may be used as a request.
     * 
     * @param ctx MSL context.
     * @param requestHeader message header to respond to.
     * @return void
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
    public void createResponse(final MslContext ctx, final MessageHeader requestHeader) throws MslKeyExchangeException, MslCryptoException, MslMasterTokenException, MslUserAuthException, MslException {
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
                return;
            } else {
                final MasterToken localMasterToken = (keyResponseData != null) ? keyResponseData.getMasterToken() : masterToken;
                initializeMessageBuilder(ctx, messageId, capabilities, localMasterToken, userIdToken, serviceTokens, null, null, null, keyExchangeData);
                return;
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
     * @return void
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
                return;
            } else {
                final MasterToken localMasterToken = (keyResponseData != null) ? keyResponseData.getMasterToken() : masterToken;
                initializeMessageBuilder(ctx, messageId, capabilities, localMasterToken, userIdToken, serviceTokens, null, null, null, null);
                return;
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
     * <p>Create a new message builder that will craft a new error message in
     * response to another message. If the message ID of the request is not
     * specified (i.e. unknown) then a random message ID will be generated.</p>
     * 
     * @param ctx MSL context.
     * @param requestMessageId message ID of request. May be null.
     * @param error the MSL error.
     * @param userMessage localized user-consumable error message. May be null.
     * @return the error header.
     * @throws MslCryptoException if there is an error encrypting or signing
     *         the message.
     * @throws MslEntityAuthException if there is an error with the entity
     *         authentication data.
     * @throws MslMessageException if no entity authentication data was
     *         returned by the MSL context.
     */
    public ErrorHeader createErrorResponse(final MslContext ctx, final Long requestMessageId, final MslError error, final String userMessage) throws MslCryptoException, MslEntityAuthException, MslMessageException {
        final EntityAuthenticationData entityAuthData = ctx.getEntityAuthenticationData(null);
        // If we have the request message ID then the error response message ID
        // must be equal to the request message ID + 1.
        long messageId;
        if (requestMessageId != null) {
            messageId = incrementMessageId(requestMessageId);
        }
        // Otherwise use a random message ID.
        else {
            messageId = MslUtils.getRandomLong(ctx);
        }
        final ResponseCode errorCode = error.getResponseCode();
        final int internalCode = error.getInternalCode();
        final String errorMsg = error.getMessage();
        return constructErrorHeader(ctx, entityAuthData, messageId, errorCode, internalCode, errorMsg, userMessage);
    }

    /**
     * Construct a new error header
     * 
     * @param ctx MSL context.
     * @param entityAuthData the entity authentication data.
     * @param messageId the message ID.
     * @param errorCode the error code.
     * @param internalCode the internal code. Negative to indicate no code.
     * @param errorMsg the error message. May be null.
     * @param userMsg the user message. May be null.
     * @throws MslMessageException if no entity authentication data is
     *         provided.
     */
    public ErrorHeader constructErrorHeader(final MslContext ctx, final EntityAuthenticationData entityAuthData, final long messageId, final ResponseCode errorCode, final int internalCode, final String errorMsg, final String userMsg) throws MslMessageException {
        return new ErrorHeader(ctx, entityAuthData, messageId, errorCode, internalCode, errorMsg, userMsg);
    }
    
    /**
     * Create a new message builder with the provided tokens and key exchange
     * data if a master token was issued or renewed.
     * 
     * @param ctx MSL context.
     * @param messageId message ID.
     * @param capabilities message capabilities.
     * @param masterToken master token. May be null unless a user ID token is
     *        provided.
     * @param userIdToken user ID token. May be null.
     * @param serviceTokens initial set of service tokens. May be null.
     * @param peerMasterToken peer master token. May be null unless a peer user
     *        ID token is provided.
     * @param peerUserIdToken peer user ID token. May be null.
     * @param peerServiceTokens initial set of peer service tokens.
     *        May be null.
     * @param keyExchangeData key exchange data. May be null.
     * @throws MslException if a user ID token is not bound to its master
     *         token.
     */
    public void initializeMessageBuilder(final MslContext ctx, final long messageId, final MessageCapabilities capabilities, final MasterToken masterToken, final UserIdToken userIdToken, final Set<ServiceToken> serviceTokens, final MasterToken peerMasterToken, final UserIdToken peerUserIdToken, final Set<ServiceToken> peerServiceTokens, final KeyExchangeData keyExchangeData) throws MslException {
        // Primary and peer token combinations will be verified when the
        // message header is constructed. So delay those checks in favor of
        // avoiding duplicate code.
        if (!ctx.isPeerToPeer() && (peerMasterToken != null || peerUserIdToken != null))
            throw new MslInternalException("Cannot set peer master token or peer user ID token when not in peer-to-peer mode.");
        
        // Set the primary fields.
        this.ctx = ctx;
        this.messageId = messageId;
        this.capabilities = capabilities;
        this.masterToken = masterToken;
        this.userIdToken = userIdToken;
        this.keyExchangeData = keyExchangeData;
        
        // If key exchange data is provided and we are not in peer-to-peer mode
        // then its master token should be used for querying service tokens.
        final MasterToken serviceMasterToken;
        if (keyExchangeData != null && !ctx.isPeerToPeer()) {
            serviceMasterToken = keyExchangeData.keyResponseData.getMasterToken();
        } else {
            serviceMasterToken = masterToken;
        }
        
        // Set the initial service tokens based on the MSL store and provided
        // service tokens.
        final Set<ServiceToken> tokens = ctx.getMslStore().getServiceTokens(serviceMasterToken, userIdToken);
        for (final ServiceToken token : tokens)
            this.serviceTokens.put(token.getName(), token);
        if (serviceTokens != null) {
            for (final ServiceToken token : serviceTokens)
                this.serviceTokens.put(token.getName(), token);
        }
        
        // Set the peer-to-peer data.
        if (ctx.isPeerToPeer()) {
            this.peerMasterToken = peerMasterToken;
            this.peerUserIdToken = peerUserIdToken;
            
            // If key exchange data is provided then its master token should
            // be used to query peer service tokens.
            final MasterToken peerServiceMasterToken;
            if (keyExchangeData != null)
                peerServiceMasterToken = keyExchangeData.keyResponseData.getMasterToken();
            else
                peerServiceMasterToken = this.peerMasterToken;
            
            // Set the initial peer service tokens based on the MSL store and
            // provided peer service tokens.
            final Set<ServiceToken> peerTokens = ctx.getMslStore().getServiceTokens(peerServiceMasterToken, peerUserIdToken);
            for (final ServiceToken peerToken : peerTokens)
                this.peerServiceTokens.put(peerToken.getName(), peerToken);
            if (peerServiceTokens != null) {
                for (final ServiceToken peerToken : peerServiceTokens)
                    this.peerServiceTokens.put(peerToken.getName(), peerToken);
            }
        }
    }
    
    /**
     * @return the message ID the builder will use.
     */
    public long getMessageId() {
        return messageId;
    }

    /**
     * @return the primary master token or null if the message will use entity
     *         authentication data.
     */
    public MasterToken getMasterToken() {
        return masterToken;
    }

    /**
     * @return the primary user ID token or null if the message will use user
     *         authentication data.
     */
    public UserIdToken getUserIdToken() {
        return userIdToken;
    }
    
    /**
     * @return the key exchange data or null if there is none.
     */
    public KeyExchangeData getKeyExchangeData() {
        return keyExchangeData;
    }
    
    /**
     * @return true if the message builder will create a message capable of
     *         encrypting the header data.
     */
    public boolean willEncryptHeader() {
        final EntityAuthenticationScheme scheme = ctx.getEntityAuthenticationData(null).getScheme();
        return masterToken != null || scheme.encrypts();
    }
    
    /**
     * @return true if the message builder will create a message capable of
     *         encrypting the payload data.
     */
    public boolean willEncryptPayloads() {
        final EntityAuthenticationScheme scheme = ctx.getEntityAuthenticationData(null).getScheme();
        return masterToken != null ||
            (!ctx.isPeerToPeer() && keyExchangeData != null) ||
            scheme.encrypts();
    }
    
    /**
     * @return true if the message builder will create a message capable of
     *         integrity protecting the header data.
     */
    public boolean willIntegrityProtectHeader() {
        final EntityAuthenticationScheme scheme = ctx.getEntityAuthenticationData(null).getScheme();
        return masterToken != null || scheme.protectsIntegrity();
    }
    
    /**
     * @return true if the message builder will create a message capable of
     *         integrity protecting the payload data.
     */
    public boolean willIntegrityProtectPayloads() {
        final EntityAuthenticationScheme scheme = ctx.getEntityAuthenticationData(null).getScheme();
        return masterToken != null ||
            (!ctx.isPeerToPeer() && keyExchangeData != null) ||
            scheme.protectsIntegrity();
    }
    
    /**
     * Construct the message header from the current message builder state.
     * 
     * @return the message header.
     * @throws MslCryptoException if there is an error encrypting or signing
     *         the message.
     * @throws MslMasterTokenException if the header master token is not
     *         trusted and needs to be to accept this message header.
     * @throws MslEntityAuthException if there is an error with the entity
     *         authentication data.
     * @throws MslMessageException if the message is non-replayable but does
     *         not include a master token.
     * @throws MslException should not happen.
     */
    public MessageHeader getHeader() throws MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslMessageException, MslException {
        final KeyResponseData response = (keyExchangeData != null) ? keyExchangeData.keyResponseData : null;
        final Set<ServiceToken> tokens = new HashSet<ServiceToken>(serviceTokens.values());
        final Long nonReplayableId;
        if (nonReplayable) {
            if (masterToken == null)
                throw new MslMessageException(MslError.NONREPLAYABLE_MESSAGE_REQUIRES_MASTERTOKEN);
            nonReplayableId = ctx.getMslStore().getNonReplayableId(masterToken);
        } else {
            nonReplayableId = null;
        }
        final HeaderData headerData = new HeaderData(messageId, nonReplayableId, renewable, handshake, capabilities, keyRequestData, response, userAuthData, userIdToken, tokens);
        final Set<ServiceToken> peerTokens = new HashSet<ServiceToken>(peerServiceTokens.values());
        final HeaderPeerData peerData = new HeaderPeerData(peerMasterToken, peerUserIdToken, peerTokens);

        return constructMessageHeader(ctx, ctx.getEntityAuthenticationData(null), masterToken, headerData, peerData);
    }

    /**
     * Construct a new message header
     * @param ctx MSL context.
     * @param entityAuthData entity authentication data. Null if a master token is provided.
     * @param masterToken master token to renew. Null if the identity is provided.
     * @param headerData message header data container.
     * @param peerData message header peer data container.
     * @return the message header.
     */ 
    protected MessageHeader constructMessageHeader(final MslContext ctx, final EntityAuthenticationData entityAuthData, final MasterToken masterToken, final HeaderData headerData, final HeaderPeerData peerData) throws MslException, MslCryptoException {
        return new MessageHeader(ctx, entityAuthData, masterToken, headerData, peerData);
    }

    /**
     * <p>Set the message ID.</p>
     * 
     * <p>This method will override the message ID that was computed when the
     * message builder was created, and should not need to be called in most
     * cases.</p>
     * 
     * @param messageId the message ID.
     * @return this.
     * @throws MslInternalException if the message ID is out of range.
     */
    public MessageBuilder setMessageId(final long messageId) {
        if (messageId < 0 || messageId > MslConstants.MAX_LONG_VALUE)
            throw new MslInternalException("Message ID " + messageId + " is out of range.");
        this.messageId = messageId;
        return this;
    }
    
    /**
     * @return true if the message will be marked non-replayable.
     */
    public boolean isNonReplayable() {
        return nonReplayable;
    }
    
    /**
     * Make the message non-replayable. If true this will also set the
     * handshake flag to false.
     * 
     * @param nonReplayable true if the message should be non-replayable.
     * @return this.
     * @see #setHandshake(boolean)
     */
    public MessageBuilder setNonReplayable(final boolean nonReplayable) {
        this.nonReplayable = nonReplayable;
        if (this.nonReplayable)
            this.handshake = false;
        return this;
    }
    
    /**
     * @return true if the message will be marked renewable.
     */
    public boolean isRenewable() {
        return renewable;
    }
    
    /**
     * Set the message renewable flag. If false this will also set the
     * handshake flag to false.
     *
     * @param renewable true if the message is renewable.
     * @return this.
     * @see #setHandshake(boolean)
     */
    public MessageBuilder setRenewable(final boolean renewable) {
        this.renewable = renewable;
        if (!this.renewable)
            this.handshake = false;
        return this;
    }
    
    /**
     * @return true if the message will be marked as a handshake message.
     */
    public boolean isHandshake() {
        return handshake;
    }
    
    /**
     * Set the message handshake flag. If true this will also set the non-
     * replayable flag to false and the renewable flag to true.
     * 
     * @param handshake true if the message is a handshake message.
     * @return this.
     * @see #setNonReplayable(boolean)
     * @see #setRenewable(boolean)
     */
    public MessageBuilder setHandshake(final boolean handshake) {
        this.handshake = handshake;
        if (this.handshake) {
            this.nonReplayable = false;
            this.renewable = true;
        }
        return this;
    }
    
    /**
     * <p>Set or change the master token and user ID token. This will overwrite
     * any existing tokens. If the user ID token is not null then any existing
     * user authentication data will be removed.</p>
     *
     * <p>Changing these tokens may result in invalidation of existing service
     * tokens. Those service tokens will be removed from the message being
     * built.</p>
     * 
     * <p>This is a special method for the {@link MslControl} class that assumes
     * the builder does not have key response data in trusted network mode.</p>
     * 
     * @param masterToken the master token.
     * @param userIdToken the user ID token. May be null.
     */
    public void setAuthTokens(final MasterToken masterToken, final UserIdToken userIdToken) {
        // Make sure the assumptions hold. Otherwise a bad message could be
        // built.
        if (userIdToken != null && !userIdToken.isBoundTo(masterToken))
            throw new MslInternalException("User ID token must be bound to master token.");
        // In trusted network mode key exchange data should only exist if this
        // is a server response. In which case this method should not be
        // getting called.
        if (keyExchangeData != null && !ctx.isPeerToPeer())
            throw new MslInternalException("Attempt to set message builder master token when key exchange data exists as a trusted network server.");

        // Load the stored service tokens.
        final Set<ServiceToken> storedTokens;
        try {
            storedTokens = ctx.getMslStore().getServiceTokens(masterToken, userIdToken);
        } catch (final MslException e) {
            // This should never happen because we already checked that the
            // user ID token is bound to the master token.
            throw new MslInternalException("Invalid master token and user ID token combination despite checking above.", e);
        }

        // Remove any service tokens that will no longer be bound.
        final Collection<ServiceToken> tokens = serviceTokens.values();
        for (final ServiceToken token : tokens) {
            if (token.isUserIdTokenBound() && !token.isBoundTo(userIdToken) ||
                token.isMasterTokenBound() && !token.isBoundTo(masterToken))
            {
                serviceTokens.remove(token.getName());
            }
        }
        
        // Add any service tokens based on the MSL store replacing ones already
        // set as they may be newer. The application will have a chance to
        // manage the service tokens before the message is constructed and
        // sent.
        for (final ServiceToken token : storedTokens)
            serviceTokens.put(token.getName(), token);

        // Set the new authentication tokens.
        this.masterToken = masterToken;
        this.userIdToken = userIdToken;
        if (this.userIdToken != null)
            this.userAuthData = null;
    }
    
    /**
     * <p>Set the user authentication data of the message.</p>
     * 
     * <p>This will overwrite any existing user authentication data.</p>
     * 
     * @param userAuthData user authentication data to set. May be null.
     * @return this.
     */
    public MessageBuilder setUserAuthenticationData(final UserAuthenticationData userAuthData) {
        this.userAuthData = userAuthData;
        return this;
    }
    
    /**
     * <p>Set the remote user of the message. This will create a user ID token
     * in trusted network mode or peer user ID token in peer-to-peer mode.</p>
     * 
     * <p>Adding a new user ID token will not impact the service tokens; it is
     * assumed that no service tokens exist that are bound to the newly created
     * user ID token.</p>
     * 
     * <p>This is a special method for the {@link MslControl} class that assumes
     * the builder does not already have a user ID token for the remote user
     * and does have a master token that the new user ID token can be bound
     * against.</p>
     * 
     * @param user remote user.
     * @throws MslCryptoException if there is an error encrypting or signing
     *         the token data.
     * @throws MslException if there is an error creating the user ID token.
     */
    public void setUser(final MslUser user) throws MslCryptoException, MslException {
        // Make sure the assumptions hold. Otherwise a bad message could be
        // built.
        if (!ctx.isPeerToPeer() && userIdToken != null ||
            ctx.isPeerToPeer() && peerUserIdToken != null)
        {
            throw new MslInternalException("User ID token or peer user ID token already exists for the remote user.");
        }
        
        // If key exchange data is provided then its master token should be
        // used for the new user ID token and for querying service tokens.
        final MasterToken uitMasterToken;
        if (keyExchangeData != null) {
            uitMasterToken = keyExchangeData.keyResponseData.getMasterToken();
        } else {
            uitMasterToken = (!ctx.isPeerToPeer()) ? masterToken : peerMasterToken;
        }
        
        // Make sure we have a master token to create the user for.
        if (uitMasterToken == null)
            throw new MslInternalException("User ID token or peer user ID token cannot be created because no corresponding master token exists.");
        
        // Create the new user ID token.
        final TokenFactory factory = ctx.getTokenFactory();
        final UserIdToken userIdToken = factory.createUserIdToken(ctx, user, uitMasterToken);
        
        // Set the new user ID token.
        if (!ctx.isPeerToPeer()) {
            this.userIdToken = userIdToken;
            this.userAuthData = null;
        } else {
            this.peerUserIdToken = userIdToken;
        }
    }
    
    /**
     * Add key request data to the message.
     * 
     * @param keyRequestData key request data to add.
     * @return this.
     */
    public MessageBuilder addKeyRequestData(final KeyRequestData keyRequestData) {
        this.keyRequestData.add(keyRequestData);
        return this;
    }
    
    /**
     * Remove key request data from the message.
     * 
     * @param keyRequestData key request data to remove.
     * @return this.
     */
    public MessageBuilder removeKeyRequestData(final KeyRequestData keyRequestData) {
        this.keyRequestData.remove(keyRequestData);
        return this;
    }

    /**
     * <p>Add a service token to the message. This will overwrite any service
     * token with the same name.</p>
     * 
     * <p>Adding a service token with empty data indicates the recipient should
     * delete the service token.</p>
     * 
     * @param serviceToken service token to add.
     * @return this.
     * @throws MslMessageException if the service token serial numbers do not
     *         match the primary master token or primary user ID token of the
     *         message being built.
     */
    public MessageBuilder addServiceToken(final ServiceToken serviceToken) throws MslMessageException {
        // If key exchange data is provided and we are not in peer-to-peer mode
        // then its master token should be used for querying service tokens.
        final MasterToken serviceMasterToken;
        if (keyExchangeData != null && !ctx.isPeerToPeer()) {
            serviceMasterToken = keyExchangeData.keyResponseData.getMasterToken();
        } else {
            serviceMasterToken = masterToken;
        }
        
        // Make sure the service token is properly bound.
        if (serviceToken.isMasterTokenBound() && !serviceToken.isBoundTo(serviceMasterToken))
            throw new MslMessageException(MslError.SERVICETOKEN_MASTERTOKEN_MISMATCH, "st " + serviceToken + "; mt " + serviceMasterToken).setMasterToken(serviceMasterToken);
        if (serviceToken.isUserIdTokenBound() && !serviceToken.isBoundTo(userIdToken))
            throw new MslMessageException(MslError.SERVICETOKEN_USERIDTOKEN_MISMATCH, "st " + serviceToken + "; uit " + userIdToken).setMasterToken(serviceMasterToken).setUserIdToken(userIdToken);
        
        // Add the service token.
        serviceTokens.put(serviceToken.getName(), serviceToken);
        return this;
    }

    /**
     * <p>Add a service token to the message if a service token with the same
     * name does not already exist.</p>
     * 
     * <p>Adding a service token with empty data indicates the recipient should
     * delete the service token.</p>
     * 
     * @param serviceToken service token to add.
     * @return this.
     * @throws MslMessageException if the service token serial numbers do not
     *         match the master token or user ID token of the message being
     *         built.
     */
    public MessageBuilder addServiceTokenIfAbsent(final ServiceToken serviceToken) throws MslMessageException {
        if (!serviceTokens.containsKey(serviceToken.getName()))
            addServiceToken(serviceToken);
        return this;
    }

    /**
     * <p>Exclude a service token from the message.</p>
     * 
     * <p>The service token will not be sent in the built message. This is not
     * the same as requesting the remote entity delete a service token.</p>
     * 
     * @param name service token name.
     * @return this.
     */
    public MessageBuilder excludeServiceToken(final String name) {
        serviceTokens.remove(name);
        return this;
    }

    /**
     * <p>Mark a service token for deletion, if it exists. Otherwise this
     * method does nothing.</p>
     * 
     * <p>The service token will be sent in the built message with an empty
     * value. This is not the same as requesting that a service token be
     * excluded from the message.</p>
     * 
     * @param name service token name.
     * @return this.
     */
    public MessageBuilder deleteServiceToken(final String name) {
        // Do nothing if the original token does not exist.
        final ServiceToken originalToken = serviceTokens.get(name);
        if (originalToken == null)
            return this;
        
        // Rebuild the original token with empty service data.
        final MasterToken masterToken = originalToken.isMasterTokenBound() ? this.masterToken : null;
        final UserIdToken userIdToken = originalToken.isUserIdTokenBound() ? this.userIdToken : null;
        try {
            final ServiceToken token = new ServiceToken(ctx, name, EMPTY_DATA, masterToken, userIdToken, false, null, new NullCryptoContext());
            return addServiceToken(token);
        } catch (final MslException e) {
            throw new MslInternalException("Failed to create and add empty service token to message.", e);
        }
    }

    /**
     * @return the unmodifiable set of service tokens that will be included in
     *         the built message.
     */
    public Set<ServiceToken> getServiceTokens() {
        return Collections.unmodifiableSet(new HashSet<ServiceToken>(serviceTokens.values()));
    }

    /**
     * @return the peer master token or null if there is none.
     */
    public MasterToken getPeerMasterToken() {
        return peerMasterToken;
    }

    /**
     * @return the peer user ID token or null if there is none.
     */
    public UserIdToken getPeerUserIdToken() {
        return peerUserIdToken;
    }
    
    /**
     * <p>Set the peer master token and peer user ID token of the message. This
     * will overwrite any existing peer master token or peer user ID token.</p>
     * 
     * <p>Changing these tokens may result in invalidation of existing peer
     * service tokens. Those peer service tokens will be removed from the
     * message being built.</p>
     * 
     * @param masterToken peer master token to set. May be null.
     * @param userIdToken peer user ID token to set. May be null.
     * @throws MslMessageException if the peer user ID token is not bound to
     *         the peer master token.
     */
    public void setPeerAuthTokens(final MasterToken masterToken, final UserIdToken userIdToken) throws MslMessageException {
        if (!ctx.isPeerToPeer())
            throw new MslInternalException("Cannot set peer master token or peer user ID token when not in peer-to-peer mode.");
        if (userIdToken != null && masterToken == null)
            throw new MslInternalException("Peer master token cannot be null when setting peer user ID token.");
        if (userIdToken != null && !userIdToken.isBoundTo(masterToken))
            throw new MslMessageException(MslError.USERIDTOKEN_MASTERTOKEN_MISMATCH, "uit " + userIdToken + "; mt " + masterToken).setMasterToken(masterToken).setUserIdToken(userIdToken);
        
        // Load the stored peer service tokens.
        final Set<ServiceToken> storedTokens;
        try {
            storedTokens = ctx.getMslStore().getServiceTokens(masterToken, userIdToken);
        } catch (final MslException e) {
            // The checks above should have prevented any invalid master token,
            // user ID token combinations.
            throw new MslInternalException("Invalid peer master token and user ID token combination despite proper check.", e);
        }

        // Remove any peer service tokens that will no longer be bound.
        final Collection<ServiceToken> tokens = peerServiceTokens.values();
        for (final ServiceToken token : tokens) {
            if (token.isUserIdTokenBound() && !token.isBoundTo(userIdToken)) {
                peerServiceTokens.remove(token.getName());
                continue;
            }
            if (token.isMasterTokenBound() && !token.isBoundTo(masterToken)) {
                peerServiceTokens.remove(token.getName());
                continue;
            }
        }
        
        // Add any peer service tokens based on the MSL store if they are not
        // already set (as a set one may be newer than the stored one).
        for (final ServiceToken token : storedTokens) {
            if (!peerServiceTokens.containsKey(token.getName()))
                peerServiceTokens.put(token.getName(), token);
        }
        
        // Set the new peer authentication tokens.
        peerUserIdToken = userIdToken;
        peerMasterToken = masterToken;
    }

    /**
     * <p>Add a peer service token to the message. This will overwrite any peer
     * service token with the same name.</p>
     * 
     * <p>Adding a service token with empty data indicates the recipient should
     * delete the service token.</p>
     * 
     * @param serviceToken service token to add.
     * @return this.
     * @throws MslMessageException if the service token serial numbers do not
     *         match the peer master token or peer user ID token of the message
     *         being built.
     */
    public MessageBuilder addPeerServiceToken(final ServiceToken serviceToken) throws MslMessageException {
        if (!ctx.isPeerToPeer())
            throw new MslInternalException("Cannot set peer service tokens when not in peer-to-peer mode.");
        if (serviceToken.isMasterTokenBound() && !serviceToken.isBoundTo(peerMasterToken))
            throw new MslMessageException(MslError.SERVICETOKEN_MASTERTOKEN_MISMATCH, "st " + serviceToken + "; mt " + peerMasterToken).setMasterToken(peerMasterToken);
        if (serviceToken.isUserIdTokenBound() && !serviceToken.isBoundTo(peerUserIdToken))
            throw new MslMessageException(MslError.SERVICETOKEN_USERIDTOKEN_MISMATCH, "st " + serviceToken + "; uit " + peerUserIdToken).setMasterToken(peerMasterToken).setUserIdToken(peerUserIdToken);
        
        // Add the peer service token.
        peerServiceTokens.put(serviceToken.getName(), serviceToken);
        return this;
    }

    /**
     * <p>Add a peer service token to the message if a peer service token with
     * the same name does not already exist.</p>
     * 
     * <p>Adding a service token with empty data indicates the recipient should
     * delete the service token.</p>
     * 
     * @param serviceToken service token to add.
     * @return this.
     * @throws MslMessageException if the service token serial numbers do not
     *         match the peer master token or peer user ID token of the message
     *         being built.
     */
    public MessageBuilder addPeerServiceTokenIfAbsent(final ServiceToken serviceToken) throws MslMessageException {
        if (!peerServiceTokens.containsKey(serviceToken.getName()))
            addPeerServiceToken(serviceToken);
        return this;
    }

    /**
     * <p>Exclude a peer service token from the message.</p>
     * 
     * <p>The service token will not be sent in the built message. This is not
     * the same as requesting the remote entity delete a service token.</p>
     * 
     * @param name service token name.
     * @return this.
     */
    public MessageBuilder excludePeerServiceToken(final String name) {
        peerServiceTokens.remove(name);
        return this;
    }

    /**
     * <p>Mark a peer service token for deletion, if it exists. Otherwise this
     * method does nothing.</p>
     * 
     * <p>The service token will be sent in the built message with an empty
     * value. This is not the same as requesting that a service token be
     * excluded from the message.</p>
     * 
     * @param name service token name.
     * @return this.
     */
    public MessageBuilder deletePeerServiceToken(final String name) {
        // Do nothing if the original token does not exist.
        final ServiceToken originalToken = peerServiceTokens.get(name);
        if (originalToken == null)
            return this;

        // Rebuild the original token with empty service data.
        final MasterToken peerMasterToken = originalToken.isMasterTokenBound() ? this.peerMasterToken : null;
        final UserIdToken peerUserIdToken = originalToken.isUserIdTokenBound() ? this.peerUserIdToken : null;
        try {
            final ServiceToken token = new ServiceToken(ctx, name, EMPTY_DATA, peerMasterToken, peerUserIdToken, false, null, new NullCryptoContext());
            return addPeerServiceToken(token);
        } catch (final MslException e) {
            throw new MslInternalException("Failed to create and add empty peer service token to message.", e);
        }
    }

    /**
     * @return the unmodifiable set of peer service tokens that will be
     *         included in the built message.
     */
    public Set<ServiceToken> getPeerServiceTokens() {
        return Collections.unmodifiableSet(new HashSet<ServiceToken>(peerServiceTokens.values()));
    }
    
    /** MSL context. */
    private MslContext ctx;
    
    /** Message header master token. */
    private MasterToken masterToken;
    /** Header data message ID. */
    private long messageId;
    /** Key exchange data. */
    private KeyExchangeData keyExchangeData;
    /** Message non-replayable. */
    private boolean nonReplayable = false;
    /** Header data renewable. */
    private boolean renewable = false;
    /** Handshake message. */
    private boolean handshake = false;
    /** Message capabilities. */
    private MessageCapabilities capabilities;
    /** Header data key request data. */
    private final Set<KeyRequestData> keyRequestData = new HashSet<KeyRequestData>();
    /** Header data user authentication data. */
    private UserAuthenticationData userAuthData = null;
    /** Header data user ID token. */
    private UserIdToken userIdToken = null;
    /** Header data service tokens keyed off token name. */
    private final Map<String,ServiceToken> serviceTokens = new HashMap<String,ServiceToken>();
    
    /** Header peer data master token. */
    private MasterToken peerMasterToken = null;
    /** Header peer data user ID token. */
    private UserIdToken peerUserIdToken = null;
    /** Header peer data service tokens keyed off token name. */
    private final Map<String,ServiceToken> peerServiceTokens = new HashMap<String,ServiceToken>();
}
