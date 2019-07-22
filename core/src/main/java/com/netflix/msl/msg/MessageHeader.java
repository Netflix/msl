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

import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import com.netflix.msl.MslConstants;
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
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.crypto.SessionCryptoContext;
import com.netflix.msl.entityauth.EntityAuthenticationData;
import com.netflix.msl.entityauth.EntityAuthenticationFactory;
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.io.MslArray;
import com.netflix.msl.io.MslEncoderException;
import com.netflix.msl.io.MslEncoderFactory;
import com.netflix.msl.io.MslEncoderFormat;
import com.netflix.msl.io.MslEncoderUtils;
import com.netflix.msl.io.MslObject;
import com.netflix.msl.keyx.KeyRequestData;
import com.netflix.msl.keyx.KeyResponseData;
import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.tokens.MslUser;
import com.netflix.msl.tokens.ServiceToken;
import com.netflix.msl.tokens.UserIdToken;
import com.netflix.msl.userauth.UserAuthenticationData;
import com.netflix.msl.userauth.UserAuthenticationFactory;
import com.netflix.msl.userauth.UserAuthenticationScheme;
import com.netflix.msl.util.Base64;
import com.netflix.msl.util.MslContext;

/**
 * <p>If a master token exists, the header data chunks will be encrypted and
 * verified using the master token. If no master token exists, the header data
 * will be verified and encrypted based on the entity authentication
 * scheme.</p>
 *
 * <p>If peer tokens exist, the message recipient is expected to use the peer
 * master token to secure its response and send the peer user ID token and peer
 * service tokens back in the header data. The request's tokens should be
 * included as the response's peer tokens.</p>
 *
 * <p>If key response data exists, it applies to the token set the receiving
 * entity uses to identify itself. In a trusted services network the key
 * response data applies to the primary tokens. In a peer-to-peer network the
 * key response data applies to the peer tokens.</p>
 *
 * <p>The header data is represented as
 * {@code
 * headerdata = {
 *   "#mandatory" : [ "messageid", "renewable", "handshake" ],
 *   "timestamp" : "int64(0,2^53^)",
 *   "messageid" : "int64(0,2^53^)",
 *   "nonreplayableid" : "int64(0,2^53^)",
 *   "renewable" : "boolean",
 *   "handshake" : "boolean",
 *   "capabilities" : capabilities,
 *   "keyrequestdata" : [ keyrequestdata ],
 *   "keyresponsedata" : keyresponsedata,
 *   "userauthdata" : userauthdata,
 *   "useridtoken" : useridtoken,
 *   "servicetokens" : [ servicetoken ],
 *   "peermastertoken" : mastertoken,
 *   "peeruseridtoken" : useridtoken,
 *   "peerservicetokens" : [ servicetoken ]
 * }} where:
 * <ul>
 * <li>{@code timestamp} is the sender time when the header is created in seconds since the UNIX epoch</li>
 * <li>{@code messageid} is the message ID</li>
 * <li>{@code nonreplayableid} is the non-replayable ID</li>
 * <li>{@code renewable} indicates if the master token and user ID are renewable</li>
 * <li>{@code handshake} indicates a handshake message</li>
 * <li>{@code capabilities} lists the sender's message capabilities</li>
 * <li>{@code keyrequestdata} is session key request data</li>
 * <li>{@code keyresponsedata} is the session key response data</li>
 * <li>{@code userauthdata} is the user authentication data</li>
 * <li>{@code useridtoken} is the user ID token</li>
 * <li>{@code servicetokens} are the service tokens</li>
 * <li>{@code peermastertoken} is the peer master token</li>
 * <li>{@code peeruseridtoken} is the peer user ID token</li>
 * <li>{@code peerservicetokens} are the peer service tokens</li>
 * </ul></p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class MessageHeader extends Header {
    /** Milliseconds per second. */
    private static final long MILLISECONDS_PER_SECOND = 1000;

    // Message header data.
    /** Key sender. */
    private static final String KEY_SENDER = "sender";
    /** Key timestamp. */
    private static final String KEY_TIMESTAMP = "timestamp";
    /** Key message ID. */
    private static final String KEY_MESSAGE_ID = "messageid";
    /** Key non-replayable ID. */
    private static final String KEY_NON_REPLAYABLE_ID = "nonreplayableid";
    /** Key non-replayable flag. */
    private static final String KEY_NON_REPLAYABLE = "nonreplayable";
    /** Key renewable flag. */
    private static final String KEY_RENEWABLE = "renewable";
    /** Key handshake flag */
    private static final String KEY_HANDSHAKE = "handshake";
    /** Key capabilities. */
    private static final String KEY_CAPABILITIES = "capabilities";
    /** Key key exchange request. */
    private static final String KEY_KEY_REQUEST_DATA = "keyrequestdata";
    /** Key key exchange response. */
    private static final String KEY_KEY_RESPONSE_DATA = "keyresponsedata";
    /** Key user authentication data. */
    private static final String KEY_USER_AUTHENTICATION_DATA = "userauthdata";
    /** Key user ID token. */
    private static final String KEY_USER_ID_TOKEN = "useridtoken";
    /** Key service tokens. */
    private static final String KEY_SERVICE_TOKENS = "servicetokens";

    // Message header peer data.
    /** Key peer master token. */
    private static final String KEY_PEER_MASTER_TOKEN = "peermastertoken";
    /** Key peer user ID token. */
    private static final String KEY_PEER_USER_ID_TOKEN = "peeruseridtoken";
    /** Key peer service tokens. */
    private static final String KEY_PEER_SERVICE_TOKENS = "peerservicetokens";

    /**
     * Container struct for message header data.
     */
    public static class HeaderData {
        /**
         * @param messageId the message ID.
         * @param nonReplayableId the message's non-replayable ID. May be null.
         * @param renewable the message's renewable flag.
         * @param handshake the message's handshake flag.
         * @param capabilities the sender's message capabilities.
         * @param keyRequestData session key request data. May be null or
         *        empty.
         * @param keyResponseData session key response data. May be null.
         * @param userAuthData the user authentication data. May be null if a
         *        user ID token is provided or there is no user authentication
         *        for this message.
         * @param userIdToken the user ID token. May be null if user
         *        authentication data is provided or there is no user
         *        authentication for this message.
         * @param serviceTokens the service tokens. May be null or empty.
         */
        public HeaderData(final long messageId, final Long nonReplayableId,
            final boolean renewable, final boolean handshake,
            final MessageCapabilities capabilities,
            final Set<KeyRequestData> keyRequestData, final KeyResponseData keyResponseData,
            final UserAuthenticationData userAuthData, final UserIdToken userIdToken,
            final Set<ServiceToken> serviceTokens)
        {
            this.messageId = messageId;
            this.nonReplayableId = nonReplayableId;
            this.renewable = renewable;
            this.handshake = handshake;
            this.capabilities = capabilities;
            this.keyRequestData = keyRequestData;
            this.keyResponseData = keyResponseData;
            this.userAuthData = userAuthData;
            this.userIdToken = userIdToken;
            this.serviceTokens = serviceTokens;
        }

        public final long messageId;
        public final Long nonReplayableId;
        public final boolean renewable;
        public final boolean handshake;
        public final MessageCapabilities capabilities;
        public final Set<KeyRequestData> keyRequestData;
        public final KeyResponseData keyResponseData;
        public final UserAuthenticationData userAuthData;
        public final UserIdToken userIdToken;
        public final Set<ServiceToken> serviceTokens;
    }

    /**
     * Container struct for header peer data.
     */
    public static class HeaderPeerData {
        /**
         * @param peerMasterToken peer master token. May be null.
         * @param peerUserIdToken peer user ID token. May be null if there is
         *        no user authentication for the peer.
         * @param peerServiceTokens peer service tokens. May be empty.
         */
        public HeaderPeerData(final MasterToken peerMasterToken, final UserIdToken peerUserIdToken,
            final Set<ServiceToken> peerServiceTokens)
        {
            this.peerMasterToken = peerMasterToken;
            this.peerUserIdToken = peerUserIdToken;
            this.peerServiceTokens = peerServiceTokens;
        }

        public final MasterToken peerMasterToken;
        public final UserIdToken peerUserIdToken;
        public final Set<ServiceToken> peerServiceTokens;
    }

    /**
     * <p>Construct a new message header with the provided message data.</p>
     *
     * <p>Headers are encrypted and signed. If a master token is provided, it
     * will be used for this purpose. Otherwise the crypto context appropriate
     * for the entity authentication scheme will be used. N.B. Either the
     * entity authentication data or the master token must be provided.</p>
     *
     * <p>Peer tokens are only processed if operating in peer-to-peer mode.</p>
     *
     * @param ctx MSL context.
     * @param entityAuthData the entity authentication data. May be null if a
     *        master token is provided.
     * @param masterToken the master token. May be null if entity
     *        authentication data is provided.
     * @param headerData message header data container.
     * @param peerData message header peer data container.
     * @throws MslEncodingException if there is an error encoding the data.
     * @throws MslCryptoException if there is an error encrypting or signing
     *         the message.
     * @throws MslMasterTokenException if the header master token is not
     *         trusted and needs to be to accept this message header.
     * @throws MslEntityAuthException if there is an error with the entity
     *         authentication data.
     */
    public MessageHeader(final MslContext ctx, final EntityAuthenticationData entityAuthData, final MasterToken masterToken, final HeaderData headerData, final HeaderPeerData peerData) throws MslCryptoException, MslEncodingException, MslMasterTokenException, MslEntityAuthException {
        // Message ID must be within range.
        if (headerData.messageId < 0 || headerData.messageId > MslConstants.MAX_LONG_VALUE)
            throw new MslInternalException("Message ID " + headerData.messageId + " is out of range.");

        // Message entity must be provided.
        if (entityAuthData == null && masterToken == null)
            throw new MslInternalException("Message entity authentication data or master token must be provided.");

        // Do not allow user authentication data to be included if the message
        // will not be encrypted.
        final boolean encrypted;
        if (masterToken != null) {
            encrypted = true;
        } else {
            final EntityAuthenticationScheme scheme = entityAuthData.getScheme();
            encrypted = scheme.encrypts();
        }
        if (!encrypted && headerData.userAuthData != null)
            throw new MslInternalException("User authentication data cannot be included if the message is not encrypted.");
        
        // Older MSL stacks expect the sender if a master token is being used.
        //
        // If the local entity does not know its entity identity, then use the
        // empty string. This will work except for the case where the old MSL
        // stack is receiving a message for which it is also the issuer of the
        // master token. That scenario will continue to fail.
        final String sender;
        if (masterToken != null) {
            final String localIdentity = ctx.getEntityAuthenticationData(null).getIdentity();
            sender = (localIdentity != null) ? localIdentity : "";
        } else {
            sender = null;
        }

        this.entityAuthData = (masterToken == null) ? entityAuthData : null;
        this.masterToken = masterToken;
        this.nonReplayableId = headerData.nonReplayableId;
        this.renewable = headerData.renewable;
        this.handshake = headerData.handshake;
        this.capabilities = headerData.capabilities;
        this.timestamp = ctx.getTime() / MILLISECONDS_PER_SECOND;
        this.messageId = headerData.messageId;
        this.keyRequestData = Collections.unmodifiableSet((headerData.keyRequestData != null) ? headerData.keyRequestData : new HashSet<KeyRequestData>());
        this.keyResponseData = headerData.keyResponseData;
        this.userAuthData = headerData.userAuthData;
        this.userIdToken = headerData.userIdToken;
        this.serviceTokens = Collections.unmodifiableSet((headerData.serviceTokens != null) ? headerData.serviceTokens : new HashSet<ServiceToken>());
        if (ctx.isPeerToPeer()) {
            this.peerMasterToken = peerData.peerMasterToken;
            this.peerUserIdToken = peerData.peerUserIdToken;
            this.peerServiceTokens = Collections.unmodifiableSet((peerData.peerServiceTokens != null) ? peerData.peerServiceTokens : new HashSet<ServiceToken>());
        } else {
            this.peerMasterToken = null;
            this.peerUserIdToken = null;
            this.peerServiceTokens = Collections.emptySet();
        }

        // Grab token verification master tokens.
        final MasterToken tokenVerificationMasterToken, peerTokenVerificationMasterToken;
        if (this.keyResponseData != null) {
            // The key response data is used for token verification in a
            // trusted services network and peer token verification in a peer-
            // to-peer network.
            if (!ctx.isPeerToPeer()) {
                tokenVerificationMasterToken = this.keyResponseData.getMasterToken();
                peerTokenVerificationMasterToken = this.peerMasterToken;
            } else {
                tokenVerificationMasterToken = this.masterToken;
                peerTokenVerificationMasterToken = this.keyResponseData.getMasterToken();
            }
        } else {
            tokenVerificationMasterToken = this.masterToken;
            peerTokenVerificationMasterToken = this.peerMasterToken;
        }

        // Check token combinations.
        if (this.userIdToken != null && (tokenVerificationMasterToken == null || !this.userIdToken.isBoundTo(tokenVerificationMasterToken)))
            throw new MslInternalException("User ID token must be bound to a master token.");
        if (this.peerUserIdToken != null && (peerTokenVerificationMasterToken == null || !this.peerUserIdToken.isBoundTo(peerTokenVerificationMasterToken)))
            throw new MslInternalException("Peer user ID token must be bound to a peer master token.");

        // Grab the user.
        if (this.userIdToken != null)
            this.user = this.userIdToken.getUser();
        else
            this.user = null;

        // All service tokens must be unbound or if bound, bound to the
        // provided tokens.
        for (final ServiceToken serviceToken : this.serviceTokens) {
            if (serviceToken.isMasterTokenBound() && (tokenVerificationMasterToken == null || !serviceToken.isBoundTo(tokenVerificationMasterToken)))
                throw new MslInternalException("Master token bound service tokens must be bound to the provided master token.");
            if (serviceToken.isUserIdTokenBound() && (this.userIdToken == null || !serviceToken.isBoundTo(this.userIdToken)))
                throw new MslInternalException("User ID token bound service tokens must be bound to the provided user ID token.");
        }
        for (final ServiceToken peerServiceToken : this.peerServiceTokens) {
            if (peerServiceToken.isMasterTokenBound() && (peerTokenVerificationMasterToken == null || !peerServiceToken.isBoundTo(peerTokenVerificationMasterToken)))
                throw new MslInternalException("Master token bound peer service tokens must be bound to the provided peer master token.");
            if (peerServiceToken.isUserIdTokenBound() && (this.peerUserIdToken == null || !peerServiceToken.isBoundTo(this.peerUserIdToken)))
                throw new MslInternalException("User ID token bound peer service tokens must be bound to the provided peer user ID token.");
        }

        // Construct the header data.
        try {
            final MslEncoderFactory encoder = ctx.getMslEncoderFactory();
            final Set<MslEncoderFormat> formats = (capabilities != null) ? capabilities.getEncoderFormats() : null;
            final MslEncoderFormat format = encoder.getPreferredFormat(formats);
            headerdata = encoder.createObject();
            if (sender != null) headerdata.put(KEY_SENDER, sender);
            headerdata.put(KEY_TIMESTAMP, this.timestamp);
            headerdata.put(KEY_MESSAGE_ID, this.messageId);
            headerdata.put(KEY_NON_REPLAYABLE, this.nonReplayableId != null);
            if (this.nonReplayableId != null) headerdata.put(KEY_NON_REPLAYABLE_ID, this.nonReplayableId);
            headerdata.put(KEY_RENEWABLE, this.renewable);
            headerdata.put(KEY_HANDSHAKE, this.handshake);
            if (this.capabilities != null) headerdata.put(KEY_CAPABILITIES, this.capabilities);
            if (this.keyRequestData.size() > 0) headerdata.put(KEY_KEY_REQUEST_DATA, MslEncoderUtils.createArray(ctx, format, this.keyRequestData));
            if (this.keyResponseData != null) headerdata.put(KEY_KEY_RESPONSE_DATA, this.keyResponseData);
            if (this.userAuthData != null) headerdata.put(KEY_USER_AUTHENTICATION_DATA, this.userAuthData);
            if (this.userIdToken != null) headerdata.put(KEY_USER_ID_TOKEN, this.userIdToken);
            if (this.serviceTokens.size() > 0) headerdata.put(KEY_SERVICE_TOKENS, MslEncoderUtils.createArray(ctx, format, this.serviceTokens));
            if (this.peerMasterToken != null) headerdata.put(KEY_PEER_MASTER_TOKEN, this.peerMasterToken);
            if (this.peerUserIdToken != null) headerdata.put(KEY_PEER_USER_ID_TOKEN, this.peerUserIdToken);
            if (this.peerServiceTokens.size() > 0) headerdata.put(KEY_PEER_SERVICE_TOKENS, MslEncoderUtils.createArray(ctx, format, this.peerServiceTokens));
        } catch (final MslEncoderException e) {
            throw new MslEncodingException(MslError.MSL_ENCODE_ERROR, "headerdata", e)
                .setMasterToken(this.masterToken)
                .setEntityAuthenticationData(this.entityAuthData)
                .setUserIdToken(this.userIdToken)
                .setUserAuthenticationData(this.userAuthData)
                .setMessageId(this.messageId);
        }

        // Create the correct crypto context.
        if (this.masterToken != null) {
            // Use a stored master token crypto context if we have one.
            final ICryptoContext cachedCryptoContext = ctx.getMslStore().getCryptoContext(this.masterToken);

            // If there was no stored crypto context try making one from
            // the master token. We can only do this if we can open up the
            // master token.
            if (cachedCryptoContext == null) {
                if (!this.masterToken.isVerified() || !this.masterToken.isDecrypted())
                    throw new MslMasterTokenException(MslError.MASTERTOKEN_UNTRUSTED, this.masterToken).setUserIdToken(this.userIdToken).setUserAuthenticationData(this.userAuthData).setMessageId(this.messageId);
                this.messageCryptoContext = new SessionCryptoContext(ctx, this.masterToken);
            } else {
                this.messageCryptoContext = cachedCryptoContext;
            }
        } else {
            try {
                final EntityAuthenticationScheme scheme = this.entityAuthData.getScheme();
                final EntityAuthenticationFactory factory = ctx.getEntityAuthenticationFactory(scheme);
                if (factory == null)
                    throw new MslEntityAuthException(MslError.ENTITYAUTH_FACTORY_NOT_FOUND, scheme.name());
                this.messageCryptoContext = factory.getCryptoContext(ctx, this.entityAuthData);
            } catch (final MslCryptoException e) {
                e.setEntityAuthenticationData(this.entityAuthData);
                e.setUserIdToken(this.userIdToken);
                e.setUserAuthenticationData(this.userAuthData);
                e.setMessageId(this.messageId);
                throw e;
            } catch (final MslEntityAuthException e) {
                e.setEntityAuthenticationData(this.entityAuthData);
                e.setUserIdToken(this.userIdToken);
                e.setUserAuthenticationData(this.userAuthData);
                e.setMessageId(this.messageId);
                throw e;
            }
        }
    }

    /**
     * <p>Construct a new message from the provided JSON object.</p>
     *
     * <p>Headers are encrypted and signed. If a master token is found, it will
     * be used for this purpose. Otherwise the crypto context appropriate for
     * the entity authentication scheme will be used. Either the master token
     * or entity authentication data must be found.</p>
     *
     * <p>If user authentication data is included user authentication will be
     * performed. If a user ID token is included then its user information is
     * considered to be trusted.</p>
     *
     * <p>Service tokens will be decrypted and verified with the provided crypto
     * contexts identified by token name. A default crypto context may be
     * provided by using the empty string as the token name; if a token name is
     * not explicitly mapped onto a crypto context, the default crypto context
     * will be used.</p>
     *
     * @param ctx MSL context.
     * @param headerdataBytes encoded header data.
     * @param entityAuthData the entity authentication data. May be null if a
     *        master token is provided.
     * @param masterToken the master token. May be null if entity
     *        authentication data is provided.
     * @param signature the header signature.
     * @param cryptoContexts the map of service token names onto crypto
     *        contexts used to decrypt and verify service tokens.
     * @throws MslEncodingException if there is an error parsing the JSON.
     * @throws MslCryptoException if there is an error decrypting or verifying
     *         the header or creating the key exchange crypto context.
     * @throws MslEntityAuthException if unable to create the entity
     *         authentication data or there is an error with the entity
     *         authentication data.
     * @throws MslKeyExchangeException if unable to create the key request data
     *         or key response data.
     * @throws MslUserAuthException if unable to create the user authentication
     *         data or authenticate the user.
     * @throws MslMasterTokenException if the header master token is not
     *         trusted and needs to be to accept this message header.
     * @throws MslMessageException if the message does not contain an entity
     *         authentication data or a master token, the header data is
     *         missing or invalid, or the message ID is negative, or the
     *         message is not encrypted and contains user authentication data.
     * @throws MslException if a token is improperly bound to another token.
     */
    protected MessageHeader(final MslContext ctx, final byte[] headerdataBytes, final EntityAuthenticationData entityAuthData, final MasterToken masterToken, final byte[] signature, final Map<String,ICryptoContext> cryptoContexts) throws MslEncodingException, MslCryptoException, MslKeyExchangeException, MslUserAuthException, MslMasterTokenException, MslMessageException, MslEntityAuthException, MslException {
        final MslEncoderFactory encoder = ctx.getMslEncoderFactory();

        final byte[] plaintext;
        try {
            this.entityAuthData = (masterToken == null) ? entityAuthData : null;
            this.masterToken = masterToken;
            if (entityAuthData == null && masterToken == null)
                throw new MslMessageException(MslError.MESSAGE_ENTITY_NOT_FOUND);

            // Create the correct crypto context.
            if (masterToken != null) {
                // Use a stored master token crypto context if we have one.
                final ICryptoContext cachedCryptoContext = ctx.getMslStore().getCryptoContext(masterToken);

                // If there was no stored crypto context try making one from
                // the master token. We can only do this if we can open up the
                // master token.
                if (cachedCryptoContext == null) {
                    if (!masterToken.isVerified() || !masterToken.isDecrypted())
                        throw new MslMasterTokenException(MslError.MASTERTOKEN_UNTRUSTED, masterToken);
                    this.messageCryptoContext = new SessionCryptoContext(ctx, masterToken);
                } else {
                    this.messageCryptoContext = cachedCryptoContext;
                }
            } else {
                try {
                    final EntityAuthenticationScheme scheme = entityAuthData.getScheme();
                    final EntityAuthenticationFactory factory = ctx.getEntityAuthenticationFactory(scheme);
                    if (factory == null)
                        throw new MslEntityAuthException(MslError.ENTITYAUTH_FACTORY_NOT_FOUND, scheme.name());
                    this.messageCryptoContext = factory.getCryptoContext(ctx, entityAuthData);
                } catch (final MslCryptoException e) {
                    e.setEntityAuthenticationData(entityAuthData);
                    throw e;
                } catch (final MslEntityAuthException e) {
                    e.setEntityAuthenticationData(entityAuthData);
                    throw e;
                }
            }

            // Verify and decrypt the header data.
            //
            // Throw different errors depending on whether or not a master
            // token was used.
            if (!this.messageCryptoContext.verify(headerdataBytes, signature, encoder)) {
                if (masterToken != null)
                    throw new MslCryptoException(MslError.MESSAGE_MASTERTOKENBASED_VERIFICATION_FAILED);
                else
                    throw new MslCryptoException(MslError.MESSAGE_ENTITYDATABASED_VERIFICATION_FAILED);
            }
            plaintext = this.messageCryptoContext.decrypt(headerdataBytes, encoder);
        } catch (final MslCryptoException e) {
            e.setMasterToken(masterToken);
            e.setEntityAuthenticationData(entityAuthData);
            throw e;
        } catch (final MslEntityAuthException e) {
            e.setMasterToken(masterToken);
            e.setEntityAuthenticationData(entityAuthData);
            throw e;
        }

        try {
            headerdata = encoder.parseObject(plaintext);

            // Pull the message ID first because any error responses need to
            // use it.
            this.messageId = headerdata.getLong(KEY_MESSAGE_ID);
            if (this.messageId < 0 || this.messageId > MslConstants.MAX_LONG_VALUE)
                throw new MslMessageException(MslError.MESSAGE_ID_OUT_OF_RANGE, "headerdata " + headerdata).setMasterToken(masterToken).setEntityAuthenticationData(entityAuthData);
        } catch (final MslEncoderException e) {
            throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "headerdata " + Base64.encode(plaintext), e).setMasterToken(masterToken).setEntityAuthenticationData(entityAuthData);
        }

        try {
            this.timestamp = (headerdata.has(KEY_TIMESTAMP)) ? headerdata.getLong(KEY_TIMESTAMP) : null;

            // Pull key response data.
            final MasterToken tokenVerificationMasterToken;
            if (headerdata.has(KEY_KEY_RESPONSE_DATA)) {
                this.keyResponseData = KeyResponseData.create(ctx, headerdata.getMslObject(KEY_KEY_RESPONSE_DATA, encoder));

                // The key response data master token is used for token
                // verification in a trusted services network. Otherwise it
                // will be used for peer token verification, which is handled
                // below.
                tokenVerificationMasterToken = (!ctx.isPeerToPeer())
                    ? this.keyResponseData.getMasterToken()
                    : masterToken;
            } else {
                this.keyResponseData = null;
                tokenVerificationMasterToken = masterToken;
            }

            // User ID tokens are always authenticated by a master token.
            this.userIdToken = (headerdata.has(KEY_USER_ID_TOKEN))
                ? new UserIdToken(ctx, headerdata.getMslObject(KEY_USER_ID_TOKEN, encoder), tokenVerificationMasterToken)
                : null;
            // Pull user authentication data.
            this.userAuthData = (headerdata.has(KEY_USER_AUTHENTICATION_DATA))
                ? UserAuthenticationData.create(ctx, tokenVerificationMasterToken, headerdata.getMslObject(KEY_USER_AUTHENTICATION_DATA, encoder))
                : null;

            // Identify the user if any.
            if (this.userAuthData != null) {
                // Reject unencrypted messages containing user authentication data.
                final boolean encrypted = (masterToken != null) ? true : entityAuthData.getScheme().encrypts();
                if (!encrypted)
                    throw new MslMessageException(MslError.UNENCRYPTED_MESSAGE_WITH_USERAUTHDATA).setUserIdToken(userIdToken).setUserAuthenticationData(userAuthData);

                // Verify the user authentication data.
                final UserAuthenticationScheme scheme = this.userAuthData.getScheme();
                final UserAuthenticationFactory factory = ctx.getUserAuthenticationFactory(scheme);
                if (factory == null)
                    throw new MslUserAuthException(MslError.USERAUTH_FACTORY_NOT_FOUND, scheme.name()).setUserIdToken(userIdToken).setUserAuthenticationData(userAuthData);
                final String identity = (this.masterToken != null) ? this.masterToken.getIdentity() : this.entityAuthData.getIdentity();
                this.user = factory.authenticate(ctx, identity, this.userAuthData, this.userIdToken);
            } else if (this.userIdToken != null) {
                this.user = this.userIdToken.getUser();
            } else {
                this.user = null;
            }

            // Service tokens are authenticated by the master token if it
            // exists or by the application crypto context.
            final Set<ServiceToken> serviceTokens = new HashSet<ServiceToken>();
            if (headerdata.has(KEY_SERVICE_TOKENS)) {
                final MslArray tokens = headerdata.getMslArray(KEY_SERVICE_TOKENS);
                for (int i = 0; i < tokens.size(); ++i) {
                    try {
                        serviceTokens.add(new ServiceToken(ctx, tokens.getMslObject(i, encoder), tokenVerificationMasterToken, this.userIdToken, cryptoContexts));
                    } catch (final MslException e) {
                        e.setMasterToken(tokenVerificationMasterToken).setUserIdToken(this.userIdToken).setUserAuthenticationData(userAuthData);
                        throw e;
                    }
                }
            }
            this.serviceTokens = Collections.unmodifiableSet(serviceTokens);
        } catch (final MslEncoderException e) {
            throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "headerdata " + headerdata, e).setMasterToken(masterToken).setEntityAuthenticationData(entityAuthData).setMessageId(this.messageId);
        } catch (final MslException e) {
            e.setMasterToken(masterToken);
            e.setEntityAuthenticationData(entityAuthData);
            e.setMessageId(this.messageId);
            throw e;
        }

        try {
            this.nonReplayableId = (headerdata.has(KEY_NON_REPLAYABLE_ID)) ? headerdata.getLong(KEY_NON_REPLAYABLE_ID) : null;
            this.renewable = headerdata.getBoolean(KEY_RENEWABLE);
            // FIXME: Make handshake required once all MSL stacks are updated.
            this.handshake = (headerdata.has(KEY_HANDSHAKE)) ? headerdata.getBoolean(KEY_HANDSHAKE) : false;

            // Verify values.
            if (nonReplayableId != null && (nonReplayableId < 0 || nonReplayableId > MslConstants.MAX_LONG_VALUE))
                throw new MslMessageException(MslError.NONREPLAYABLE_ID_OUT_OF_RANGE, "headerdata " + headerdata);

            // Pull message capabilities.
            if (headerdata.has(KEY_CAPABILITIES)) {
                final MslObject capabilitiesMo = headerdata.getMslObject(KEY_CAPABILITIES, encoder);
                this.capabilities = new MessageCapabilities(capabilitiesMo);
            } else {
                this.capabilities = null;
            }

            // Pull key request data containers.
            final Set<KeyRequestData> keyRequestData = new HashSet<KeyRequestData>();
            if (headerdata.has(KEY_KEY_REQUEST_DATA)) {
                final MslArray keyRequests = headerdata.getMslArray(KEY_KEY_REQUEST_DATA);
                for (int i = 0; i < keyRequests.size(); ++i) {
                    keyRequestData.add(KeyRequestData.create(ctx, keyRequests.getMslObject(i, encoder)));
                }
            }
            this.keyRequestData = Collections.unmodifiableSet(keyRequestData);

            // Only process peer-to-peer tokens if in peer-to-peer mode.
            if (ctx.isPeerToPeer()) {
                // Pull peer master token.
                this.peerMasterToken = (headerdata.has(KEY_PEER_MASTER_TOKEN))
                    ? new MasterToken(ctx, headerdata.getMslObject(KEY_PEER_MASTER_TOKEN, encoder))
                    : null;
                // The key response data master token is used for peer token
                // verification if in peer-to-peer mode.
                final MasterToken peerVerificationMasterToken;
                if (this.keyResponseData != null)
                    peerVerificationMasterToken = this.keyResponseData.getMasterToken();
                else
                    peerVerificationMasterToken = this.peerMasterToken;

                // Pull peer user ID token. User ID tokens are always
                // authenticated by a master token.
                try {
                    this.peerUserIdToken = (headerdata.has(KEY_PEER_USER_ID_TOKEN))
                        ? new UserIdToken(ctx, headerdata.getMslObject(KEY_PEER_USER_ID_TOKEN, encoder), peerVerificationMasterToken)
                        : null;
                } catch (final MslException e) {
                    e.setMasterToken(peerVerificationMasterToken);
                    throw e;
                }

                // Peer service tokens are authenticated by the peer master
                // token if it exists or by the application crypto context.
                final Set<ServiceToken> peerServiceTokens = new HashSet<ServiceToken>();
                if (headerdata.has(KEY_PEER_SERVICE_TOKENS)) {
                    final MslArray tokens = headerdata.getMslArray(KEY_PEER_SERVICE_TOKENS);
                    for (int i = 0; i < tokens.size(); ++i) {
                        try {
                            peerServiceTokens.add(new ServiceToken(ctx, tokens.getMslObject(i, encoder), peerVerificationMasterToken, this.peerUserIdToken, cryptoContexts));
                        } catch (final MslException e) {
                            e.setMasterToken(peerVerificationMasterToken).setUserIdToken(this.peerUserIdToken);
                            throw e;
                        }
                    }
                }
                this.peerServiceTokens = Collections.unmodifiableSet(peerServiceTokens);
            } else {
                this.peerMasterToken = null;
                this.peerUserIdToken = null;
                this.peerServiceTokens = Collections.emptySet();
            }
        } catch (final MslEncoderException e) {
            throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "headerdata " + headerdata.toString(), e)
                .setMasterToken(masterToken)
                .setEntityAuthenticationData(entityAuthData)
                .setUserIdToken(this.userIdToken)
                .setUserAuthenticationData(this.userAuthData)
                .setMessageId(this.messageId);
        } catch (final MslException e) {
            e.setMasterToken(masterToken);
            e.setEntityAuthenticationData(entityAuthData);
            e.setUserIdToken(this.userIdToken);
            e.setUserAuthenticationData(this.userAuthData);
            e.setMessageId(this.messageId);
            throw e;
        }
    }

    /**
     * @return true if the message header crypto context provides encryption.
     * @see #getCryptoContext()
     */
    public boolean isEncrypting() {
        return masterToken != null || entityAuthData.getScheme().encrypts();
    }

    /**
     * Returns the crypto context that was used to process the header data.
     * This crypto context should also be used to process the payload data if
     * no key response data is included in the message.
     *
     * @return the header data crypto context.
     * @see #isEncrypting()
     */
    public ICryptoContext getCryptoContext() {
        return messageCryptoContext;
    }

    /**
     * Returns the user if the user has been authenticated or a user ID token
     * was provided.
     *
     * @return the user. May be null.
     */
    public MslUser getUser() {
        return user;
    }

    /**
     * Returns the entity authentication data. May be null if the entity has
     * already been authenticated and is using a master token instead.
     *
     * @return the entity authentication data.
     */
    public EntityAuthenticationData getEntityAuthenticationData() {
        return entityAuthData;
    }

    /**
     * Returns the primary master token identifying the entity and containing
     * the session keys. May be null if the entity has not been authenticated.
     *
     * @return the master token. May be null.
     */
    public MasterToken getMasterToken() {
        return masterToken;
    }

    /**
     * @return the timestamp. May be null.
     */
    public Date getTimestamp() {
        return (timestamp != null) ? new Date(timestamp * MILLISECONDS_PER_SECOND) : null;
    }

    /**
     * @return the message ID.
     */
    public long getMessageId() {
        return messageId;
    }

    /**
     * @return the non-replayable ID. May be null.
     */
    public Long getNonReplayableId() {
        return nonReplayableId;
    }

    /**
     * @return true if the message renewable flag is set.
     */
    public boolean isRenewable() {
        return renewable;
    }

    /**
     * @return true if the message handshake flag is set.
     */
    public boolean isHandshake() {
        return handshake;
    }

    /**
     * @return the message capabilities. May be null.
     */
    public MessageCapabilities getMessageCapabilities() {
        return capabilities;
    }

    /**
     * @return key request data. May be empty.
     */
    public Set<KeyRequestData> getKeyRequestData() {
        return keyRequestData;
    }

    /**
     * @return key response data. May be null.
     */
    public KeyResponseData getKeyResponseData() {
        return keyResponseData;
    }

    /**
     * Returns the user authentication data. May be null if the user has
     * already been authenticated and is using a user ID token or if there is
     * no user authentication requested.
     *
     * @return the user authentication data. May be null.
     */
    public UserAuthenticationData getUserAuthenticationData() {
        return userAuthData;
    }

    /**
     * Returns the primary user ID token identifying the user. May be null if
     * the user has not been authenticated.
     *
     * @return the user ID token. May be null.
     */
    public UserIdToken getUserIdToken() {
        return userIdToken;
    }

    /**
     * Returns the primary service tokens included in this message.
     *
     * The returned list is immutable.
     *
     * @return the service tokens. May be empty if no there are no service
     *         tokens.
     */
    public Set<ServiceToken> getServiceTokens() {
        return serviceTokens;
    }

    /**
     * Returns the master token that should be used by an entity responding to
     * this message. Will be null if the responding entity should use its own
     * entity authentication data or the primary master token.
     *
     * @return the peer master token. May be null.
     */
    public MasterToken getPeerMasterToken() {
        return peerMasterToken;
    }

    /**
     * Returns the user ID token that must be used by an entity responding to
     * this message if an peer master token is provided. May be null if peer
     * user authentication has not occurred. Will be null if there is no peer
     * master token.
     *
     * @return the peer user ID token. May be null.
     */
    public UserIdToken getPeerUserIdToken() {
        return peerUserIdToken;
    }

    /**
     * <p>Returns the service tokens that must be used by an entity responding
     * to this message. May be null if the responding entity should use the
     * primary service tokens.</p>
     *
     * <p>The returned list is immutable.</p>
     *
     * @return the peer service tokens. May be empty if no there are no peer
     *         service tokens.
     */
    public Set<ServiceToken> getPeerServiceTokens() {
        return peerServiceTokens;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.io.MslEncodable#toMslEncoding(com.netflix.msl.io.MslEncoderFactory, com.netflix.msl.io.MslEncoderFormat)
     */
    @Override
    public byte[] toMslEncoding(final MslEncoderFactory encoder, final MslEncoderFormat format) throws MslEncoderException {
        // Return any cached encoding.
        if (encodings.containsKey(format))
            return encodings.get(format);

        // Encrypt and sign the header data.
        final byte[] plaintext = encoder.encodeObject(headerdata, format);
        final byte[] ciphertext;
        try {
            ciphertext = this.messageCryptoContext.encrypt(plaintext, encoder, format);
        } catch (final MslCryptoException e) {
            throw new MslEncoderException("Error encrypting the header data.", e);
        }
        final byte[] signature;
        try {
            signature = this.messageCryptoContext.sign(ciphertext, encoder, format);
        } catch (final MslCryptoException e) {
            throw new MslEncoderException("Error signging the header data.", e);
        }

        // Create the encoding.
        final MslObject header = encoder.createObject();
        if (masterToken != null)
            header.put(Header.KEY_MASTER_TOKEN, masterToken);
        else
            header.put(Header.KEY_ENTITY_AUTHENTICATION_DATA, entityAuthData);
        header.put(Header.KEY_HEADERDATA, ciphertext);
        header.put(Header.KEY_SIGNATURE, signature);
        final byte[] encoding = encoder.encodeObject(header, format);

        // Cache and return the encoding.
        encodings.put(format, encoding);
        return encoding;
    }

    /* (non-Javadoc)
     * @see java.lang.Object#equals(java.lang.Object)
     */
    @Override
    public boolean equals(final Object obj) {
        if (this == obj) return true;
        if (!(obj instanceof MessageHeader)) return false;
        final MessageHeader that = (MessageHeader) obj;
        return (masterToken != null && masterToken.equals(that.masterToken) ||
            entityAuthData != null && entityAuthData.equals(that.entityAuthData)) &&
            (timestamp != null && timestamp.equals(that.timestamp) ||
             timestamp == null && that.timestamp == null) &&
            messageId == that.messageId &&
            (nonReplayableId != null && nonReplayableId.equals(that.nonReplayableId) ||
             nonReplayableId == null && that.nonReplayableId == null) &&
            renewable == that.renewable &&
            handshake == that.handshake &&
            (capabilities != null && capabilities.equals(that.capabilities) ||
             capabilities == that.capabilities) &&
            keyRequestData.equals(that.keyRequestData) &&
            (keyResponseData != null && keyResponseData.equals(that.keyResponseData) ||
             keyResponseData == that.keyResponseData) &&
            (userAuthData != null && userAuthData.equals(that.userAuthData) ||
             userAuthData == that.userAuthData) &&
            (userIdToken != null && userIdToken.equals(that.userIdToken) ||
             userIdToken == that.userIdToken) &&
            serviceTokens.equals(that.serviceTokens) &&
            (peerMasterToken != null && peerMasterToken.equals(that.peerMasterToken) ||
             peerMasterToken == that.peerMasterToken) &&
            (peerUserIdToken != null && peerUserIdToken.equals(that.peerUserIdToken) ||
             peerUserIdToken == that.peerUserIdToken) &&
            peerServiceTokens.equals(that.peerServiceTokens);
    }

    /* (non-Javadoc)
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode() {
        return ((masterToken != null) ? masterToken.hashCode() : entityAuthData.hashCode()) ^
            ((timestamp != null) ? timestamp.hashCode() : 0) ^
            Long.valueOf(messageId).hashCode() ^
            ((nonReplayableId != null) ? nonReplayableId.hashCode() : 0) ^
            Boolean.valueOf(renewable).hashCode() ^
            Boolean.valueOf(handshake).hashCode() ^
            ((capabilities != null) ? capabilities.hashCode() : 0) ^
            keyRequestData.hashCode() ^
            ((keyResponseData != null) ? keyResponseData.hashCode() : 0) ^
            ((userAuthData != null) ? userAuthData.hashCode() : 0) ^
            ((userIdToken != null) ? userIdToken.hashCode() : 0) ^
            serviceTokens.hashCode() ^
            ((peerMasterToken != null) ? peerMasterToken.hashCode() : 0) ^
            ((peerUserIdToken != null) ? peerUserIdToken.hashCode() : 0) ^
            peerServiceTokens.hashCode();
    }

    /** Entity authentication data. */
    protected final EntityAuthenticationData entityAuthData;
    /** Master token. */
    protected final MasterToken masterToken;
    /** Header data. */
    protected final MslObject headerdata;

    /** Timestamp in seconds since the epoch. */
    private final Long timestamp;
    /** Message ID. */
    private final long messageId;
    /** Non-replayable ID. */
    private final Long nonReplayableId;
    /** Renewable. */
    private final boolean renewable;
    /** Handshake message. */
    private final boolean handshake;
    /** Message capabilities. */
    private final MessageCapabilities capabilities;
    /** Key request data. */
    private final Set<KeyRequestData> keyRequestData;
    /** Key response data. */
    private final KeyResponseData keyResponseData;
    /** User authentication data. */
    private final UserAuthenticationData userAuthData;
    /** User ID token. */
    private final UserIdToken userIdToken;
    /** Service tokens (immutable). */
    private final Set<ServiceToken> serviceTokens;

    /** Peer master token. */
    private final MasterToken peerMasterToken;
    /** Peer user ID token. */
    private final UserIdToken peerUserIdToken;
    /** Peer service tokens (immutable). */
    private final Set<ServiceToken> peerServiceTokens;

    /** User (if authenticated). */
    private final MslUser user;

    /** Message crypto context. */
    protected final ICryptoContext messageCryptoContext;

    /** Cached encodings. */
    protected final Map<MslEncoderFormat,byte[]> encodings = new HashMap<MslEncoderFormat,byte[]>();
}
