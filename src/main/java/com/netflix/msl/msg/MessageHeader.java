/**
 * Copyright (c) 2012-2014 Netflix, Inc.  All rights reserved.
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
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.xml.bind.DatatypeConverter;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

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
import com.netflix.msl.keyx.KeyRequestData;
import com.netflix.msl.keyx.KeyResponseData;
import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.tokens.MslUser;
import com.netflix.msl.tokens.ServiceToken;
import com.netflix.msl.tokens.UserIdToken;
import com.netflix.msl.userauth.UserAuthenticationData;
import com.netflix.msl.userauth.UserAuthenticationFactory;
import com.netflix.msl.userauth.UserAuthenticationScheme;
import com.netflix.msl.util.JsonUtils;
import com.netflix.msl.util.MslContext;

/**
 * <p>If a master token exists, the header data chunks will be encrypted and
 * verified using the master token. The sender will also be included. If no
 * master token exists, the header data will be verified and encrypted based on
 * the entity authentication scheme.</p>
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
 *   "sender" : "string",
 *   "recipient" : "string",
 *   "messageid" : "int64(0,2^53^)",
 *   "nonreplayableid" : "int64(0,2^53^)",
 *   "nonreplayable" : "boolean",
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
 * <li>{@code sender} is the sender entity identity</li>
 * <li>{@code recipient} is the intended recipient's entity identity</li>
 * <li>{@code messageid} is the message ID</li>
 * <li>{@code nonreplayableid} is the non-replayable ID</li>
 * <li>{@code nonreplayable} indicates if the message is nonreplayable</li>
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
    // Message header data.
    /** JSON key sender. */
    private static final String KEY_SENDER = "sender";
    /** JSON key recipient. */
    private static final String KEY_RECIPIENT = "recipient";
    /** JSON key message ID. */
    private static final String KEY_MESSAGE_ID = "messageid";
    /** JSON key non-replayable ID. */
    private static final String KEY_NON_REPLAYABLE_ID = "nonreplayableid";
    /** JSON key non-replayable flag. */
    private static final String KEY_NON_REPLAYABLE = "nonreplayable";
    /** JSON key renewable flag. */
    private static final String KEY_RENEWABLE = "renewable";
    /** JSON key handshake flag */
    private static final String KEY_HANDSHAKE = "handshake";
    /** JSON key capabilities. */
    private static final String KEY_CAPABILITIES = "capabilities";
    /** JSON key key exchange request. */
    private static final String KEY_KEY_REQUEST_DATA = "keyrequestdata";
    /** JSON key key exchange response. */
    private static final String KEY_KEY_RESPONSE_DATA = "keyresponsedata";
    /** JSON key user authentication data. */
    private static final String KEY_USER_AUTHENTICATION_DATA = "userauthdata";
    /** JSON key user ID token. */
    private static final String KEY_USER_ID_TOKEN = "useridtoken";
    /** JSON key service tokens. */
    private static final String KEY_SERVICE_TOKENS = "servicetokens";
    
    // Message header peer data.
    /** JSON key peer master token. */
    private static final String KEY_PEER_MASTER_TOKEN = "peermastertoken";
    /** JSON key peer user ID token. */
    private static final String KEY_PEER_USER_ID_TOKEN = "peeruseridtoken";
    /** JSON key peer service tokens. */
    private static final String KEY_PEER_SERVICE_TOKENS = "peerservicetokens";
    
    /**
     * Container struct for message header data.
     */
    public static class HeaderData {
        /**
         * @param recipient the message recipient's entity identity. May be
         *        null.
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
        public HeaderData(final String recipient, final long messageId, final Long nonReplayableId,
            final boolean renewable, final boolean handshake,
            final MessageCapabilities capabilities,
            final Set<KeyRequestData> keyRequestData, final KeyResponseData keyResponseData,
            final UserAuthenticationData userAuthData, final UserIdToken userIdToken,
            final Set<ServiceToken> serviceTokens)
        {
            this.recipient = recipient;
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
        
        public final String recipient;
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
     * @throws MslEncodingException if there is an error encoding the JSON
     *         data.
     * @throws MslCryptoException if there is an error encrypting or signing
     *         the message.
     * @throws MslMasterTokenException if the header master token is not
     *         trusted and needs to be to accept this message header.
     * @throws MslEntityAuthException if there is an error with the entity
     *         authentication data.
     * @throws MslMessageException if no entity authentication data or master
     *         token is provided.
     */
    public MessageHeader(final MslContext ctx, final EntityAuthenticationData entityAuthData, final MasterToken masterToken, final HeaderData headerData, final HeaderPeerData peerData) throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslMessageException {
        this.entityAuthData = (masterToken == null) ? entityAuthData : null;
        this.masterToken = masterToken;
        this.nonReplayableId = headerData.nonReplayableId;
        this.nonReplayable = false;
        this.renewable = headerData.renewable;
        this.handshake = headerData.handshake;
        this.capabilities = headerData.capabilities;
        this.sender = (this.masterToken != null) ? ctx.getEntityAuthenticationData(null).getIdentity() : null;
        this.recipient = headerData.recipient;
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
        
        // Message ID must be within range.
        if (this.messageId < 0 || this.messageId > MslConstants.MAX_LONG_VALUE)
            throw new MslInternalException("Message ID " + this.messageId + " is out of range.");
        
        // Message entity must be provided.
        if (this.entityAuthData == null && this.masterToken == null)
            throw new MslInternalException("Message entity authentication data or master token must be provided.");
        
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
        
        // Construct the JSON.
        final JSONObject headerJO = new JSONObject();
        try {
            if (this.sender != null) headerJO.put(KEY_SENDER, this.sender);
            if (this.recipient != null) headerJO.put(KEY_RECIPIENT, this.recipient);
            headerJO.put(KEY_MESSAGE_ID, this.messageId);
            headerJO.put(KEY_NON_REPLAYABLE, this.nonReplayable);
            if (this.nonReplayableId != null) headerJO.put(KEY_NON_REPLAYABLE_ID, this.nonReplayableId);
            headerJO.put(KEY_RENEWABLE, this.renewable);
            headerJO.put(KEY_HANDSHAKE, this.handshake);
            headerJO.put(KEY_CAPABILITIES, this.capabilities);
            if (this.keyRequestData.size() > 0) headerJO.put(KEY_KEY_REQUEST_DATA, JsonUtils.createArray(this.keyRequestData));
            if (this.keyResponseData != null) headerJO.put(KEY_KEY_RESPONSE_DATA, this.keyResponseData);
            if (this.userAuthData != null) headerJO.put(KEY_USER_AUTHENTICATION_DATA, this.userAuthData);
            if (this.userIdToken != null) headerJO.put(KEY_USER_ID_TOKEN, this.userIdToken);
            if (this.serviceTokens.size() > 0) headerJO.put(KEY_SERVICE_TOKENS, JsonUtils.createArray(this.serviceTokens));
            if (this.peerMasterToken != null) headerJO.put(KEY_PEER_MASTER_TOKEN, this.peerMasterToken);
            if (this.peerUserIdToken != null) headerJO.put(KEY_PEER_USER_ID_TOKEN, this.peerUserIdToken);
            if (this.peerServiceTokens.size() > 0) headerJO.put(KEY_PEER_SERVICE_TOKENS, JsonUtils.createArray(this.peerServiceTokens));
        } catch (final JSONException e) {
            throw new MslEncodingException(MslError.JSON_ENCODE_ERROR, "headerdata", e)
                .setEntity(this.masterToken)
                .setEntity(this.entityAuthData)
                .setUser(this.peerUserIdToken)
                .setUser(this.userAuthData)
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
                    throw new MslMasterTokenException(MslError.MASTERTOKEN_UNTRUSTED, this.masterToken).setUser(this.userIdToken).setUser(this.userAuthData).setMessageId(this.messageId);
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
                e.setEntity(this.entityAuthData);
                e.setUser(this.userIdToken);
                e.setUser(this.userAuthData);
                e.setMessageId(this.messageId);
                throw e;
            } catch (final MslEntityAuthException e) {
                e.setEntity(this.entityAuthData);
                e.setUser(this.userIdToken);
                e.setUser(this.userAuthData);
                e.setMessageId(this.messageId);
                throw e;
            }
        }
        
        // Encrypt and sign the header data.
        try {
            this.plaintext = headerJO.toString().getBytes(MslConstants.DEFAULT_CHARSET);
            this.headerdata = this.messageCryptoContext.encrypt(plaintext);
            this.signature = this.messageCryptoContext.sign(this.headerdata);
            this.verified = true;
        } catch (final MslCryptoException e) {
            e.setEntity(this.masterToken);
            e.setEntity(this.entityAuthData);
            e.setUser(this.userIdToken);
            e.setUser(this.userAuthData);
            e.setMessageId(this.messageId);
            throw e;
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
     * @param headerdata header data JSON representation.
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
     *         missing or invalid, or the message ID is negative.
     * @throws MslException if a token is improperly bound to another token.
     */
    protected MessageHeader(final MslContext ctx, final String headerdata, final EntityAuthenticationData entityAuthData, final MasterToken masterToken, final byte[] signature, final Map<String,ICryptoContext> cryptoContexts) throws MslEncodingException, MslCryptoException, MslKeyExchangeException, MslUserAuthException, MslMasterTokenException, MslMessageException, MslEntityAuthException, MslException {
        try {
            this.entityAuthData = (masterToken == null) ? entityAuthData : null;
            this.masterToken = masterToken;
            this.signature = signature;
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
                    e.setEntity(entityAuthData);
                    throw e;
                } catch (final MslEntityAuthException e) {
                    e.setEntity(entityAuthData);
                    throw e;
                }
            }
            
            // Verify and decrypt the header data.
            try {
                this.headerdata = DatatypeConverter.parseBase64Binary(headerdata);
            } catch (final IllegalArgumentException e) {
                throw new MslMessageException(MslError.HEADER_DATA_INVALID, headerdata, e).setEntity(masterToken).setEntity(entityAuthData);
            }
            if (this.headerdata == null || this.headerdata.length == 0)
                throw new MslMessageException(MslError.HEADER_DATA_MISSING, headerdata).setEntity(masterToken).setEntity(entityAuthData);
            this.verified = this.messageCryptoContext.verify(this.headerdata, this.signature);
            this.plaintext = (this.verified) ? this.messageCryptoContext.decrypt(this.headerdata) : null;
        } catch (final MslCryptoException e) {
            e.setEntity(masterToken);
            e.setEntity(entityAuthData);
            throw e;
        } catch (final MslEntityAuthException e) {
            e.setEntity(masterToken);
            e.setEntity(entityAuthData);
            throw e;
        }
        
        // If verification failed we cannot parse the plaintext.
        if (this.plaintext == null) {
            this.messageId = 1;
            this.sender = null;
            this.recipient = null;
            this.keyResponseData = null;
            this.userIdToken = null;
            this.userAuthData = null;
            this.user = null;
            this.serviceTokens = Collections.emptySet();
            this.nonReplayableId = null;
            this.nonReplayable = false;
            this.renewable = false;
            this.handshake = false;
            this.capabilities = null;
            this.keyRequestData = Collections.emptySet();
            this.peerMasterToken = null;
            this.peerUserIdToken = null;
            this.peerServiceTokens = Collections.emptySet();
            return;
        }
        
        final String headerdataJson = new String(plaintext, MslConstants.DEFAULT_CHARSET);
        final JSONObject headerdataJO;
        try {
            headerdataJO = new JSONObject(headerdataJson);
            
            // Pull the message ID first because any error responses need to
            // use it.
            this.messageId = headerdataJO.getLong(KEY_MESSAGE_ID);
            if (this.messageId < 0 || this.messageId > MslConstants.MAX_LONG_VALUE)
                throw new MslMessageException(MslError.MESSAGE_ID_OUT_OF_RANGE, "headerdata " + headerdataJson).setEntity(masterToken).setEntity(entityAuthData);
        } catch (final JSONException e) {
            throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "headerdata " + headerdataJson, e).setEntity(masterToken).setEntity(entityAuthData);
        }
        
        try {
            // If the message was sent with a master token pull the sender.
            this.sender = (this.masterToken != null) ? headerdataJO.getString(KEY_SENDER) : null;
            this.recipient = (headerdataJO.has(KEY_RECIPIENT)) ? headerdataJO.getString(KEY_RECIPIENT) : null;
            
            // Pull key response data.
            final MasterToken tokenVerificationMasterToken;
            if (headerdataJO.has(KEY_KEY_RESPONSE_DATA)) {
                this.keyResponseData = KeyResponseData.create(ctx, headerdataJO.getJSONObject(KEY_KEY_RESPONSE_DATA));
                
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
            this.userIdToken = (headerdataJO.has(KEY_USER_ID_TOKEN))
                ? new UserIdToken(ctx, headerdataJO.getJSONObject(KEY_USER_ID_TOKEN), tokenVerificationMasterToken)
                : null;
            // Pull user authentication data.
            this.userAuthData = (headerdataJO.has(KEY_USER_AUTHENTICATION_DATA))
                ? UserAuthenticationData.create(ctx, tokenVerificationMasterToken, headerdataJO.getJSONObject(KEY_USER_AUTHENTICATION_DATA))
                : null;

            // Verify the user authentication data.
            if (this.userAuthData != null) {
                final UserAuthenticationScheme scheme = this.userAuthData.getScheme();
                final UserAuthenticationFactory factory = ctx.getUserAuthenticationFactory(scheme);
                if (factory == null)
                    throw new MslUserAuthException(MslError.USERAUTH_FACTORY_NOT_FOUND, scheme.name()).setUser(userIdToken).setUser(userAuthData);
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
            if (headerdataJO.has(KEY_SERVICE_TOKENS)) {
                final JSONArray tokens = headerdataJO.getJSONArray(KEY_SERVICE_TOKENS);
                for (int i = 0; i < tokens.length(); ++i) {
                    try {
                        serviceTokens.add(new ServiceToken(ctx, tokens.getJSONObject(i), tokenVerificationMasterToken, this.userIdToken, cryptoContexts));
                    } catch (final MslException e) {
                        e.setEntity(tokenVerificationMasterToken).setUser(this.userIdToken).setUser(userAuthData);
                        throw e;
                    }
                }
            }
            this.serviceTokens = Collections.unmodifiableSet(serviceTokens);
        } catch (final JSONException e) {
            throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "headerdata " + headerdataJson, e).setEntity(masterToken).setEntity(entityAuthData).setMessageId(this.messageId);
        } catch (final MslException e) {
            e.setEntity(masterToken);
            e.setEntity(entityAuthData);
            e.setMessageId(this.messageId);
            throw e;
        }
        
        try {
            this.nonReplayableId = (headerdataJO.has(KEY_NON_REPLAYABLE_ID)) ? headerdataJO.getLong(KEY_NON_REPLAYABLE_ID) : null;
            this.nonReplayable = (headerdataJO.has(KEY_NON_REPLAYABLE)) ? headerdataJO.getBoolean(KEY_NON_REPLAYABLE) : false;
            this.renewable = headerdataJO.getBoolean(KEY_RENEWABLE);
            // FIXME: Make handshake required once all MSL stacks are updated.
            this.handshake = (headerdataJO.has(KEY_HANDSHAKE)) ? headerdataJO.getBoolean(KEY_HANDSHAKE) : false;
            
            // Verify values.
            if (nonReplayableId != null && (nonReplayableId < 0 || nonReplayableId > MslConstants.MAX_LONG_VALUE))
                throw new MslMessageException(MslError.NONREPLAYABLE_ID_OUT_OF_RANGE, "headerdata " + headerdataJson);
            
            // Pull message capabilities.
            if (headerdataJO.has(KEY_CAPABILITIES)) {
                final JSONObject capabilitiesJO = headerdataJO.getJSONObject(KEY_CAPABILITIES);
                this.capabilities = new MessageCapabilities(capabilitiesJO);
            } else {
                this.capabilities = null;
            }
            
            // Pull key request data containers.
            final Set<KeyRequestData> keyRequestData = new HashSet<KeyRequestData>();
            if (headerdataJO.has(KEY_KEY_REQUEST_DATA)) {
                final JSONArray keyRequests = headerdataJO.getJSONArray(KEY_KEY_REQUEST_DATA);
                for (int i = 0; i < keyRequests.length(); ++i) {
                    keyRequestData.add(KeyRequestData.create(ctx, keyRequests.getJSONObject(i)));
                }
            }
            this.keyRequestData = Collections.unmodifiableSet(keyRequestData);
            
            // Only process peer-to-peer tokens if in peer-to-peer mode.
            if (ctx.isPeerToPeer()) {
                // Pull peer master token.
                this.peerMasterToken = (headerdataJO.has(KEY_PEER_MASTER_TOKEN))
                    ? new MasterToken(ctx, headerdataJO.getJSONObject(KEY_PEER_MASTER_TOKEN))
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
                    this.peerUserIdToken = (headerdataJO.has(KEY_PEER_USER_ID_TOKEN))
                        ? new UserIdToken(ctx, headerdataJO.getJSONObject(KEY_PEER_USER_ID_TOKEN), peerVerificationMasterToken)
                        : null;
                } catch (final MslException e) {
                    e.setEntity(peerVerificationMasterToken);
                    throw e;
                }
    
                // Peer service tokens are authenticated by the peer master
                // token if it exists or by the application crypto context.
                final Set<ServiceToken> peerServiceTokens = new HashSet<ServiceToken>();
                if (headerdataJO.has(KEY_PEER_SERVICE_TOKENS)) {
                    final JSONArray tokens = headerdataJO.getJSONArray(KEY_PEER_SERVICE_TOKENS);
                    for (int i = 0; i < tokens.length(); ++i) {
                        try {
                            peerServiceTokens.add(new ServiceToken(ctx, tokens.getJSONObject(i), peerVerificationMasterToken, this.peerUserIdToken, cryptoContexts));
                        } catch (final MslException e) {
                            e.setEntity(peerVerificationMasterToken).setUser(this.peerUserIdToken);
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
        } catch (final JSONException e) {
            throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "headerdata " + headerdataJO.toString(), e)
                .setEntity(masterToken)
                .setEntity(entityAuthData)
                .setUser(this.userIdToken)
                .setUser(this.userAuthData)
                .setMessageId(this.messageId);
        } catch (final MslException e) {
            e.setEntity(masterToken);
            e.setEntity(entityAuthData);
            e.setUser(this.userIdToken);
            e.setUser(this.userAuthData);
            e.setMessageId(this.messageId);
            throw e;
        }
    }

    /**
     * <p>Returns true if the header data has been decrypted and parsed. If
     * this method returns false then the other methods that return the header
     * data will return {@code null}, {@code false}, or empty collections
     * instead of the actual header data.</p>
     * 
     * @return true if the decrypted content is available. (Implies verified.)
     */
    public boolean isDecrypted() {
        return plaintext != null;
    }

    /**
     * @return true if the token has been verified.
     */
    public boolean isVerified() {
        return verified;
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
     * @return the sender entity identity. Will be {@code null} if the message
     *         is using entity authentication data.
     */
    public String getSender() {
        return sender;
    }
    
    /**
     * @return the recipient entity identity. Will be {@code null} if there is
     *         no specified recipient.
     */
    public String getRecipient() {
        return recipient;
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
     * @return true if the message non-replayable flag is set.
     */
    public boolean isNonReplayable() {
        return nonReplayable;
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
     * @see org.json.JSONString#toJSONString()
     */
    @Override
    public String toJSONString() {
        try {
            final JSONObject jsonObj = new JSONObject();
            if (masterToken != null)
                jsonObj.put(KEY_MASTER_TOKEN, masterToken);
            else
                jsonObj.put(KEY_ENTITY_AUTHENTICATION_DATA, entityAuthData);
            jsonObj.put(KEY_HEADERDATA, DatatypeConverter.printBase64Binary(headerdata));
            jsonObj.put(KEY_SIGNATURE, DatatypeConverter.printBase64Binary(signature));
            return jsonObj.toString();
        } catch (final JSONException e) {
            throw new MslInternalException("Error encoding " + this.getClass().getName() + " JSON.", e);
        }
    }
    
    /* (non-Javadoc)
     * @see java.lang.Object#equals(java.lang.Object)
     */
    @Override
    public boolean equals(final Object obj) {
        if (obj == this) return true;
        if (!(obj instanceof MessageHeader)) return false;
        final MessageHeader that = (MessageHeader)obj;
        return (masterToken != null && masterToken.equals(that.masterToken) ||
                entityAuthData != null && entityAuthData.equals(that.entityAuthData)) &&
               (sender != null && sender.equals(that.sender) ||
                sender == that.sender) &&
               (recipient != null && recipient.equals(that.recipient) ||
                recipient == that.recipient) &&
               messageId == that.messageId &&
               (nonReplayableId != null && nonReplayableId.equals(that.nonReplayableId) ||
                nonReplayableId == that.nonReplayableId) &&
               nonReplayable == that.nonReplayable &&
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
            ((sender != null) ? sender.hashCode() : 0) ^
            ((recipient != null) ? recipient.hashCode() : 0) ^
            Long.valueOf(messageId).hashCode() ^
            ((nonReplayableId != null) ? nonReplayableId.hashCode() : 0) ^
            Boolean.valueOf(nonReplayable).hashCode() ^
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
    private final EntityAuthenticationData entityAuthData;
    /** Master token. */
    private final MasterToken masterToken;
    /** Header data (ciphertext). */
    private final byte[] headerdata;
    /** Header data (plaintext) */
    private final byte[] plaintext;
    /** Signature. */
    private final byte[] signature;
    
    /** Sender. */
    private final String sender;
    /** Recipient. */
    private final String recipient;
    /** Message ID. */
    private final long messageId;
    /** Non-replayable ID. */
    private final Long nonReplayableId;
    /** Non-replayable. */
    private final boolean nonReplayable;
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
    private final ICryptoContext messageCryptoContext;
    
    /** Message header is verified. */
    private final boolean verified;
}
