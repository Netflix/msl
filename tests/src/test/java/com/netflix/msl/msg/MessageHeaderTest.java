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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;

import com.netflix.msl.MslConstants;
import com.netflix.msl.MslConstants.CompressionAlgorithm;
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
import com.netflix.msl.crypto.NullCryptoContext;
import com.netflix.msl.crypto.SessionCryptoContext;
import com.netflix.msl.entityauth.EntityAuthenticationData;
import com.netflix.msl.entityauth.EntityAuthenticationFactory;
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.entityauth.MockPresharedAuthenticationFactory;
import com.netflix.msl.entityauth.PresharedAuthenticationData;
import com.netflix.msl.io.MslArray;
import com.netflix.msl.io.MslEncoderException;
import com.netflix.msl.io.MslEncoderFactory;
import com.netflix.msl.io.MslEncoderFormat;
import com.netflix.msl.io.MslEncoderUtils;
import com.netflix.msl.io.MslObject;
import com.netflix.msl.keyx.KeyExchangeFactory;
import com.netflix.msl.keyx.KeyExchangeFactory.KeyExchangeData;
import com.netflix.msl.keyx.KeyRequestData;
import com.netflix.msl.keyx.KeyResponseData;
import com.netflix.msl.keyx.SymmetricWrappedExchange;
import com.netflix.msl.keyx.SymmetricWrappedExchange.KeyId;
import com.netflix.msl.msg.MessageHeader.HeaderData;
import com.netflix.msl.msg.MessageHeader.HeaderPeerData;
import com.netflix.msl.test.ExpectedMslException;
import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.tokens.ServiceToken;
import com.netflix.msl.tokens.UserIdToken;
import com.netflix.msl.userauth.EmailPasswordAuthenticationData;
import com.netflix.msl.userauth.MockEmailPasswordAuthenticationFactory;
import com.netflix.msl.userauth.UserAuthenticationData;
import com.netflix.msl.util.Base64;
import com.netflix.msl.util.MockMslContext;
import com.netflix.msl.util.MslContext;
import com.netflix.msl.util.MslTestUtils;

/**
 * Message header unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class MessageHeaderTest {
    /** Milliseconds per second. */
    private static final long MILLISECONDS_PER_SECOND = 1000;
    
    /** Key entity authentication data. */
    private static final String KEY_ENTITY_AUTHENTICATION_DATA = "entityauthdata";
    /** Key master token. */
    private static final String KEY_MASTER_TOKEN = "mastertoken";
    /** Key header data. */
    private static final String KEY_HEADERDATA = "headerdata";
    /** Key error data signature. */
    private static final String KEY_SIGNATURE = "signature";

    // Message header data.
    /** Key timestamp. */
    private static final String KEY_TIMESTAMP = "timestamp";
    /** Key message ID. */
    private static final String KEY_MESSAGE_ID = "messageid";
    /** Key non-replayable ID. */
    private static final String KEY_NON_REPLAYABLE_ID = "nonreplayableid";
    /** Key renewable flag. */
    private static final String KEY_RENEWABLE = "renewable";
    /** Key handshake flag */
    private static final String KEY_HANDSHAKE = "handshake";
    /** Key capabilities. */
    private static final String KEY_CAPABILITIES = "capabilities";
    /** Key key negotiation request. */
    private static final String KEY_KEY_REQUEST_DATA = "keyrequestdata";
    /** Key key negotiation response. */
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
     * Checks if the given timestamp is close to "now".
     * 
     * @param timestamp the timestamp to compare.
     * @return true if the timestamp is about now.
     */
    private static boolean isAboutNow(final Date timestamp) {
        final long now = System.currentTimeMillis();
        final long time = timestamp.getTime();
        return (now - 1000 <= time && time <= now + 1000);
    }

    /**
     * Checks if the given timestamp is close to "now".
     * 
     * @param seconds the timestamp to compare in seconds since the epoch.
     * @return true if the timestamp is about now.
     */
    private static boolean isAboutNowSeconds(final long seconds) {
        final long now = System.currentTimeMillis();
        final long time = seconds * MILLISECONDS_PER_SECOND;
        return (now - 1000 <= time && time <= now + 1000);
    }
    
    private static final Set<CompressionAlgorithm> ALGOS = new HashSet<CompressionAlgorithm>();
    private static final List<String> LANGUAGES = Arrays.asList(new String[] {"en-US"});
    private static final Set<MslEncoderFormat> FORMATS = new HashSet<MslEncoderFormat>();
    
    private static MasterToken MASTER_TOKEN;
    private static final long MESSAGE_ID = 1;
    private static final Long NON_REPLAYABLE_ID = 1L;
    private static final boolean RENEWABLE = true;
    private static final boolean HANDSHAKE = false;
    private static MessageCapabilities CAPABILITIES;
    private static final Set<KeyRequestData> KEY_REQUEST_DATA = new HashSet<KeyRequestData>();
    private static KeyResponseData KEY_RESPONSE_DATA;
    private static UserAuthenticationData USER_AUTH_DATA;
    private static UserIdToken USER_ID_TOKEN;
    private static MasterToken PEER_MASTER_TOKEN;
    private static UserIdToken PEER_USER_ID_TOKEN;
    private static final Set<KeyRequestData> PEER_KEY_REQUEST_DATA = new HashSet<KeyRequestData>();
    private static KeyResponseData PEER_KEY_RESPONSE_DATA;
    private static final Map<String,ICryptoContext> CRYPTO_CONTEXTS = Collections.emptyMap();

    /** MSL trusted network context. */
    private static MslContext trustedNetCtx;
    /** MSL peer-to-peer context. */
    private static MslContext p2pCtx;
    /** MSL encoder factory. */
    private static MslEncoderFactory encoder;
    /** MSL encoder format. */
    private static MslEncoderFormat format;
    
    /**
     * A helper class for building message header data.
     */
    private static class HeaderDataBuilder {
        /**
         * Create a new header data builder with the default constant values
         * and a random set of service tokens that may be bound to the provided
         * master token and user ID token.
         * 
         * @param ctx MSL context.
         * @param masterToken message header master token. May be null.
         * @param userIdToken message header user ID token. May be null.
         * @param serviceTokens true to create service tokens. Otherwise the
         *        service token value will be set to null.
         * @throws MslEncodingException if there is an error encoding the JSON
         *         data.
         * @throws MslCryptoException if there is an error encrypting or signing
         *         the token data.
         * @throws MslException if there is an error compressing the data.
         */
        public HeaderDataBuilder(final MslContext ctx, final MasterToken masterToken, final UserIdToken userIdToken, final boolean serviceTokens) throws MslEncodingException, MslCryptoException, MslException {
            final Set<ServiceToken> tokens = (serviceTokens) ? MslTestUtils.getServiceTokens(ctx, masterToken, userIdToken) : null;
            values.put(KEY_MESSAGE_ID, MESSAGE_ID);
            values.put(KEY_NON_REPLAYABLE_ID, NON_REPLAYABLE_ID);
            values.put(KEY_RENEWABLE, RENEWABLE);
            values.put(KEY_HANDSHAKE, HANDSHAKE);
            values.put(KEY_CAPABILITIES, CAPABILITIES);
            values.put(KEY_KEY_REQUEST_DATA, (!ctx.isPeerToPeer()) ? KEY_REQUEST_DATA : PEER_KEY_REQUEST_DATA);
            values.put(KEY_KEY_RESPONSE_DATA, (!ctx.isPeerToPeer()) ? KEY_RESPONSE_DATA : PEER_KEY_RESPONSE_DATA);
            values.put(KEY_USER_AUTHENTICATION_DATA, USER_AUTH_DATA);
            values.put(KEY_USER_ID_TOKEN, userIdToken);
            values.put(KEY_SERVICE_TOKENS, tokens);
        }
        
        /**
         * Create a new header data builder with the default constant values
         * and the provided set of service tokens.
         * 
         * @param ctx MSL context.
         * @param userIdToken message header user ID token. May be null.
         * @param serviceTokens message header service tokens. May be null.
         */
        public HeaderDataBuilder(final MslContext ctx, final UserIdToken userIdToken, final Set<ServiceToken> serviceTokens) {
            values.put(KEY_MESSAGE_ID, MESSAGE_ID);
            values.put(KEY_NON_REPLAYABLE_ID, NON_REPLAYABLE_ID);
            values.put(KEY_RENEWABLE, RENEWABLE);
            values.put(KEY_HANDSHAKE, HANDSHAKE);
            values.put(KEY_CAPABILITIES, CAPABILITIES);
            values.put(KEY_KEY_REQUEST_DATA, (!ctx.isPeerToPeer()) ? KEY_REQUEST_DATA : PEER_KEY_REQUEST_DATA);
            values.put(KEY_KEY_RESPONSE_DATA, (!ctx.isPeerToPeer()) ? KEY_RESPONSE_DATA : PEER_KEY_RESPONSE_DATA);
            values.put(KEY_USER_AUTHENTICATION_DATA, USER_AUTH_DATA);
            values.put(KEY_USER_ID_TOKEN, userIdToken);
            values.put(KEY_SERVICE_TOKENS, serviceTokens);
        }
        
        /**
         * Set the value for the specified message data field.
         * 
         * @param key message header field name.
         * @param value message header field value.
         * @return the builder.
         */
        public HeaderDataBuilder set(final String key, final Object value) {
            values.put(key, value);
            return this;
        }
        
        /**
         * @return the current set of service tokens. May be null.
         */
        @SuppressWarnings("unchecked")
        public Set<ServiceToken> getServiceTokens() {
            return (Set<ServiceToken>)values.get(KEY_SERVICE_TOKENS);
        }
        
        /**
         * Builds a new header data container with the currently set values.
         * 
         * @return the header data.
         */
        @SuppressWarnings("unchecked")
        public HeaderData build() {
            final Long messageId = (Long)values.get(KEY_MESSAGE_ID);
            final Long nonReplayableId = (Long)values.get(KEY_NON_REPLAYABLE_ID);
            final Boolean renewable = (Boolean)values.get(KEY_RENEWABLE);
            final Boolean handshake = (Boolean)values.get(KEY_HANDSHAKE);
            final MessageCapabilities capabilities = (MessageCapabilities)values.get(KEY_CAPABILITIES);
            final Set<KeyRequestData> keyRequestData = (Set<KeyRequestData>)values.get(KEY_KEY_REQUEST_DATA);
            final KeyResponseData keyResponseData = (KeyResponseData)values.get(KEY_KEY_RESPONSE_DATA);
            final UserAuthenticationData userAuthData = (UserAuthenticationData)values.get(KEY_USER_AUTHENTICATION_DATA);
            final UserIdToken userIdToken = (UserIdToken)values.get(KEY_USER_ID_TOKEN);
            final Set<ServiceToken> serviceTokens = (Set<ServiceToken>)values.get(KEY_SERVICE_TOKENS);
            return new HeaderData(messageId, nonReplayableId, renewable, handshake, capabilities, keyRequestData, keyResponseData, userAuthData, userIdToken, serviceTokens);
        }
        
        /** Header data values. */
        private final Map<String,Object> values = new HashMap<String,Object>();
    }
    
    @Rule
    public ExpectedMslException thrown = ExpectedMslException.none();
    
    @BeforeClass
    public static void setup() throws MslException {
        trustedNetCtx = new MockMslContext(EntityAuthenticationScheme.PSK, false);
        p2pCtx = new MockMslContext(EntityAuthenticationScheme.PSK, true);
        encoder = trustedNetCtx.getMslEncoderFactory();
        
        ALGOS.add(CompressionAlgorithm.GZIP);
        ALGOS.add(CompressionAlgorithm.LZW);
        FORMATS.add(MslEncoderFormat.JSON);
        CAPABILITIES = new MessageCapabilities(ALGOS, LANGUAGES, FORMATS);
        format = encoder.getPreferredFormat(CAPABILITIES.getEncoderFormats());
        
        MASTER_TOKEN = MslTestUtils.getMasterToken(trustedNetCtx, 1, 1);
        
        final KeyRequestData keyRequestData = new SymmetricWrappedExchange.RequestData(KeyId.PSK);
        final KeyExchangeFactory factory = trustedNetCtx.getKeyExchangeFactory(keyRequestData.getKeyExchangeScheme());
        final KeyExchangeData keyxData = factory.generateResponse(trustedNetCtx, format, keyRequestData, MASTER_TOKEN);
        KEY_REQUEST_DATA.add(keyRequestData);
        KEY_RESPONSE_DATA = keyxData.keyResponseData;
        
        USER_AUTH_DATA = new EmailPasswordAuthenticationData(MockEmailPasswordAuthenticationFactory.EMAIL, MockEmailPasswordAuthenticationFactory.PASSWORD);
        USER_ID_TOKEN = MslTestUtils.getUserIdToken(trustedNetCtx, MASTER_TOKEN, 1, MockEmailPasswordAuthenticationFactory.USER);
        
        PEER_MASTER_TOKEN = MslTestUtils.getMasterToken(p2pCtx, 1, 2);
        PEER_USER_ID_TOKEN = MslTestUtils.getUserIdToken(p2pCtx, PEER_MASTER_TOKEN, 1, MockEmailPasswordAuthenticationFactory.USER);
        
        final KeyRequestData peerKeyRequestData = new SymmetricWrappedExchange.RequestData(KeyId.PSK);
        final KeyExchangeFactory peerFactory = p2pCtx.getKeyExchangeFactory(peerKeyRequestData.getKeyExchangeScheme());
        final KeyExchangeData peerKeyxData = peerFactory.generateResponse(p2pCtx, format, peerKeyRequestData, PEER_MASTER_TOKEN);
        PEER_KEY_REQUEST_DATA.add(peerKeyRequestData);
        PEER_KEY_RESPONSE_DATA = peerKeyxData.keyResponseData;
    }
    
    @AfterClass
    public static void teardown() {
        format = null;
        encoder = null;
        p2pCtx = null;
        trustedNetCtx = null;
    }
    
    @Before
    public void reset() {
        trustedNetCtx.getMslStore().clearCryptoContexts();
        trustedNetCtx.getMslStore().clearServiceTokens();
        p2pCtx.getMslStore().clearCryptoContexts();
        p2pCtx.getMslStore().clearServiceTokens();
    }
    
    @Test
    public void entityAuthDataCtors() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslException {
        // Service tokens may be created with the key response data tokens. The
        // key response data master token has the same serial number as the
        // original master token so we can use the same user ID token.
        final HeaderDataBuilder builder = new HeaderDataBuilder(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
        final HeaderData headerData = builder.build();
        final Set<ServiceToken> peerServiceTokens = MslTestUtils.getServiceTokens(trustedNetCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
        final HeaderPeerData peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
        final EntityAuthenticationData entityAuthData = trustedNetCtx.getEntityAuthenticationData(null);
        final MessageHeader messageHeader = new MessageHeader(trustedNetCtx, entityAuthData, null, headerData, peerData);
        
        assertTrue(messageHeader.isEncrypting());
        assertEquals(NON_REPLAYABLE_ID, messageHeader.getNonReplayableId());
        assertEquals(RENEWABLE, messageHeader.isRenewable());
        assertEquals(HANDSHAKE, messageHeader.isHandshake());
        assertEquals(CAPABILITIES, messageHeader.getMessageCapabilities());
        assertNotNull(messageHeader.getCryptoContext());
        assertEquals(entityAuthData, messageHeader.getEntityAuthenticationData());
        final Set<KeyRequestData> keyRequestData = messageHeader.getKeyRequestData();
        assertTrue(keyRequestData.containsAll(KEY_REQUEST_DATA));
        assertEquals(KEY_RESPONSE_DATA, messageHeader.getKeyResponseData());
        assertNull(messageHeader.getMasterToken());
        assertTrue(isAboutNow(messageHeader.getTimestamp()));
        assertEquals(MESSAGE_ID, messageHeader.getMessageId());
        assertNull(messageHeader.getPeerMasterToken());
        assertTrue(messageHeader.getPeerServiceTokens().isEmpty());
        assertNull(messageHeader.getPeerUserIdToken());
        final Set<ServiceToken> serviceTokens = builder.getServiceTokens();
        assertTrue(messageHeader.getServiceTokens().containsAll(serviceTokens));
        assertEquals(USER_AUTH_DATA, messageHeader.getUserAuthenticationData());
        assertEquals(USER_ID_TOKEN, messageHeader.getUserIdToken());
        assertEquals(USER_ID_TOKEN.getUser(), messageHeader.getUser());
    }
    
    @Test
    public void entityAuthDataReplayable() throws MslEncodingException, MslCryptoException, MslException {
        // Service tokens may be created with the key response data tokens. The
        // key response data master token has the same serial number as the
        // original master token so we can use the same user ID token.
        final HeaderDataBuilder builder = new HeaderDataBuilder(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
        builder.set(KEY_NON_REPLAYABLE_ID, null);
        final HeaderData headerData = builder.build();
        final Set<ServiceToken> peerServiceTokens = MslTestUtils.getServiceTokens(trustedNetCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
        final HeaderPeerData peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
        final EntityAuthenticationData entityAuthData = trustedNetCtx.getEntityAuthenticationData(null);
        final MessageHeader messageHeader = new MessageHeader(trustedNetCtx, entityAuthData, null, headerData, peerData);
        
        assertTrue(messageHeader.isEncrypting());
        assertNull(messageHeader.getNonReplayableId());
        assertEquals(RENEWABLE, messageHeader.isRenewable());
        assertEquals(HANDSHAKE, messageHeader.isHandshake());
        assertEquals(CAPABILITIES, messageHeader.getMessageCapabilities());
        assertNotNull(messageHeader.getCryptoContext());
        assertEquals(entityAuthData, messageHeader.getEntityAuthenticationData());
        final Set<KeyRequestData> keyRequestData = messageHeader.getKeyRequestData();
        assertTrue(keyRequestData.containsAll(KEY_REQUEST_DATA));
        assertEquals(KEY_RESPONSE_DATA, messageHeader.getKeyResponseData());
        assertNull(messageHeader.getMasterToken());
        assertTrue(isAboutNow(messageHeader.getTimestamp()));
        assertEquals(MESSAGE_ID, messageHeader.getMessageId());
        assertNull(messageHeader.getPeerMasterToken());
        assertTrue(messageHeader.getPeerServiceTokens().isEmpty());
        assertNull(messageHeader.getPeerUserIdToken());
        final Set<ServiceToken> serviceTokens = builder.getServiceTokens();
        assertTrue(messageHeader.getServiceTokens().containsAll(serviceTokens));
        assertEquals(USER_AUTH_DATA, messageHeader.getUserAuthenticationData());
        assertEquals(USER_ID_TOKEN, messageHeader.getUserIdToken());
        assertEquals(USER_ID_TOKEN.getUser(), messageHeader.getUser());
    }
    
    @Test
    public void entityAuthDataMslObject() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslException, MslEncoderException, UnsupportedEncodingException {
        // Service tokens may be created with the key response data tokens. The
        // key response data master token has the same serial number as the
        // original master token so we can use the same user ID token.
        final HeaderDataBuilder builder = new HeaderDataBuilder(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
        final HeaderData headerData = builder.build();
        final Set<ServiceToken> peerServiceTokens = MslTestUtils.getServiceTokens(trustedNetCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
        final HeaderPeerData peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
        final EntityAuthenticationData entityAuthData = trustedNetCtx.getEntityAuthenticationData(null);
        final MessageHeader messageHeader = new MessageHeader(trustedNetCtx, entityAuthData, null, headerData, peerData);
        
        final EntityAuthenticationScheme scheme = entityAuthData.getScheme();
        final EntityAuthenticationFactory factory = trustedNetCtx.getEntityAuthenticationFactory(scheme);
        final ICryptoContext cryptoContext = factory.getCryptoContext(trustedNetCtx, entityAuthData);
        
        final MslObject mo = MslTestUtils.toMslObject(encoder, messageHeader);
        final MslObject entityAuthDataMo = mo.getMslObject(KEY_ENTITY_AUTHENTICATION_DATA, encoder);
        assertTrue(MslEncoderUtils.equalObjects(MslTestUtils.toMslObject(encoder, entityAuthData), entityAuthDataMo));
        assertFalse(mo.has(KEY_MASTER_TOKEN));
        final byte[] ciphertext = mo.getBytes(KEY_HEADERDATA);
        final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
        final MslObject headerdata = encoder.parseObject(plaintext);
        final byte[] signature = mo.getBytes(KEY_SIGNATURE);
        assertTrue(cryptoContext.verify(ciphertext, signature, encoder));
        
        assertEquals(NON_REPLAYABLE_ID, (Long)headerdata.getLong(KEY_NON_REPLAYABLE_ID));
        assertEquals(RENEWABLE, headerdata.getBoolean(KEY_RENEWABLE));
        assertEquals(HANDSHAKE, headerdata.getBoolean(KEY_HANDSHAKE));
        assertTrue(MslEncoderUtils.equalObjects(MslTestUtils.toMslObject(encoder, CAPABILITIES), headerdata.getMslObject(KEY_CAPABILITIES, encoder)));
        assertTrue(MslEncoderUtils.equalArrays(MslEncoderUtils.createArray(trustedNetCtx, format, KEY_REQUEST_DATA), headerdata.getMslArray(KEY_KEY_REQUEST_DATA)));
        assertTrue(MslEncoderUtils.equalObjects(MslTestUtils.toMslObject(encoder, KEY_RESPONSE_DATA), headerdata.getMslObject(KEY_KEY_RESPONSE_DATA, encoder)));
        assertTrue(isAboutNowSeconds(headerdata.getLong(KEY_TIMESTAMP)));
        assertEquals(MESSAGE_ID, headerdata.getLong(KEY_MESSAGE_ID));
        assertFalse(headerdata.has(KEY_PEER_MASTER_TOKEN));
        assertFalse(headerdata.has(KEY_PEER_SERVICE_TOKENS));
        assertFalse(headerdata.has(KEY_PEER_USER_ID_TOKEN));
        final Set<ServiceToken> serviceTokens = builder.getServiceTokens();
        assertTrue(MslEncoderUtils.equalArrays(MslEncoderUtils.createArray(trustedNetCtx, format, serviceTokens), headerdata.getMslArray(KEY_SERVICE_TOKENS)));
        assertTrue(MslEncoderUtils.equalObjects(MslTestUtils.toMslObject(encoder, USER_AUTH_DATA), headerdata.getMslObject(KEY_USER_AUTHENTICATION_DATA, encoder)));
        assertTrue(MslEncoderUtils.equalObjects(MslTestUtils.toMslObject(encoder, USER_ID_TOKEN), headerdata.getMslObject(KEY_USER_ID_TOKEN, encoder)));
    }
    
    @Test
    public void entityAuthDataReplayableMslObject() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslException, MslEncoderException, UnsupportedEncodingException {
        // Service tokens may be created with the key response data tokens. The
        // key response data master token has the same serial number as the
        // original master token so we can use the same user ID token.
        final HeaderDataBuilder builder = new HeaderDataBuilder(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
        builder.set(KEY_NON_REPLAYABLE_ID, null);
        final HeaderData headerData = builder.build();
        final Set<ServiceToken> peerServiceTokens = MslTestUtils.getServiceTokens(trustedNetCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
        final HeaderPeerData peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
        final EntityAuthenticationData entityAuthData = trustedNetCtx.getEntityAuthenticationData(null);
        final MessageHeader messageHeader = new MessageHeader(trustedNetCtx, entityAuthData, null, headerData, peerData);
        
        final EntityAuthenticationScheme scheme = entityAuthData.getScheme();
        final EntityAuthenticationFactory factory = trustedNetCtx.getEntityAuthenticationFactory(scheme);
        final ICryptoContext cryptoContext = factory.getCryptoContext(trustedNetCtx, entityAuthData);
        
        final MslObject mo = MslTestUtils.toMslObject(encoder, messageHeader);
        final MslObject entityAuthDataMo = mo.getMslObject(KEY_ENTITY_AUTHENTICATION_DATA, encoder);
        assertTrue(MslEncoderUtils.equalObjects(MslTestUtils.toMslObject(encoder, entityAuthData), entityAuthDataMo));
        assertFalse(mo.has(KEY_MASTER_TOKEN));
        final byte[] ciphertext = mo.getBytes(KEY_HEADERDATA);
        final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
        final MslObject headerdata = encoder.parseObject(plaintext);
        final byte[] signature = mo.getBytes(KEY_SIGNATURE);
        assertTrue(cryptoContext.verify(ciphertext, signature, encoder));
        
        assertFalse(headerdata.has(KEY_NON_REPLAYABLE_ID));
        assertEquals(RENEWABLE, headerdata.getBoolean(KEY_RENEWABLE));
        assertEquals(HANDSHAKE, headerdata.getBoolean(KEY_HANDSHAKE));
        assertTrue(MslEncoderUtils.equalObjects(MslTestUtils.toMslObject(encoder, CAPABILITIES), headerdata.getMslObject(KEY_CAPABILITIES, encoder)));
        assertTrue(MslEncoderUtils.equalArrays(MslEncoderUtils.createArray(trustedNetCtx, format, KEY_REQUEST_DATA), headerdata.getMslArray(KEY_KEY_REQUEST_DATA)));
        assertTrue(MslEncoderUtils.equalObjects(MslTestUtils.toMslObject(encoder, KEY_RESPONSE_DATA), headerdata.getMslObject(KEY_KEY_RESPONSE_DATA, encoder)));
        assertTrue(isAboutNowSeconds(headerdata.getLong(KEY_TIMESTAMP)));
        assertEquals(MESSAGE_ID, headerdata.getLong(KEY_MESSAGE_ID));
        assertFalse(headerdata.has(KEY_PEER_MASTER_TOKEN));
        assertFalse(headerdata.has(KEY_PEER_SERVICE_TOKENS));
        assertFalse(headerdata.has(KEY_PEER_USER_ID_TOKEN));
        final Set<ServiceToken> serviceTokens = builder.getServiceTokens();
        assertTrue(MslEncoderUtils.equalArrays(MslEncoderUtils.createArray(trustedNetCtx, format, serviceTokens), headerdata.getMslArray(KEY_SERVICE_TOKENS)));
        assertTrue(MslEncoderUtils.equalObjects(MslTestUtils.toMslObject(encoder, USER_AUTH_DATA), headerdata.getMslObject(KEY_USER_AUTHENTICATION_DATA, encoder)));
        assertTrue(MslEncoderUtils.equalObjects(MslTestUtils.toMslObject(encoder, USER_ID_TOKEN), headerdata.getMslObject(KEY_USER_ID_TOKEN, encoder)));
    }
    
    @Test
    public void entityAuthDataPeerCtors() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslException {
        final HeaderDataBuilder builder = new HeaderDataBuilder(p2pCtx, null, null, true);
        final HeaderData headerData = builder.build();
        // Peer service tokens may be created with the key response data master
        // token. The peer key response data master token has the same serial
        // number as the original peer master token so we can use the same peer
        // user ID token.
        final Set<ServiceToken> peerServiceTokens = MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
        final HeaderPeerData peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
        final EntityAuthenticationData entityAuthData = p2pCtx.getEntityAuthenticationData(null);
        final MessageHeader messageHeader = new MessageHeader(p2pCtx, entityAuthData, null, headerData, peerData);
        
        assertTrue(messageHeader.isEncrypting());
        assertEquals(NON_REPLAYABLE_ID, messageHeader.getNonReplayableId());
        assertEquals(RENEWABLE, messageHeader.isRenewable());
        assertEquals(HANDSHAKE, messageHeader.isHandshake());
        assertEquals(CAPABILITIES, messageHeader.getMessageCapabilities());
        assertNotNull(messageHeader.getCryptoContext());
        assertEquals(entityAuthData, messageHeader.getEntityAuthenticationData());
        final Set<KeyRequestData> keyRequestData = messageHeader.getKeyRequestData();
        assertTrue(keyRequestData.containsAll(PEER_KEY_REQUEST_DATA));
        assertEquals(PEER_KEY_RESPONSE_DATA, messageHeader.getKeyResponseData());
        assertNull(messageHeader.getMasterToken());
        assertTrue(isAboutNow(messageHeader.getTimestamp()));
        assertEquals(MESSAGE_ID, messageHeader.getMessageId());
        assertEquals(PEER_MASTER_TOKEN, messageHeader.getPeerMasterToken());
        assertTrue(messageHeader.getPeerServiceTokens().containsAll(peerServiceTokens));
        assertEquals(PEER_USER_ID_TOKEN, messageHeader.getPeerUserIdToken());
        final Set<ServiceToken> serviceTokens = builder.getServiceTokens();
        assertTrue(messageHeader.getServiceTokens().containsAll(serviceTokens));
        assertEquals(USER_AUTH_DATA, messageHeader.getUserAuthenticationData());
        assertNull(messageHeader.getUserIdToken());
        assertNull(messageHeader.getUser());
    }
    
    @Test
    public void entityAuthDataReplayablePeerCtors() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslException {
        final HeaderDataBuilder builder = new HeaderDataBuilder(p2pCtx, null, null, true);
        builder.set(KEY_NON_REPLAYABLE_ID, null);
        final HeaderData headerData = builder.build();
        // Peer service tokens may be created with the key response data master
        // token. The peer key response data master token has the same serial
        // number as the original peer master token so we can use the same peer
        // user ID token.
        final Set<ServiceToken> peerServiceTokens = MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
        final HeaderPeerData peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
        final EntityAuthenticationData entityAuthData = p2pCtx.getEntityAuthenticationData(null);
        final MessageHeader messageHeader = new MessageHeader(p2pCtx, entityAuthData, null, headerData, peerData);
        
        assertTrue(messageHeader.isEncrypting());
        assertNull(messageHeader.getNonReplayableId());
        assertEquals(RENEWABLE, messageHeader.isRenewable());
        assertEquals(HANDSHAKE, messageHeader.isHandshake());
        assertEquals(CAPABILITIES, messageHeader.getMessageCapabilities());
        assertNotNull(messageHeader.getCryptoContext());
        assertEquals(entityAuthData, messageHeader.getEntityAuthenticationData());
        final Set<KeyRequestData> keyRequestData = messageHeader.getKeyRequestData();
        assertTrue(keyRequestData.containsAll(PEER_KEY_REQUEST_DATA));
        assertEquals(PEER_KEY_RESPONSE_DATA, messageHeader.getKeyResponseData());
        assertNull(messageHeader.getMasterToken());
        assertTrue(isAboutNow(messageHeader.getTimestamp()));
        assertEquals(MESSAGE_ID, messageHeader.getMessageId());
        assertEquals(PEER_MASTER_TOKEN, messageHeader.getPeerMasterToken());
        assertTrue(messageHeader.getPeerServiceTokens().containsAll(peerServiceTokens));
        assertEquals(PEER_USER_ID_TOKEN, messageHeader.getPeerUserIdToken());
        final Set<ServiceToken> serviceTokens = builder.getServiceTokens();
        assertTrue(messageHeader.getServiceTokens().containsAll(serviceTokens));
        assertEquals(USER_AUTH_DATA, messageHeader.getUserAuthenticationData());
        assertNull(messageHeader.getUserIdToken());
        assertNull(messageHeader.getUser());
    }
    
    @Test
    public void entityAuthDataPeerMslObject() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslException, MslEncoderException, UnsupportedEncodingException {
        final HeaderDataBuilder builder = new HeaderDataBuilder(p2pCtx, null, null, true);
        final HeaderData headerData = builder.build();
        // Peer service tokens may be created with the key response data master
        // token. The peer key response data master token has the same serial
        // number as the original peer master token so we can use the same peer
        // user ID token.
        final Set<ServiceToken> peerServiceTokens = MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
        final HeaderPeerData peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
        final EntityAuthenticationData entityAuthData = p2pCtx.getEntityAuthenticationData(null);
        final MessageHeader messageHeader = new MessageHeader(p2pCtx, entityAuthData, null, headerData, peerData);
        
        final EntityAuthenticationScheme scheme = entityAuthData.getScheme();
        final EntityAuthenticationFactory factory = p2pCtx.getEntityAuthenticationFactory(scheme);
        final ICryptoContext cryptoContext = factory.getCryptoContext(p2pCtx, entityAuthData);
        
        final MslObject mo = MslTestUtils.toMslObject(encoder, messageHeader);
        final MslObject entityAuthDataMo = mo.getMslObject(KEY_ENTITY_AUTHENTICATION_DATA, encoder);
        assertTrue(MslEncoderUtils.equalObjects(MslTestUtils.toMslObject(encoder, entityAuthData), entityAuthDataMo));
        assertFalse(mo.has(KEY_MASTER_TOKEN));
        final byte[] ciphertext = mo.getBytes(KEY_HEADERDATA);
        final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
        final MslObject headerdata = encoder.parseObject(plaintext);
        final byte[] signature = mo.getBytes(KEY_SIGNATURE);
        assertTrue(cryptoContext.verify(ciphertext, signature, encoder));
        
        assertEquals(NON_REPLAYABLE_ID, (Long)headerdata.getLong(KEY_NON_REPLAYABLE_ID));
        assertEquals(RENEWABLE, headerdata.getBoolean(KEY_RENEWABLE));
        assertEquals(HANDSHAKE, headerdata.getBoolean(KEY_HANDSHAKE));
        assertTrue(MslEncoderUtils.equalObjects(MslTestUtils.toMslObject(encoder, CAPABILITIES), headerdata.getMslObject(KEY_CAPABILITIES, encoder)));
        assertTrue(MslEncoderUtils.equalArrays(MslEncoderUtils.createArray(p2pCtx, format, PEER_KEY_REQUEST_DATA), headerdata.getMslArray(KEY_KEY_REQUEST_DATA)));
        assertTrue(MslEncoderUtils.equalObjects(MslTestUtils.toMslObject(encoder, PEER_KEY_RESPONSE_DATA), headerdata.getMslObject(KEY_KEY_RESPONSE_DATA, encoder)));
        assertTrue(isAboutNowSeconds(headerdata.getLong(KEY_TIMESTAMP)));
        assertEquals(MESSAGE_ID, headerdata.getLong(KEY_MESSAGE_ID));
        assertTrue(MslEncoderUtils.equalObjects(MslTestUtils.toMslObject(encoder, PEER_MASTER_TOKEN), headerdata.getMslObject(KEY_PEER_MASTER_TOKEN, encoder)));
        assertTrue(MslEncoderUtils.equalArrays(MslEncoderUtils.createArray(p2pCtx, format, peerServiceTokens), headerdata.getMslArray(KEY_PEER_SERVICE_TOKENS)));
        assertTrue(MslEncoderUtils.equalObjects(MslTestUtils.toMslObject(encoder, PEER_USER_ID_TOKEN), headerdata.getMslObject(KEY_PEER_USER_ID_TOKEN, encoder)));
        final Set<ServiceToken> serviceTokens = builder.getServiceTokens();
        assertTrue(MslEncoderUtils.equalArrays(MslEncoderUtils.createArray(p2pCtx, format, serviceTokens), headerdata.getMslArray(KEY_SERVICE_TOKENS)));
        assertTrue(MslEncoderUtils.equalObjects(MslTestUtils.toMslObject(encoder, USER_AUTH_DATA), headerdata.getMslObject(KEY_USER_AUTHENTICATION_DATA, encoder)));
        assertFalse(headerdata.has(KEY_USER_ID_TOKEN));
    }
    
    @Test
    public void entityAuthDataReplayablePeerMslObject() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslException, MslEncoderException, UnsupportedEncodingException {
        final HeaderDataBuilder builder = new HeaderDataBuilder(p2pCtx, null, null, true);
        builder.set(KEY_NON_REPLAYABLE_ID, null);
        final HeaderData headerData = builder.build();
        // Peer service tokens may be created with the key response data master
        // token. The peer key response data master token has the same serial
        // number as the original peer master token so we can use the same peer
        // user ID token.
        final Set<ServiceToken> peerServiceTokens = MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
        final HeaderPeerData peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
        final EntityAuthenticationData entityAuthData = p2pCtx.getEntityAuthenticationData(null);
        final MessageHeader messageHeader = new MessageHeader(p2pCtx, entityAuthData, null, headerData, peerData);
        
        final EntityAuthenticationScheme scheme = entityAuthData.getScheme();
        final EntityAuthenticationFactory factory = p2pCtx.getEntityAuthenticationFactory(scheme);
        final ICryptoContext cryptoContext = factory.getCryptoContext(p2pCtx, entityAuthData);
        
        final MslObject mo = MslTestUtils.toMslObject(encoder, messageHeader);
        final MslObject entityAuthDataMo = mo.getMslObject(KEY_ENTITY_AUTHENTICATION_DATA, encoder);
        assertTrue(MslEncoderUtils.equalObjects(MslTestUtils.toMslObject(encoder, entityAuthData), entityAuthDataMo));
        assertFalse(mo.has(KEY_MASTER_TOKEN));
        final byte[] ciphertext = mo.getBytes(KEY_HEADERDATA);
        final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
        final MslObject headerdata = encoder.parseObject(plaintext);
        final byte[] signature = mo.getBytes(KEY_SIGNATURE);
        assertTrue(cryptoContext.verify(ciphertext, signature, encoder));
        
        assertFalse(headerdata.has(KEY_NON_REPLAYABLE_ID));
        assertEquals(RENEWABLE, headerdata.getBoolean(KEY_RENEWABLE));
        assertEquals(HANDSHAKE, headerdata.getBoolean(KEY_HANDSHAKE));
        assertTrue(MslEncoderUtils.equalObjects(MslTestUtils.toMslObject(encoder, CAPABILITIES), headerdata.getMslObject(KEY_CAPABILITIES, encoder)));
        assertTrue(MslEncoderUtils.equalArrays(MslEncoderUtils.createArray(p2pCtx, format, PEER_KEY_REQUEST_DATA), headerdata.getMslArray(KEY_KEY_REQUEST_DATA)));
        assertTrue(MslEncoderUtils.equalObjects(MslTestUtils.toMslObject(encoder, PEER_KEY_RESPONSE_DATA), headerdata.getMslObject(KEY_KEY_RESPONSE_DATA, encoder)));
        assertTrue(isAboutNowSeconds(headerdata.getLong(KEY_TIMESTAMP)));
        assertEquals(MESSAGE_ID, headerdata.getLong(KEY_MESSAGE_ID));
        assertTrue(MslEncoderUtils.equalObjects(MslTestUtils.toMslObject(encoder, PEER_MASTER_TOKEN), headerdata.getMslObject(KEY_PEER_MASTER_TOKEN, encoder)));
        assertTrue(MslEncoderUtils.equalArrays(MslEncoderUtils.createArray(p2pCtx, format, peerServiceTokens), headerdata.getMslArray(KEY_PEER_SERVICE_TOKENS)));
        assertTrue(MslEncoderUtils.equalObjects(MslTestUtils.toMslObject(encoder, PEER_USER_ID_TOKEN), headerdata.getMslObject(KEY_PEER_USER_ID_TOKEN, encoder)));
        final Set<ServiceToken> serviceTokens = builder.getServiceTokens();
        assertTrue(MslEncoderUtils.equalArrays(MslEncoderUtils.createArray(p2pCtx, format, serviceTokens), headerdata.getMslArray(KEY_SERVICE_TOKENS)));
        assertTrue(MslEncoderUtils.equalObjects(MslTestUtils.toMslObject(encoder, USER_AUTH_DATA), headerdata.getMslObject(KEY_USER_AUTHENTICATION_DATA, encoder)));
        assertFalse(headerdata.has(KEY_USER_ID_TOKEN));
    }
    
    @Test
    public void masterTokenCtors() throws MslMasterTokenException, MslEntityAuthException, MslException {
        // Service tokens may be created with the key response data tokens. The
        // key response data master token has the same serial number as the
        // original master token so we can use the same user ID token.
        final HeaderDataBuilder builder = new HeaderDataBuilder(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
        final HeaderData headerData = builder.build();
        final Set<ServiceToken> peerServiceTokens = MslTestUtils.getServiceTokens(trustedNetCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
        final HeaderPeerData peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
        final EntityAuthenticationData entityAuthData = trustedNetCtx.getEntityAuthenticationData(null);
        final MessageHeader messageHeader = new MessageHeader(trustedNetCtx, entityAuthData, MASTER_TOKEN, headerData, peerData);
        
        assertTrue(messageHeader.isEncrypting());
        assertEquals(NON_REPLAYABLE_ID, messageHeader.getNonReplayableId());
        assertEquals(RENEWABLE, messageHeader.isRenewable());
        assertEquals(HANDSHAKE, messageHeader.isHandshake());
        assertEquals(CAPABILITIES, messageHeader.getMessageCapabilities());
        assertNotNull(messageHeader.getCryptoContext());
        assertNull(messageHeader.getEntityAuthenticationData());
        final Set<KeyRequestData> keyRequestData = messageHeader.getKeyRequestData();
        assertTrue(keyRequestData.containsAll(KEY_REQUEST_DATA));
        assertEquals(KEY_RESPONSE_DATA, messageHeader.getKeyResponseData());
        assertEquals(MASTER_TOKEN, messageHeader.getMasterToken());
        assertTrue(isAboutNow(messageHeader.getTimestamp()));
        assertEquals(MESSAGE_ID, messageHeader.getMessageId());
        assertNull(messageHeader.getPeerMasterToken());
        assertTrue(messageHeader.getPeerServiceTokens().isEmpty());
        assertNull(messageHeader.getPeerUserIdToken());
        final Set<ServiceToken> serviceTokens = builder.getServiceTokens();
        assertTrue(messageHeader.getServiceTokens().containsAll(serviceTokens));
        assertEquals(USER_AUTH_DATA, messageHeader.getUserAuthenticationData());
        assertEquals(USER_ID_TOKEN, messageHeader.getUserIdToken());
        assertEquals(USER_ID_TOKEN.getUser(), messageHeader.getUser());
    }
    
    @Test
    public void masterTokenMslObject() throws MslEntityAuthException, MslException, MslEncoderException, UnsupportedEncodingException {
        // Service tokens may be created with the key response data tokens. The
        // key response data master token has the same serial number as the
        // original master token so we can use the same user ID token.
        final HeaderDataBuilder builder = new HeaderDataBuilder(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
        final HeaderData headerData = builder.build();
        final Set<ServiceToken> peerServiceTokens = MslTestUtils.getServiceTokens(trustedNetCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
        final HeaderPeerData peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
        final EntityAuthenticationData entityAuthData = trustedNetCtx.getEntityAuthenticationData(null);
        final MessageHeader messageHeader = new MessageHeader(trustedNetCtx, entityAuthData, MASTER_TOKEN, headerData, peerData);
        
        final ICryptoContext cryptoContext = new SessionCryptoContext(trustedNetCtx, MASTER_TOKEN);
        
        final MslObject mo = MslTestUtils.toMslObject(encoder, messageHeader);
        assertFalse(mo.has(KEY_ENTITY_AUTHENTICATION_DATA));
        final MslObject masterToken = mo.getMslObject(KEY_MASTER_TOKEN, encoder);
        assertTrue(MslEncoderUtils.equalObjects(MslTestUtils.toMslObject(encoder, MASTER_TOKEN), masterToken));
        final byte[] ciphertext = mo.getBytes(KEY_HEADERDATA);
        final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
        final MslObject headerdata = encoder.parseObject(plaintext);
        final byte[] signature = mo.getBytes(KEY_SIGNATURE);
        assertTrue(cryptoContext.verify(ciphertext, signature, encoder));
        
        assertEquals(NON_REPLAYABLE_ID, (Long)headerdata.getLong(KEY_NON_REPLAYABLE_ID));
        assertEquals(RENEWABLE, headerdata.getBoolean(KEY_RENEWABLE));
        assertEquals(HANDSHAKE, headerdata.getBoolean(KEY_HANDSHAKE));
        assertTrue(MslEncoderUtils.equalObjects(MslTestUtils.toMslObject(encoder, CAPABILITIES), headerdata.getMslObject(KEY_CAPABILITIES, encoder)));
        assertTrue(MslEncoderUtils.equalArrays(MslEncoderUtils.createArray(trustedNetCtx, format, KEY_REQUEST_DATA), headerdata.getMslArray(KEY_KEY_REQUEST_DATA)));
        assertTrue(MslEncoderUtils.equalObjects(MslTestUtils.toMslObject(encoder, KEY_RESPONSE_DATA), headerdata.getMslObject(KEY_KEY_RESPONSE_DATA, encoder)));
        assertTrue(isAboutNowSeconds(headerdata.getLong(KEY_TIMESTAMP)));
        assertEquals(MESSAGE_ID, headerdata.getLong(KEY_MESSAGE_ID));
        assertFalse(headerdata.has(KEY_PEER_MASTER_TOKEN));
        assertFalse(headerdata.has(KEY_PEER_SERVICE_TOKENS));
        assertFalse(headerdata.has(KEY_PEER_USER_ID_TOKEN));
        final Set<ServiceToken> serviceTokens = builder.getServiceTokens();
        assertTrue(MslEncoderUtils.equalArrays(MslEncoderUtils.createArray(trustedNetCtx, format, serviceTokens), headerdata.getMslArray(KEY_SERVICE_TOKENS)));
        assertTrue(MslEncoderUtils.equalObjects(MslTestUtils.toMslObject(encoder, USER_AUTH_DATA), headerdata.getMslObject(KEY_USER_AUTHENTICATION_DATA, encoder)));
        assertTrue(MslEncoderUtils.equalObjects(MslTestUtils.toMslObject(encoder, USER_ID_TOKEN), headerdata.getMslObject(KEY_USER_ID_TOKEN, encoder)));
    }
    
    @Test
    public void masterTokenPeerCtors() throws MslMasterTokenException, MslEntityAuthException, MslException {
        // The key response data master token has the same serial number as
        // the original master token so we can use the same service tokens and
        // user ID token.
        final HeaderDataBuilder builder = new HeaderDataBuilder(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
        final HeaderData headerData = builder.build();
        // Peer service tokens may be created with the key response data master
        // token. The peer key response data master token has the same serial
        // number as the original peer master token so we can use the same peer
        // user ID token.
        final Set<ServiceToken> peerServiceTokens = MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
        final HeaderPeerData peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
        final EntityAuthenticationData entityAuthData = p2pCtx.getEntityAuthenticationData(null);
        final MessageHeader messageHeader = new MessageHeader(p2pCtx, entityAuthData, MASTER_TOKEN, headerData, peerData);
        
        assertTrue(messageHeader.isEncrypting());
        assertEquals(NON_REPLAYABLE_ID, messageHeader.getNonReplayableId());
        assertEquals(RENEWABLE, messageHeader.isRenewable());
        assertEquals(HANDSHAKE, messageHeader.isHandshake());
        assertEquals(CAPABILITIES, messageHeader.getMessageCapabilities());
        assertNotNull(messageHeader.getCryptoContext());
        assertNull(messageHeader.getEntityAuthenticationData());
        final Set<KeyRequestData> keyRequestData = messageHeader.getKeyRequestData();
        assertTrue(keyRequestData.containsAll(PEER_KEY_REQUEST_DATA));
        assertEquals(PEER_KEY_RESPONSE_DATA, messageHeader.getKeyResponseData());
        assertEquals(MASTER_TOKEN, messageHeader.getMasterToken());
        assertTrue(isAboutNow(messageHeader.getTimestamp()));
        assertEquals(MESSAGE_ID, messageHeader.getMessageId());
        assertEquals(PEER_MASTER_TOKEN, messageHeader.getPeerMasterToken());
        assertTrue(messageHeader.getPeerServiceTokens().containsAll(peerServiceTokens));
        assertEquals(PEER_USER_ID_TOKEN, messageHeader.getPeerUserIdToken());
        final Set<ServiceToken> serviceTokens = builder.getServiceTokens();
        assertTrue(messageHeader.getServiceTokens().containsAll(serviceTokens));
        assertEquals(USER_AUTH_DATA, messageHeader.getUserAuthenticationData());
        assertEquals(USER_ID_TOKEN, messageHeader.getUserIdToken());
        assertEquals(USER_ID_TOKEN.getUser(), messageHeader.getUser());
    }
    
    @Test
    public void masterTokenPeerMslObject() throws MslMasterTokenException, MslEntityAuthException, MslException, MslEncoderException, UnsupportedEncodingException {
        // The key response data master token has the same serial number as
        // the original master token so we can use the same service tokens and
        // user ID token.
        final HeaderDataBuilder builder = new HeaderDataBuilder(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
        final HeaderData headerData = builder.build();
        // Peer service tokens may be created with the key response data master
        // token. The peer key response data master token has the same serial
        // number as the original peer master token so we can use the same peer
        // user ID token.
        final Set<ServiceToken> peerServiceTokens = MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
        final HeaderPeerData peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
        final EntityAuthenticationData entityAuthData = p2pCtx.getEntityAuthenticationData(null);
        final MessageHeader messageHeader = new MessageHeader(p2pCtx, entityAuthData, MASTER_TOKEN, headerData, peerData);
        
        final ICryptoContext cryptoContext = new SessionCryptoContext(trustedNetCtx, MASTER_TOKEN);
        
        final MslObject mo = MslTestUtils.toMslObject(encoder, messageHeader);
        assertFalse(mo.has(KEY_ENTITY_AUTHENTICATION_DATA));
        final MslObject masterToken = mo.getMslObject(KEY_MASTER_TOKEN, encoder);
        assertTrue(MslEncoderUtils.equalObjects(MslTestUtils.toMslObject(encoder, MASTER_TOKEN), masterToken));
        final byte[] ciphertext = mo.getBytes(KEY_HEADERDATA);
        final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
        final MslObject headerdata = encoder.parseObject(plaintext);
        final byte[] signature = mo.getBytes(KEY_SIGNATURE);
        assertTrue(cryptoContext.verify(ciphertext, signature, encoder));
        
        assertEquals(NON_REPLAYABLE_ID, (Long)headerdata.getLong(KEY_NON_REPLAYABLE_ID));
        assertEquals(RENEWABLE, headerdata.getBoolean(KEY_RENEWABLE));
        assertEquals(HANDSHAKE, headerdata.getBoolean(KEY_HANDSHAKE));
        assertTrue(MslEncoderUtils.equalObjects(MslTestUtils.toMslObject(encoder, CAPABILITIES), headerdata.getMslObject(KEY_CAPABILITIES, encoder)));
        assertTrue(MslEncoderUtils.equalArrays(MslEncoderUtils.createArray(p2pCtx, format, PEER_KEY_REQUEST_DATA), headerdata.getMslArray(KEY_KEY_REQUEST_DATA)));
        assertTrue(MslEncoderUtils.equalObjects(MslTestUtils.toMslObject(encoder, PEER_KEY_RESPONSE_DATA), headerdata.getMslObject(KEY_KEY_RESPONSE_DATA, encoder)));
        assertTrue(isAboutNowSeconds(headerdata.getLong(KEY_TIMESTAMP)));
        assertEquals(MESSAGE_ID, headerdata.getLong(KEY_MESSAGE_ID));
        assertTrue(MslEncoderUtils.equalObjects(MslTestUtils.toMslObject(encoder, PEER_MASTER_TOKEN), headerdata.getMslObject(KEY_PEER_MASTER_TOKEN, encoder)));
        assertTrue(MslEncoderUtils.equalArrays(MslEncoderUtils.createArray(p2pCtx, format, peerServiceTokens), headerdata.getMslArray(KEY_PEER_SERVICE_TOKENS)));
        assertTrue(MslEncoderUtils.equalObjects(MslTestUtils.toMslObject(encoder, PEER_USER_ID_TOKEN), headerdata.getMslObject(KEY_PEER_USER_ID_TOKEN, encoder)));
        final Set<ServiceToken> serviceTokens = builder.getServiceTokens();
        assertTrue(MslEncoderUtils.equalArrays(MslEncoderUtils.createArray(p2pCtx, format, serviceTokens), headerdata.getMslArray(KEY_SERVICE_TOKENS)));
        assertTrue(MslEncoderUtils.equalObjects(MslTestUtils.toMslObject(encoder, USER_AUTH_DATA), headerdata.getMslObject(KEY_USER_AUTHENTICATION_DATA, encoder)));
        assertTrue(MslEncoderUtils.equalObjects(MslTestUtils.toMslObject(encoder, USER_ID_TOKEN), headerdata.getMslObject(KEY_USER_ID_TOKEN, encoder)));
    }
    
    @Test
    public void nullArgumentsEntityAuthCtor() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslException {
        final HeaderDataBuilder builder = new HeaderDataBuilder(p2pCtx, null, null, false);
        builder.set(KEY_CAPABILITIES, null);
        builder.set(KEY_KEY_REQUEST_DATA, null);
        builder.set(KEY_KEY_RESPONSE_DATA, null);
        builder.set(KEY_USER_AUTHENTICATION_DATA, null);
        final HeaderData headerData = builder.build();
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final EntityAuthenticationData entityAuthData = p2pCtx.getEntityAuthenticationData(null);
        final MessageHeader messageHeader = new MessageHeader(p2pCtx, entityAuthData, null, headerData, peerData);
        
        assertTrue(messageHeader.isEncrypting());
        assertEquals(NON_REPLAYABLE_ID, messageHeader.getNonReplayableId());
        assertEquals(RENEWABLE, messageHeader.isRenewable());
        assertEquals(HANDSHAKE, messageHeader.isHandshake());
        assertNull(messageHeader.getMessageCapabilities());
        assertNotNull(messageHeader.getCryptoContext());
        assertEquals(entityAuthData, messageHeader.getEntityAuthenticationData());
        assertTrue(messageHeader.getKeyRequestData().isEmpty());
        assertNull(messageHeader.getKeyResponseData());
        assertNull(messageHeader.getMasterToken());
        assertTrue(isAboutNow(messageHeader.getTimestamp()));
        assertEquals(MESSAGE_ID, messageHeader.getMessageId());
        assertNull(messageHeader.getPeerMasterToken());
        assertTrue(messageHeader.getPeerServiceTokens().isEmpty());
        assertNull(messageHeader.getPeerUserIdToken());
        assertTrue(messageHeader.getServiceTokens().isEmpty());
        assertNull(messageHeader.getUserAuthenticationData());
        assertNull(messageHeader.getUserIdToken());
        assertNull(messageHeader.getUser());
    }

    @Test
    public void emptyArgumentsEntityAuthCtor() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslException {
        final Set<KeyRequestData> keyRequestData = Collections.emptySet();
        final Set<ServiceToken> serviceTokens = Collections.emptySet();
        final HeaderDataBuilder builder = new HeaderDataBuilder(p2pCtx, null, null, false);
        builder.set(KEY_CAPABILITIES, null);
        builder.set(KEY_KEY_REQUEST_DATA, keyRequestData);
        builder.set(KEY_KEY_RESPONSE_DATA, null);
        builder.set(KEY_USER_AUTHENTICATION_DATA, null);
        builder.set(KEY_SERVICE_TOKENS, serviceTokens);
        final HeaderData headerData = builder.build();
        final Set<ServiceToken> peerServiceTokens = Collections.emptySet();
        final HeaderPeerData peerData = new HeaderPeerData(null, null, peerServiceTokens);
        final EntityAuthenticationData entityAuthData = p2pCtx.getEntityAuthenticationData(null);
        final MessageHeader messageHeader = new MessageHeader(p2pCtx, entityAuthData, null, headerData, peerData);

        assertTrue(messageHeader.isEncrypting());
        assertEquals(NON_REPLAYABLE_ID, messageHeader.getNonReplayableId());
        assertEquals(RENEWABLE, messageHeader.isRenewable());
        assertEquals(HANDSHAKE, messageHeader.isHandshake());
        assertNull(messageHeader.getMessageCapabilities());
        assertNotNull(messageHeader.getCryptoContext());
        assertEquals(entityAuthData, messageHeader.getEntityAuthenticationData());
        assertTrue(messageHeader.getKeyRequestData().isEmpty());
        assertNull(messageHeader.getKeyResponseData());
        assertNull(messageHeader.getMasterToken());
        assertTrue(isAboutNow(messageHeader.getTimestamp()));
        assertEquals(MESSAGE_ID, messageHeader.getMessageId());
        assertNull(messageHeader.getPeerMasterToken());
        assertTrue(messageHeader.getPeerServiceTokens().isEmpty());
        assertNull(messageHeader.getPeerUserIdToken());
        assertTrue(messageHeader.getServiceTokens().isEmpty());
        assertNull(messageHeader.getUserAuthenticationData());
        assertNull(messageHeader.getUserIdToken());
        assertNull(messageHeader.getUser());
    }
    
    @Test
    public void nullArgumentsMasterTokenCtor() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslException {
        final HeaderDataBuilder builder = new HeaderDataBuilder(p2pCtx, null, null, false);
        builder.set(KEY_CAPABILITIES, null);
        builder.set(KEY_KEY_REQUEST_DATA, null);
        builder.set(KEY_KEY_RESPONSE_DATA, null);
        builder.set(KEY_USER_AUTHENTICATION_DATA, null);
        final HeaderData headerData = builder.build();
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final MessageHeader messageHeader = new MessageHeader(p2pCtx, null, MASTER_TOKEN, headerData, peerData);
        
        assertTrue(messageHeader.isEncrypting());
        assertEquals(NON_REPLAYABLE_ID, messageHeader.getNonReplayableId());
        assertEquals(RENEWABLE, messageHeader.isRenewable());
        assertEquals(HANDSHAKE, messageHeader.isHandshake());
        assertNull(messageHeader.getMessageCapabilities());
        assertNotNull(messageHeader.getCryptoContext());
        assertNull(messageHeader.getEntityAuthenticationData());
        assertTrue(messageHeader.getKeyRequestData().isEmpty());
        assertNull(messageHeader.getKeyResponseData());
        assertEquals(MASTER_TOKEN, messageHeader.getMasterToken());
        assertTrue(isAboutNow(messageHeader.getTimestamp()));
        assertEquals(MESSAGE_ID, messageHeader.getMessageId());
        assertNull(messageHeader.getPeerMasterToken());
        assertTrue(messageHeader.getPeerServiceTokens().isEmpty());
        assertNull(messageHeader.getPeerUserIdToken());
        assertTrue(messageHeader.getServiceTokens().isEmpty());
        assertNull(messageHeader.getUserAuthenticationData());
        assertNull(messageHeader.getUserIdToken());
        assertNull(messageHeader.getUser());
    }
    
    @Test
    public void emptyArgumentsMasterTokenCtor() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslException {
        final Set<KeyRequestData> keyRequestData = Collections.emptySet();
        final Set<ServiceToken> serviceTokens = Collections.emptySet();
        final HeaderDataBuilder builder = new HeaderDataBuilder(p2pCtx, null, null, false);
        builder.set(KEY_CAPABILITIES, null);
        builder.set(KEY_KEY_REQUEST_DATA, keyRequestData);
        builder.set(KEY_KEY_RESPONSE_DATA, null);
        builder.set(KEY_USER_AUTHENTICATION_DATA, null);
        builder.set(KEY_SERVICE_TOKENS, serviceTokens);
        final HeaderData headerData = builder.build();
        final Set<ServiceToken> peerServiceTokens = Collections.emptySet();
        final HeaderPeerData peerData = new HeaderPeerData(null, null, peerServiceTokens);
        final MessageHeader messageHeader = new MessageHeader(p2pCtx, null, MASTER_TOKEN, headerData, peerData);

        assertTrue(messageHeader.isEncrypting());
        assertEquals(NON_REPLAYABLE_ID, messageHeader.getNonReplayableId());
        assertEquals(RENEWABLE, messageHeader.isRenewable());
        assertEquals(HANDSHAKE, messageHeader.isHandshake());
        assertNull(messageHeader.getMessageCapabilities());
        assertNotNull(messageHeader.getCryptoContext());
        assertNull(messageHeader.getEntityAuthenticationData());
        assertTrue(messageHeader.getKeyRequestData().isEmpty());
        assertNull(messageHeader.getKeyResponseData());
        assertEquals(MASTER_TOKEN, messageHeader.getMasterToken());
        assertTrue(isAboutNow(messageHeader.getTimestamp()));
        assertEquals(MESSAGE_ID, messageHeader.getMessageId());
        assertNull(messageHeader.getPeerMasterToken());
        assertTrue(messageHeader.getPeerServiceTokens().isEmpty());
        assertNull(messageHeader.getPeerUserIdToken());
        assertTrue(messageHeader.getServiceTokens().isEmpty());
        assertNull(messageHeader.getUserAuthenticationData());
        assertNull(messageHeader.getUserIdToken());
        assertNull(messageHeader.getUser());
    }
    
    @Test
    public void x509isEncrypting() throws MslException {
        final MslContext x509Ctx = new MockMslContext(EntityAuthenticationScheme.X509, false);
        
        final HeaderDataBuilder builder = new HeaderDataBuilder(x509Ctx, MASTER_TOKEN, USER_ID_TOKEN, false);
        builder.set(KEY_USER_AUTHENTICATION_DATA, null);
        final HeaderData headerData = builder.build();
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final EntityAuthenticationData entityAuthData = x509Ctx.getEntityAuthenticationData(null);
        final MessageHeader messageHeader = new MessageHeader(x509Ctx, entityAuthData, null, headerData, peerData);
        
        assertFalse(messageHeader.isEncrypting());
    }
    
    @Test(expected = MslInternalException.class)
    public void missingBothAuthDataCtor() throws MslMasterTokenException, MslEntityAuthException, MslException {
        final HeaderDataBuilder builder = new HeaderDataBuilder(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, false);
        final HeaderData headerData = builder.build();
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        new MessageHeader(trustedNetCtx, null, null, headerData, peerData);
    }
    
    @Test(expected = MslInternalException.class)
    public void userIdTokenNullMasterTokenCtor() throws MslMasterTokenException, MslEntityAuthException, MslException {
        final HeaderDataBuilder builder = new HeaderDataBuilder(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, false);
        builder.set(KEY_KEY_REQUEST_DATA, null);
        builder.set(KEY_KEY_RESPONSE_DATA, null);
        final HeaderData headerData = builder.build();
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final EntityAuthenticationData entityAuthData = trustedNetCtx.getEntityAuthenticationData(null);
        new MessageHeader(trustedNetCtx, entityAuthData, null, headerData, peerData);
    }
    
    @Test(expected = MslInternalException.class)
    public void userIdTokenMismatchedMasterTokenCtor() throws MslMasterTokenException, MslEntityAuthException, MslException {
        final UserIdToken userIdToken = MslTestUtils.getUserIdToken(trustedNetCtx, PEER_MASTER_TOKEN, 1, MockEmailPasswordAuthenticationFactory.USER);
        final HeaderDataBuilder builder = new HeaderDataBuilder(trustedNetCtx, MASTER_TOKEN, userIdToken, false);
        builder.set(KEY_KEY_REQUEST_DATA, null);
        builder.set(KEY_KEY_RESPONSE_DATA, null);
        final HeaderData headerData = builder.build();
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        new MessageHeader(trustedNetCtx, null, MASTER_TOKEN, headerData, peerData);
    }
    
    @Test(expected = MslInternalException.class)
    public void serviceTokenNullMasterTokenCtor() throws MslMasterTokenException, MslEntityAuthException, MslException {
        final HeaderDataBuilder builder = new HeaderDataBuilder(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
        builder.set(KEY_KEY_REQUEST_DATA, null);
        builder.set(KEY_KEY_RESPONSE_DATA, null);
        final HeaderData headerData = builder.build();
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final EntityAuthenticationData entityAuthData = trustedNetCtx.getEntityAuthenticationData(null);
        new MessageHeader(trustedNetCtx, entityAuthData, null, headerData, peerData);
    }
    
    @Test(expected = MslInternalException.class)
    public void serviceTokenMismatchedMasterTokenCtor() throws MslMasterTokenException, MslEntityAuthException, MslException {
        final HeaderDataBuilder builder = new HeaderDataBuilder(trustedNetCtx, PEER_MASTER_TOKEN, null, true);
        builder.set(KEY_KEY_REQUEST_DATA, null);
        builder.set(KEY_KEY_RESPONSE_DATA, null);
        builder.set(KEY_USER_ID_TOKEN, USER_ID_TOKEN);
        final HeaderData headerData = builder.build();
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        new MessageHeader(trustedNetCtx, null, MASTER_TOKEN, headerData, peerData);
    }
    
    @Test(expected = MslInternalException.class)
    public void serviceTokenNullUserIdTokenCtor() throws MslMasterTokenException, MslEntityAuthException, MslException {
        final HeaderDataBuilder builder = new HeaderDataBuilder(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
        builder.set(KEY_KEY_REQUEST_DATA, null);
        builder.set(KEY_KEY_RESPONSE_DATA, null);
        builder.set(KEY_USER_ID_TOKEN, null);
        final HeaderData headerData = builder.build();
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        new MessageHeader(trustedNetCtx, null, MASTER_TOKEN, headerData, peerData);
    }
    
    @Test(expected = MslInternalException.class)
    public void serviceTokenMismatchedUserIdTokenCtor() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslException {
        // Technically the implementation does not hit this check because it
        // will bail out earlier, but in case the implementation changes the
        // order of checks (which it should not) this test will catch it.
        //
        // We cannot construct inconsistent service tokens via the ServiceToken
        // ctor, so pass in a mismatched user ID token.
        final HeaderDataBuilder builder = new HeaderDataBuilder(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
        builder.set(KEY_KEY_REQUEST_DATA, null);
        builder.set(KEY_KEY_RESPONSE_DATA, null);
        builder.set(KEY_USER_ID_TOKEN, PEER_USER_ID_TOKEN);
        final HeaderData headerData = builder.build();
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        new MessageHeader(trustedNetCtx, null, MASTER_TOKEN, headerData, peerData);
    }
    
    @Test(expected = MslInternalException.class)
    public void peerUserIdTokenNullPeerMasterTokenCtor() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslException {
        final HeaderDataBuilder builder = new HeaderDataBuilder(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, false);
        builder.set(KEY_KEY_REQUEST_DATA, null);
        builder.set(KEY_KEY_RESPONSE_DATA, null);
        final HeaderData headerData = builder.build();
        final HeaderPeerData peerData = new HeaderPeerData(null, PEER_USER_ID_TOKEN, null);
        final EntityAuthenticationData entityAuthData = p2pCtx.getEntityAuthenticationData(null);
        new MessageHeader(p2pCtx, entityAuthData, null, headerData, peerData);
    }
    
    @Test(expected = MslInternalException.class)
    public void peerUserIdTokenMismatchedPeerMasterTokenCtor() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslException {
        final HeaderDataBuilder builder = new HeaderDataBuilder(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, false);
        builder.set(KEY_KEY_REQUEST_DATA, null);
        builder.set(KEY_KEY_RESPONSE_DATA, null);
        final HeaderData headerData = builder.build();
        final UserIdToken peerUserIdToken = MslTestUtils.getUserIdToken(p2pCtx, MASTER_TOKEN, 1, MockEmailPasswordAuthenticationFactory.USER);
        final HeaderPeerData peerData = new HeaderPeerData(PEER_MASTER_TOKEN, peerUserIdToken, null);
        final EntityAuthenticationData entityAuthData = p2pCtx.getEntityAuthenticationData(null);
        new MessageHeader(p2pCtx, entityAuthData, null, headerData, peerData);
    }
    
    @Test(expected = MslInternalException.class)
    public void peerServiceTokenNullMasterTokenCtor() throws MslMasterTokenException, MslEntityAuthException, MslException {
        final HeaderDataBuilder builder = new HeaderDataBuilder(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, false);
        builder.set(KEY_KEY_REQUEST_DATA, null);
        builder.set(KEY_KEY_RESPONSE_DATA, null);
        final HeaderData headerData = builder.build();
        final Set<ServiceToken> peerServiceTokens = MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, null);
        final HeaderPeerData peerData = new HeaderPeerData(null, null, peerServiceTokens);
        final EntityAuthenticationData entityAuthData = p2pCtx.getEntityAuthenticationData(null);
        new MessageHeader(p2pCtx, entityAuthData, null, headerData, peerData);
    }
    
    @Test(expected = MslInternalException.class)
    public void peerServiceTokenMismatchedMasterTokenCtor() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslException {
        final HeaderDataBuilder builder = new HeaderDataBuilder(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, false);
        builder.set(KEY_KEY_REQUEST_DATA, null);
        builder.set(KEY_KEY_RESPONSE_DATA, null);
        final HeaderData headerData = builder.build();
        final Set<ServiceToken> peerServiceTokens = MslTestUtils.getServiceTokens(p2pCtx, MASTER_TOKEN, null);
        final HeaderPeerData peerData = new HeaderPeerData(PEER_MASTER_TOKEN, null, peerServiceTokens);
        final EntityAuthenticationData entityAuthData = p2pCtx.getEntityAuthenticationData(null);
        new MessageHeader(p2pCtx, entityAuthData, null, headerData, peerData);
    }
    
    @Test(expected = MslInternalException.class)
    public void peerServiceTokenNullUserIdTokenCtor() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslException {
        final HeaderDataBuilder builder = new HeaderDataBuilder(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, false);
        builder.set(KEY_KEY_REQUEST_DATA, null);
        builder.set(KEY_KEY_RESPONSE_DATA, null);
        final HeaderData headerData = builder.build();
        final Set<ServiceToken> peerServiceTokens = MslTestUtils.getServiceTokens(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
        final HeaderPeerData peerData = new HeaderPeerData(PEER_MASTER_TOKEN, null, peerServiceTokens);
        final EntityAuthenticationData entityAuthData = p2pCtx.getEntityAuthenticationData(null);
        new MessageHeader(p2pCtx, entityAuthData, null, headerData, peerData);
    }
    
    @Test(expected = MslInternalException.class)
    public void peerServiceTokenMismatchedUserIdTokenCtor() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslException {
        // Technically the implementation does not hit this check because it
        // will bail out earlier, but in case the implementation changes the
        // order of checks (which it should not) this test will catch it.
        //
        // We cannot construct inconsistent service tokens via the ServiceToken
        // ctor, so pass in a mismatched user ID token.
        final HeaderDataBuilder builder = new HeaderDataBuilder(p2pCtx, null, null, false);
        builder.set(KEY_KEY_REQUEST_DATA, null);
        builder.set(KEY_KEY_RESPONSE_DATA, null);
        final HeaderData headerData = builder.build();
        final Set<ServiceToken> peerServiceTokens = MslTestUtils.getServiceTokens(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
        final HeaderPeerData peerData = new HeaderPeerData(PEER_MASTER_TOKEN, USER_ID_TOKEN, peerServiceTokens);
        final EntityAuthenticationData entityAuthData = p2pCtx.getEntityAuthenticationData(null);
        new MessageHeader(p2pCtx, entityAuthData, null, headerData, peerData);
    }
    
    @Test
    public void untrustedMasterTokenCtor() throws MslEncodingException, MslCryptoException, MslEncoderException, MslException {
        thrown.expect(MslMasterTokenException.class);
        thrown.expectMslError(MslError.MASTERTOKEN_UNTRUSTED);
        thrown.expectMessageId(MESSAGE_ID);

        final HeaderDataBuilder builder = new HeaderDataBuilder(p2pCtx, null, null, false);
        builder.set(KEY_KEY_REQUEST_DATA, null);
        builder.set(KEY_KEY_RESPONSE_DATA, null);
        final HeaderData headerData = builder.build();
        final HeaderPeerData peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, null);
        final MasterToken masterToken = MslTestUtils.getUntrustedMasterToken(p2pCtx);
        new MessageHeader(p2pCtx, null, masterToken, headerData, peerData);
    }
    
    @Test
    public void unsupportedEntityAuthSchemeCtor() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslException {
        thrown.expect(MslEntityAuthException.class);
        thrown.expectMslError(MslError.ENTITYAUTH_FACTORY_NOT_FOUND);
        thrown.expectMessageId(MESSAGE_ID);

        final MockMslContext ctx = new MockMslContext(EntityAuthenticationScheme.PSK, false);
        final EntityAuthenticationData entityAuthData = ctx.getEntityAuthenticationData(null);
        ctx.removeEntityAuthenticationFactory(entityAuthData.getScheme());
        
        final HeaderDataBuilder builder = new HeaderDataBuilder(ctx, null, null, false);
        builder.set(KEY_KEY_REQUEST_DATA, null);
        builder.set(KEY_KEY_RESPONSE_DATA, null);
        final HeaderData headerData = builder.build();
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        new MessageHeader(ctx, entityAuthData, null, headerData, peerData);
    }
    
    @Test
    public void cachedCryptoContextMasterTokenCtor() throws MslEncodingException, MslCryptoException, MslEncoderException, MslException {
        // We should be okay with an untrusted master token if a crypto context
        // is associated with it.
        final MasterToken masterToken = MslTestUtils.getUntrustedMasterToken(p2pCtx);
        final ICryptoContext cryptoContext = new NullCryptoContext();
        p2pCtx.getMslStore().setCryptoContext(masterToken, cryptoContext);

        final UserIdToken userIdToken = MslTestUtils.getUserIdToken(p2pCtx, masterToken, 1, MockEmailPasswordAuthenticationFactory.USER);
        final HeaderDataBuilder builder = new HeaderDataBuilder(p2pCtx, masterToken, null, true);
        builder.set(KEY_USER_ID_TOKEN, userIdToken);
        final HeaderData headerData = builder.build();
        final Set<ServiceToken> peerServiceTokens = MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
        final HeaderPeerData peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
        final MessageHeader messageHeader = new MessageHeader(p2pCtx, null, masterToken, headerData, peerData);
        
        assertEquals(NON_REPLAYABLE_ID, messageHeader.getNonReplayableId());
        assertEquals(RENEWABLE, messageHeader.isRenewable());
        assertEquals(HANDSHAKE, messageHeader.isHandshake());
        assertNotNull(messageHeader.getCryptoContext());
        assertNull(messageHeader.getEntityAuthenticationData());
        final Set<KeyRequestData> keyRequestData = messageHeader.getKeyRequestData();
        assertTrue(keyRequestData.containsAll(PEER_KEY_REQUEST_DATA));
        assertEquals(PEER_KEY_RESPONSE_DATA, messageHeader.getKeyResponseData());
        assertEquals(masterToken, messageHeader.getMasterToken());
        assertEquals(MESSAGE_ID, messageHeader.getMessageId());
        assertEquals(PEER_MASTER_TOKEN, messageHeader.getPeerMasterToken());
        assertTrue(messageHeader.getPeerServiceTokens().containsAll(peerServiceTokens));
        assertEquals(PEER_USER_ID_TOKEN, messageHeader.getPeerUserIdToken());
        final Set<ServiceToken> serviceTokens = builder.getServiceTokens();
        assertTrue(messageHeader.getServiceTokens().containsAll(serviceTokens));
        assertEquals(USER_AUTH_DATA, messageHeader.getUserAuthenticationData());
        assertEquals(userIdToken, messageHeader.getUserIdToken());
        assertEquals(userIdToken.getUser(), messageHeader.getUser());
    }
    
    @Test
    public void entityAuthDataParseHeader() throws MslMasterTokenException, MslEntityAuthException, MslException, MslEncoderException {
        // Service tokens may be created with the key response data tokens. The
        // key response data master token has the same serial number as the
        // original master token so we can use the same user ID token.
        final HeaderDataBuilder builder = new HeaderDataBuilder(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
        final HeaderData headerData = builder.build();
        final Set<ServiceToken> peerServiceTokens = MslTestUtils.getServiceTokens(trustedNetCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
        final HeaderPeerData peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
        final EntityAuthenticationData entityAuthData = trustedNetCtx.getEntityAuthenticationData(null);
        final MessageHeader messageHeader = new MessageHeader(trustedNetCtx, entityAuthData, null, headerData, peerData);
        
        final MslObject messageHeaderMo = MslTestUtils.toMslObject(encoder, messageHeader);
        final Header header = Header.parseHeader(trustedNetCtx, messageHeaderMo, CRYPTO_CONTEXTS);
        assertNotNull(header);
        assertTrue(header instanceof MessageHeader);
        final MessageHeader moMessageHeader = (MessageHeader)header;
        
        assertEquals(messageHeader.getNonReplayableId(), moMessageHeader.getNonReplayableId());
        assertEquals(messageHeader.isRenewable(), moMessageHeader.isRenewable());
        assertNotNull(messageHeader.getCryptoContext());
        assertEquals(messageHeader.getEntityAuthenticationData(), moMessageHeader.getEntityAuthenticationData());
        final Set<KeyRequestData> keyRequestData = messageHeader.getKeyRequestData();
        final Set<KeyRequestData> moKeyRequestData = moMessageHeader.getKeyRequestData();
        assertTrue(keyRequestData.containsAll(moKeyRequestData));
        assertTrue(moKeyRequestData.containsAll(keyRequestData));
        assertEquals(messageHeader.getKeyResponseData(), moMessageHeader.getKeyResponseData());
        assertEquals(messageHeader.getMasterToken(), moMessageHeader.getMasterToken());
        assertEquals(messageHeader.getMessageId(), moMessageHeader.getMessageId());
        assertNull(messageHeader.getPeerMasterToken());
        assertTrue(messageHeader.getPeerServiceTokens().isEmpty());
        assertNull(messageHeader.getPeerUserIdToken());
        final Set<ServiceToken> serviceTokens = messageHeader.getServiceTokens();
        final Set<ServiceToken> moServiceTokens = moMessageHeader.getServiceTokens();
        assertTrue(serviceTokens.containsAll(moServiceTokens));
        assertTrue(moServiceTokens.containsAll(serviceTokens));
        assertEquals(messageHeader.getUserAuthenticationData(), moMessageHeader.getUserAuthenticationData());
        assertEquals(messageHeader.getUserIdToken(), moMessageHeader.getUserIdToken());
        assertEquals(messageHeader.getUser(), moMessageHeader.getUser());
    }
    
    @Test
    public void entityAuthDataPeerParseHeader() throws MslMasterTokenException, MslEntityAuthException, MslException, MslEncoderException {
        // Service tokens may be created with the key response data tokens. The
        // key response data master token has the same serial number as the
        // original master token so we can use the same user ID token.
        final HeaderDataBuilder builder = new HeaderDataBuilder(p2pCtx, null, null, true);
        final HeaderData headerData = builder.build();
        final Set<ServiceToken> peerServiceTokens = MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
        final HeaderPeerData peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
        final EntityAuthenticationData entityAuthData = p2pCtx.getEntityAuthenticationData(null);
        final MessageHeader messageHeader = new MessageHeader(p2pCtx, entityAuthData, null, headerData, peerData);
        
        final MslObject messageHeaderMo = MslTestUtils.toMslObject(encoder, messageHeader);
        final Header header = Header.parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS);
        assertNotNull(header);
        assertTrue(header instanceof MessageHeader);
        final MessageHeader moMessageHeader = (MessageHeader)header;
        
        assertEquals(messageHeader.getNonReplayableId(), moMessageHeader.getNonReplayableId());
        assertEquals(messageHeader.isRenewable(), moMessageHeader.isRenewable());
        assertNotNull(messageHeader.getCryptoContext());
        assertEquals(messageHeader.getEntityAuthenticationData(), moMessageHeader.getEntityAuthenticationData());
        final Set<KeyRequestData> keyRequestData = messageHeader.getKeyRequestData();
        final Set<KeyRequestData> moKeyRequestData = moMessageHeader.getKeyRequestData();
        assertTrue(keyRequestData.containsAll(moKeyRequestData));
        assertTrue(moKeyRequestData.containsAll(keyRequestData));
        assertEquals(messageHeader.getKeyResponseData(), moMessageHeader.getKeyResponseData());
        assertEquals(messageHeader.getMasterToken(), moMessageHeader.getMasterToken());
        assertEquals(messageHeader.getMessageId(), moMessageHeader.getMessageId());
        assertEquals(messageHeader.getPeerMasterToken(), moMessageHeader.getPeerMasterToken());
        final Set<ServiceToken> moPeerServiceTokens = moMessageHeader.getPeerServiceTokens();
        assertTrue(peerServiceTokens.containsAll(moPeerServiceTokens));
        assertTrue(moPeerServiceTokens.containsAll(peerServiceTokens));
        assertEquals(messageHeader.getPeerUserIdToken(), moMessageHeader.getPeerUserIdToken());
        final Set<ServiceToken> serviceTokens = messageHeader.getServiceTokens();
        final Set<ServiceToken> moServiceTokens = moMessageHeader.getServiceTokens();
        assertTrue(serviceTokens.containsAll(moServiceTokens));
        assertTrue(moServiceTokens.containsAll(serviceTokens));
        assertEquals(messageHeader.getUserAuthenticationData(), moMessageHeader.getUserAuthenticationData());
        assertEquals(messageHeader.getUserIdToken(), moMessageHeader.getUserIdToken());
        assertNotNull(moMessageHeader.getUser());
    }
    
    @Test
    public void masterTokenParseHeader() throws MslMasterTokenException, MslEntityAuthException, MslException, MslEncoderException {
        final HeaderDataBuilder builder = new HeaderDataBuilder(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
        final HeaderData headerData = builder.build();
        final Set<ServiceToken> peerServiceTokens = MslTestUtils.getServiceTokens(trustedNetCtx,PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
        final HeaderPeerData peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
        final EntityAuthenticationData entityAuthData = trustedNetCtx.getEntityAuthenticationData(null);
        final MessageHeader messageHeader = new MessageHeader(trustedNetCtx, entityAuthData, MASTER_TOKEN, headerData, peerData);
        
        final MslObject messageHeaderMo = MslTestUtils.toMslObject(encoder, messageHeader);
        final Header header = Header.parseHeader(trustedNetCtx, messageHeaderMo, CRYPTO_CONTEXTS);
        assertNotNull(header);
        assertTrue(header instanceof MessageHeader);
        final MessageHeader moMessageHeader = (MessageHeader)header;
        
        assertEquals(messageHeader.getNonReplayableId(), moMessageHeader.getNonReplayableId());
        assertEquals(messageHeader.isRenewable(), moMessageHeader.isRenewable());
        assertNotNull(messageHeader.getCryptoContext());
        assertEquals(messageHeader.getEntityAuthenticationData(), moMessageHeader.getEntityAuthenticationData());
        final Set<KeyRequestData> keyRequestData = messageHeader.getKeyRequestData();
        final Set<KeyRequestData> moKeyRequestData = moMessageHeader.getKeyRequestData();
        assertTrue(keyRequestData.containsAll(moKeyRequestData));
        assertTrue(moKeyRequestData.containsAll(keyRequestData));
        assertEquals(messageHeader.getKeyResponseData(), moMessageHeader.getKeyResponseData());
        assertEquals(messageHeader.getMasterToken(), moMessageHeader.getMasterToken());
        assertEquals(messageHeader.getMessageId(), moMessageHeader.getMessageId());
        assertNull(moMessageHeader.getPeerMasterToken());
        assertTrue(moMessageHeader.getPeerServiceTokens().isEmpty());
        assertNull(moMessageHeader.getPeerUserIdToken());
        final Set<ServiceToken> serviceTokens = messageHeader.getServiceTokens();
        final Set<ServiceToken> moServiceTokens = moMessageHeader.getServiceTokens();
        assertTrue(serviceTokens.containsAll(moServiceTokens));
        assertTrue(moServiceTokens.containsAll(serviceTokens));
        assertEquals(messageHeader.getUserAuthenticationData(), moMessageHeader.getUserAuthenticationData());
        assertEquals(messageHeader.getUserIdToken(), moMessageHeader.getUserIdToken());
        assertEquals(messageHeader.getUser(), moMessageHeader.getUser());
    }
    
    @Test
    public void masterTokenPeerParseHeader() throws MslMasterTokenException, MslEntityAuthException, MslException, MslEncoderException {
        final HeaderDataBuilder builder = new HeaderDataBuilder(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
        final HeaderData headerData = builder.build();
        final Set<ServiceToken> peerServiceTokens = MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
        final HeaderPeerData peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
        final EntityAuthenticationData entityAuthData = p2pCtx.getEntityAuthenticationData(null);
        final MessageHeader messageHeader = new MessageHeader(p2pCtx, entityAuthData, MASTER_TOKEN, headerData, peerData);
        
        final MslObject messageHeaderMo = MslTestUtils.toMslObject(encoder, messageHeader);
        final Header header = Header.parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS);
        assertNotNull(header);
        assertTrue(header instanceof MessageHeader);
        final MessageHeader moMessageHeader = (MessageHeader)header;
        
        assertEquals(messageHeader.getNonReplayableId(), moMessageHeader.getNonReplayableId());
        assertEquals(messageHeader.isRenewable(), moMessageHeader.isRenewable());
        assertNotNull(messageHeader.getCryptoContext());
        assertEquals(messageHeader.getEntityAuthenticationData(), moMessageHeader.getEntityAuthenticationData());
        final Set<KeyRequestData> keyRequestData = messageHeader.getKeyRequestData();
        final Set<KeyRequestData> moKeyRequestData = moMessageHeader.getKeyRequestData();
        assertTrue(keyRequestData.containsAll(moKeyRequestData));
        assertTrue(moKeyRequestData.containsAll(keyRequestData));
        assertEquals(messageHeader.getKeyResponseData(), moMessageHeader.getKeyResponseData());
        assertEquals(messageHeader.getMasterToken(), moMessageHeader.getMasterToken());
        assertEquals(messageHeader.getMessageId(), moMessageHeader.getMessageId());
        assertEquals(messageHeader.getPeerMasterToken(), moMessageHeader.getPeerMasterToken());
        final Set<ServiceToken> moPeerServiceTokens = moMessageHeader.getPeerServiceTokens();
        assertTrue(peerServiceTokens.containsAll(moPeerServiceTokens));
        assertTrue(moPeerServiceTokens.containsAll(peerServiceTokens));
        assertEquals(messageHeader.getPeerUserIdToken(), moMessageHeader.getPeerUserIdToken());
        final Set<ServiceToken> serviceTokens = messageHeader.getServiceTokens();
        final Set<ServiceToken> moServiceTokens = moMessageHeader.getServiceTokens();
        assertTrue(serviceTokens.containsAll(moServiceTokens));
        assertTrue(moServiceTokens.containsAll(serviceTokens));
        assertEquals(messageHeader.getUserAuthenticationData(), moMessageHeader.getUserAuthenticationData());
        assertEquals(messageHeader.getUserIdToken(), moMessageHeader.getUserIdToken());
        assertEquals(messageHeader.getUser(), moMessageHeader.getUser());
    }
    
    @Test
    public void userAuthDataParseHeader() throws MslEncoderException, MslKeyExchangeException, MslUserAuthException, MslException {
        final HeaderDataBuilder builder = new HeaderDataBuilder(trustedNetCtx, MASTER_TOKEN, null, true);
        final HeaderData headerData = builder.build();
        final Set<ServiceToken> peerServiceTokens = MslTestUtils.getServiceTokens(trustedNetCtx,PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
        final HeaderPeerData peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
        final EntityAuthenticationData entityAuthData = trustedNetCtx.getEntityAuthenticationData(null);
        final MessageHeader messageHeader = new MessageHeader(trustedNetCtx, entityAuthData, MASTER_TOKEN, headerData, peerData);
        
        final MslObject messageHeaderMo = MslTestUtils.toMslObject(encoder, messageHeader);
        final Header header = Header.parseHeader(trustedNetCtx, messageHeaderMo, CRYPTO_CONTEXTS);
        assertNotNull(header);
        assertTrue(header instanceof MessageHeader);
        final MessageHeader moMessageHeader = (MessageHeader)header;
        
        assertEquals(messageHeader.getNonReplayableId(), moMessageHeader.getNonReplayableId());
        assertEquals(messageHeader.isRenewable(), moMessageHeader.isRenewable());
        assertNotNull(messageHeader.getCryptoContext());
        assertEquals(messageHeader.getEntityAuthenticationData(), moMessageHeader.getEntityAuthenticationData());
        final Set<KeyRequestData> keyRequestData = messageHeader.getKeyRequestData();
        final Set<KeyRequestData> moKeyRequestData = moMessageHeader.getKeyRequestData();
        assertTrue(keyRequestData.containsAll(moKeyRequestData));
        assertTrue(moKeyRequestData.containsAll(keyRequestData));
        assertEquals(messageHeader.getKeyResponseData(), moMessageHeader.getKeyResponseData());
        assertEquals(messageHeader.getMasterToken(), moMessageHeader.getMasterToken());
        assertEquals(messageHeader.getMessageId(), moMessageHeader.getMessageId());
        assertNull(moMessageHeader.getPeerMasterToken());
        assertTrue(moMessageHeader.getPeerServiceTokens().isEmpty());
        assertNull(moMessageHeader.getPeerUserIdToken());
        final Set<ServiceToken> serviceTokens = messageHeader.getServiceTokens();
        final Set<ServiceToken> moServiceTokens = moMessageHeader.getServiceTokens();
        assertTrue(serviceTokens.containsAll(moServiceTokens));
        assertTrue(moServiceTokens.containsAll(serviceTokens));
        assertEquals(messageHeader.getUserAuthenticationData(), moMessageHeader.getUserAuthenticationData());
        assertEquals(messageHeader.getUserIdToken(), moMessageHeader.getUserIdToken());
        assertNotNull(moMessageHeader.getUser());
    }
    
    @Test
    public void userAuthDataPeerParseHeader() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslMessageException, MslKeyExchangeException, MslUserAuthException, MslEncoderException, MslException {
        final HeaderDataBuilder builder = new HeaderDataBuilder(p2pCtx, MASTER_TOKEN, null, true);
        final HeaderData headerData = builder.build();
        final Set<ServiceToken> peerServiceTokens = MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
        final HeaderPeerData peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
        final EntityAuthenticationData entityAuthData = p2pCtx.getEntityAuthenticationData(null);
        final MessageHeader messageHeader = new MessageHeader(p2pCtx, entityAuthData, MASTER_TOKEN, headerData, peerData);
        
        final MslObject messageHeaderMo = MslTestUtils.toMslObject(encoder, messageHeader);
        final Header header = Header.parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS);
        assertNotNull(header);
        assertTrue(header instanceof MessageHeader);
        final MessageHeader moMessageHeader = (MessageHeader)header;
        
        assertEquals(messageHeader.getNonReplayableId(), moMessageHeader.getNonReplayableId());
        assertEquals(messageHeader.isRenewable(), moMessageHeader.isRenewable());
        assertNotNull(messageHeader.getCryptoContext());
        assertEquals(messageHeader.getEntityAuthenticationData(), moMessageHeader.getEntityAuthenticationData());
        final Set<KeyRequestData> keyRequestData = messageHeader.getKeyRequestData();
        final Set<KeyRequestData> moKeyRequestData = moMessageHeader.getKeyRequestData();
        assertTrue(keyRequestData.containsAll(moKeyRequestData));
        assertTrue(moKeyRequestData.containsAll(keyRequestData));
        assertEquals(messageHeader.getKeyResponseData(), moMessageHeader.getKeyResponseData());
        assertEquals(messageHeader.getMasterToken(), moMessageHeader.getMasterToken());
        assertEquals(messageHeader.getMessageId(), moMessageHeader.getMessageId());
        assertEquals(messageHeader.getPeerMasterToken(), moMessageHeader.getPeerMasterToken());
        final Set<ServiceToken> moPeerServiceTokens = moMessageHeader.getPeerServiceTokens();
        assertTrue(peerServiceTokens.containsAll(moPeerServiceTokens));
        assertTrue(moPeerServiceTokens.containsAll(peerServiceTokens));
        assertEquals(messageHeader.getPeerUserIdToken(), moMessageHeader.getPeerUserIdToken());
        final Set<ServiceToken> serviceTokens = messageHeader.getServiceTokens();
        final Set<ServiceToken> moServiceTokens = moMessageHeader.getServiceTokens();
        assertTrue(serviceTokens.containsAll(moServiceTokens));
        assertTrue(moServiceTokens.containsAll(serviceTokens));
        assertEquals(messageHeader.getUserAuthenticationData(), moMessageHeader.getUserAuthenticationData());
        assertEquals(messageHeader.getUserIdToken(), moMessageHeader.getUserIdToken());
        assertNotNull(moMessageHeader.getUser());
    }
    
    @Test
    public void untrustedMasterTokenParseHeader() throws MslEncodingException, MslCryptoException, MslEncoderException, MslException {
        thrown.expect(MslMasterTokenException.class);
        thrown.expectMslError(MslError.MASTERTOKEN_UNTRUSTED);

        // We can first create a message header with an untrusted master token
        // by having a cached crypto context.
        final MasterToken masterToken = MslTestUtils.getUntrustedMasterToken(p2pCtx);
        final ICryptoContext cryptoContext = new NullCryptoContext();
        p2pCtx.getMslStore().setCryptoContext(masterToken, cryptoContext);

        final UserIdToken userIdToken = MslTestUtils.getUserIdToken(p2pCtx, masterToken, 1, MockEmailPasswordAuthenticationFactory.USER);
        final HeaderDataBuilder builder = new HeaderDataBuilder(p2pCtx, masterToken, null, true);
        builder.set(KEY_KEY_REQUEST_DATA, null);
        builder.set(KEY_KEY_RESPONSE_DATA, null);
        builder.set(KEY_USER_ID_TOKEN, userIdToken);
        final HeaderData headerData = builder.build();
        final Set<ServiceToken> peerServiceTokens = MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
        final HeaderPeerData peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
        final MessageHeader messageHeader = new MessageHeader(p2pCtx, null, masterToken, headerData, peerData);
        
        // Removing the cached crypto context means the master token must now
        // be trusted when parsing a message header.
        p2pCtx.getMslStore().clearCryptoContexts();
        
        final MslObject messageHeaderMo = MslTestUtils.toMslObject(encoder, messageHeader);
        Header.parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS);
    }
    
    @Test
    public void unsupportedEntityAuthSchemeParseHeader() throws MslEncodingException, MslEntityAuthException, MslCryptoException, MslKeyExchangeException, MslUserAuthException, MslException, MslEncoderException {
        thrown.expect(MslEntityAuthException.class);
        thrown.expectMslError(MslError.ENTITYAUTH_FACTORY_NOT_FOUND);

        // We can first create a message header when the entity authentication
        // scheme is supported.
        final MockMslContext ctx = new MockMslContext(EntityAuthenticationScheme.PSK, false);
        final HeaderDataBuilder builder = new HeaderDataBuilder(ctx, null, null, true);
        builder.set(KEY_KEY_REQUEST_DATA, null);
        builder.set(KEY_KEY_RESPONSE_DATA, null);
        final HeaderData headerData = builder.build();
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final EntityAuthenticationData entityAuthData = ctx.getEntityAuthenticationData(null);
        final MessageHeader messageHeader = new MessageHeader(ctx, entityAuthData, null, headerData, peerData);
        
        // Removing support for the entity authentication scheme will now fail
        // parsing of message headers.
        ctx.removeEntityAuthenticationFactory(entityAuthData.getScheme());
        
        final MslObject messageHeaderMo = MslTestUtils.toMslObject(encoder, messageHeader);
        Header.parseHeader(ctx, messageHeaderMo, CRYPTO_CONTEXTS);
    }
    
    @Test
    public void unsupportedUserAuthSchemeParseHeader() throws MslKeyExchangeException, MslUserAuthException, MslEncoderException, MslException {
        thrown.expect(MslUserAuthException.class);
        thrown.expectMslError(MslError.USERAUTH_FACTORY_NOT_FOUND);
        thrown.expectMessageId(MESSAGE_ID);

        // We can first create a message header when the user authentication
        // scheme is supported.
        final MockMslContext ctx = new MockMslContext(EntityAuthenticationScheme.PSK, false);
        final HeaderDataBuilder builder = new HeaderDataBuilder(ctx, null, null, false);
        builder.set(KEY_KEY_REQUEST_DATA, null);
        builder.set(KEY_KEY_RESPONSE_DATA, null);
        final HeaderData headerData = builder.build();
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final MessageHeader messageHeader = new MessageHeader(ctx, null, MASTER_TOKEN, headerData, peerData);
        
        // Remove support for the user authentication scheme will now fail
        // user authentication.
        ctx.removeUserAuthenticationFactory(USER_AUTH_DATA.getScheme());
        
        final MslObject messageHeaderMo = MslTestUtils.toMslObject(encoder, messageHeader);
        Header.parseHeader(ctx, messageHeaderMo, CRYPTO_CONTEXTS);
    }
    
    @Test
    public void cachedCryptoContextMasterTokenParseHeader() throws MslEncodingException, MslCryptoException, MslEncoderException, MslException {
        // We should be okay with an untrusted master token if a crypto context
        // is associated with it.
        final MasterToken masterToken = MslTestUtils.getUntrustedMasterToken(p2pCtx);
        final ICryptoContext cryptoContext = new NullCryptoContext();
        p2pCtx.getMslStore().setCryptoContext(masterToken, cryptoContext);

        final UserIdToken userIdToken = MslTestUtils.getUserIdToken(p2pCtx, masterToken, 1, MockEmailPasswordAuthenticationFactory.USER);
        final HeaderDataBuilder builder = new HeaderDataBuilder(p2pCtx, masterToken, null, true);
        builder.set(KEY_USER_ID_TOKEN, userIdToken);
        final HeaderData headerData = builder.build();
        final Set<ServiceToken> peerServiceTokens = MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
        final HeaderPeerData peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
        final MessageHeader messageHeader = new MessageHeader(p2pCtx, null, masterToken, headerData, peerData);
        
        final MslObject messageHeaderMo = MslTestUtils.toMslObject(encoder, messageHeader);
        final Header header = Header.parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS);
        assertNotNull(header);
        assertTrue(header instanceof MessageHeader);
        final MessageHeader moMessageHeader = (MessageHeader)header;
        
        assertEquals(messageHeader.getNonReplayableId(), moMessageHeader.getNonReplayableId());
        assertEquals(messageHeader.isRenewable(), moMessageHeader.isRenewable());
        assertNotNull(messageHeader.getCryptoContext());
        assertEquals(messageHeader.getEntityAuthenticationData(), moMessageHeader.getEntityAuthenticationData());
        final Set<KeyRequestData> keyRequestData = messageHeader.getKeyRequestData();
        final Set<KeyRequestData> moKeyRequestData = moMessageHeader.getKeyRequestData();
        assertTrue(keyRequestData.containsAll(moKeyRequestData));
        assertTrue(moKeyRequestData.containsAll(keyRequestData));
        assertEquals(messageHeader.getKeyResponseData(), moMessageHeader.getKeyResponseData());
        // The reconstructed untrusted service token won't pass tests for
        // equality.
        assertNotNull(moMessageHeader.getMasterToken());
        assertEquals(messageHeader.getMessageId(), moMessageHeader.getMessageId());
        assertEquals(messageHeader.getPeerMasterToken(), moMessageHeader.getPeerMasterToken());
        final Set<ServiceToken> moPeerServiceTokens = moMessageHeader.getPeerServiceTokens();
        assertTrue(peerServiceTokens.containsAll(moPeerServiceTokens));
        assertTrue(moPeerServiceTokens.containsAll(peerServiceTokens));
        assertEquals(messageHeader.getPeerUserIdToken(), moMessageHeader.getPeerUserIdToken());
        final Set<ServiceToken> serviceTokens = messageHeader.getServiceTokens();
        final Set<ServiceToken> moServiceTokens = moMessageHeader.getServiceTokens();
        assertTrue(serviceTokens.containsAll(moServiceTokens));
        assertTrue(moServiceTokens.containsAll(serviceTokens));
        assertEquals(messageHeader.getUserAuthenticationData(), moMessageHeader.getUserAuthenticationData());
        assertEquals(messageHeader.getUserIdToken(), moMessageHeader.getUserIdToken());
        assertEquals(messageHeader.getUser(), moMessageHeader.getUser());
    }
    
    @Test
    public void invalidEntityAuthDataParseHeader() throws MslMasterTokenException, MslEntityAuthException, MslException, MslEncoderException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MSL_PARSE_ERROR);

        final HeaderDataBuilder builder = new HeaderDataBuilder(trustedNetCtx, null, null, false);
        builder.set(KEY_USER_ID_TOKEN, USER_ID_TOKEN);
        final HeaderData headerData = builder.build();
        final HeaderPeerData peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, null);
        final EntityAuthenticationData entityAuthData = trustedNetCtx.getEntityAuthenticationData(null);
        final MessageHeader messageHeader = new MessageHeader(trustedNetCtx, entityAuthData, null, headerData, peerData);
        final MslObject messageHeaderMo = MslTestUtils.toMslObject(encoder, messageHeader);
        
        messageHeaderMo.put(KEY_ENTITY_AUTHENTICATION_DATA, "x");
        
        Header.parseHeader(trustedNetCtx, messageHeaderMo, CRYPTO_CONTEXTS);
    }
    
    @Test
    public void missingBothAuthDataParseHeader() throws MslEncodingException, MslEntityAuthException, MslCryptoException, MslKeyExchangeException, MslUserAuthException, MslException, MslEncoderException {
        thrown.expect(MslMessageException.class);
        thrown.expectMslError(MslError.MESSAGE_ENTITY_NOT_FOUND);

        final HeaderDataBuilder builder = new HeaderDataBuilder(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, false);
        final HeaderData headerData = builder.build();
        final HeaderPeerData peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, null);
        final EntityAuthenticationData entityAuthData = trustedNetCtx.getEntityAuthenticationData(null);
        final MessageHeader messageHeader = new MessageHeader(trustedNetCtx, entityAuthData, MASTER_TOKEN, headerData, peerData);
        final MslObject messageHeaderMo = MslTestUtils.toMslObject(encoder, messageHeader);

        messageHeaderMo.remove(KEY_ENTITY_AUTHENTICATION_DATA);
        messageHeaderMo.remove(KEY_MASTER_TOKEN);
        
        Header.parseHeader(trustedNetCtx, messageHeaderMo, CRYPTO_CONTEXTS);
    }
    
    @Test
    public void invalidMasterTokenParseHeader() throws MslEncodingException, MslEntityAuthException, MslCryptoException, MslKeyExchangeException, MslUserAuthException, MslException, MslEncoderException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MSL_PARSE_ERROR);

        final HeaderDataBuilder builder = new HeaderDataBuilder(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, false);
        final HeaderData headerData = builder.build();
        final HeaderPeerData peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, null);
        final EntityAuthenticationData entityAuthData = trustedNetCtx.getEntityAuthenticationData(null);
        final MessageHeader messageHeader = new MessageHeader(trustedNetCtx, entityAuthData, MASTER_TOKEN, headerData, peerData);
        final MslObject messageHeaderMo = MslTestUtils.toMslObject(encoder, messageHeader);
        
        messageHeaderMo.put(KEY_MASTER_TOKEN, "x");
        
        Header.parseHeader(trustedNetCtx, messageHeaderMo, CRYPTO_CONTEXTS);
    }
    
    @Test
    public void missingSignatureParseHeader() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslException, MslEncoderException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MSL_PARSE_ERROR);

        final HeaderDataBuilder builder = new HeaderDataBuilder(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, false);
        final HeaderData headerData = builder.build();
        final HeaderPeerData peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, null);
        final EntityAuthenticationData entityAuthData = trustedNetCtx.getEntityAuthenticationData(null);
        final MessageHeader messageHeader = new MessageHeader(trustedNetCtx, entityAuthData, MASTER_TOKEN, headerData, peerData);
        final MslObject messageHeaderMo = MslTestUtils.toMslObject(encoder, messageHeader);
        
        assertNotNull(messageHeaderMo.remove(KEY_SIGNATURE));
        
        Header.parseHeader(trustedNetCtx, messageHeaderMo, CRYPTO_CONTEXTS);
    }
    
    @Test
    public void invalidSignatureParseHeader() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslException, MslEncoderException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MSL_PARSE_ERROR);

        final HeaderDataBuilder builder = new HeaderDataBuilder(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, false);
        final HeaderData headerData = builder.build();
        final HeaderPeerData peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, null);
        final EntityAuthenticationData entityAuthData = trustedNetCtx.getEntityAuthenticationData(null);
        final MessageHeader messageHeader = new MessageHeader(trustedNetCtx, entityAuthData, MASTER_TOKEN, headerData, peerData);
        final MslObject messageHeaderMo = MslTestUtils.toMslObject(encoder, messageHeader);
        
        messageHeaderMo.put(KEY_SIGNATURE, "x");
        
        Header.parseHeader(trustedNetCtx, messageHeaderMo, CRYPTO_CONTEXTS);
    }
    
    @Test
    public void incorrectSignatureParseHeader() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslException, MslEncoderException {
        thrown.expect(MslCryptoException.class);
        thrown.expectMslError(MslError.MESSAGE_ENTITYDATABASED_VERIFICATION_FAILED);

        final HeaderDataBuilder builder = new HeaderDataBuilder(trustedNetCtx, null, null, false);
        final HeaderData headerData = builder.build();
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final EntityAuthenticationData entityAuthData = trustedNetCtx.getEntityAuthenticationData(null);
        final MessageHeader messageHeader = new MessageHeader(trustedNetCtx, entityAuthData, null, headerData, peerData);
        final MslObject messageHeaderMo = MslTestUtils.toMslObject(encoder, messageHeader);
        
        messageHeaderMo.put(KEY_SIGNATURE, Base64.decode("AAA="));
        
        Header.parseHeader(trustedNetCtx, messageHeaderMo, CRYPTO_CONTEXTS);
    }
    
    @Test
    public void missingHeaderdataParseHeader() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslException, MslEncoderException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MSL_PARSE_ERROR);

        final HeaderDataBuilder builder = new HeaderDataBuilder(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, false);
        final HeaderData headerData = builder.build();
        final HeaderPeerData peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, null);
        final EntityAuthenticationData entityAuthData = trustedNetCtx.getEntityAuthenticationData(null);
        final MessageHeader messageHeader = new MessageHeader(trustedNetCtx, entityAuthData, MASTER_TOKEN, headerData, peerData);
        final MslObject messageHeaderMo = MslTestUtils.toMslObject(encoder, messageHeader);
        
        assertNotNull(messageHeaderMo.remove(KEY_HEADERDATA));
        
        Header.parseHeader(trustedNetCtx, messageHeaderMo, CRYPTO_CONTEXTS);
    }
    
    @Test
    public void invalidHeaderDataParseHeader() throws MslEncodingException, MslEntityAuthException, MslCryptoException, MslKeyExchangeException, MslUserAuthException, MslException, MslEncoderException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MSL_PARSE_ERROR);

        final HeaderDataBuilder builder = new HeaderDataBuilder(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, false);
        final HeaderData headerData = builder.build();
        final HeaderPeerData peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, null);
        final EntityAuthenticationData entityAuthData = trustedNetCtx.getEntityAuthenticationData(null);
        final MessageHeader messageHeader = new MessageHeader(trustedNetCtx, entityAuthData, MASTER_TOKEN, headerData, peerData);
        final MslObject messageHeaderMo = MslTestUtils.toMslObject(encoder, messageHeader);
        
        messageHeaderMo.put(KEY_HEADERDATA, "x");
        
        Header.parseHeader(trustedNetCtx, messageHeaderMo, CRYPTO_CONTEXTS);
    }
    
    @Test
    public void corruptHeaderDataParseHeader() throws MslEncodingException, MslEntityAuthException, MslException, MslEncoderException, UnsupportedEncodingException {
        thrown.expect(MslCryptoException.class);
        thrown.expectMslError(MslError.MESSAGE_MASTERTOKENBASED_VERIFICATION_FAILED);

        final HeaderDataBuilder builder = new HeaderDataBuilder(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, false);
        final HeaderData headerData = builder.build();
        final HeaderPeerData peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, null);
        final EntityAuthenticationData entityAuthData = trustedNetCtx.getEntityAuthenticationData(null);
        final MessageHeader messageHeader = new MessageHeader(trustedNetCtx, entityAuthData, MASTER_TOKEN, headerData, peerData);
        final MslObject messageHeaderMo = MslTestUtils.toMslObject(encoder, messageHeader);
        
        final byte[] ciphertext = messageHeaderMo.getBytes(KEY_HEADERDATA);
        ++ciphertext[0];
        messageHeaderMo.put(KEY_HEADERDATA, ciphertext);
        
        Header.parseHeader(trustedNetCtx, messageHeaderMo, CRYPTO_CONTEXTS);
    }
    
    @Test
    public void missingPairsEntityAuthParseHeader() throws MslEncoderException, MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslException {
        final HeaderDataBuilder builder = new HeaderDataBuilder(p2pCtx, null, null, false);
        builder.set(KEY_KEY_REQUEST_DATA, null);
        builder.set(KEY_KEY_RESPONSE_DATA, null);
        builder.set(KEY_USER_AUTHENTICATION_DATA, null);
        final HeaderData headerData = builder.build();
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final EntityAuthenticationData entityAuthData = p2pCtx.getEntityAuthenticationData(null);
        final MessageHeader messageHeader = new MessageHeader(p2pCtx, entityAuthData, null, headerData, peerData);
        
        final MslObject messageHeaderMo = MslTestUtils.toMslObject(encoder, messageHeader);
        final Header header = Header.parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS);
        assertNotNull(header);
        assertTrue(header instanceof MessageHeader);
        final MessageHeader moMessageHeader = (MessageHeader)header;
        
        assertEquals(messageHeader.getNonReplayableId(), moMessageHeader.getNonReplayableId());
        assertEquals(messageHeader.isRenewable(), moMessageHeader.isRenewable());
        assertNotNull(messageHeader.getCryptoContext());
        assertEquals(messageHeader.getEntityAuthenticationData(), moMessageHeader.getEntityAuthenticationData());
        final Set<KeyRequestData> keyRequestData = messageHeader.getKeyRequestData();
        final Set<KeyRequestData> moKeyRequestData = moMessageHeader.getKeyRequestData();
        assertTrue(keyRequestData.containsAll(moKeyRequestData));
        assertTrue(moKeyRequestData.containsAll(keyRequestData));
        assertEquals(messageHeader.getKeyResponseData(), moMessageHeader.getKeyResponseData());
        assertEquals(messageHeader.getMasterToken(), moMessageHeader.getMasterToken());
        assertEquals(messageHeader.getMessageId(), moMessageHeader.getMessageId());
        assertEquals(messageHeader.getPeerMasterToken(), moMessageHeader.getPeerMasterToken());
        final Set<ServiceToken> peerServiceTokens = messageHeader.getPeerServiceTokens();
        final Set<ServiceToken> moPeerServiceTokens = moMessageHeader.getPeerServiceTokens();
        assertTrue(peerServiceTokens.containsAll(moPeerServiceTokens));
        assertTrue(moPeerServiceTokens.containsAll(peerServiceTokens));
        assertEquals(messageHeader.getPeerUserIdToken(), moMessageHeader.getPeerUserIdToken());
        final Set<ServiceToken> serviceTokens = messageHeader.getServiceTokens();
        final Set<ServiceToken> moServiceTokens = moMessageHeader.getServiceTokens();
        assertTrue(serviceTokens.containsAll(moServiceTokens));
        assertTrue(moServiceTokens.containsAll(serviceTokens));
        assertEquals(messageHeader.getUserAuthenticationData(), moMessageHeader.getUserAuthenticationData());
        assertEquals(messageHeader.getUserIdToken(), moMessageHeader.getUserIdToken());
        assertEquals(messageHeader.getUser(), moMessageHeader.getUser());
    }
    
    @Test
    public void emptyArraysEntityAuthParseHeader() throws MslEncodingException, MslKeyExchangeException, MslUserAuthException, MslException, MslEncoderException, UnsupportedEncodingException {
        final HeaderDataBuilder builder = new HeaderDataBuilder(p2pCtx, null, null, false);
        builder.set(KEY_KEY_REQUEST_DATA, null);
        builder.set(KEY_KEY_RESPONSE_DATA, null);
        builder.set(KEY_USER_AUTHENTICATION_DATA, null);
        final HeaderData headerData = builder.build();
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final EntityAuthenticationData entityAuthData = p2pCtx.getEntityAuthenticationData(null);
        final MessageHeader messageHeader = new MessageHeader(p2pCtx, entityAuthData, null, headerData, peerData);
        final MslObject messageHeaderMo = MslTestUtils.toMslObject(encoder, messageHeader);
        
        // Before modifying the header data we need to decrypt it.
        final EntityAuthenticationScheme scheme = entityAuthData.getScheme();
        final EntityAuthenticationFactory factory = p2pCtx.getEntityAuthenticationFactory(scheme);
        final ICryptoContext cryptoContext = factory.getCryptoContext(p2pCtx, entityAuthData);
        final byte[] ciphertext = messageHeaderMo.getBytes(KEY_HEADERDATA);
        final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
        final MslObject headerdataMo = encoder.parseObject(plaintext);
        
        // After modifying the header data we need to encrypt it.
        headerdataMo.put(KEY_KEY_REQUEST_DATA, encoder.createArray());
        headerdataMo.put(KEY_SERVICE_TOKENS, encoder.createArray());
        headerdataMo.put(KEY_PEER_SERVICE_TOKENS, encoder.createArray());
        final byte[] headerdata = cryptoContext.encrypt(encoder.encodeObject(headerdataMo, format), encoder, format);
        messageHeaderMo.put(KEY_HEADERDATA, headerdata);
        
        // The header data must be signed or it will not be processed.
        final byte[] signature = cryptoContext.sign(headerdata, encoder, format);
        messageHeaderMo.put(KEY_SIGNATURE, signature);
        
        final Header header = Header.parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS);
        assertNotNull(header);
        assertTrue(header instanceof MessageHeader);
        final MessageHeader moMessageHeader = (MessageHeader)header;
        
        assertEquals(messageHeader.getNonReplayableId(), moMessageHeader.getNonReplayableId());
        assertEquals(messageHeader.isRenewable(), moMessageHeader.isRenewable());
        assertNotNull(messageHeader.getCryptoContext());
        assertEquals(messageHeader.getEntityAuthenticationData(), moMessageHeader.getEntityAuthenticationData());
        final Set<KeyRequestData> keyRequestData = messageHeader.getKeyRequestData();
        final Set<KeyRequestData> moKeyRequestData = moMessageHeader.getKeyRequestData();
        assertTrue(keyRequestData.containsAll(moKeyRequestData));
        assertTrue(moKeyRequestData.containsAll(keyRequestData));
        assertEquals(messageHeader.getKeyResponseData(), moMessageHeader.getKeyResponseData());
        assertEquals(messageHeader.getMasterToken(), moMessageHeader.getMasterToken());
        assertEquals(messageHeader.getMessageId(), moMessageHeader.getMessageId());
        assertEquals(messageHeader.getPeerMasterToken(), moMessageHeader.getPeerMasterToken());
        final Set<ServiceToken> peerServiceTokens = messageHeader.getPeerServiceTokens();
        final Set<ServiceToken> moPeerServiceTokens = moMessageHeader.getPeerServiceTokens();
        assertTrue(peerServiceTokens.containsAll(moPeerServiceTokens));
        assertTrue(moPeerServiceTokens.containsAll(peerServiceTokens));
        assertEquals(messageHeader.getPeerUserIdToken(), moMessageHeader.getPeerUserIdToken());
        final Set<ServiceToken> serviceTokens = messageHeader.getServiceTokens();
        final Set<ServiceToken> moServiceTokens = moMessageHeader.getServiceTokens();
        assertTrue(serviceTokens.containsAll(moServiceTokens));
        assertTrue(moServiceTokens.containsAll(serviceTokens));
        assertEquals(messageHeader.getUserAuthenticationData(), moMessageHeader.getUserAuthenticationData());
        assertEquals(messageHeader.getUserIdToken(), moMessageHeader.getUserIdToken());
        assertEquals(messageHeader.getUser(), moMessageHeader.getUser());
    }
    
    @Test
    public void missingPairsMasterTokenParseHeader() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslException, MslEncoderException {
        final HeaderDataBuilder builder = new HeaderDataBuilder(p2pCtx, null, null, false);
        builder.set(KEY_KEY_REQUEST_DATA, null);
        builder.set(KEY_KEY_RESPONSE_DATA, null);
        builder.set(KEY_USER_AUTHENTICATION_DATA, null);
        final HeaderData headerData = builder.build();
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final MessageHeader messageHeader = new MessageHeader(p2pCtx, null, MASTER_TOKEN, headerData, peerData);
        
        final MslObject messageHeaderMo = MslTestUtils.toMslObject(encoder, messageHeader);
        final Header header = Header.parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS);
        assertNotNull(header);
        assertTrue(header instanceof MessageHeader);
        final MessageHeader moMessageHeader = (MessageHeader)header;
        
        assertEquals(messageHeader.getNonReplayableId(), moMessageHeader.getNonReplayableId());
        assertEquals(messageHeader.isRenewable(), moMessageHeader.isRenewable());
        assertNotNull(messageHeader.getCryptoContext());
        assertEquals(messageHeader.getEntityAuthenticationData(), moMessageHeader.getEntityAuthenticationData());
        final Set<KeyRequestData> keyRequestData = messageHeader.getKeyRequestData();
        final Set<KeyRequestData> moKeyRequestData = moMessageHeader.getKeyRequestData();
        assertTrue(keyRequestData.containsAll(moKeyRequestData));
        assertTrue(moKeyRequestData.containsAll(keyRequestData));
        assertEquals(messageHeader.getKeyResponseData(), moMessageHeader.getKeyResponseData());
        assertEquals(messageHeader.getMasterToken(), moMessageHeader.getMasterToken());
        assertEquals(messageHeader.getMessageId(), moMessageHeader.getMessageId());
        assertEquals(messageHeader.getPeerMasterToken(), moMessageHeader.getPeerMasterToken());
        final Set<ServiceToken> peerServiceTokens = messageHeader.getPeerServiceTokens();
        final Set<ServiceToken> moPeerServiceTokens = moMessageHeader.getPeerServiceTokens();
        assertTrue(peerServiceTokens.containsAll(moPeerServiceTokens));
        assertTrue(moPeerServiceTokens.containsAll(peerServiceTokens));
        assertEquals(messageHeader.getPeerUserIdToken(), moMessageHeader.getPeerUserIdToken());
        final Set<ServiceToken> serviceTokens = messageHeader.getServiceTokens();
        final Set<ServiceToken> moServiceTokens = moMessageHeader.getServiceTokens();
        assertTrue(serviceTokens.containsAll(moServiceTokens));
        assertTrue(moServiceTokens.containsAll(serviceTokens));
        assertEquals(messageHeader.getUserAuthenticationData(), moMessageHeader.getUserAuthenticationData());
        assertEquals(messageHeader.getUserIdToken(), moMessageHeader.getUserIdToken());
        assertEquals(messageHeader.getUser(), moMessageHeader.getUser());
    }
    
    @Test
    public void emptyArraysMasterTokenParseHeader() throws MslEncoderException, UnsupportedEncodingException, MslEncodingException, MslEntityAuthException, MslKeyExchangeException, MslUserAuthException, MslException {
        final HeaderDataBuilder builder = new HeaderDataBuilder(p2pCtx, null, null, false);
        builder.set(KEY_KEY_REQUEST_DATA, null);
        builder.set(KEY_KEY_RESPONSE_DATA, null);
        builder.set(KEY_USER_AUTHENTICATION_DATA, null);
        final HeaderData headerData = builder.build();
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final MessageHeader messageHeader = new MessageHeader(p2pCtx, null, MASTER_TOKEN, headerData, peerData);
        final MslObject messageHeaderMo = MslTestUtils.toMslObject(encoder, messageHeader);
        
        // Before modifying the header data we need to decrypt it.
        final ICryptoContext cryptoContext = new SessionCryptoContext(p2pCtx, MASTER_TOKEN);
        final byte[] ciphertext = messageHeaderMo.getBytes(KEY_HEADERDATA);
        final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
        final MslObject headerdataMo = encoder.parseObject(plaintext);
        
        // After modifying the header data we need to encrypt it.
        headerdataMo.put(KEY_KEY_REQUEST_DATA, encoder.createArray());
        headerdataMo.put(KEY_SERVICE_TOKENS, encoder.createArray());
        headerdataMo.put(KEY_PEER_SERVICE_TOKENS, encoder.createArray());
        final byte[] headerdata = cryptoContext.encrypt(encoder.encodeObject(headerdataMo, format), encoder, format);
        messageHeaderMo.put(KEY_HEADERDATA, headerdata);
        
        // The header data must be signed or it will not be processed.
        final byte[] signature = cryptoContext.sign(headerdata, encoder, format);
        messageHeaderMo.put(KEY_SIGNATURE, signature);
        
        final Header header = Header.parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS);
        assertNotNull(header);
        assertTrue(header instanceof MessageHeader);
        final MessageHeader moMessageHeader = (MessageHeader)header;
        
        assertEquals(messageHeader.getNonReplayableId(), moMessageHeader.getNonReplayableId());
        assertEquals(messageHeader.isRenewable(), moMessageHeader.isRenewable());
        assertNotNull(messageHeader.getCryptoContext());
        assertEquals(messageHeader.getEntityAuthenticationData(), moMessageHeader.getEntityAuthenticationData());
        final Set<KeyRequestData> keyRequestData = messageHeader.getKeyRequestData();
        final Set<KeyRequestData> moKeyRequestData = moMessageHeader.getKeyRequestData();
        assertTrue(keyRequestData.containsAll(moKeyRequestData));
        assertTrue(moKeyRequestData.containsAll(keyRequestData));
        assertEquals(messageHeader.getKeyResponseData(), moMessageHeader.getKeyResponseData());
        assertEquals(messageHeader.getMasterToken(), moMessageHeader.getMasterToken());
        assertEquals(messageHeader.getMessageId(), moMessageHeader.getMessageId());
        assertEquals(messageHeader.getPeerMasterToken(), moMessageHeader.getPeerMasterToken());
        final Set<ServiceToken> peerServiceTokens = messageHeader.getPeerServiceTokens();
        final Set<ServiceToken> moPeerServiceTokens = moMessageHeader.getPeerServiceTokens();
        assertTrue(peerServiceTokens.containsAll(moPeerServiceTokens));
        assertTrue(moPeerServiceTokens.containsAll(peerServiceTokens));
        assertEquals(messageHeader.getPeerUserIdToken(), moMessageHeader.getPeerUserIdToken());
        final Set<ServiceToken> serviceTokens = messageHeader.getServiceTokens();
        final Set<ServiceToken> moServiceTokens = moMessageHeader.getServiceTokens();
        assertTrue(serviceTokens.containsAll(moServiceTokens));
        assertTrue(moServiceTokens.containsAll(serviceTokens));
        assertEquals(messageHeader.getUserAuthenticationData(), moMessageHeader.getUserAuthenticationData());
        assertEquals(messageHeader.getUserIdToken(), moMessageHeader.getUserIdToken());
        assertEquals(messageHeader.getUser(), moMessageHeader.getUser());
    }

    @Test
    public void userIdTokenNullMasterTokenParseHeader() throws MslEncodingException, MslEntityAuthException, MslCryptoException, MslKeyExchangeException, MslUserAuthException, MslException, MslEncoderException, UnsupportedEncodingException {
        thrown.expect(MslException.class);
        thrown.expectMessageId(MESSAGE_ID);

        // Since removing the master token will prevent the header data from
        // getting parsed, and removing the master token from the key exchange
        // data will also prevent the header data from getting parsed, the only
        // way to simulate this is to use entity authentication data and insert
        // a user ID token.
        final HeaderDataBuilder builder = new HeaderDataBuilder(trustedNetCtx, null, null, true);
        builder.set(KEY_KEY_REQUEST_DATA, null);
        builder.set(KEY_KEY_RESPONSE_DATA, null);
        final HeaderData headerData = builder.build();
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final EntityAuthenticationData entityAuthData = trustedNetCtx.getEntityAuthenticationData(null);
        final MessageHeader messageHeader = new MessageHeader(trustedNetCtx, entityAuthData, null, headerData, peerData);
        final MslObject messageHeaderMo = MslTestUtils.toMslObject(encoder, messageHeader);
        
        // Before modifying the header data we need to decrypt it.
        final EntityAuthenticationScheme scheme = entityAuthData.getScheme();
        final EntityAuthenticationFactory factory = trustedNetCtx.getEntityAuthenticationFactory(scheme);
        final ICryptoContext cryptoContext = factory.getCryptoContext(trustedNetCtx, entityAuthData);
        final byte[] ciphertext = messageHeaderMo.getBytes(KEY_HEADERDATA);
        final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
        final MslObject headerdataMo = encoder.parseObject(plaintext);
        
        // After modifying the header data we need to encrypt it.
        final UserIdToken userIdToken = MslTestUtils.getUserIdToken(trustedNetCtx, MASTER_TOKEN, 1, MockEmailPasswordAuthenticationFactory.USER);
        headerdataMo.put(KEY_USER_ID_TOKEN, userIdToken);
        final byte[] headerdata = cryptoContext.encrypt(encoder.encodeObject(headerdataMo, format), encoder, format);
        messageHeaderMo.put(KEY_HEADERDATA, headerdata);
        
        // The header data must be signed or it will not be processed.
        final byte[] signature = cryptoContext.sign(headerdata, encoder, format);
        messageHeaderMo.put(KEY_SIGNATURE, signature);
        
        Header.parseHeader(trustedNetCtx, messageHeaderMo, CRYPTO_CONTEXTS);
    }
    
    @Test
    public void userIdTokenMismatchedMasterTokenParseHeader() throws MslMasterTokenException, MslEntityAuthException, MslException, MslEncoderException, UnsupportedEncodingException {
        thrown.expect(MslException.class);
        thrown.expectMessageId(MESSAGE_ID);

        final HeaderDataBuilder builder = new HeaderDataBuilder(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
        builder.set(KEY_KEY_REQUEST_DATA, null);
        builder.set(KEY_KEY_RESPONSE_DATA, null);
        final HeaderData headerData = builder.build();
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final MessageHeader messageHeader = new MessageHeader(trustedNetCtx, null, MASTER_TOKEN, headerData, peerData);
        final MslObject messageHeaderMo = MslTestUtils.toMslObject(encoder, messageHeader);
        
        // Before modifying the header data we need to decrypt it.
        final ICryptoContext cryptoContext = new SessionCryptoContext(trustedNetCtx, MASTER_TOKEN);
        final byte[] ciphertext = messageHeaderMo.getBytes(KEY_HEADERDATA);
        final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
        final MslObject headerdataMo = encoder.parseObject(plaintext);
        
        // After modifying the header data we need to encrypt it.
        final UserIdToken userIdToken = MslTestUtils.getUserIdToken(trustedNetCtx, PEER_MASTER_TOKEN, 1, MockEmailPasswordAuthenticationFactory.USER);
        headerdataMo.put(KEY_USER_ID_TOKEN, userIdToken);
        final byte[] headerdata = cryptoContext.encrypt(encoder.encodeObject(headerdataMo, format), encoder, format);
        messageHeaderMo.put(KEY_HEADERDATA, headerdata);
        
        // The header data must be signed or it will not be processed.
        final byte[] signature = cryptoContext.sign(headerdata, encoder, format);
        messageHeaderMo.put(KEY_SIGNATURE, signature);
        
        Header.parseHeader(trustedNetCtx, messageHeaderMo, CRYPTO_CONTEXTS);
    }
    
    @Test
    public void userIdTokenMismatchedUserAuthDataParseHeader() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslMessageException, MslKeyExchangeException, MslUserAuthException, MslEncoderException, MslException {
        thrown.expect(MslUserAuthException.class);
        thrown.expectMslError(MslError.USERIDTOKEN_USERAUTH_DATA_MISMATCH);
        thrown.expectMessageId(MESSAGE_ID);

        final HeaderDataBuilder builder = new HeaderDataBuilder(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, false);
        builder.set(KEY_KEY_REQUEST_DATA, null);
        builder.set(KEY_KEY_RESPONSE_DATA, null);
        builder.set(KEY_USER_AUTHENTICATION_DATA, null);
        final HeaderData headerData = builder.build();
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final MessageHeader messageHeader = new MessageHeader(trustedNetCtx, null, MASTER_TOKEN, headerData, peerData);
        final MslObject messageHeaderMo = MslTestUtils.toMslObject(encoder, messageHeader);
        
        // Before modifying the header data we need to decrypt it.
        final ICryptoContext cryptoContext = new SessionCryptoContext(trustedNetCtx, MASTER_TOKEN);
        final byte[] ciphertext = messageHeaderMo.getBytes(KEY_HEADERDATA);
        final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
        final MslObject headerdataMo = encoder.parseObject(plaintext);
        
        // After modifying the header data we need to encrypt it.
        final UserAuthenticationData userAuthData = new EmailPasswordAuthenticationData(MockEmailPasswordAuthenticationFactory.EMAIL_2, MockEmailPasswordAuthenticationFactory.PASSWORD_2);
        headerdataMo.put(KEY_USER_AUTHENTICATION_DATA, userAuthData);
        final byte[] headerdata = cryptoContext.encrypt(encoder.encodeObject(headerdataMo, format), encoder, format);
        messageHeaderMo.put(KEY_HEADERDATA, headerdata);
        
        // The header data must be signed or it will not be processed.
        final byte[] signature = cryptoContext.sign(headerdata, encoder, format);
        messageHeaderMo.put(KEY_SIGNATURE, signature);
        
        Header.parseHeader(trustedNetCtx, messageHeaderMo, CRYPTO_CONTEXTS);
    }
    
    @Test
    public void peerUserIdTokenMissingPeerMasterTokenParseHeader() throws MslEncodingException, MslEntityAuthException, MslException, UnsupportedEncodingException, MslEncoderException {
        thrown.expect(MslException.class);
        thrown.expectMessageId(MESSAGE_ID);

        final HeaderDataBuilder builder = new HeaderDataBuilder(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, false);
        builder.set(KEY_KEY_REQUEST_DATA, null);
        builder.set(KEY_KEY_RESPONSE_DATA, null);
        final HeaderData headerData = builder.build();
        final Set<ServiceToken> peerServiceTokens = MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
        final HeaderPeerData peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
        final MessageHeader messageHeader = new MessageHeader(p2pCtx, null, MASTER_TOKEN, headerData, peerData);
        final MslObject messageHeaderMo = MslTestUtils.toMslObject(encoder, messageHeader);
        
        // Before modifying the header data we need to decrypt it.
        final ICryptoContext cryptoContext = new SessionCryptoContext(p2pCtx, MASTER_TOKEN);
        final byte[] ciphertext = messageHeaderMo.getBytes(KEY_HEADERDATA);
        final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
        final MslObject headerdataMo = encoder.parseObject(plaintext);
        
        // After modifying the header data we need to encrypt it.
        assertNotNull(headerdataMo.remove(KEY_PEER_MASTER_TOKEN));
        final byte[] headerdata = cryptoContext.encrypt(encoder.encodeObject(headerdataMo, format), encoder, format);
        messageHeaderMo.put(KEY_HEADERDATA, headerdata);
        
        // The header data must be signed or it will not be processed.
        final byte[] signature = cryptoContext.sign(headerdata, encoder, format);
        messageHeaderMo.put(KEY_SIGNATURE, signature);
        
        Header.parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS);
    }
    
    @Test(expected = MslException.class)
    public void peerUserIdTokenMismatchedPeerMasterTokenParseHeader() throws MslEncoderException, UnsupportedEncodingException, MslEntityAuthException, MslException {
        final HeaderDataBuilder builder = new HeaderDataBuilder(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
        builder.set(KEY_KEY_REQUEST_DATA, null);
        builder.set(KEY_KEY_RESPONSE_DATA, null);
        final HeaderData headerData = builder.build();
        final Set<ServiceToken> peerServiceTokens = MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
        final HeaderPeerData peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
        final MessageHeader messageHeader = new MessageHeader(p2pCtx, null, MASTER_TOKEN, headerData, peerData);
        final MslObject messageHeaderMo = MslTestUtils.toMslObject(encoder, messageHeader);
        
        // Before modifying the header data we need to decrypt it.
        final ICryptoContext cryptoContext = new SessionCryptoContext(p2pCtx, MASTER_TOKEN);
        final byte[] ciphertext = messageHeaderMo.getBytes(KEY_HEADERDATA);
        final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
        final MslObject headerdataMo = encoder.parseObject(plaintext);
        
        // After modifying the header data we need to encrypt it.
        headerdataMo.put(KEY_PEER_MASTER_TOKEN, MASTER_TOKEN);
        final byte[] headerdata = cryptoContext.encrypt(encoder.encodeObject(headerdataMo, format), encoder, format);
        messageHeaderMo.put(KEY_HEADERDATA, headerdata);
        
        // The header data must be signed or it will not be processed.
        final byte[] signature = cryptoContext.sign(headerdata, encoder, format);
        messageHeaderMo.put(KEY_SIGNATURE, signature);
        
        Header.parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS);
    }
    
    @Test
    public void serviceTokenMismatchedMasterTokenParseHeader() throws MslEncoderException, UnsupportedEncodingException, MslEncodingException, MslEntityAuthException, MslKeyExchangeException, MslUserAuthException, MslException {
        thrown.expect(MslException.class);
        thrown.expectMessageId(MESSAGE_ID);

        final HeaderDataBuilder builder = new HeaderDataBuilder(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
        builder.set(KEY_KEY_REQUEST_DATA, null);
        builder.set(KEY_KEY_RESPONSE_DATA, null);
        final HeaderData headerData = builder.build();
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final MessageHeader messageHeader = new MessageHeader(trustedNetCtx, null, MASTER_TOKEN, headerData, peerData);
        final MslObject messageHeaderMo = MslTestUtils.toMslObject(encoder, messageHeader);
        
        // Before modifying the header data we need to decrypt it.
        final ICryptoContext cryptoContext = new SessionCryptoContext(trustedNetCtx, MASTER_TOKEN);
        final byte[] ciphertext = messageHeaderMo.getBytes(KEY_HEADERDATA);
        final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
        final MslObject headerdataMo = encoder.parseObject(plaintext);
        
        // After modifying the header data we need to encrypt it.
        final Set<ServiceToken> serviceTokens = builder.getServiceTokens();
        serviceTokens.addAll(MslTestUtils.getServiceTokens(trustedNetCtx, PEER_MASTER_TOKEN, null));
        headerdataMo.put(KEY_SERVICE_TOKENS, MslEncoderUtils.createArray(trustedNetCtx, format, serviceTokens));
        final byte[] headerdata = cryptoContext.encrypt(encoder.encodeObject(headerdataMo, format), encoder, format);
        messageHeaderMo.put(KEY_HEADERDATA, headerdata);
        
        // The header data must be signed or it will not be processed.
        final byte[] signature = cryptoContext.sign(headerdata, encoder, format);
        messageHeaderMo.put(KEY_SIGNATURE, signature);
        
        Header.parseHeader(trustedNetCtx, messageHeaderMo, CRYPTO_CONTEXTS);
    }
    
    @Test
    public void serviceTokenMismatchedUserIdTokenParseHeader() throws UnsupportedEncodingException, MslMasterTokenException, MslEntityAuthException, MslException, MslEncoderException {
        thrown.expect(MslException.class);
        thrown.expectMessageId(MESSAGE_ID);

        final HeaderDataBuilder builder = new HeaderDataBuilder(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
        builder.set(KEY_KEY_REQUEST_DATA, null);
        builder.set(KEY_KEY_RESPONSE_DATA, null);
        final HeaderData headerData = builder.build();
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final MessageHeader messageHeader = new MessageHeader(trustedNetCtx, null, MASTER_TOKEN, headerData, peerData);
        final MslObject messageHeaderMo = MslTestUtils.toMslObject(encoder, messageHeader);
        
        // Before modifying the header data we need to decrypt it.
        final ICryptoContext cryptoContext = new SessionCryptoContext(trustedNetCtx, MASTER_TOKEN);
        final byte[] ciphertext = messageHeaderMo.getBytes(KEY_HEADERDATA);
        final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
        final MslObject headerdataMo = encoder.parseObject(plaintext);
        
        // After modifying the header data we need to encrypt it.
        final Set<ServiceToken> serviceTokens = builder.getServiceTokens();
        final UserIdToken userIdToken = MslTestUtils.getUserIdToken(trustedNetCtx, MASTER_TOKEN, 2, MockEmailPasswordAuthenticationFactory.USER);
        serviceTokens.addAll(MslTestUtils.getServiceTokens(trustedNetCtx, MASTER_TOKEN, userIdToken));
        headerdataMo.put(KEY_SERVICE_TOKENS, MslEncoderUtils.createArray(trustedNetCtx, format, serviceTokens));
        final byte[] headerdata = cryptoContext.encrypt(encoder.encodeObject(headerdataMo, format), encoder, format);
        messageHeaderMo.put(KEY_HEADERDATA, headerdata);
        
        // The header data must be signed or it will not be processed.
        final byte[] signature = cryptoContext.sign(headerdata, encoder, format);
        messageHeaderMo.put(KEY_SIGNATURE, signature);
        
        Header.parseHeader(trustedNetCtx, messageHeaderMo, CRYPTO_CONTEXTS);
    }
    
    @Test
    public void peerServiceTokenMissingPeerMasterTokenParseHeader() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslException, UnsupportedEncodingException, MslEncoderException {
        thrown.expect(MslException.class);
        thrown.expectMessageId(MESSAGE_ID);

        final HeaderDataBuilder builder = new HeaderDataBuilder(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
        builder.set(KEY_KEY_REQUEST_DATA, null);
        builder.set(KEY_KEY_RESPONSE_DATA, null);
        final HeaderData headerData = builder.build();
        final Set<ServiceToken> peerServiceTokens = MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, null);
        final HeaderPeerData peerData = new HeaderPeerData(PEER_MASTER_TOKEN, null, peerServiceTokens);
        final MessageHeader messageHeader = new MessageHeader(p2pCtx, null, MASTER_TOKEN, headerData, peerData);
        final MslObject messageHeaderMo = MslTestUtils.toMslObject(encoder, messageHeader);
        
        // Before modifying the header data we need to decrypt it.
        final ICryptoContext cryptoContext = new SessionCryptoContext(p2pCtx, MASTER_TOKEN);
        final byte[] ciphertext = messageHeaderMo.getBytes(KEY_HEADERDATA);
        final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
        final MslObject headerdataMo = encoder.parseObject(plaintext);
        
        // After modifying the header data we need to encrypt it.
        assertNotNull(headerdataMo.remove(KEY_PEER_MASTER_TOKEN));
        final byte[] headerdata = cryptoContext.encrypt(encoder.encodeObject(headerdataMo, format), encoder, format);
        messageHeaderMo.put(KEY_HEADERDATA, headerdata);
        
        // The header data must be signed or it will not be processed.
        final byte[] signature = cryptoContext.sign(headerdata, encoder, format);
        messageHeaderMo.put(KEY_SIGNATURE, signature);
        
        Header.parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS);
    }
    
    @Test
    public void peerServiceTokenMismatchedPeerMasterTokenParseHeader() throws MslMasterTokenException, MslEntityAuthException, MslException, UnsupportedEncodingException, MslEncoderException {
        thrown.expect(MslException.class);
        thrown.expectMessageId(MESSAGE_ID);

        final HeaderDataBuilder builder = new HeaderDataBuilder(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
        builder.set(KEY_KEY_REQUEST_DATA, null);
        builder.set(KEY_KEY_RESPONSE_DATA, null);
        final HeaderData headerData = builder.build();
        final Set<ServiceToken> peerServiceTokens = MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, null);
        final HeaderPeerData peerData = new HeaderPeerData(PEER_MASTER_TOKEN, null, peerServiceTokens);
        final MessageHeader messageHeader = new MessageHeader(p2pCtx, null, MASTER_TOKEN, headerData, peerData);
        final MslObject messageHeaderMo = MslTestUtils.toMslObject(encoder, messageHeader);
        
        // Before modifying the header data we need to decrypt it.
        final ICryptoContext cryptoContext = new SessionCryptoContext(p2pCtx, MASTER_TOKEN);
        final byte[] ciphertext = messageHeaderMo.getBytes(KEY_HEADERDATA);
        final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
        final MslObject headerdataMo = encoder.parseObject(plaintext);
        
        // After modifying the header data we need to encrypt it.
        headerdataMo.put(KEY_PEER_MASTER_TOKEN, MASTER_TOKEN);
        final byte[] headerdata = cryptoContext.encrypt(encoder.encodeObject(headerdataMo, format), encoder, format);
        messageHeaderMo.put(KEY_HEADERDATA, headerdata);
        
        // The header data must be signed or it will not be processed.
        final byte[] signature = cryptoContext.sign(headerdata, encoder, format);
        messageHeaderMo.put(KEY_SIGNATURE, signature);
        
        Header.parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS);
    }
    
    @Test
    public void peerServiceTokenMismatchedPeerUserIdTokenParseHeader() throws UnsupportedEncodingException, MslEncodingException, MslMasterTokenException, MslEntityAuthException, MslException, MslEncoderException {
        thrown.expect(MslException.class);
        thrown.expectMessageId(MESSAGE_ID);

        final HeaderDataBuilder builder = new HeaderDataBuilder(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
        builder.set(KEY_KEY_REQUEST_DATA, null);
        builder.set(KEY_KEY_RESPONSE_DATA, null);
        final HeaderData headerData = builder.build();
        final Set<ServiceToken> peerServiceTokens = MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
        final HeaderPeerData peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
        final MessageHeader messageHeader = new MessageHeader(p2pCtx, null, MASTER_TOKEN, headerData, peerData);
        final MslObject messageHeaderMo = MslTestUtils.toMslObject(encoder, messageHeader);
        
        // Before modifying the header data we need to decrypt it.
        final ICryptoContext cryptoContext = new SessionCryptoContext(p2pCtx, MASTER_TOKEN);
        final byte[] ciphertext = messageHeaderMo.getBytes(KEY_HEADERDATA);
        final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
        final MslObject headerdataMo = encoder.parseObject(plaintext);
        
        // After modifying the header data we need to encrypt it.
        final UserIdToken userIdToken = MslTestUtils.getUserIdToken(p2pCtx, PEER_MASTER_TOKEN, 2, MockEmailPasswordAuthenticationFactory.USER);
        headerdataMo.put(KEY_PEER_USER_ID_TOKEN, userIdToken);
        final byte[] headerdata = cryptoContext.encrypt(encoder.encodeObject(headerdataMo, format), encoder, format);
        messageHeaderMo.put(KEY_HEADERDATA, headerdata);
        
        // The header data must be signed or it will not be processed.
        final byte[] signature = cryptoContext.sign(headerdata, encoder, format);
        messageHeaderMo.put(KEY_SIGNATURE, signature);
        
        Header.parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS);
    }

    @Test
    public void missingTimestamp() throws MslEncoderException, MslKeyExchangeException, MslUserAuthException, MslException {
        final HeaderDataBuilder builder = new HeaderDataBuilder(trustedNetCtx, null, null, false);
        builder.set(KEY_KEY_REQUEST_DATA, null);
        builder.set(KEY_KEY_RESPONSE_DATA, null);
        builder.set(KEY_USER_AUTHENTICATION_DATA, null);
        final HeaderData headerData = builder.build();
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final MessageHeader messageHeader = new MessageHeader(trustedNetCtx, null, MASTER_TOKEN, headerData, peerData);
        final MslObject messageHeaderMo = MslTestUtils.toMslObject(encoder, messageHeader);
        
        // Before modifying the header data we need to decrypt it.
        final ICryptoContext cryptoContext = new SessionCryptoContext(trustedNetCtx, MASTER_TOKEN);
        final byte[] ciphertext = messageHeaderMo.getBytes(KEY_HEADERDATA);
        final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
        final MslObject headerdataMo = encoder.parseObject(plaintext);
        
        // After modifying the header data we need to encrypt it.
        assertNotNull(headerdataMo.remove(KEY_TIMESTAMP));
        final byte[] headerdata = cryptoContext.encrypt(encoder.encodeObject(headerdataMo, format), encoder, format);
        messageHeaderMo.put(KEY_HEADERDATA, headerdata);
        
        // The header data must be signed or it will not be processed.
        final byte[] signature = cryptoContext.sign(headerdata, encoder, format);
        messageHeaderMo.put(KEY_SIGNATURE, signature);
        
        Header.parseHeader(trustedNetCtx, messageHeaderMo, CRYPTO_CONTEXTS);
    }
    
    @Test
    public void invalidTimestamp() throws MslEncoderException, MslKeyExchangeException, MslUserAuthException, MslException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MSL_PARSE_ERROR);

        final HeaderDataBuilder builder = new HeaderDataBuilder(trustedNetCtx, null, null, false);
        builder.set(KEY_KEY_REQUEST_DATA, null);
        builder.set(KEY_KEY_RESPONSE_DATA, null);
        builder.set(KEY_USER_AUTHENTICATION_DATA, null);
        final HeaderData headerData = builder.build();
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final MessageHeader messageHeader = new MessageHeader(trustedNetCtx, null, MASTER_TOKEN, headerData, peerData);
        final MslObject messageHeaderMo = MslTestUtils.toMslObject(encoder, messageHeader);
        
        // Before modifying the header data we need to decrypt it.
        final ICryptoContext cryptoContext = new SessionCryptoContext(trustedNetCtx, MASTER_TOKEN);
        final byte[] ciphertext = messageHeaderMo.getBytes(KEY_HEADERDATA);
        final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
        final MslObject headerdataMo = encoder.parseObject(plaintext);
        
        // After modifying the header data we need to encrypt it.
        headerdataMo.put(KEY_TIMESTAMP, "x");
        final byte[] headerdata = cryptoContext.encrypt(encoder.encodeObject(headerdataMo, format), encoder, format);
        messageHeaderMo.put(KEY_HEADERDATA, headerdata);
        
        // The header data must be signed or it will not be processed.
        final byte[] signature = cryptoContext.sign(headerdata, encoder, format);
        messageHeaderMo.put(KEY_SIGNATURE, signature);
        
        Header.parseHeader(trustedNetCtx, messageHeaderMo, CRYPTO_CONTEXTS);
    }
    
    @Test
    public void missingMessageIdParseHeader() throws UnsupportedEncodingException, MslEncoderException, MslEncodingException, MslEntityAuthException, MslKeyExchangeException, MslUserAuthException, MslException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MSL_PARSE_ERROR);

        final HeaderDataBuilder builder = new HeaderDataBuilder(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
        builder.set(KEY_KEY_REQUEST_DATA, null);
        builder.set(KEY_KEY_RESPONSE_DATA, null);
        final HeaderData headerData = builder.build();
        final Set<ServiceToken> peerServiceTokens = MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
        final HeaderPeerData peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
        final MessageHeader messageHeader = new MessageHeader(p2pCtx, null, MASTER_TOKEN, headerData, peerData);
        final MslObject messageHeaderMo = MslTestUtils.toMslObject(encoder, messageHeader);
        
        // Before modifying the header data we need to decrypt it.
        final ICryptoContext cryptoContext = new SessionCryptoContext(p2pCtx, MASTER_TOKEN);
        final byte[] ciphertext = messageHeaderMo.getBytes(KEY_HEADERDATA);
        final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
        final MslObject headerdataMo = encoder.parseObject(plaintext);
        
        // After modifying the header data we need to encrypt it.
        assertNotNull(headerdataMo.remove(KEY_MESSAGE_ID));
        final byte[] headerdata = cryptoContext.encrypt(encoder.encodeObject(headerdataMo, format), encoder, format);
        messageHeaderMo.put(KEY_HEADERDATA, headerdata);
        
        // The header data must be signed or it will not be processed.
        final byte[] signature = cryptoContext.sign(headerdata, encoder, format);
        messageHeaderMo.put(KEY_SIGNATURE, signature);
        
        Header.parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS);
    }
    
    @Test
    public void invalidMessageIdParseHeader() throws MslEncoderException, MslEncodingException, MslEntityAuthException, MslCryptoException, MslKeyExchangeException, MslUserAuthException, MslException, UnsupportedEncodingException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MSL_PARSE_ERROR);

        final HeaderDataBuilder builder = new HeaderDataBuilder(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
        builder.set(KEY_KEY_REQUEST_DATA, null);
        builder.set(KEY_KEY_RESPONSE_DATA, null);
        final HeaderData headerData = builder.build();
        final Set<ServiceToken> peerServiceTokens = MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
        final HeaderPeerData peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
        final MessageHeader messageHeader = new MessageHeader(p2pCtx, null, MASTER_TOKEN, headerData, peerData);
        final MslObject messageHeaderMo = MslTestUtils.toMslObject(encoder, messageHeader);
        
        // Before modifying the header data we need to decrypt it.
        final ICryptoContext cryptoContext = new SessionCryptoContext(p2pCtx, MASTER_TOKEN);
        final byte[] ciphertext = messageHeaderMo.getBytes(KEY_HEADERDATA);
        final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
        final MslObject headerdataMo = encoder.parseObject(plaintext);
        
        // After modifying the header data we need to encrypt it.
        headerdataMo.put(KEY_MESSAGE_ID, "x");
        final byte[] headerdata = cryptoContext.encrypt(encoder.encodeObject(headerdataMo, format), encoder, format);
        messageHeaderMo.put(KEY_HEADERDATA, headerdata);
        
        // The header data must be signed or it will not be processed.
        final byte[] signature = cryptoContext.sign(headerdata, encoder, format);
        messageHeaderMo.put(KEY_SIGNATURE, signature);
        
        Header.parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS);
    }
    
    @Test(expected = MslInternalException.class)
    public void negativeMessageIdCtor() throws MslException {
        final HeaderDataBuilder builder = new HeaderDataBuilder(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, false);
        builder.set(KEY_MESSAGE_ID, -1L);
        builder.set(KEY_KEY_REQUEST_DATA, null);
        builder.set(KEY_KEY_RESPONSE_DATA, null);
        final HeaderData headerData = builder.build();
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        new MessageHeader(p2pCtx, null, MASTER_TOKEN, headerData, peerData);
    }
    
    @Test(expected = MslInternalException.class)
    public void tooLargeMessageIdCtor() throws MslException {
        final HeaderDataBuilder builder = new HeaderDataBuilder(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, false);
        builder.set(KEY_MESSAGE_ID, MslConstants.MAX_LONG_VALUE + 1);
        builder.set(KEY_KEY_REQUEST_DATA, null);
        builder.set(KEY_KEY_RESPONSE_DATA, null);
        final HeaderData headerData = builder.build();
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        new MessageHeader(p2pCtx, null, MASTER_TOKEN, headerData, peerData);
    }
    
    @Test
    public void negativeMessageIdParseHeader() throws MslEncoderException, MslKeyExchangeException, MslUserAuthException, MslException {
        thrown.expect(MslMessageException.class);
        thrown.expectMslError(MslError.MESSAGE_ID_OUT_OF_RANGE);

        final HeaderDataBuilder builder = new HeaderDataBuilder(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
        builder.set(KEY_KEY_REQUEST_DATA, null);
        builder.set(KEY_KEY_RESPONSE_DATA, null);
        final HeaderData headerData = builder.build();
        final Set<ServiceToken> peerServiceTokens = MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
        final HeaderPeerData peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
        final MessageHeader messageHeader = new MessageHeader(p2pCtx, null, MASTER_TOKEN, headerData, peerData);
        final MslObject messageHeaderMo = MslTestUtils.toMslObject(encoder, messageHeader);
        
        // Before modifying the header data we need to decrypt it.
        final ICryptoContext cryptoContext = new SessionCryptoContext(p2pCtx, MASTER_TOKEN);
        final byte[] ciphertext = messageHeaderMo.getBytes(KEY_HEADERDATA);
        final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
        final MslObject headerdataMo = encoder.parseObject(plaintext);
        
        // After modifying the header data we need to encrypt it.
        headerdataMo.put(KEY_MESSAGE_ID, -1);
        final byte[] headerdata = cryptoContext.encrypt(encoder.encodeObject(headerdataMo, format), encoder, format);
        messageHeaderMo.put(KEY_HEADERDATA, headerdata);
        
        // The header data must be signed or it will not be processed.
        final byte[] signature = cryptoContext.sign(headerdata, encoder, format);
        messageHeaderMo.put(KEY_SIGNATURE, signature);
        
        Header.parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS);
    }
    
    @Test
    public void tooLargeMessageIdParseHeader() throws MslEncoderException, MslKeyExchangeException, MslUserAuthException, MslException {
        thrown.expect(MslMessageException.class);
        thrown.expectMslError(MslError.MESSAGE_ID_OUT_OF_RANGE);

        final HeaderDataBuilder builder = new HeaderDataBuilder(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
        builder.set(KEY_KEY_REQUEST_DATA, null);
        builder.set(KEY_KEY_RESPONSE_DATA, null);
        final HeaderData headerData = builder.build();
        final Set<ServiceToken> peerServiceTokens = MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
        final HeaderPeerData peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
        final MessageHeader messageHeader = new MessageHeader(p2pCtx, null, MASTER_TOKEN, headerData, peerData);
        final MslObject messageHeaderMo = MslTestUtils.toMslObject(encoder, messageHeader);
        
        // Before modifying the header data we need to decrypt it.
        final ICryptoContext cryptoContext = new SessionCryptoContext(p2pCtx, MASTER_TOKEN);
        final byte[] ciphertext = messageHeaderMo.getBytes(KEY_HEADERDATA);
        final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
        final MslObject headerdataMo = encoder.parseObject(plaintext);
        
        // After modifying the header data we need to encrypt it.
        headerdataMo.put(KEY_MESSAGE_ID, MslConstants.MAX_LONG_VALUE + 1);
        final byte[] headerdata = cryptoContext.encrypt(encoder.encodeObject(headerdataMo, format), encoder, format);
        messageHeaderMo.put(KEY_HEADERDATA, headerdata);
        
        // The header data must be signed or it will not be processed.
        final byte[] signature = cryptoContext.sign(headerdata, encoder, format);
        messageHeaderMo.put(KEY_SIGNATURE, signature);
        
        Header.parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS);
    }
    
    @Test
    public void invalidNonReplayableParseHeader() throws MslEncodingException, MslEntityAuthException, MslCryptoException, MslKeyExchangeException, MslUserAuthException, MslException, UnsupportedEncodingException, MslEncoderException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MSL_PARSE_ERROR);
        thrown.expectMessageId(MESSAGE_ID);

        final HeaderDataBuilder builder = new HeaderDataBuilder(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
        builder.set(KEY_KEY_REQUEST_DATA, null);
        builder.set(KEY_KEY_RESPONSE_DATA, null);
        final HeaderData headerData = builder.build();
        final Set<ServiceToken> peerServiceTokens = MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
        final HeaderPeerData peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
        final MessageHeader messageHeader = new MessageHeader(p2pCtx, null, MASTER_TOKEN, headerData, peerData);
        final MslObject messageHeaderMo = MslTestUtils.toMslObject(encoder, messageHeader);
        
        // Before modifying the header data we need to decrypt it.
        final ICryptoContext cryptoContext = new SessionCryptoContext(p2pCtx, MASTER_TOKEN);
        final byte[] ciphertext = messageHeaderMo.getBytes(KEY_HEADERDATA);
        final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
        final MslObject headerdataMo = encoder.parseObject(plaintext);
        
        // After modifying the header data we need to encrypt it.
        headerdataMo.put(KEY_NON_REPLAYABLE_ID, "x");
        final byte[] headerdata = cryptoContext.encrypt(encoder.encodeObject(headerdataMo, format), encoder, format);
        messageHeaderMo.put(KEY_HEADERDATA, headerdata);
        
        // The header data must be signed or it will not be processed.
        final byte[] signature = cryptoContext.sign(headerdata, encoder, format);
        messageHeaderMo.put(KEY_SIGNATURE, signature);
        
        Header.parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS);
    }
    
    @Test
    public void missingRenewableParseHeader() throws UnsupportedEncodingException, MslEncoderException, MslEncodingException, MslEntityAuthException, MslKeyExchangeException, MslUserAuthException, MslException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MSL_PARSE_ERROR);
        thrown.expectMessageId(MESSAGE_ID);

        final HeaderDataBuilder builder = new HeaderDataBuilder(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
        builder.set(KEY_KEY_REQUEST_DATA, null);
        builder.set(KEY_KEY_RESPONSE_DATA, null);
        final HeaderData headerData = builder.build();
        final Set<ServiceToken> peerServiceTokens = MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
        final HeaderPeerData peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
        final MessageHeader messageHeader = new MessageHeader(p2pCtx, null, MASTER_TOKEN, headerData, peerData);
        final MslObject messageHeaderMo = MslTestUtils.toMslObject(encoder, messageHeader);
        
        // Before modifying the header data we need to decrypt it.
        final ICryptoContext cryptoContext = new SessionCryptoContext(p2pCtx, MASTER_TOKEN);
        final byte[] ciphertext = messageHeaderMo.getBytes(KEY_HEADERDATA);
        final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
        final MslObject headerdataMo = encoder.parseObject(plaintext);
        
        // After modifying the header data we need to encrypt it.
        assertNotNull(headerdataMo.remove(KEY_RENEWABLE));
        final byte[] headerdata = cryptoContext.encrypt(encoder.encodeObject(headerdataMo, format), encoder, format);
        messageHeaderMo.put(KEY_HEADERDATA, headerdata);
        
        // The header data must be signed or it will not be processed.
        final byte[] signature = cryptoContext.sign(headerdata, encoder, format);
        messageHeaderMo.put(KEY_SIGNATURE, signature);
        
        Header.parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS);
    }
    
    @Test
    public void invalidRenewableParseHeader() throws UnsupportedEncodingException, MslEncoderException, MslEncodingException, MslEntityAuthException, MslKeyExchangeException, MslUserAuthException, MslException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MSL_PARSE_ERROR);
        thrown.expectMessageId(MESSAGE_ID);

        final HeaderDataBuilder builder = new HeaderDataBuilder(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
        builder.set(KEY_KEY_REQUEST_DATA, null);
        builder.set(KEY_KEY_RESPONSE_DATA, null);
        final HeaderData headerData = builder.build();
        final Set<ServiceToken> peerServiceTokens = MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
        final HeaderPeerData peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
        final MessageHeader messageHeader = new MessageHeader(p2pCtx, null, MASTER_TOKEN, headerData, peerData);
        final MslObject messageHeaderMo = MslTestUtils.toMslObject(encoder, messageHeader);
        
        // Before modifying the header data we need to decrypt it.
        final ICryptoContext cryptoContext = new SessionCryptoContext(p2pCtx, MASTER_TOKEN);
        final byte[] ciphertext = messageHeaderMo.getBytes(KEY_HEADERDATA);
        final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
        final MslObject headerdataMo = encoder.parseObject(plaintext);
        
        // After modifying the header data we need to encrypt it.
        headerdataMo.put(KEY_RENEWABLE, "x");
        final byte[] headerdata = cryptoContext.encrypt(encoder.encodeObject(headerdataMo, format), encoder, format);
        messageHeaderMo.put(KEY_HEADERDATA, headerdata);
        
        // The header data must be signed or it will not be processed.
        final byte[] signature = cryptoContext.sign(headerdata, encoder, format);
        messageHeaderMo.put(KEY_SIGNATURE, signature);
        
        Header.parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS);
    }
    
    
    @Test
    public void missingHandshakeParseHeader() throws UnsupportedEncodingException, MslEncoderException, MslEncodingException, MslEntityAuthException, MslKeyExchangeException, MslUserAuthException, MslException {
        // FIXME It is okay for the handshake flag to be missing for now.
//        thrown.expect(MslEncodingException.class);
//        thrown.expectMslError(MslError.MSL_PARSE_ERROR);
//        thrown.expectMessageId(MESSAGE_ID);
        
        final HeaderDataBuilder builder = new HeaderDataBuilder(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
        builder.set(KEY_KEY_REQUEST_DATA, null);
        builder.set(KEY_KEY_RESPONSE_DATA, null);
        final HeaderData headerData = builder.build();
        final Set<ServiceToken> peerServiceTokens = MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
        final HeaderPeerData peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
        final MessageHeader messageHeader = new MessageHeader(p2pCtx, null, MASTER_TOKEN, headerData, peerData);
        final MslObject messageHeaderMo = MslTestUtils.toMslObject(encoder, messageHeader);
        
        // Before modifying the header data we need to decrypt it.
        final ICryptoContext cryptoContext = new SessionCryptoContext(p2pCtx, MASTER_TOKEN);
        final byte[] ciphertext = messageHeaderMo.getBytes(KEY_HEADERDATA);
        final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
        final MslObject headerdataMo = encoder.parseObject(plaintext);
        
        // After modifying the header data we need to encrypt it.
        assertNotNull(headerdataMo.remove(KEY_HANDSHAKE));
        final byte[] headerdata = cryptoContext.encrypt(encoder.encodeObject(headerdataMo, format), encoder, format);
        messageHeaderMo.put(KEY_HEADERDATA, headerdata);
        
        // The header data must be signed or it will not be processed.
        final byte[] signature = cryptoContext.sign(headerdata, encoder, format);
        messageHeaderMo.put(KEY_SIGNATURE, signature);
        
        // FIXME For now a missing handshake flag will result in a false value.
        final Header header = Header.parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS);
        assertTrue(header instanceof MessageHeader);
        final MessageHeader moMessageHeader = (MessageHeader)header;
        assertFalse(moMessageHeader.isHandshake());
    }
    
    @Test
    public void invalidHandshakeParseHeader() throws UnsupportedEncodingException, MslEncoderException, MslEncodingException, MslEntityAuthException, MslKeyExchangeException, MslUserAuthException, MslException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MSL_PARSE_ERROR);
        thrown.expectMessageId(MESSAGE_ID);

        final HeaderDataBuilder builder = new HeaderDataBuilder(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
        builder.set(KEY_KEY_REQUEST_DATA, null);
        builder.set(KEY_KEY_RESPONSE_DATA, null);
        final HeaderData headerData = builder.build();
        final Set<ServiceToken> peerServiceTokens = MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
        final HeaderPeerData peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
        final MessageHeader messageHeader = new MessageHeader(p2pCtx, null, MASTER_TOKEN, headerData, peerData);
        final MslObject messageHeaderMo = MslTestUtils.toMslObject(encoder, messageHeader);
        
        // Before modifying the header data we need to decrypt it.
        final ICryptoContext cryptoContext = new SessionCryptoContext(p2pCtx, MASTER_TOKEN);
        final byte[] ciphertext = messageHeaderMo.getBytes(KEY_HEADERDATA);
        final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
        final MslObject headerdataMo = encoder.parseObject(plaintext);
        
        // After modifying the header data we need to encrypt it.
        headerdataMo.put(KEY_HANDSHAKE, "x");
        final byte[] headerdata = cryptoContext.encrypt(encoder.encodeObject(headerdataMo, format), encoder, format);
        messageHeaderMo.put(KEY_HEADERDATA, headerdata);
        
        // The header data must be signed or it will not be processed.
        final byte[] signature = cryptoContext.sign(headerdata, encoder, format);
        messageHeaderMo.put(KEY_SIGNATURE, signature);
        
        Header.parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS);
    }
    
    @Test
    public void invalidCapabilities() throws MslEncoderException, MslKeyExchangeException, MslUserAuthException, MslException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MSL_PARSE_ERROR);
        thrown.expectMessageId(MESSAGE_ID);

        final HeaderDataBuilder builder = new HeaderDataBuilder(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
        builder.set(KEY_KEY_REQUEST_DATA, null);
        builder.set(KEY_KEY_RESPONSE_DATA, null);
        final HeaderData headerData = builder.build();
        final Set<ServiceToken> peerServiceTokens = MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
        final HeaderPeerData peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
        final MessageHeader messageHeader = new MessageHeader(p2pCtx, null, MASTER_TOKEN, headerData, peerData);
        final MslObject messageHeaderMo = MslTestUtils.toMslObject(encoder, messageHeader);
        
        // Before modifying the header data we need to decrypt it.
        final ICryptoContext cryptoContext = new SessionCryptoContext(p2pCtx, MASTER_TOKEN);
        final byte[] ciphertext = messageHeaderMo.getBytes(KEY_HEADERDATA);
        final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
        final MslObject headerdataMo = encoder.parseObject(plaintext);
        
        // After modifying the header data we need to encrypt it.
        headerdataMo.put(KEY_CAPABILITIES, "x");
        final byte[] headerdata = cryptoContext.encrypt(encoder.encodeObject(headerdataMo, format), encoder, format);
        messageHeaderMo.put(KEY_HEADERDATA, headerdata);
        
        // The header data must be signed or it will not be processed.
        final byte[] signature = cryptoContext.sign(headerdata, encoder, format);
        messageHeaderMo.put(KEY_SIGNATURE, signature);
        
        Header.parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS);
    }
    
    @Test
    public void invalidKeyRequestDataArrayParseHeader() throws MslEncoderException, UnsupportedEncodingException, MslEncodingException, MslEntityAuthException, MslKeyExchangeException, MslUserAuthException, MslException {
        thrown.expect(MslException.class);
        thrown.expectMessageId(MESSAGE_ID);

        final HeaderDataBuilder builder = new HeaderDataBuilder(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
        builder.set(KEY_KEY_REQUEST_DATA, null);
        builder.set(KEY_KEY_RESPONSE_DATA, null);
        final HeaderData headerData = builder.build();
        final Set<ServiceToken> peerServiceTokens = MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
        final HeaderPeerData peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
        final MessageHeader messageHeader = new MessageHeader(p2pCtx, null, MASTER_TOKEN, headerData, peerData);
        final MslObject messageHeaderMo = MslTestUtils.toMslObject(encoder, messageHeader);
        
        // Before modifying the header data we need to decrypt it.
        final ICryptoContext cryptoContext = new SessionCryptoContext(p2pCtx, MASTER_TOKEN);
        final byte[] ciphertext = messageHeaderMo.getBytes(KEY_HEADERDATA);
        final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
        final MslObject headerdataMo = encoder.parseObject(plaintext);
        
        // After modifying the header data we need to encrypt it.
        headerdataMo.put(KEY_KEY_REQUEST_DATA, "x");
        final byte[] headerdata = cryptoContext.encrypt(encoder.encodeObject(headerdataMo, format), encoder, format);
        messageHeaderMo.put(KEY_HEADERDATA, headerdata);
        
        // The header data must be signed or it will not be processed.
        final byte[] signature = cryptoContext.sign(headerdata, encoder, format);
        messageHeaderMo.put(KEY_SIGNATURE, signature);
        
        Header.parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS);
    }
    
    @Test
    public void invalidKeyRequestDataParseHeader() throws MslEncodingException, MslEntityAuthException, MslCryptoException, MslKeyExchangeException, MslUserAuthException, MslException, UnsupportedEncodingException, MslEncoderException {
        thrown.expect(MslException.class);
        thrown.expectMessageId(MESSAGE_ID);

        final HeaderDataBuilder builder = new HeaderDataBuilder(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
        builder.set(KEY_KEY_REQUEST_DATA, null);
        builder.set(KEY_KEY_RESPONSE_DATA, null);
        final HeaderData headerData = builder.build();
        final Set<ServiceToken> peerServiceTokens = MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
        final HeaderPeerData peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
        final MessageHeader messageHeader = new MessageHeader(p2pCtx, null, MASTER_TOKEN, headerData, peerData);
        final MslObject messageHeaderMo = MslTestUtils.toMslObject(encoder, messageHeader);
        
        // Before modifying the header data we need to decrypt it.
        final ICryptoContext cryptoContext = new SessionCryptoContext(p2pCtx, MASTER_TOKEN);
        final byte[] ciphertext = messageHeaderMo.getBytes(KEY_HEADERDATA);
        final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
        final MslObject headerdataMo = encoder.parseObject(plaintext);
        
        // After modifying the header data we need to encrypt it.
        final MslArray a = encoder.createArray();
        a.put(-1, "x");
        headerdataMo.put(KEY_PEER_SERVICE_TOKENS, a);
        final byte[] headerdata = cryptoContext.encrypt(encoder.encodeObject(headerdataMo, format), encoder, format);
        messageHeaderMo.put(KEY_HEADERDATA, headerdata);
        
        // The header data must be signed or it will not be processed.
        final byte[] signature = cryptoContext.sign(headerdata, encoder, format);
        messageHeaderMo.put(KEY_SIGNATURE, signature);
        
        Header.parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS);
    }
    
    @Test
    public void invalidServiceTokensArrayParseHeader() throws MslEncoderException, UnsupportedEncodingException, MslEncodingException, MslEntityAuthException, MslKeyExchangeException, MslUserAuthException, MslException {
        thrown.expect(MslException.class);
        thrown.expectMessageId(MESSAGE_ID);

        final HeaderDataBuilder builder = new HeaderDataBuilder(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
        builder.set(KEY_KEY_REQUEST_DATA, null);
        builder.set(KEY_KEY_RESPONSE_DATA, null);
        final HeaderData headerData = builder.build();
        final Set<ServiceToken> peerServiceTokens = MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
        final HeaderPeerData peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
        final MessageHeader messageHeader = new MessageHeader(p2pCtx, null, MASTER_TOKEN, headerData, peerData);
        final MslObject messageHeaderMo = MslTestUtils.toMslObject(encoder, messageHeader);
        
        // Before modifying the header data we need to decrypt it.
        final ICryptoContext cryptoContext = new SessionCryptoContext(p2pCtx, MASTER_TOKEN);
        final byte[] ciphertext = messageHeaderMo.getBytes(KEY_HEADERDATA);
        final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
        final MslObject headerdataMo = encoder.parseObject(plaintext);
        
        // After modifying the header data we need to encrypt it.
        headerdataMo.put(KEY_SERVICE_TOKENS, "x");
        final byte[] headerdata = cryptoContext.encrypt(encoder.encodeObject(headerdataMo, format), encoder, format);
        messageHeaderMo.put(KEY_HEADERDATA, headerdata);
        
        // The header data must be signed or it will not be processed.
        final byte[] signature = cryptoContext.sign(headerdata, encoder, format);
        messageHeaderMo.put(KEY_SIGNATURE, signature);
        
        Header.parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS);
    }
    
    @Test
    public void invalidServiceTokenParseHeader() throws UnsupportedEncodingException, MslEntityAuthException, MslKeyExchangeException, MslUserAuthException, MslException, MslEncoderException {
        thrown.expect(MslException.class);
        thrown.expectMessageId(MESSAGE_ID);

        final HeaderDataBuilder builder = new HeaderDataBuilder(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
        builder.set(KEY_KEY_REQUEST_DATA, null);
        builder.set(KEY_KEY_RESPONSE_DATA, null);
        final HeaderData headerData = builder.build();
        final Set<ServiceToken> peerServiceTokens = MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
        final HeaderPeerData peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
        final MessageHeader messageHeader = new MessageHeader(p2pCtx, null, MASTER_TOKEN, headerData, peerData);
        final MslObject messageHeaderMo = MslTestUtils.toMslObject(encoder, messageHeader);
        
        // Before modifying the header data we need to decrypt it.
        final ICryptoContext cryptoContext = new SessionCryptoContext(p2pCtx, MASTER_TOKEN);
        final byte[] ciphertext = messageHeaderMo.getBytes(KEY_HEADERDATA);
        final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
        final MslObject headerdataMo = encoder.parseObject(plaintext);
        
        // After modifying the header data we need to encrypt it.
        final MslArray a = encoder.createArray();
        a.put(-1, "x");
        headerdataMo.put(KEY_SERVICE_TOKENS, a);
        final byte[] headerdata = cryptoContext.encrypt(encoder.encodeObject(headerdataMo, format), encoder, format);
        messageHeaderMo.put(KEY_HEADERDATA, headerdata);
        
        // The header data must be signed or it will not be processed.
        final byte[] signature = cryptoContext.sign(headerdata, encoder, format);
        messageHeaderMo.put(KEY_SIGNATURE, signature);
        
        Header.parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS);
    }
    
    @Test
    public void invalidPeerServiceTokensArrayParseHeader() throws MslEncoderException, UnsupportedEncodingException, MslEncodingException, MslEntityAuthException, MslKeyExchangeException, MslUserAuthException, MslException {
        thrown.expect(MslException.class);
        thrown.expectMessageId(MESSAGE_ID);

        final HeaderDataBuilder builder = new HeaderDataBuilder(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
        builder.set(KEY_KEY_REQUEST_DATA, null);
        builder.set(KEY_KEY_RESPONSE_DATA, null);
        final HeaderData headerData = builder.build();
        final Set<ServiceToken> peerServiceTokens = MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
        final HeaderPeerData peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
        final MessageHeader messageHeader = new MessageHeader(p2pCtx, null, MASTER_TOKEN, headerData, peerData);
        final MslObject messageHeaderMo = MslTestUtils.toMslObject(encoder, messageHeader);
        
        // Before modifying the header data we need to decrypt it.
        final ICryptoContext cryptoContext = new SessionCryptoContext(p2pCtx, MASTER_TOKEN);
        final byte[] ciphertext = messageHeaderMo.getBytes(KEY_HEADERDATA);
        final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
        final MslObject headerdataMo = encoder.parseObject(plaintext);
        
        // After modifying the header data we need to encrypt it.
        headerdataMo.put(KEY_PEER_SERVICE_TOKENS, "x");
        final byte[] headerdata = cryptoContext.encrypt(encoder.encodeObject(headerdataMo, format), encoder, format);
        messageHeaderMo.put(KEY_HEADERDATA, headerdata);
        
        // The header data must be signed or it will not be processed.
        final byte[] signature = cryptoContext.sign(headerdata, encoder, format);
        messageHeaderMo.put(KEY_SIGNATURE, signature);
        
        Header.parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS);
    }
    
    @Test
    public void invalidPeerServiceTokenParseHeader() throws MslEncoderException, UnsupportedEncodingException, MslEncodingException, MslEntityAuthException, MslKeyExchangeException, MslUserAuthException, MslException {
        thrown.expect(MslException.class);
        thrown.expectMessageId(MESSAGE_ID);

        final HeaderDataBuilder builder = new HeaderDataBuilder(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
        builder.set(KEY_KEY_REQUEST_DATA, null);
        builder.set(KEY_KEY_RESPONSE_DATA, null);
        final HeaderData headerData = builder.build();
        final Set<ServiceToken> peerServiceTokens = MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
        final HeaderPeerData peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
        final MessageHeader messageHeader = new MessageHeader(p2pCtx, null, MASTER_TOKEN, headerData, peerData);
        final MslObject messageHeaderMo = MslTestUtils.toMslObject(encoder, messageHeader);
        
        // Before modifying the header data we need to decrypt it.
        final ICryptoContext cryptoContext = new SessionCryptoContext(p2pCtx, MASTER_TOKEN);
        final byte[] ciphertext = messageHeaderMo.getBytes(KEY_HEADERDATA);
        final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
        final MslObject headerdataMo = encoder.parseObject(plaintext);
        
        // After modifying the header data we need to encrypt it.
        final MslArray a = encoder.createArray();
        a.put(-1, "x");
        headerdataMo.put(KEY_PEER_SERVICE_TOKENS, a);
        final byte[] headerdata = cryptoContext.encrypt(encoder.encodeObject(headerdataMo, format), encoder, format);
        messageHeaderMo.put(KEY_HEADERDATA, headerdata);
        
        // The header data must be signed or it will not be processed.
        final byte[] signature = cryptoContext.sign(headerdata, encoder, format);
        messageHeaderMo.put(KEY_SIGNATURE, signature);
        
        Header.parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS);
    }
    
    @Test
    public void invalidPeerMasterTokenParseHeader() throws MslEncoderException, UnsupportedEncodingException, MslEncodingException, MslEntityAuthException, MslKeyExchangeException, MslUserAuthException, MslException {
        thrown.expect(MslException.class);
        thrown.expectMessageId(MESSAGE_ID);

        final HeaderDataBuilder builder = new HeaderDataBuilder(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
        builder.set(KEY_KEY_REQUEST_DATA, null);
        builder.set(KEY_KEY_RESPONSE_DATA, null);
        final HeaderData headerData = builder.build();
        final Set<ServiceToken> peerServiceTokens = MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
        final HeaderPeerData peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
        final MessageHeader messageHeader = new MessageHeader(p2pCtx, null, MASTER_TOKEN, headerData, peerData);
        final MslObject messageHeaderMo = MslTestUtils.toMslObject(encoder, messageHeader);
        
        // Before modifying the header data we need to decrypt it.
        final ICryptoContext cryptoContext = new SessionCryptoContext(p2pCtx, MASTER_TOKEN);
        final byte[] ciphertext = messageHeaderMo.getBytes(KEY_HEADERDATA);
        final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
        final MslObject headerdataMo = encoder.parseObject(plaintext);
        
        // After modifying the header data we need to encrypt it.
        headerdataMo.put(KEY_PEER_MASTER_TOKEN, "x");
        final byte[] headerdata = cryptoContext.encrypt(encoder.encodeObject(headerdataMo, format), encoder, format);
        messageHeaderMo.put(KEY_HEADERDATA, headerdata);
        
        // The header data must be signed or it will not be processed.
        final byte[] signature = cryptoContext.sign(headerdata, encoder, format);
        messageHeaderMo.put(KEY_SIGNATURE, signature);
        
        Header.parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS);
    }
    
    @Test
    public void invalidPeerUserIdTokenParseHeader() throws MslEncoderException, UnsupportedEncodingException, MslEncodingException, MslEntityAuthException, MslKeyExchangeException, MslUserAuthException, MslException {
        thrown.expect(MslException.class);
        thrown.expectMessageId(MESSAGE_ID);

        final HeaderDataBuilder builder = new HeaderDataBuilder(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
        builder.set(KEY_KEY_REQUEST_DATA, null);
        builder.set(KEY_KEY_RESPONSE_DATA, null);
        final HeaderData headerData = builder.build();
        final Set<ServiceToken> peerServiceTokens = MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
        final HeaderPeerData peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
        final MessageHeader messageHeader = new MessageHeader(p2pCtx, null, MASTER_TOKEN, headerData, peerData);
        final MslObject messageHeaderMo = MslTestUtils.toMslObject(encoder, messageHeader);
        
        // Before modifying the header data we need to decrypt it.
        final ICryptoContext cryptoContext = new SessionCryptoContext(p2pCtx, MASTER_TOKEN);
        final byte[] ciphertext = messageHeaderMo.getBytes(KEY_HEADERDATA);
        final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
        final MslObject headerdataMo = encoder.parseObject(plaintext);
        
        // After modifying the header data we need to encrypt it.
        headerdataMo.put(KEY_PEER_USER_ID_TOKEN, "x");
        final byte[] headerdata = cryptoContext.encrypt(encoder.encodeObject(headerdataMo, format), encoder, format);
        messageHeaderMo.put(KEY_HEADERDATA, headerdata);
        
        // The header data must be signed or it will not be processed.
        final byte[] signature = cryptoContext.sign(headerdata, encoder, format);
        messageHeaderMo.put(KEY_SIGNATURE, signature);
        
        Header.parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS);
    }
    
    @Test
    public void invalidUserAuthParseHeader() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslMessageException, MslKeyExchangeException, MslUserAuthException, MslEncoderException, MslException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMessageId(MESSAGE_ID);

        final HeaderDataBuilder builder = new HeaderDataBuilder(p2pCtx, MASTER_TOKEN, null, true);
        builder.set(KEY_KEY_REQUEST_DATA, null);
        builder.set(KEY_KEY_RESPONSE_DATA, null);
        final HeaderData headerData = builder.build();
        final Set<ServiceToken> peerServiceTokens = MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
        final HeaderPeerData peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
        final MessageHeader messageHeader = new MessageHeader(p2pCtx, null, MASTER_TOKEN, headerData, peerData);
        final MslObject messageHeaderMo = MslTestUtils.toMslObject(encoder, messageHeader);
        
        // Before modifying the header data we need to decrypt it.
        final ICryptoContext cryptoContext = new SessionCryptoContext(p2pCtx, MASTER_TOKEN);
        final byte[] ciphertext = messageHeaderMo.getBytes(KEY_HEADERDATA);
        final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
        final MslObject headerdataMo = encoder.parseObject(plaintext);
        
        // After modifying the header data we need to encrypt it.
        headerdataMo.put(KEY_USER_AUTHENTICATION_DATA, "x");
        final byte[] headerdata = cryptoContext.encrypt(encoder.encodeObject(headerdataMo, format), encoder, format);
        messageHeaderMo.put(KEY_HEADERDATA, headerdata);
        
        // The header data must be signed or it will not be processed.
        final byte[] signature = cryptoContext.sign(headerdata, encoder, format);
        messageHeaderMo.put(KEY_SIGNATURE, signature);
        
        Header.parseHeader(p2pCtx, messageHeaderMo, CRYPTO_CONTEXTS);
    }
    
    @Test(expected = MslInternalException.class)
    public void unencryptedUserAuthDataCtor() throws MslEncodingException, MslCryptoException, MslException {
        final MslContext x509Ctx = new MockMslContext(EntityAuthenticationScheme.X509, false);
        
        final HeaderDataBuilder builder = new HeaderDataBuilder(x509Ctx, null, null, false);
        final HeaderData headerData = builder.build();
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final EntityAuthenticationData entityAuthData = x509Ctx.getEntityAuthenticationData(null);
        new MessageHeader(x509Ctx, entityAuthData, null, headerData, peerData);
    }
    
    @Test
    public void unencryptedUserAuthDataParseHeader() throws MslEncodingException, MslCryptoException, MslException, MslEncoderException {
        thrown.expect(MslMessageException.class);
        thrown.expectMslError(MslError.UNENCRYPTED_MESSAGE_WITH_USERAUTHDATA);
        thrown.expectMessageId(MESSAGE_ID);

        final MslContext x509Ctx = new MockMslContext(EntityAuthenticationScheme.X509, false);

        final HeaderDataBuilder builder = new HeaderDataBuilder(x509Ctx, null, null, true);
        builder.set(KEY_USER_AUTHENTICATION_DATA, null);
        final HeaderData headerData = builder.build();
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final EntityAuthenticationData entityAuthData = x509Ctx.getEntityAuthenticationData(null);
        final MessageHeader messageHeader = new MessageHeader(x509Ctx, entityAuthData, null, headerData, peerData);
        final MslObject messageHeaderMo = MslTestUtils.toMslObject(encoder, messageHeader);
        
        // The header data is not encrypted.
        final byte[] plaintext = messageHeaderMo.getBytes(KEY_HEADERDATA);
        final MslObject headerdataMo = encoder.parseObject(plaintext);
        headerdataMo.put(KEY_USER_AUTHENTICATION_DATA, USER_AUTH_DATA);
        final byte[] headerdata = encoder.encodeObject(headerdataMo, format);
        messageHeaderMo.put(KEY_HEADERDATA, headerdata);
        
        // The header data must be signed or it will not be processed.
        final EntityAuthenticationFactory factory = x509Ctx.getEntityAuthenticationFactory(entityAuthData.getScheme());
        final ICryptoContext cryptoContext = factory.getCryptoContext(x509Ctx, entityAuthData);
        final byte[] signature = cryptoContext.sign(headerdata, encoder, format);
        messageHeaderMo.put(KEY_SIGNATURE, signature);
        
        Header.parseHeader(x509Ctx, messageHeaderMo, CRYPTO_CONTEXTS);
    }
    
    @Test(expected = UnsupportedOperationException.class)
    public void immutableKeyRequestData() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslException {
        final HeaderDataBuilder builder = new HeaderDataBuilder(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, false);
        final HeaderData headerData = builder.build();
        final HeaderPeerData peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, null);
        final MessageHeader messageHeader = new MessageHeader(trustedNetCtx, null, MASTER_TOKEN, headerData, peerData);
        
        messageHeader.getKeyRequestData().clear();
    }
    
    @Test(expected = UnsupportedOperationException.class)
    public void immutableServiceTokens() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslException {
        final HeaderDataBuilder builder = new HeaderDataBuilder(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, false);
        final HeaderData headerData = builder.build();
        final HeaderPeerData peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, null);
        final MessageHeader messageHeader = new MessageHeader(trustedNetCtx, null, MASTER_TOKEN, headerData, peerData);
        
        messageHeader.getServiceTokens().clear();
    }
    
    @Test(expected = UnsupportedOperationException.class)
    public void immutablePeerServiceTokens() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslException {
        final HeaderDataBuilder builder = new HeaderDataBuilder(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, false);
        final HeaderData headerData = builder.build();
        final Set<ServiceToken> peerServiceTokens = MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
        final HeaderPeerData peerData = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokens);
        final MessageHeader messageHeader = new MessageHeader(p2pCtx, null, MASTER_TOKEN, headerData, peerData);
        
        messageHeader.getPeerServiceTokens().clear();
    }
    
    @Test
    public void equalsMasterToken() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslException, MslEncoderException {
        final HeaderDataBuilder builder = new HeaderDataBuilder(trustedNetCtx, null, null, false);
        final HeaderData headerData = builder.build();
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        
        final MasterToken masterTokenA = MslTestUtils.getMasterToken(trustedNetCtx, 1, 1);
        final MasterToken masterTokenB = MslTestUtils.getMasterToken(trustedNetCtx, 1, 2);
        final MessageHeader messageHeaderA = new MessageHeader(trustedNetCtx, null, masterTokenA, headerData, peerData);
        final MessageHeader messageHeaderB = new MessageHeader(trustedNetCtx, null, masterTokenB, headerData, peerData);
        final MessageHeader messageHeaderA2 = (MessageHeader)Header.parseHeader(trustedNetCtx, MslTestUtils.toMslObject(encoder, messageHeaderA), CRYPTO_CONTEXTS);
        
        assertTrue(messageHeaderA.equals(messageHeaderA));
        assertEquals(messageHeaderA.hashCode(), messageHeaderA.hashCode());
        
        assertFalse(messageHeaderA.equals(messageHeaderB));
        assertFalse(messageHeaderB.equals(messageHeaderA));
        assertTrue(messageHeaderA.hashCode() != messageHeaderB.hashCode());
        
        assertTrue(messageHeaderA.equals(messageHeaderA2));
        assertTrue(messageHeaderA2.equals(messageHeaderA));
        assertEquals(messageHeaderA.hashCode(), messageHeaderA2.hashCode());
    }
    
    @Test
    public void equalsEntityAuthData() throws MslMasterTokenException, MslEntityAuthException, MslException, MslEncoderException {
        final HeaderDataBuilder builder = new HeaderDataBuilder(trustedNetCtx, null, null, false);
        final HeaderData headerData = builder.build();
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        
        final EntityAuthenticationData entityAuthDataA = new PresharedAuthenticationData(MockPresharedAuthenticationFactory.PSK_ESN);
        final EntityAuthenticationData entityAuthDataB = new PresharedAuthenticationData(MockPresharedAuthenticationFactory.PSK_ESN2);
        final MessageHeader messageHeaderA = new MessageHeader(trustedNetCtx, entityAuthDataA, null, headerData, peerData);
        final MessageHeader messageHeaderB = new MessageHeader(trustedNetCtx, entityAuthDataB, null, headerData, peerData);
        final MessageHeader messageHeaderA2 = (MessageHeader)Header.parseHeader(trustedNetCtx, MslTestUtils.toMslObject(encoder, messageHeaderA), CRYPTO_CONTEXTS);
        
        assertTrue(messageHeaderA.equals(messageHeaderA));
        assertEquals(messageHeaderA.hashCode(), messageHeaderA.hashCode());
        
        assertFalse(messageHeaderA.equals(messageHeaderB));
        assertFalse(messageHeaderB.equals(messageHeaderA));
        assertTrue(messageHeaderA.hashCode() != messageHeaderB.hashCode());
        
        assertTrue(messageHeaderA.equals(messageHeaderA2));
        assertTrue(messageHeaderA2.equals(messageHeaderA));
        assertEquals(messageHeaderA.hashCode(), messageHeaderA2.hashCode());
    }
    
    @Test
    public void equalsMasterTokenEntityAuthData() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslException, MslEncoderException {
        final HeaderDataBuilder builder = new HeaderDataBuilder(trustedNetCtx, null, null, false);
        final HeaderData headerData = builder.build();
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        
        final EntityAuthenticationData entityAuthData = trustedNetCtx.getEntityAuthenticationData(null);
        final MessageHeader messageHeaderA = new MessageHeader(trustedNetCtx, null, MASTER_TOKEN, headerData, peerData);
        final MessageHeader messageHeaderB = new MessageHeader(trustedNetCtx, entityAuthData, null, headerData, peerData);
        final MessageHeader messageHeaderA2 = (MessageHeader)Header.parseHeader(trustedNetCtx, MslTestUtils.toMslObject(encoder, messageHeaderA), CRYPTO_CONTEXTS);
        
        assertTrue(messageHeaderA.equals(messageHeaderA));
        assertEquals(messageHeaderA.hashCode(), messageHeaderA.hashCode());
        
        assertFalse(messageHeaderA.equals(messageHeaderB));
        assertFalse(messageHeaderB.equals(messageHeaderA));
        assertTrue(messageHeaderA.hashCode() != messageHeaderB.hashCode());
        
        assertTrue(messageHeaderA.equals(messageHeaderA2));
        assertTrue(messageHeaderA2.equals(messageHeaderA));
        assertEquals(messageHeaderA.hashCode(), messageHeaderA2.hashCode());
    }
    
    @Test
    public void equalsTimestamp() throws MslEncodingException, MslCryptoException, MslException, InterruptedException, MslEncoderException {
        final HeaderDataBuilder builder = new HeaderDataBuilder(trustedNetCtx, null, null, false);
        final HeaderData headerData = builder.build();
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        
        final MessageHeader messageHeaderA = new MessageHeader(trustedNetCtx, null, MASTER_TOKEN, headerData, peerData);
        Thread.sleep(MILLISECONDS_PER_SECOND);
        final MessageHeader messageHeaderB = new MessageHeader(trustedNetCtx, null, MASTER_TOKEN, headerData, peerData);
        final MessageHeader messageHeaderA2 = (MessageHeader)Header.parseHeader(trustedNetCtx, MslTestUtils.toMslObject(encoder, messageHeaderA), CRYPTO_CONTEXTS);
        
        assertTrue(messageHeaderA.equals(messageHeaderA));
        assertEquals(messageHeaderA.hashCode(), messageHeaderA.hashCode());
        
        assertFalse(messageHeaderA.equals(messageHeaderB));
        assertFalse(messageHeaderB.equals(messageHeaderA));
        assertTrue(messageHeaderA.hashCode() != messageHeaderB.hashCode());
        
        assertTrue(messageHeaderA.equals(messageHeaderA2));
        assertTrue(messageHeaderA2.equals(messageHeaderA));
        assertEquals(messageHeaderA.hashCode(), messageHeaderA2.hashCode());
    }
    
    @Test
    public void equalsMessageId() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslException, MslEncoderException {
        final Set<ServiceToken> serviceTokens = MslTestUtils.getServiceTokens(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
        final HeaderData headerDataA = new HeaderDataBuilder(trustedNetCtx, USER_ID_TOKEN, serviceTokens).set(KEY_MESSAGE_ID, 1L).build();
        final HeaderData headerDataB = new HeaderDataBuilder(trustedNetCtx, USER_ID_TOKEN, serviceTokens).set(KEY_MESSAGE_ID, 2L).build();
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        
        final MessageHeader messageHeaderA = new MessageHeader(trustedNetCtx, null, MASTER_TOKEN, headerDataA, peerData);
        final MessageHeader messageHeaderB = new MessageHeader(trustedNetCtx, null, MASTER_TOKEN, headerDataB, peerData);
        final MessageHeader messageHeaderA2 = (MessageHeader)Header.parseHeader(trustedNetCtx, MslTestUtils.toMslObject(encoder, messageHeaderA), CRYPTO_CONTEXTS);
        
        assertTrue(messageHeaderA.equals(messageHeaderA));
        assertEquals(messageHeaderA.hashCode(), messageHeaderA.hashCode());
        
        assertFalse(messageHeaderA.equals(messageHeaderB));
        assertFalse(messageHeaderB.equals(messageHeaderA));
        assertTrue(messageHeaderA.hashCode() != messageHeaderB.hashCode());
        
        assertTrue(messageHeaderA.equals(messageHeaderA2));
        assertTrue(messageHeaderA2.equals(messageHeaderA));
        assertEquals(messageHeaderA.hashCode(), messageHeaderA2.hashCode());
    }
    
    @Test
    public void equalsNonReplayable() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslKeyExchangeException, MslUserAuthException, MslException, MslEncoderException {
        final Set<ServiceToken> serviceTokens = MslTestUtils.getServiceTokens(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
        final HeaderData headerDataA = new HeaderDataBuilder(trustedNetCtx, USER_ID_TOKEN, serviceTokens).set(KEY_NON_REPLAYABLE_ID, 1L).build();
        final HeaderData headerDataB = new HeaderDataBuilder(trustedNetCtx, USER_ID_TOKEN, serviceTokens).set(KEY_NON_REPLAYABLE_ID, 2L).build();
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        
        final MessageHeader messageHeaderA = new MessageHeader(trustedNetCtx, null, MASTER_TOKEN, headerDataA, peerData);
        final MessageHeader messageHeaderB = new MessageHeader(trustedNetCtx, null, MASTER_TOKEN, headerDataB, peerData);
        final MessageHeader messageHeaderA2 = (MessageHeader)Header.parseHeader(trustedNetCtx, MslTestUtils.toMslObject(encoder, messageHeaderA), CRYPTO_CONTEXTS);
        
        assertTrue(messageHeaderA.equals(messageHeaderA));
        assertEquals(messageHeaderA.hashCode(), messageHeaderA.hashCode());
        
        assertFalse(messageHeaderA.equals(messageHeaderB));
        assertFalse(messageHeaderB.equals(messageHeaderA));
        assertTrue(messageHeaderA.hashCode() != messageHeaderB.hashCode());
        
        assertTrue(messageHeaderA.equals(messageHeaderA2));
        assertTrue(messageHeaderA2.equals(messageHeaderA));
        assertEquals(messageHeaderA.hashCode(), messageHeaderA2.hashCode());
    }
    
    @Test
    public void equalsRenewable() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslException, MslEncoderException {
        final Set<ServiceToken> serviceTokens = MslTestUtils.getServiceTokens(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
        final HeaderData headerDataA = new HeaderDataBuilder(trustedNetCtx, USER_ID_TOKEN, serviceTokens).set(KEY_RENEWABLE, true).build();
        final HeaderData headerDataB = new HeaderDataBuilder(trustedNetCtx, USER_ID_TOKEN, serviceTokens).set(KEY_RENEWABLE, false).build();
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        
        final MessageHeader messageHeaderA = new MessageHeader(trustedNetCtx, null, MASTER_TOKEN, headerDataA, peerData);
        final MessageHeader messageHeaderB = new MessageHeader(trustedNetCtx, null, MASTER_TOKEN, headerDataB, peerData);
        final MessageHeader messageHeaderA2 = (MessageHeader)Header.parseHeader(trustedNetCtx, MslTestUtils.toMslObject(encoder, messageHeaderA), CRYPTO_CONTEXTS);
        
        assertTrue(messageHeaderA.equals(messageHeaderA));
        assertEquals(messageHeaderA.hashCode(), messageHeaderA.hashCode());
        
        assertFalse(messageHeaderA.equals(messageHeaderB));
        assertFalse(messageHeaderB.equals(messageHeaderA));
        assertTrue(messageHeaderA.hashCode() != messageHeaderB.hashCode());
        
        assertTrue(messageHeaderA.equals(messageHeaderA2));
        assertTrue(messageHeaderA2.equals(messageHeaderA));
        assertEquals(messageHeaderA.hashCode(), messageHeaderA2.hashCode());
    }
    
    @Test
    public void equalsHandshake() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslException, MslEncoderException {
        final Set<ServiceToken> serviceTokens = MslTestUtils.getServiceTokens(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
        final HeaderData headerDataA = new HeaderDataBuilder(trustedNetCtx, USER_ID_TOKEN, serviceTokens).set(KEY_HANDSHAKE, true).build();
        final HeaderData headerDataB = new HeaderDataBuilder(trustedNetCtx, USER_ID_TOKEN, serviceTokens).set(KEY_HANDSHAKE, false).build();
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        
        final MessageHeader messageHeaderA = new MessageHeader(trustedNetCtx, null, MASTER_TOKEN, headerDataA, peerData);
        final MessageHeader messageHeaderB = new MessageHeader(trustedNetCtx, null, MASTER_TOKEN, headerDataB, peerData);
        final MessageHeader messageHeaderA2 = (MessageHeader)Header.parseHeader(trustedNetCtx, MslTestUtils.toMslObject(encoder, messageHeaderA), CRYPTO_CONTEXTS);
        
        assertTrue(messageHeaderA.equals(messageHeaderA));
        assertEquals(messageHeaderA.hashCode(), messageHeaderA.hashCode());
        
        assertFalse(messageHeaderA.equals(messageHeaderB));
        assertFalse(messageHeaderB.equals(messageHeaderA));
        assertTrue(messageHeaderA.hashCode() != messageHeaderB.hashCode());
        
        assertTrue(messageHeaderA.equals(messageHeaderA2));
        assertTrue(messageHeaderA2.equals(messageHeaderA));
        assertEquals(messageHeaderA.hashCode(), messageHeaderA2.hashCode());
    }
    
    @Test
    public void equalsCapabilities() throws MslKeyExchangeException, MslUserAuthException, MslException, MslEncoderException {
        final MessageCapabilities capsA = new MessageCapabilities(ALGOS, LANGUAGES, FORMATS);
        final MessageCapabilities capsB = new MessageCapabilities(new HashSet<CompressionAlgorithm>(), new ArrayList<String>(), new HashSet<MslEncoderFormat>());
        final HeaderData headerDataA = new HeaderDataBuilder(trustedNetCtx, USER_ID_TOKEN, null).set(KEY_CAPABILITIES, capsA).build();
        final HeaderData headerDataB = new HeaderDataBuilder(trustedNetCtx, USER_ID_TOKEN, null).set(KEY_CAPABILITIES, capsB).build();
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        
        final MessageHeader messageHeaderA = new MessageHeader(trustedNetCtx, null, MASTER_TOKEN, headerDataA, peerData);
        final MessageHeader messageHeaderB = new MessageHeader(trustedNetCtx, null, MASTER_TOKEN, headerDataB, peerData);
        final MessageHeader messageHeaderA2 = (MessageHeader)Header.parseHeader(trustedNetCtx, MslTestUtils.toMslObject(encoder, messageHeaderA), CRYPTO_CONTEXTS);
        
        assertTrue(messageHeaderA.equals(messageHeaderA));
        assertEquals(messageHeaderA.hashCode(), messageHeaderA.hashCode());
        
        assertFalse(messageHeaderA.equals(messageHeaderB));
        assertFalse(messageHeaderB.equals(messageHeaderA));
        assertTrue(messageHeaderA.hashCode() != messageHeaderB.hashCode());
        
        assertTrue(messageHeaderA.equals(messageHeaderA2));
        assertTrue(messageHeaderA2.equals(messageHeaderA));
        assertEquals(messageHeaderA.hashCode(), messageHeaderA2.hashCode());
    }
    
    @Test
    public void equalsKeyRequestData() throws MslEncodingException, MslEntityAuthException, MslCryptoException, MslKeyExchangeException, MslUserAuthException, MslException, MslEncoderException {
        final Set<ServiceToken> serviceTokens = MslTestUtils.getServiceTokens(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
        final Set<KeyRequestData> keyRequestDataA = new HashSet<KeyRequestData>();
        keyRequestDataA.add(new SymmetricWrappedExchange.RequestData(KeyId.SESSION));
        final Set<KeyRequestData> keyRequestDataB = new HashSet<KeyRequestData>();
        keyRequestDataB.add(new SymmetricWrappedExchange.RequestData(KeyId.PSK));
        final HeaderData headerDataA = new HeaderDataBuilder(trustedNetCtx, USER_ID_TOKEN, serviceTokens).set(KEY_KEY_REQUEST_DATA, keyRequestDataA).build();
        final HeaderData headerDataB = new HeaderDataBuilder(trustedNetCtx, USER_ID_TOKEN, serviceTokens).set(KEY_KEY_REQUEST_DATA, keyRequestDataB).build();
        final HeaderData headerDataC = new HeaderDataBuilder(trustedNetCtx, USER_ID_TOKEN, serviceTokens).set(KEY_KEY_REQUEST_DATA, null).build();
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        
        final MessageHeader messageHeaderA = new MessageHeader(trustedNetCtx, null, MASTER_TOKEN, headerDataA, peerData);
        final MessageHeader messageHeaderB = new MessageHeader(trustedNetCtx, null, MASTER_TOKEN, headerDataB, peerData);
        final MessageHeader messageHeaderC = new MessageHeader(trustedNetCtx, null, MASTER_TOKEN, headerDataC, peerData);
        final MessageHeader messageHeaderA2 = (MessageHeader)Header.parseHeader(trustedNetCtx, MslTestUtils.toMslObject(encoder, messageHeaderA), CRYPTO_CONTEXTS);
        
        assertTrue(messageHeaderA.equals(messageHeaderA));
        assertEquals(messageHeaderA.hashCode(), messageHeaderA.hashCode());
        
        assertFalse(messageHeaderA.equals(messageHeaderB));
        assertFalse(messageHeaderB.equals(messageHeaderA));
        assertTrue(messageHeaderA.hashCode() != messageHeaderB.hashCode());
        
        assertFalse(messageHeaderA.equals(messageHeaderC));
        assertFalse(messageHeaderC.equals(messageHeaderA));
        assertTrue(messageHeaderA.hashCode() != messageHeaderC.hashCode());
        
        assertTrue(messageHeaderA.equals(messageHeaderA2));
        assertTrue(messageHeaderA2.equals(messageHeaderA));
        assertEquals(messageHeaderA.hashCode(), messageHeaderA2.hashCode());
    }
    
    @Test
    public void equalsKeyResponseData() throws MslEncodingException, MslEntityAuthException, MslCryptoException, MslKeyExchangeException, MslUserAuthException, MslException, MslEncoderException {
        final Set<ServiceToken> serviceTokens = MslTestUtils.getServiceTokens(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
        final KeyRequestData keyRequestData = KEY_REQUEST_DATA.toArray(new KeyRequestData[0])[0];
        final KeyExchangeFactory factory = trustedNetCtx.getKeyExchangeFactory(keyRequestData.getKeyExchangeScheme());
        final KeyExchangeData keyxDataA = factory.generateResponse(trustedNetCtx, format, keyRequestData, MASTER_TOKEN);
        final KeyResponseData keyResponseDataA = keyxDataA.keyResponseData;
        final KeyExchangeData keyxDataB = factory.generateResponse(trustedNetCtx, format, keyRequestData, MASTER_TOKEN);
        final KeyResponseData keyResponseDataB = keyxDataB.keyResponseData;
        final HeaderData headerDataA = new HeaderDataBuilder(trustedNetCtx, USER_ID_TOKEN, serviceTokens).set(KEY_KEY_RESPONSE_DATA, keyResponseDataA).build();
        final HeaderData headerDataB = new HeaderDataBuilder(trustedNetCtx, USER_ID_TOKEN, serviceTokens).set(KEY_KEY_RESPONSE_DATA, keyResponseDataB).build();
        final HeaderData headerDataC = new HeaderDataBuilder(trustedNetCtx, USER_ID_TOKEN, serviceTokens).set(KEY_KEY_RESPONSE_DATA, null).build();
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        
        final MessageHeader messageHeaderA = new MessageHeader(trustedNetCtx, null, MASTER_TOKEN, headerDataA, peerData);
        final MessageHeader messageHeaderB = new MessageHeader(trustedNetCtx, null, MASTER_TOKEN, headerDataB, peerData);
        final MessageHeader messageHeaderC = new MessageHeader(trustedNetCtx, null, MASTER_TOKEN, headerDataC, peerData);
        final MessageHeader messageHeaderA2 = (MessageHeader)Header.parseHeader(trustedNetCtx, MslTestUtils.toMslObject(encoder, messageHeaderA), CRYPTO_CONTEXTS);
        
        assertTrue(messageHeaderA.equals(messageHeaderA));
        assertEquals(messageHeaderA.hashCode(), messageHeaderA.hashCode());
        
        assertFalse(messageHeaderA.equals(messageHeaderB));
        assertFalse(messageHeaderB.equals(messageHeaderA));
        assertTrue(messageHeaderA.hashCode() != messageHeaderB.hashCode());
        
        assertFalse(messageHeaderA.equals(messageHeaderC));
        assertFalse(messageHeaderC.equals(messageHeaderA));
        assertTrue(messageHeaderA.hashCode() != messageHeaderC.hashCode());
        
        assertTrue(messageHeaderA.equals(messageHeaderA2));
        assertTrue(messageHeaderA2.equals(messageHeaderA));
        assertEquals(messageHeaderA.hashCode(), messageHeaderA2.hashCode());
    }
    
    @Test
    public void equalsUserAuthData() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslKeyExchangeException, MslUserAuthException, MslException, MslEncoderException {
        final Set<ServiceToken> serviceTokens = MslTestUtils.getServiceTokens(trustedNetCtx, MASTER_TOKEN, null);
        final UserAuthenticationData userAuthDataA = new EmailPasswordAuthenticationData(MockEmailPasswordAuthenticationFactory.EMAIL + "A", MockEmailPasswordAuthenticationFactory.PASSWORD);
        final UserAuthenticationData userAuthDataB = new EmailPasswordAuthenticationData(MockEmailPasswordAuthenticationFactory.EMAIL + "B", MockEmailPasswordAuthenticationFactory.PASSWORD);
        final HeaderData headerDataA = new HeaderDataBuilder(trustedNetCtx, null, serviceTokens).set(KEY_USER_AUTHENTICATION_DATA, userAuthDataA).build();
        final HeaderData headerDataB = new HeaderDataBuilder(trustedNetCtx, null, serviceTokens).set(KEY_USER_AUTHENTICATION_DATA, userAuthDataB).build();
        final HeaderData headerDataC = new HeaderDataBuilder(trustedNetCtx, null, serviceTokens).set(KEY_USER_AUTHENTICATION_DATA, null).build();
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        
        final MessageHeader messageHeaderA = new MessageHeader(trustedNetCtx, null, MASTER_TOKEN, headerDataA, peerData);
        final MessageHeader messageHeaderB = new MessageHeader(trustedNetCtx, null, MASTER_TOKEN, headerDataB, peerData);
        final MessageHeader messageHeaderC = new MessageHeader(trustedNetCtx, null, MASTER_TOKEN, headerDataC, peerData);
        
        assertTrue(messageHeaderA.equals(messageHeaderA));
        assertEquals(messageHeaderA.hashCode(), messageHeaderA.hashCode());
        
        assertFalse(messageHeaderA.equals(messageHeaderB));
        assertFalse(messageHeaderB.equals(messageHeaderA));
        assertTrue(messageHeaderA.hashCode() != messageHeaderB.hashCode());
        
        assertFalse(messageHeaderA.equals(messageHeaderC));
        assertFalse(messageHeaderC.equals(messageHeaderA));
        assertTrue(messageHeaderA.hashCode() != messageHeaderC.hashCode());
        
        // This test does not include a parsed header to avoid requiring user
        // authentication to succeed.
    }
    
    @Test
    public void equalsUserIdToken() throws MslEncodingException, MslEntityAuthException, MslCryptoException, MslKeyExchangeException, MslUserAuthException, MslException, MslEncoderException {
        final UserIdToken userIdTokenA = MslTestUtils.getUserIdToken(trustedNetCtx, MASTER_TOKEN, 1, MockEmailPasswordAuthenticationFactory.USER);
        final UserIdToken userIdTokenB = MslTestUtils.getUserIdToken(trustedNetCtx, MASTER_TOKEN, 2, MockEmailPasswordAuthenticationFactory.USER);
        final HeaderData headerDataA = new HeaderDataBuilder(trustedNetCtx, userIdTokenA, null).build();
        final HeaderData headerDataB = new HeaderDataBuilder(trustedNetCtx, userIdTokenB, null).build();
        final HeaderData headerDataC = new HeaderDataBuilder(trustedNetCtx, null, null).build();
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        
        final MessageHeader messageHeaderA = new MessageHeader(trustedNetCtx, null, MASTER_TOKEN, headerDataA, peerData);
        final MessageHeader messageHeaderB = new MessageHeader(trustedNetCtx, null, MASTER_TOKEN, headerDataB, peerData);
        final MessageHeader messageHeaderC = new MessageHeader(trustedNetCtx, null, MASTER_TOKEN, headerDataC, peerData);
        final MessageHeader messageHeaderA2 = (MessageHeader)Header.parseHeader(trustedNetCtx, MslTestUtils.toMslObject(encoder, messageHeaderA), CRYPTO_CONTEXTS);
        
        assertTrue(messageHeaderA.equals(messageHeaderA));
        assertEquals(messageHeaderA.hashCode(), messageHeaderA.hashCode());
        
        assertFalse(messageHeaderA.equals(messageHeaderB));
        assertFalse(messageHeaderB.equals(messageHeaderA));
        assertTrue(messageHeaderA.hashCode() != messageHeaderB.hashCode());
        
        assertFalse(messageHeaderA.equals(messageHeaderC));
        assertFalse(messageHeaderC.equals(messageHeaderA));
        assertTrue(messageHeaderA.hashCode() != messageHeaderC.hashCode());
        
        assertTrue(messageHeaderA.equals(messageHeaderA2));
        assertTrue(messageHeaderA2.equals(messageHeaderA));
        assertEquals(messageHeaderA.hashCode(), messageHeaderA2.hashCode());
    }
    
    @Test
    public void equalsServiceTokens() throws MslEncodingException, MslEntityAuthException, MslCryptoException, MslKeyExchangeException, MslUserAuthException, MslException, MslEncoderException {
        final Set<ServiceToken> serviceTokensA = MslTestUtils.getServiceTokens(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
        final Set<ServiceToken> serviceTokensB = MslTestUtils.getServiceTokens(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
        final HeaderData headerDataA = new HeaderDataBuilder(trustedNetCtx, USER_ID_TOKEN, serviceTokensA).build();
        final HeaderData headerDataB = new HeaderDataBuilder(trustedNetCtx, USER_ID_TOKEN, serviceTokensB).build();
        final HeaderData headerDataC = new HeaderDataBuilder(trustedNetCtx, USER_ID_TOKEN, null).build();
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        
        final MessageHeader messageHeaderA = new MessageHeader(trustedNetCtx, null, MASTER_TOKEN, headerDataA, peerData);
        final MessageHeader messageHeaderB = new MessageHeader(trustedNetCtx, null, MASTER_TOKEN, headerDataB, peerData);
        final MessageHeader messageHeaderC = new MessageHeader(trustedNetCtx, null, MASTER_TOKEN, headerDataC, peerData);
        final MessageHeader messageHeaderA2 = (MessageHeader)Header.parseHeader(trustedNetCtx, MslTestUtils.toMslObject(encoder, messageHeaderA), CRYPTO_CONTEXTS);
        
        assertTrue(messageHeaderA.equals(messageHeaderA));
        assertEquals(messageHeaderA.hashCode(), messageHeaderA.hashCode());
        
        assertFalse(messageHeaderA.equals(messageHeaderB));
        assertFalse(messageHeaderB.equals(messageHeaderA));
        assertTrue(messageHeaderA.hashCode() != messageHeaderB.hashCode());
        
        assertFalse(messageHeaderA.equals(messageHeaderC));
        assertFalse(messageHeaderC.equals(messageHeaderA));
        assertTrue(messageHeaderA.hashCode() != messageHeaderC.hashCode());
        
        assertTrue(messageHeaderA.equals(messageHeaderA2));
        assertTrue(messageHeaderA2.equals(messageHeaderA));
        assertEquals(messageHeaderA.hashCode(), messageHeaderA2.hashCode());
    }
    
    @Test
    public void equalsPeerMasterToken() throws MslEncodingException, MslEntityAuthException, MslCryptoException, MslKeyExchangeException, MslUserAuthException, MslException, MslEncoderException {
        final HeaderDataBuilder builder = new HeaderDataBuilder(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
        final HeaderData headerData = builder.build();
        final MasterToken peerMasterTokenA = MslTestUtils.getMasterToken(p2pCtx, 1, 1);
        final MasterToken peerMasterTokenB = MslTestUtils.getMasterToken(p2pCtx, 1, 2);
        final HeaderPeerData peerDataA = new HeaderPeerData(peerMasterTokenA, null, null);
        final HeaderPeerData peerDataB = new HeaderPeerData(peerMasterTokenB, null, null);
        final HeaderPeerData peerDataC = new HeaderPeerData(null, null, null);
        
        final MessageHeader messageHeaderA = new MessageHeader(p2pCtx, null, MASTER_TOKEN, headerData, peerDataA);
        final MessageHeader messageHeaderB = new MessageHeader(p2pCtx, null, MASTER_TOKEN, headerData, peerDataB);
        final MessageHeader messageHeaderC = new MessageHeader(p2pCtx, null, MASTER_TOKEN, headerData, peerDataC);
        final MessageHeader messageHeaderA2 = (MessageHeader)Header.parseHeader(p2pCtx, MslTestUtils.toMslObject(encoder, messageHeaderA), CRYPTO_CONTEXTS);
        
        assertTrue(messageHeaderA.equals(messageHeaderA));
        assertEquals(messageHeaderA.hashCode(), messageHeaderA.hashCode());
        
        assertFalse(messageHeaderA.equals(messageHeaderB));
        assertFalse(messageHeaderB.equals(messageHeaderA));
        assertTrue(messageHeaderA.hashCode() != messageHeaderB.hashCode());
        
        assertFalse(messageHeaderA.equals(messageHeaderC));
        assertFalse(messageHeaderC.equals(messageHeaderA));
        assertTrue(messageHeaderA.hashCode() != messageHeaderC.hashCode());
        
        assertTrue(messageHeaderA.equals(messageHeaderA2));
        assertTrue(messageHeaderA2.equals(messageHeaderA));
        assertEquals(messageHeaderA.hashCode(), messageHeaderA2.hashCode());
    }
    
    @Test
    public void equalsPeerUserIdToken() throws MslEncodingException, MslEntityAuthException, MslCryptoException, MslKeyExchangeException, MslUserAuthException, MslException, MslEncoderException {
        final HeaderDataBuilder builder = new HeaderDataBuilder(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
        final HeaderData headerData = builder.build();
        final UserIdToken peerUserIdTokenA = MslTestUtils.getUserIdToken(p2pCtx, PEER_MASTER_TOKEN, 1, MockEmailPasswordAuthenticationFactory.USER);
        final UserIdToken peerUserIdTokenB = MslTestUtils.getUserIdToken(p2pCtx, PEER_MASTER_TOKEN, 2, MockEmailPasswordAuthenticationFactory.USER);
        final HeaderPeerData peerDataA = new HeaderPeerData(PEER_MASTER_TOKEN, peerUserIdTokenA, null);
        final HeaderPeerData peerDataB = new HeaderPeerData(PEER_MASTER_TOKEN, peerUserIdTokenB, null);
        final HeaderPeerData peerDataC = new HeaderPeerData(PEER_MASTER_TOKEN, null, null);
        
        final MessageHeader messageHeaderA = new MessageHeader(p2pCtx, null, MASTER_TOKEN, headerData, peerDataA);
        final MessageHeader messageHeaderB = new MessageHeader(p2pCtx, null, MASTER_TOKEN, headerData, peerDataB);
        final MessageHeader messageHeaderC = new MessageHeader(p2pCtx, null, MASTER_TOKEN, headerData, peerDataC);
        final MessageHeader messageHeaderA2 = (MessageHeader)Header.parseHeader(p2pCtx, MslTestUtils.toMslObject(encoder, messageHeaderA), CRYPTO_CONTEXTS);
        
        assertTrue(messageHeaderA.equals(messageHeaderA));
        assertEquals(messageHeaderA.hashCode(), messageHeaderA.hashCode());
        
        assertFalse(messageHeaderA.equals(messageHeaderB));
        assertFalse(messageHeaderB.equals(messageHeaderA));
        assertTrue(messageHeaderA.hashCode() != messageHeaderB.hashCode());
        
        assertFalse(messageHeaderA.equals(messageHeaderC));
        assertFalse(messageHeaderC.equals(messageHeaderA));
        assertTrue(messageHeaderA.hashCode() != messageHeaderC.hashCode());
        
        assertTrue(messageHeaderA.equals(messageHeaderA2));
        assertTrue(messageHeaderA2.equals(messageHeaderA));
        assertEquals(messageHeaderA.hashCode(), messageHeaderA2.hashCode());
    }
    
    @Test
    public void equalsPeerServiceTokens() throws MslEncodingException, MslEntityAuthException, MslCryptoException, MslKeyExchangeException, MslUserAuthException, MslException, MslEncoderException {
        final HeaderDataBuilder builder = new HeaderDataBuilder(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN, true);
        final HeaderData headerData = builder.build();
        final Set<ServiceToken> peerServiceTokensA = MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
        final Set<ServiceToken> peerServiceTokensB = MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
        final HeaderPeerData peerDataA = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokensA);
        final HeaderPeerData peerDataB = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, peerServiceTokensB);
        final HeaderPeerData peerDataC = new HeaderPeerData(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, null);
        
        final MessageHeader messageHeaderA = new MessageHeader(p2pCtx, null, MASTER_TOKEN, headerData, peerDataA);
        final MessageHeader messageHeaderB = new MessageHeader(p2pCtx, null, MASTER_TOKEN, headerData, peerDataB);
        final MessageHeader messageHeaderC = new MessageHeader(p2pCtx, null, MASTER_TOKEN, headerData, peerDataC);
        final MessageHeader messageHeaderA2 = (MessageHeader)Header.parseHeader(p2pCtx, MslTestUtils.toMslObject(encoder, messageHeaderA), CRYPTO_CONTEXTS);
        
        assertTrue(messageHeaderA.equals(messageHeaderA));
        assertEquals(messageHeaderA.hashCode(), messageHeaderA.hashCode());
        
        assertFalse(messageHeaderA.equals(messageHeaderB));
        assertFalse(messageHeaderB.equals(messageHeaderA));
        assertTrue(messageHeaderA.hashCode() != messageHeaderB.hashCode());
        
        assertFalse(messageHeaderA.equals(messageHeaderC));
        assertFalse(messageHeaderC.equals(messageHeaderA));
        assertTrue(messageHeaderA.hashCode() != messageHeaderC.hashCode());
        
        assertTrue(messageHeaderA.equals(messageHeaderA2));
        assertTrue(messageHeaderA2.equals(messageHeaderA));
        assertEquals(messageHeaderA.hashCode(), messageHeaderA2.hashCode());
    }
    
    @Test
    public void equalsObject() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslException {
        final HeaderDataBuilder builder = new HeaderDataBuilder(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, false);
        final HeaderData headerData = builder.build();
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final MessageHeader messageHeader = new MessageHeader(trustedNetCtx, null, MASTER_TOKEN, headerData, peerData);
        
        assertFalse(messageHeader.equals(null));
        assertFalse(messageHeader.equals(MASTER_TOKEN));
        assertTrue(messageHeader.hashCode() != MASTER_TOKEN.hashCode());
    }
}
