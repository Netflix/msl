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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import com.netflix.msl.MslConstants.CompressionAlgorithm;
import com.netflix.msl.MslConstants.ResponseCode;
import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslEntityAuthException;
import com.netflix.msl.MslException;
import com.netflix.msl.MslInternalException;
import com.netflix.msl.MslKeyExchangeException;
import com.netflix.msl.MslMasterTokenException;
import com.netflix.msl.MslMessageException;
import com.netflix.msl.MslUserAuthException;
import com.netflix.msl.MslUserIdTokenException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.entityauth.EntityAuthenticationData;
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.entityauth.MockPresharedAuthenticationFactory;
import com.netflix.msl.entityauth.MockRsaAuthenticationFactory;
import com.netflix.msl.entityauth.PresharedAuthenticationData;
import com.netflix.msl.entityauth.RsaAuthenticationData;
import com.netflix.msl.entityauth.UnauthenticatedAuthenticationData;
import com.netflix.msl.io.MslEncoderException;
import com.netflix.msl.io.MslEncoderFactory;
import com.netflix.msl.io.MslEncoderFormat;
import com.netflix.msl.io.MslObject;
import com.netflix.msl.io.MslTokenizer;
import com.netflix.msl.keyx.KeyExchangeFactory;
import com.netflix.msl.keyx.KeyExchangeFactory.KeyExchangeData;
import com.netflix.msl.keyx.KeyRequestData;
import com.netflix.msl.keyx.KeyResponseData;
import com.netflix.msl.keyx.SymmetricWrappedExchange;
import com.netflix.msl.keyx.SymmetricWrappedExchange.KeyId;
import com.netflix.msl.msg.MessageHeader.HeaderData;
import com.netflix.msl.msg.MessageHeader.HeaderPeerData;
import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.util.MockMslContext;
import com.netflix.msl.util.MslContext;
import com.netflix.msl.util.MslTestUtils;

/**
 * Message output stream unit tests.
 *
 * These tests assume the MessageOutputStream does not construct the header
 * data but delegates that to the Header. Likewise for PayloadChunks. So there
 * are no checks for proper encoding.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class MessageOutputStreamTest {
	/** MSL encoder format. */
	private static final MslEncoderFormat ENCODER_FORMAT = MslEncoderFormat.JSON;

    /** Maximum number of payload chunks to generate. */
    private static final int MAX_PAYLOAD_CHUNKS = 10;
    /** Maximum payload chunk data size in bytes. */
    private static final int MAX_DATA_SIZE = 1024 * 1024;
    /** Compressible data. */
    private static final byte[] COMPRESSIBLE_DATA = new String(
        "Kiba and Nami immortalized in code. I will never forget you. I'm sorry and I love you. Forgive me." +
        "Kiba and Nami immortalized in code. I will never forget you. I'm sorry and I love you. Forgive me." +
        "Kiba and Nami immortalized in code. I will never forget you. I'm sorry and I love you. Forgive me."
    ).getBytes();
    /** I/O operation timeout in milliseconds. */
    private static final int TIMEOUT = 20;
    
    /** Random. */
    private static Random random = new Random();
    /** MSL context. */
    private static MslContext ctx;
    /** MSL encoder factory. */
    private static MslEncoderFactory encoder;
    /** Destination output stream. */
    private static ByteArrayOutputStream destination = new ByteArrayOutputStream();
    /** Payload crypto context. */
    private static ICryptoContext PAYLOAD_CRYPTO_CONTEXT;
    /** Header service token crypto contexts. */
    private static Map<String,ICryptoContext> cryptoContexts = new HashMap<String,ICryptoContext>();
    
    private static MessageFactory messageFactory = new MessageFactory();
    private static EntityAuthenticationData ENTITY_AUTH_DATA;
    private static MessageHeader MESSAGE_HEADER;
    private static ErrorHeader ERROR_HEADER;
    private static final Set<KeyRequestData> KEY_REQUEST_DATA = new HashSet<KeyRequestData>();
    private static KeyResponseData KEY_RESPONSE_DATA;
    private static ICryptoContext KEYX_CRYPTO_CONTEXT;

    private static final String UNAUTHENTICATED_ESN = "MOCKUNAUTH-ESN";
    
    @BeforeClass
    public static void setup() throws MslMasterTokenException, MslEntityAuthException, MslException {
        ctx = new MockMslContext(EntityAuthenticationScheme.PSK, false);
        encoder = ctx.getMslEncoderFactory();
        
        final HeaderData headerData = new HeaderData(1, null, false, false, ctx.getMessageCapabilities(), null, null, null, null, null);
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        ENTITY_AUTH_DATA = ctx.getEntityAuthenticationData(null);
        MESSAGE_HEADER = new MessageHeader(ctx, ENTITY_AUTH_DATA, null, headerData, peerData);
        PAYLOAD_CRYPTO_CONTEXT = MESSAGE_HEADER.getCryptoContext();
        
        ERROR_HEADER =  new ErrorHeader(ctx, ENTITY_AUTH_DATA, 1, ResponseCode.FAIL, 3, "errormsg", "usermsg");
        
        final KeyRequestData keyRequest = new SymmetricWrappedExchange.RequestData(KeyId.PSK);
        KEY_REQUEST_DATA.add(keyRequest);
        final KeyExchangeFactory factory = ctx.getKeyExchangeFactory(keyRequest.getKeyExchangeScheme());
        final KeyExchangeData keyxData = factory.generateResponse(ctx, ENCODER_FORMAT, keyRequest, ENTITY_AUTH_DATA);
        KEY_RESPONSE_DATA = keyxData.keyResponseData;
        KEYX_CRYPTO_CONTEXT = keyxData.cryptoContext;
    }
    
    @AfterClass
    public static void teardown() {
        KEYX_CRYPTO_CONTEXT = null;
        KEY_RESPONSE_DATA = null;
        KEY_REQUEST_DATA.clear();
        PAYLOAD_CRYPTO_CONTEXT = null;
        ERROR_HEADER = null;
        MESSAGE_HEADER = null;
        encoder = null;
        ctx = null;
    }
    
    @After
    public void reset() {
        destination.reset();
    }
    
    @Test
    public void messageHeader() throws IOException, MslEncoderException, MslEncodingException, MslEntityAuthException, MslKeyExchangeException, MslUserAuthException, MslException {
        final MessageOutputStream mos = new MessageOutputStream(ctx, destination, MESSAGE_HEADER, PAYLOAD_CRYPTO_CONTEXT);
        mos.close();
        
        final InputStream mslMessage = new ByteArrayInputStream(destination.toByteArray());
        final MslTokenizer tokenizer = encoder.createTokenizer(mslMessage);
        
        // There should be one header.
        assertTrue(tokenizer.more(TIMEOUT));
        final Object first = tokenizer.nextObject(TIMEOUT);
        assertTrue(first instanceof MslObject);
        final MslObject headerMo = (MslObject)first;
        
        // The reconstructed header should be equal to the original.
        final Header header = Header.parseHeader(ctx, headerMo, cryptoContexts);
        assertTrue(header instanceof MessageHeader);
        final MessageHeader messageHeader = (MessageHeader)header;
        assertEquals(MESSAGE_HEADER, messageHeader);
        
        // There should be one payload with no data indicating end of message.
        assertTrue(tokenizer.more(TIMEOUT));
        final Object second = tokenizer.nextObject(TIMEOUT);
        assertTrue(second instanceof MslObject);
        final MslObject payloadMo = (MslObject)second;
        
        // Verify the payload.
        final ICryptoContext cryptoContext = messageHeader.getCryptoContext();
        assertNotNull(cryptoContext);
        final PayloadChunk payload = new PayloadChunk(ctx, payloadMo, cryptoContext);
        assertTrue(payload.isEndOfMessage());
        assertEquals(1, payload.getSequenceNumber());
        assertEquals(MESSAGE_HEADER.getMessageId(), payload.getMessageId());
        assertEquals(0, payload.getData().length);
        
        // There should be nothing else.
        assertFalse(tokenizer.more(TIMEOUT));
        
        // Verify cached payloads.
        final List<PayloadChunk> payloads = mos.getPayloads();
        assertEquals(1, payloads.size());
        assertEquals(payload, payloads.get(0));
        
        // Close the tokenizer.
        tokenizer.close();
    }
    
    @Test
    public void errorHeader() throws IOException, MslEncodingException, MslEntityAuthException, MslKeyExchangeException, MslUserAuthException, MslException, MslEncoderException {
        final MessageOutputStream mos = new MessageOutputStream(ctx, destination, ERROR_HEADER, ENCODER_FORMAT);
        mos.close();

        final InputStream mslMessage = new ByteArrayInputStream(destination.toByteArray());
        final MslTokenizer tokenizer = encoder.createTokenizer(mslMessage);
        
        // There should be one header.
        assertTrue(tokenizer.more(TIMEOUT));
        final Object first = tokenizer.nextObject(TIMEOUT);
        assertTrue(first instanceof MslObject);
        final MslObject headerMo = (MslObject)first;

        // The reconstructed header should be equal to the original.
        final Header header = Header.parseHeader(ctx, headerMo, cryptoContexts);
        assertTrue(header instanceof ErrorHeader);
        assertEquals(ERROR_HEADER, header);
        
        // There should be no payloads.
        assertFalse(tokenizer.more(TIMEOUT));
        
        // Verify cached payloads.
        final List<PayloadChunk> payloads = mos.getPayloads();
        assertEquals(0, payloads.size());
        
        // Close the tokenizer.
        tokenizer.close();
    }
    
    @Test
    public void entityAuthSchemeEncrypts() throws IOException, MslEncoderException, MslUserAuthException, MslMessageException, MslKeyExchangeException, MslUserIdTokenException, MslException {
        final HeaderData headerData = new HeaderData(1, null, false, false, null, null, null, null, null, null);
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final EntityAuthenticationData entityAuthData = new PresharedAuthenticationData(MockPresharedAuthenticationFactory.PSK_ESN);
        final MessageHeader messageHeader = new MessageHeader(ctx, entityAuthData, null, headerData, peerData);
        
        final ICryptoContext cryptoContext = messageHeader.getCryptoContext();
        final MessageOutputStream mos = new MessageOutputStream(ctx, destination, messageHeader, cryptoContext);
        assertTrue(mos.encryptsPayloads());
        mos.close();
    }
    
    @Test
    public void entityAuthSchemeDoesNotEncrypt() throws IOException, MslEncoderException, MslUserAuthException, MslMessageException, MslKeyExchangeException, MslUserIdTokenException, MslException {
        final HeaderData headerData = new HeaderData(1, null, false, false, null, null, null, null, null, null);
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final EntityAuthenticationData entityAuthData = new RsaAuthenticationData(MockRsaAuthenticationFactory.RSA_ESN, MockRsaAuthenticationFactory.RSA_PUBKEY_ID);
        final MessageHeader messageHeader = new MessageHeader(ctx, entityAuthData, null, headerData, peerData);

        final ICryptoContext cryptoContext = messageHeader.getCryptoContext();
        final MessageOutputStream mos = new MessageOutputStream(ctx, destination, messageHeader, cryptoContext);
        assertFalse(mos.encryptsPayloads());
        mos.close();
    }
    
    @Test
    public void entityAuthSchemeIntegrityProtects() throws IOException, MslEncoderException, MslUserAuthException, MslMessageException, MslKeyExchangeException, MslUserIdTokenException, MslException {
        final HeaderData headerData = new HeaderData(1, null, false, false, null, null, null, null, null, null);
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final EntityAuthenticationData entityAuthData = new RsaAuthenticationData(MockRsaAuthenticationFactory.RSA_ESN, MockRsaAuthenticationFactory.RSA_PUBKEY_ID);
        final MessageHeader messageHeader = new MessageHeader(ctx, entityAuthData, null, headerData, peerData);
        
        final ICryptoContext cryptoContext = messageHeader.getCryptoContext();
        final MessageOutputStream mos = new MessageOutputStream(ctx, destination, messageHeader, cryptoContext);
        assertTrue(mos.protectsPayloadIntegrity());
        mos.close();
    }
    
    @Test
    public void entityAuthSchemeDoesNotIntegrityProtect() throws IOException, MslEncoderException, MslUserAuthException, MslMessageException, MslKeyExchangeException, MslUserIdTokenException, MslException {
        final HeaderData headerData = new HeaderData(1, null, false, false, null, null, null, null, null, null);
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final EntityAuthenticationData entityAuthData = new UnauthenticatedAuthenticationData(UNAUTHENTICATED_ESN);
        final MessageHeader messageHeader = new MessageHeader(ctx, entityAuthData, null, headerData, peerData);

        final ICryptoContext cryptoContext = messageHeader.getCryptoContext();
        final MessageOutputStream mos = new MessageOutputStream(ctx, destination, messageHeader, cryptoContext);
        assertFalse(mos.protectsPayloadIntegrity());
        mos.close();
    }
    
    @Test
    public void entityAuthSchemeKeyxEncrypts() throws IOException, MslEncoderException, MslUserAuthException, MslMessageException, MslKeyExchangeException, MslUserIdTokenException, MslException {
        final HeaderData headerData = new HeaderData(1, null, false, false, null, null, KEY_RESPONSE_DATA, null, null, null);
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final EntityAuthenticationData entityAuthData = new PresharedAuthenticationData(MockPresharedAuthenticationFactory.PSK_ESN);
        final MessageHeader messageHeader = new MessageHeader(ctx, entityAuthData, null, headerData, peerData);
        
        final MessageOutputStream mos = new MessageOutputStream(ctx, destination, messageHeader, KEYX_CRYPTO_CONTEXT);
        assertTrue(mos.encryptsPayloads());
        mos.close();
    }
    
    @Test
    public void entityAuthSchemeKeyxIntegrityProtects() throws IOException, MslEncoderException, MslUserAuthException, MslMessageException, MslKeyExchangeException, MslUserIdTokenException, MslException {
        final HeaderData headerData = new HeaderData(1, null, false, false, null, null, KEY_RESPONSE_DATA, null, null, null);
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final EntityAuthenticationData entityAuthData = new RsaAuthenticationData(MockRsaAuthenticationFactory.RSA_ESN, MockRsaAuthenticationFactory.RSA_PUBKEY_ID);
        final MessageHeader messageHeader = new MessageHeader(ctx, entityAuthData, null, headerData, peerData);
        
        final MessageOutputStream mos = new MessageOutputStream(ctx, destination, messageHeader, KEYX_CRYPTO_CONTEXT);
        assertTrue(mos.protectsPayloadIntegrity());
        mos.close();
    }
    
    @Test
    public void entityAuthSchemeDoesNotKeyxEncrypts() throws IOException, MslEncoderException, MslUserAuthException, MslMessageException, MslKeyExchangeException, MslUserIdTokenException, MslException {
        final HeaderData headerData = new HeaderData(1, null, false, false, null, null, KEY_RESPONSE_DATA, null, null, null);
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final EntityAuthenticationData entityAuthData = new RsaAuthenticationData(MockRsaAuthenticationFactory.RSA_ESN, MockRsaAuthenticationFactory.RSA_PUBKEY_ID);
        final MessageHeader messageHeader = new MessageHeader(ctx, entityAuthData, null, headerData, peerData);

        final MessageOutputStream mos = new MessageOutputStream(ctx, destination, messageHeader, KEYX_CRYPTO_CONTEXT);
        assertTrue(mos.encryptsPayloads());
        mos.close();
    }
    
    @Test
    public void entityAuthSchemeDoesNotKeyxIntegrityProtects() throws IOException, MslEncoderException, MslUserAuthException, MslMessageException, MslKeyExchangeException, MslUserIdTokenException, MslException {
        final HeaderData headerData = new HeaderData(1, null, false, false, null, null, KEY_RESPONSE_DATA, null, null, null);
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final EntityAuthenticationData entityAuthData = new UnauthenticatedAuthenticationData(UNAUTHENTICATED_ESN);
        final MessageHeader messageHeader = new MessageHeader(ctx, entityAuthData, null, headerData, peerData);

        final MessageOutputStream mos = new MessageOutputStream(ctx, destination, messageHeader, KEYX_CRYPTO_CONTEXT);
        assertTrue(mos.protectsPayloadIntegrity());
        mos.close();
    }
    
    @Test
    public void masterTokenEncrypts() throws IOException, MslEncoderException, MslUserAuthException, MslMessageException, MslKeyExchangeException, MslUserIdTokenException, MslException {
        final MasterToken masterToken = MslTestUtils.getMasterToken(ctx, 1, 1);
        final HeaderData headerData = new HeaderData(1, null, false, false, null, null, null, null, null, null);
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final MessageHeader messageHeader = new MessageHeader(ctx, null, masterToken, headerData, peerData);

        final ICryptoContext cryptoContext = messageHeader.getCryptoContext();
        final MessageOutputStream mos = new MessageOutputStream(ctx, destination, messageHeader, cryptoContext);
        assertTrue(mos.encryptsPayloads());
        mos.close();
    }
    
    @Test
    public void masterTokenIntegrityProtects() throws IOException, MslEncoderException, MslUserAuthException, MslMessageException, MslKeyExchangeException, MslUserIdTokenException, MslException {
        final MasterToken masterToken = MslTestUtils.getMasterToken(ctx, 1, 1);
        final HeaderData headerData = new HeaderData(1, null, false, false, null, null, null, null, null, null);
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final MessageHeader messageHeader = new MessageHeader(ctx, null, masterToken, headerData, peerData);

        final ICryptoContext cryptoContext = messageHeader.getCryptoContext();
        final MessageOutputStream mos = new MessageOutputStream(ctx, destination, messageHeader, cryptoContext);
        assertTrue(mos.protectsPayloadIntegrity());
        mos.close();
    }
    
    @Test
    public void masterTokenKeyxEncrypts() throws IOException, MslEncoderException, MslUserAuthException, MslMessageException, MslKeyExchangeException, MslUserIdTokenException, MslException {
        final MasterToken masterToken = MslTestUtils.getMasterToken(ctx, 1, 1);
        final HeaderData headerData = new HeaderData(1, null, false, false, null, null, KEY_RESPONSE_DATA, null, null, null);
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final MessageHeader messageHeader = new MessageHeader(ctx, null, masterToken, headerData, peerData);

        final MessageOutputStream mos = new MessageOutputStream(ctx, destination, messageHeader, KEYX_CRYPTO_CONTEXT);
        assertTrue(mos.encryptsPayloads());
        mos.close();
    }
    
    @Test
    public void masterTokenKeyxIntegrityProtects() throws IOException, MslEncoderException, MslUserAuthException, MslMessageException, MslKeyExchangeException, MslUserIdTokenException, MslException {
        final MasterToken masterToken = MslTestUtils.getMasterToken(ctx, 1, 1);
        final HeaderData headerData = new HeaderData(1, null, false, false, null, null, KEY_RESPONSE_DATA, null, null, null);
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final MessageHeader messageHeader = new MessageHeader(ctx, null, masterToken, headerData, peerData);

        final MessageOutputStream mos = new MessageOutputStream(ctx, destination, messageHeader, KEYX_CRYPTO_CONTEXT);
        assertTrue(mos.protectsPayloadIntegrity());
        mos.close();
    }
    
    @Test
    public void writeOffsets() throws IOException, MslEncoderException, MslEncodingException, MslEntityAuthException, MslKeyExchangeException, MslUserAuthException, MslException {
        final byte[] data = new byte[32];
        random.nextBytes(data);
        final int from = 8;
        final int length = 8;
        final int to = from + length; // exclusive
        final MessageOutputStream mos = new MessageOutputStream(ctx, destination, MESSAGE_HEADER, PAYLOAD_CRYPTO_CONTEXT);
        mos.write(data, from, length);
        mos.close();

        final InputStream mslMessage = new ByteArrayInputStream(destination.toByteArray());
        final MslTokenizer tokenizer = encoder.createTokenizer(mslMessage);
        
        // There should be one header.
        assertTrue(tokenizer.more(TIMEOUT));
        final Object first = tokenizer.nextObject(TIMEOUT);
        assertTrue(first instanceof MslObject);
        final MslObject headerMo = (MslObject)first;
        
        // We assume the reconstructed header is equal to the original.
        final Header header = Header.parseHeader(ctx, headerMo, cryptoContexts);
        assertTrue(header instanceof MessageHeader);
        final MessageHeader messageHeader = (MessageHeader)header;
        
        // There should be one payload.
        assertTrue(tokenizer.more(TIMEOUT));
        final Object second = tokenizer.nextObject(TIMEOUT);
        assertTrue(second instanceof MslObject);
        final MslObject payloadMo = (MslObject)second;
        
        // Verify the payload.
        final ICryptoContext cryptoContext = messageHeader.getCryptoContext();
        assertNotNull(cryptoContext);
        final PayloadChunk payload = new PayloadChunk(ctx, payloadMo, cryptoContext);
        assertTrue(payload.isEndOfMessage());
        assertEquals(1, payload.getSequenceNumber());
        assertEquals(MESSAGE_HEADER.getMessageId(), payload.getMessageId());
        assertArrayEquals(Arrays.copyOfRange(data, from, to), payload.getData());
        
        // There should be nothing else.
        assertFalse(tokenizer.more(TIMEOUT));
        
        // Verify cached payloads.
        final List<PayloadChunk> payloads = mos.getPayloads();
        assertEquals(1, payloads.size());
        assertEquals(payload, payloads.get(0));
        
        // Close the tokenizer.
        tokenizer.close();
    }
    
    @Test
    public void writeBytes() throws IOException, MslEncoderException, MslEncodingException, MslEntityAuthException, MslKeyExchangeException, MslUserAuthException, MslException {
        final byte[] data = new byte[32];
        random.nextBytes(data);
        final MessageOutputStream mos = new MessageOutputStream(ctx, destination, MESSAGE_HEADER, PAYLOAD_CRYPTO_CONTEXT);
        mos.write(data);
        mos.close();

        final InputStream mslMessage = new ByteArrayInputStream(destination.toByteArray());
        final MslTokenizer tokenizer = encoder.createTokenizer(mslMessage);
        
        // There should be one header.
        assertTrue(tokenizer.more(TIMEOUT));
        final Object first = tokenizer.nextObject(TIMEOUT);
        assertTrue(first instanceof MslObject);
        final MslObject headerMo = (MslObject)first;
        
        // We assume the reconstructed header is equal to the original.
        final Header header = Header.parseHeader(ctx, headerMo, cryptoContexts);
        assertTrue(header instanceof MessageHeader);
        final MessageHeader messageHeader = (MessageHeader)header;
        
        // There should be one payload.
        assertTrue(tokenizer.more(TIMEOUT));
        final Object second = tokenizer.nextObject(TIMEOUT);
        assertTrue(second instanceof MslObject);
        final MslObject payloadMo = (MslObject)second;
        
        // Verify the payload.
        final ICryptoContext cryptoContext = messageHeader.getCryptoContext();
        assertNotNull(cryptoContext);
        final PayloadChunk payload = new PayloadChunk(ctx, payloadMo, cryptoContext);
        assertTrue(payload.isEndOfMessage());
        assertEquals(1, payload.getSequenceNumber());
        assertEquals(MESSAGE_HEADER.getMessageId(), payload.getMessageId());
        assertArrayEquals(data, payload.getData());
        
        // There should be nothing else.
        assertFalse(tokenizer.more(TIMEOUT));
        
        // Verify cached payloads.
        final List<PayloadChunk> payloads = mos.getPayloads();
        assertEquals(1, payloads.size());
        assertEquals(payload, payloads.get(0));
        
        // Close the tokenizer.
        tokenizer.close();
    }
    
    @Test
    public void writeInt() throws IOException, MslEncoderException, MslEncodingException, MslEntityAuthException, MslKeyExchangeException, MslUserAuthException, MslException {
        final int value = 1;
        final MessageOutputStream mos = new MessageOutputStream(ctx, destination, MESSAGE_HEADER, PAYLOAD_CRYPTO_CONTEXT);
        mos.write(value);
        mos.close();

        final InputStream mslMessage = new ByteArrayInputStream(destination.toByteArray());
        final MslTokenizer tokenizer = encoder.createTokenizer(mslMessage);
        
        // There should be one header.
        assertTrue(tokenizer.more(TIMEOUT));
        final Object first = tokenizer.nextObject(TIMEOUT);
        assertTrue(first instanceof MslObject);
        final MslObject headerMo = (MslObject)first;
        
        // We assume the reconstructed header is equal to the original.
        final Header header = Header.parseHeader(ctx, headerMo, cryptoContexts);
        assertTrue(header instanceof MessageHeader);
        final MessageHeader messageHeader = (MessageHeader)header;
        
        // There should be one payload.
        assertTrue(tokenizer.more(TIMEOUT));
        final Object second = tokenizer.nextObject(TIMEOUT);
        assertTrue(second instanceof MslObject);
        final MslObject payloadMo = (MslObject)second;
        
        // Verify the payload.
        final ICryptoContext cryptoContext = messageHeader.getCryptoContext();
        assertNotNull(cryptoContext);
        final PayloadChunk payload = new PayloadChunk(ctx, payloadMo, cryptoContext);
        assertTrue(payload.isEndOfMessage());
        assertEquals(1, payload.getSequenceNumber());
        assertEquals(MESSAGE_HEADER.getMessageId(), payload.getMessageId());
        assertArrayEquals(new byte[] { value }, payload.getData());
        
        // There should be nothing else.
        assertFalse(tokenizer.more(TIMEOUT));
        
        // Verify cached payloads.
        final List<PayloadChunk> payloads = mos.getPayloads();
        assertEquals(1, payloads.size());
        assertEquals(payload, payloads.get(0));
        
        // Close the tokenizer.
        tokenizer.close();
    }
    
    @Test
    public void compressed() throws IOException, MslEncoderException, MslEncodingException, MslEntityAuthException, MslKeyExchangeException, MslUserAuthException, MslException {
        final MessageOutputStream mos = new MessageOutputStream(ctx, destination, MESSAGE_HEADER, PAYLOAD_CRYPTO_CONTEXT);
        
        // Write the first payload.
        assertTrue(mos.setCompressionAlgorithm(null));
        final byte[] first = Arrays.copyOf(COMPRESSIBLE_DATA, COMPRESSIBLE_DATA.length);
        random.nextBytes(first);
        mos.write(first);
        
        // Changing the compressed value should result in a new payload.
        assertTrue(mos.setCompressionAlgorithm(CompressionAlgorithm.GZIP));
        final byte[] secondA = Arrays.copyOf(first, 2 * first.length);
        System.arraycopy(COMPRESSIBLE_DATA, 0, secondA, COMPRESSIBLE_DATA.length, COMPRESSIBLE_DATA.length);
        random.nextBytes(secondA);
        mos.write(secondA);
        
        // Setting the compressed value to the same should maintain the same
        // payload.
        assertTrue(mos.setCompressionAlgorithm(CompressionAlgorithm.GZIP));
        final byte[] secondB = Arrays.copyOf(first, 3 * first.length);
        System.arraycopy(COMPRESSIBLE_DATA, 0, secondB, COMPRESSIBLE_DATA.length, COMPRESSIBLE_DATA.length);
        System.arraycopy(COMPRESSIBLE_DATA, 0, secondB, 2 * COMPRESSIBLE_DATA.length, COMPRESSIBLE_DATA.length);
        random.nextBytes(secondB);
        mos.write(secondB);
        
        // Changing the compressed value should flush the second payload.
        assertTrue(mos.setCompressionAlgorithm(null));
        
        // Closing should create a final end-of-message payload.
        mos.close();
        
        // Grab the MSL objects.
        final InputStream mslMessage = new ByteArrayInputStream(destination.toByteArray());
        final MslTokenizer tokenizer = encoder.createTokenizer(mslMessage);
        final MslObject headerMo = tokenizer.nextObject(TIMEOUT);
        final List<MslObject> payloadMos = new ArrayList<MslObject>();
        while (tokenizer.more(TIMEOUT))
            payloadMos.add(tokenizer.nextObject(TIMEOUT));
        tokenizer.close();
        
        // Verify the number and contents of the payloads.
        final MessageHeader messageHeader = (MessageHeader)Header.parseHeader(ctx, headerMo, cryptoContexts);
        final ICryptoContext cryptoContext = messageHeader.getCryptoContext();
        assertEquals(3, payloadMos.size());
        final PayloadChunk firstPayload = new PayloadChunk(ctx, payloadMos.get(0), cryptoContext);
        assertArrayEquals(first, firstPayload.getData());
        final PayloadChunk secondPayload = new PayloadChunk(ctx, payloadMos.get(1), cryptoContext);
        assertArrayEquals(secondA, Arrays.copyOfRange(secondPayload.getData(), 0, secondA.length));
        assertArrayEquals(secondB, Arrays.copyOfRange(secondPayload.getData(), secondA.length, secondA.length + secondB.length));
        final PayloadChunk thirdPayload = new PayloadChunk(ctx, payloadMos.get(2), cryptoContext);
        assertEquals(0, thirdPayload.getData().length);
        assertTrue(thirdPayload.isEndOfMessage());
        
        // Verify cached payloads.
        final List<PayloadChunk> payloads = mos.getPayloads();
        assertEquals(payloadMos.size(), payloads.size());
        assertEquals(firstPayload, payloads.get(0));
        assertEquals(secondPayload, payloads.get(1));
        assertEquals(thirdPayload, payloads.get(2));
    }
    
    @Test
    public void flush() throws IOException, MslEncoderException, MslEncodingException, MslEntityAuthException, MslKeyExchangeException, MslUserAuthException, MslException {
        final MessageOutputStream mos = new MessageOutputStream(ctx, destination, MESSAGE_HEADER, PAYLOAD_CRYPTO_CONTEXT);
        
        // Write the first payload.
        final byte[] first = new byte[10];
        random.nextBytes(first);
        mos.write(first);
        
        // Flushing should result in a new payload.
        mos.flush();
        final byte[] secondA = new byte[20];
        random.nextBytes(secondA);
        mos.write(secondA);
        
        // Not flushing should maintain the same payload.
        final byte[] secondB = new byte[30];
        random.nextBytes(secondB);
        mos.write(secondB);
        
        // Flush the second payload.
        mos.flush();
        
        // Closing should create a final end-of-message payload.
        mos.close();
        
        // Grab the MSL objects.
        final InputStream mslMessage = new ByteArrayInputStream(destination.toByteArray());
        final MslTokenizer tokenizer = encoder.createTokenizer(mslMessage);
        final MslObject headerMo = tokenizer.nextObject(TIMEOUT);
        final List<MslObject> payloadMos = new ArrayList<MslObject>();
        while (tokenizer.more(TIMEOUT))
            payloadMos.add(tokenizer.nextObject(TIMEOUT));
        tokenizer.close();
        
        // Verify the number and contents of the payloads.
        final MessageHeader messageHeader = (MessageHeader)Header.parseHeader(ctx, headerMo, cryptoContexts);
        final ICryptoContext cryptoContext = messageHeader.getCryptoContext();
        assertEquals(3, payloadMos.size());
        final PayloadChunk firstPayload = new PayloadChunk(ctx, payloadMos.get(0), cryptoContext);
        assertArrayEquals(first, firstPayload.getData());
        final PayloadChunk secondPayload = new PayloadChunk(ctx, payloadMos.get(1), cryptoContext);
        assertArrayEquals(secondA, Arrays.copyOfRange(secondPayload.getData(), 0, secondA.length));
        assertArrayEquals(secondB, Arrays.copyOfRange(secondPayload.getData(), secondA.length, secondA.length + secondB.length));
        final PayloadChunk thirdPayload = new PayloadChunk(ctx, payloadMos.get(2), cryptoContext);
        assertEquals(0, thirdPayload.getData().length);
        assertTrue(thirdPayload.isEndOfMessage());
        
        // Verify cached payloads.
        final List<PayloadChunk> payloads = mos.getPayloads();
        assertEquals(payloadMos.size(), payloads.size());
        assertEquals(firstPayload, payloads.get(0));
        assertEquals(secondPayload, payloads.get(1));
        assertEquals(thirdPayload, payloads.get(2));
    }
    
    @Test(expected = MslInternalException.class)
    public void writeErrorHeader() throws MslMasterTokenException, MslCryptoException, IOException {
        final MessageOutputStream mos = new MessageOutputStream(ctx, destination, ERROR_HEADER, ENCODER_FORMAT);
        try {
            mos.write(new byte[0]);
        } finally {
            mos.close();
        }
    }
    
    @Test(expected = MslInternalException.class)
    public void writeHandshakeMessage() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslMessageException, IOException {
        final HeaderData headerData = new HeaderData(1, null, false, true, ctx.getMessageCapabilities(), null, null, null, null, null);
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final MessageHeader messageHeader = new MessageHeader(ctx, ENTITY_AUTH_DATA, null, headerData, peerData);
        
        final MessageOutputStream mos = new MessageOutputStream(ctx, destination, messageHeader, messageHeader.getCryptoContext());
        try {
            mos.write(new byte[0]);
        } finally {
            mos.close();
        }
    }
    
    @Test(expected = IOException.class)
    public void closed() throws MslMasterTokenException, MslCryptoException, IOException {
        final MessageOutputStream mos = new MessageOutputStream(ctx, destination, MESSAGE_HEADER, PAYLOAD_CRYPTO_CONTEXT);
        mos.close();
        mos.write(new byte[0]);
    }
    
    @Test
    public void flushErrorHeader() throws IOException, MslMasterTokenException, MslCryptoException {
        final MessageOutputStream mos = new MessageOutputStream(ctx, destination, ERROR_HEADER, ENCODER_FORMAT);
        try {
            // No data so this should be a no-op.
            mos.flush();
        } finally {
            mos.close();
        }
    }
    
    @Test
    public void stopCaching() throws IOException {
        final MessageOutputStream mos = new MessageOutputStream(ctx, destination, MESSAGE_HEADER, PAYLOAD_CRYPTO_CONTEXT);
        
        // Write the first payload.
        final byte[] first = new byte[10];
        random.nextBytes(first);
        mos.write(first);
        mos.flush();
        
        // Verify one payload.
        final List<PayloadChunk> onePayload = mos.getPayloads();
        assertEquals(1, onePayload.size());
        
        // Stop caching.
        mos.stopCaching();
        final List<PayloadChunk> zeroPayload = mos.getPayloads();
        assertEquals(0, zeroPayload.size());
        
        // Write the second payload.
        final byte[] secondA = new byte[20];
        random.nextBytes(secondA);
        mos.write(secondA);
        
        // Verify zero payloads.
        final List<PayloadChunk> twoPayload = mos.getPayloads();
        assertEquals(0, twoPayload.size());
        
        // Close
        mos.close();
    }
    
    @Test
    public void multiClose() throws IOException, MslEncodingException, MslEntityAuthException, MslKeyExchangeException, MslUserAuthException, MslException, MslEncoderException {
        final MessageOutputStream mos = new MessageOutputStream(ctx, destination, MESSAGE_HEADER, PAYLOAD_CRYPTO_CONTEXT);
        mos.close();
        mos.close();

        final InputStream mslMessage = new ByteArrayInputStream(destination.toByteArray());
        final MslTokenizer tokenizer = encoder.createTokenizer(mslMessage);
        
        // There should be one header.
        assertTrue(tokenizer.more(TIMEOUT));
        final Object first = tokenizer.nextObject(TIMEOUT);
        assertTrue(first instanceof MslObject);
        final MslObject headerMo = (MslObject)first;
        
        // We assume the reconstructed header is equal to the original.
        final Header header = Header.parseHeader(ctx, headerMo, cryptoContexts);
        assertTrue(header instanceof MessageHeader);
        final MessageHeader messageHeader = (MessageHeader)header;
        
        // There should be one payload with no data indicating end of message.
        assertTrue(tokenizer.more(TIMEOUT));
        final Object second = tokenizer.nextObject(TIMEOUT);
        assertTrue(second instanceof MslObject);
        final MslObject payloadMo = (MslObject)second;
        
        // Verify the payload.
        final ICryptoContext cryptoContext = messageHeader.getCryptoContext();
        assertNotNull(cryptoContext);
        final PayloadChunk payload = new PayloadChunk(ctx, payloadMo, cryptoContext);
        assertTrue(payload.isEndOfMessage());
        assertEquals(1, payload.getSequenceNumber());
        assertEquals(MESSAGE_HEADER.getMessageId(), payload.getMessageId());
        assertEquals(0, payload.getData().length);
        
        // There should be nothing else.
        assertFalse(tokenizer.more(TIMEOUT));
        
        // Verify cached payloads.
        final List<PayloadChunk> payloads = mos.getPayloads();
        assertEquals(1, payloads.size());
        assertEquals(payload, payloads.get(0));
        
        // Close the tokenizer.
        tokenizer.close();
    }
    
    @Test
    public void stressWrite() throws IOException, MslEncoderException, MslEncodingException, MslEntityAuthException, MslKeyExchangeException, MslUserAuthException, MslException {
        final MessageOutputStream mos = new MessageOutputStream(ctx, destination, MESSAGE_HEADER, PAYLOAD_CRYPTO_CONTEXT);
        mos.setCompressionAlgorithm(null);
        
        // Generate some payload chunks, keeping track of what we're writing.
        final ByteArrayOutputStream message = new ByteArrayOutputStream();
        final int count = random.nextInt(MAX_PAYLOAD_CHUNKS) + 1;
        for (int i = 0; i < count; ++i) {
            // Randomly choose to set the compression algorithm and call flush.
            if (random.nextBoolean()) mos.flush();
            mos.setCompressionAlgorithm(random.nextBoolean() ? CompressionAlgorithm.GZIP : null);
            final byte[] data = new byte[random.nextInt(MAX_DATA_SIZE) + 1];
            random.nextBytes(data);
            mos.write(data);
            message.write(data);
        }
        mos.close();
        
        // The destination should have received the message header followed by
        // one or more payload chunks.
        final InputStream mslMessage = new ByteArrayInputStream(destination.toByteArray());
        final MslTokenizer tokenizer = encoder.createTokenizer(mslMessage);
        final MslObject headerMo = tokenizer.nextObject(TIMEOUT);
        final List<MslObject> payloadMos = new ArrayList<MslObject>();
        while (tokenizer.more(TIMEOUT))
            payloadMos.add(tokenizer.nextObject(TIMEOUT));
        tokenizer.close();
        
        final Header header = Header.parseHeader(ctx, headerMo, cryptoContexts);
        assertTrue(header instanceof MessageHeader);
        final MessageHeader messageHeader = (MessageHeader)header;
        
        // Verify payloads, cached payloads, and aggregate data.
        int sequenceNumber = 1;
        final ByteArrayOutputStream data = new ByteArrayOutputStream();
        final ICryptoContext cryptoContext = messageHeader.getCryptoContext();
        final List<PayloadChunk> payloads = mos.getPayloads();
        assertEquals(payloadMos.size(), payloads.size());
        for (int i = 0; i < payloadMos.size(); ++i) {
            final PayloadChunk payload = new PayloadChunk(ctx, payloadMos.get(i), cryptoContext);
            assertEquals(sequenceNumber++, payload.getSequenceNumber());
            assertEquals(messageHeader.getMessageId(), payload.getMessageId());
            assertEquals(i == payloadMos.size() - 1, payload.isEndOfMessage());
            data.write(payload.getData());
            assertEquals(payload, payloads.get(i));
        }
        assertArrayEquals(message.toByteArray(), data.toByteArray());
    }
    
    @Test
    public void noCtxCompressionAlgorithm() throws IOException, MslKeyExchangeException, MslUserAuthException, MslException {
        final MockMslContext ctx = new MockMslContext(EntityAuthenticationScheme.PSK, false);
        ctx.setMessageCapabilities(null);
        
        // The intersection of compression algorithms is computed when a
        // response header is generated.
        final MessageBuilder builder = messageFactory.createResponse(ctx, MESSAGE_HEADER);
        final MessageHeader responseHeader = builder.getHeader();

        final MessageOutputStream mos = new MessageOutputStream(ctx, destination, responseHeader, PAYLOAD_CRYPTO_CONTEXT);
        assertFalse(mos.setCompressionAlgorithm(CompressionAlgorithm.GZIP));
        assertFalse(mos.setCompressionAlgorithm(CompressionAlgorithm.LZW));
        mos.write(COMPRESSIBLE_DATA);
        mos.close();
        
        final List<PayloadChunk> payloads = mos.getPayloads();
        assertEquals(1, payloads.size());
        assertNull(payloads.get(0).getCompressionAlgo());
    }
    
    @Test
    public void noRequestCompressionAlgorithm() throws IOException, MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslMessageException {
        final HeaderData headerData = new HeaderData(1, null, false, false, null, null, null, null, null, null);
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final MessageHeader messageHeader = new MessageHeader(ctx, ENTITY_AUTH_DATA, null, headerData, peerData);
        
        final MessageOutputStream mos = new MessageOutputStream(ctx, destination, messageHeader, PAYLOAD_CRYPTO_CONTEXT);
        assertFalse(mos.setCompressionAlgorithm(CompressionAlgorithm.GZIP));
        assertFalse(mos.setCompressionAlgorithm(CompressionAlgorithm.LZW));
        mos.write(COMPRESSIBLE_DATA);
        mos.close();
        
        final List<PayloadChunk> payloads = mos.getPayloads();
        assertEquals(1, payloads.size());
        assertNull(payloads.get(0).getCompressionAlgo());
    }
    
    @Test
    public void bestCompressionAlgorithm() throws IOException, MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslMessageException {
        final MessageOutputStream mos = new MessageOutputStream(ctx, destination, MESSAGE_HEADER, PAYLOAD_CRYPTO_CONTEXT);
        mos.write(COMPRESSIBLE_DATA);
        mos.close();
        
        final List<PayloadChunk> payloads = mos.getPayloads();
        assertEquals(1, payloads.size());
        
        final MessageCapabilities capabilities = ctx.getMessageCapabilities();
        final Set<CompressionAlgorithm> algos = capabilities.getCompressionAlgorithms();
        final CompressionAlgorithm bestAlgo = CompressionAlgorithm.getPreferredAlgorithm(algos);
        assertEquals(bestAlgo, payloads.get(0).getCompressionAlgo());
    }
    
    @Test
    public void setCompressionAlgorithm() throws IOException, MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslMessageException {
        final MessageOutputStream mos = new MessageOutputStream(ctx, destination, MESSAGE_HEADER, PAYLOAD_CRYPTO_CONTEXT);
        assertTrue(mos.setCompressionAlgorithm(CompressionAlgorithm.GZIP));
        mos.write(COMPRESSIBLE_DATA);
        assertTrue(mos.setCompressionAlgorithm(CompressionAlgorithm.LZW));
        mos.write(COMPRESSIBLE_DATA);
        mos.close();
        
        final List<PayloadChunk> payloads = mos.getPayloads();
        assertEquals(2, payloads.size());
        assertEquals(CompressionAlgorithm.GZIP, payloads.get(0).getCompressionAlgo());
        assertEquals(CompressionAlgorithm.LZW, payloads.get(1).getCompressionAlgo());
    }
    
    @Test
    public void oneCompressionAlgorithm() throws IOException, MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslMessageException {
        final Set<CompressionAlgorithm> algos = new HashSet<CompressionAlgorithm>();
        algos.add(CompressionAlgorithm.GZIP);
        final MessageCapabilities capabilities = new MessageCapabilities(algos, null, null);

        final HeaderData headerData = new HeaderData(1, null, false, false, capabilities, null, null, null, null, null);
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final MessageHeader messageHeader = new MessageHeader(ctx, ENTITY_AUTH_DATA, null, headerData, peerData);

        final MessageOutputStream mos = new MessageOutputStream(ctx, destination, messageHeader, PAYLOAD_CRYPTO_CONTEXT);
        assertFalse(mos.setCompressionAlgorithm(CompressionAlgorithm.LZW));
        mos.write(COMPRESSIBLE_DATA);
        mos.close();

        final List<PayloadChunk> payloads = mos.getPayloads();
        assertEquals(1, payloads.size());
        assertEquals(CompressionAlgorithm.GZIP, payloads.get(0).getCompressionAlgo());
    }
}
