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

import static org.junit.Assert.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;

import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import com.netflix.msl.MslConstants;
import com.netflix.msl.MslConstants.CompressionAlgorithm;
import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslEntityAuthException;
import com.netflix.msl.MslException;
import com.netflix.msl.MslInternalException;
import com.netflix.msl.MslKeyExchangeException;
import com.netflix.msl.MslMasterTokenException;
import com.netflix.msl.MslMessageException;
import com.netflix.msl.MslUserAuthException;
import com.netflix.msl.MslConstants.ResponseCode;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.entityauth.EntityAuthenticationData;
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.msg.MessageHeader.HeaderData;
import com.netflix.msl.msg.MessageHeader.HeaderPeerData;
import com.netflix.msl.util.MockMslContext;
import com.netflix.msl.util.MslContext;

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
    
    /** Random. */
    private static Random random = new Random();
    /** MSL context. */
    private static MslContext ctx;
    /** Destination output stream. */
    private static ByteArrayOutputStream destination = new ByteArrayOutputStream();
    /** Payload crypto context. */
    private static ICryptoContext PAYLOAD_CRYPTO_CONTEXT;
    /** Header service token crypto contexts. */
    private static Map<String,ICryptoContext> cryptoContexts = new HashMap<String,ICryptoContext>();
    
    private static EntityAuthenticationData ENTITY_AUTH_DATA;
    private static MessageHeader MESSAGE_HEADER;
    private static ErrorHeader ERROR_HEADER;
    
    @BeforeClass
    public static void setup() throws MslMasterTokenException, MslEntityAuthException, MslException {
        ctx = new MockMslContext(EntityAuthenticationScheme.PSK, false);
        
        final HeaderData headerData = new HeaderData(null, 1, null, false, false, ctx.getMessageCapabilities(), null, null, null, null, null);
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        ENTITY_AUTH_DATA = ctx.getEntityAuthenticationData(null);
        MESSAGE_HEADER = new MessageHeader(ctx, ENTITY_AUTH_DATA, null, headerData, peerData);
        PAYLOAD_CRYPTO_CONTEXT = MESSAGE_HEADER.getCryptoContext();
        
        ERROR_HEADER =  new ErrorHeader(ctx, ENTITY_AUTH_DATA, null, 1, ResponseCode.FAIL, 3, "errormsg", "usermsg");
    }
    
    @AfterClass
    public static void teardown() {
        PAYLOAD_CRYPTO_CONTEXT = null;
        ERROR_HEADER = null;
        MESSAGE_HEADER = null;
        ctx = null;
    }
    
    @After
    public void reset() {
        destination.reset();
    }
    
    @Test
    public void messageHeader() throws IOException, JSONException, MslEncodingException, MslEntityAuthException, MslKeyExchangeException, MslUserAuthException, MslException {
        final MessageOutputStream mos = new MessageOutputStream(ctx, destination, MslConstants.DEFAULT_CHARSET, MESSAGE_HEADER, PAYLOAD_CRYPTO_CONTEXT);
        mos.close();
        
        final String mslMessage = destination.toString(MslConstants.DEFAULT_CHARSET.name());
        final JSONTokener tokener = new JSONTokener(mslMessage);
        
        // There should be one header.
        assertTrue(tokener.more());
        final Object first = tokener.nextValue();
        assertTrue(first instanceof JSONObject);
        final JSONObject headerJo = (JSONObject)first;
        
        // The reconstructed header should be equal to the original.
        final Header header = Header.parseHeader(ctx, headerJo, cryptoContexts);
        assertTrue(header instanceof MessageHeader);
        final MessageHeader messageHeader = (MessageHeader)header;
        assertEquals(MESSAGE_HEADER, messageHeader);
        
        // There should be one payload with no data indicating end of message.
        assertTrue(tokener.more());
        final Object second = tokener.nextValue();
        assertTrue(second instanceof JSONObject);
        final JSONObject payloadJo = (JSONObject)second;
        
        // Verify the payload.
        final ICryptoContext cryptoContext = messageHeader.getCryptoContext();
        assertNotNull(cryptoContext);
        final PayloadChunk payload = new PayloadChunk(payloadJo, cryptoContext);
        assertTrue(payload.isEndOfMessage());
        assertEquals(1, payload.getSequenceNumber());
        assertEquals(MESSAGE_HEADER.getMessageId(), payload.getMessageId());
        assertEquals(0, payload.getData().length);
        
        // There should be nothing else.
        assertFalse(tokener.more());
        
        // Verify cached payloads.
        final List<PayloadChunk> payloads = mos.getPayloads();
        assertEquals(1, payloads.size());
        assertEquals(payload, payloads.get(0));
    }
    
    @Test
    public void errorHeader() throws IOException, MslEncodingException, MslEntityAuthException, MslKeyExchangeException, MslUserAuthException, MslException, JSONException {
        final MessageOutputStream mos = new MessageOutputStream(ctx, destination, MslConstants.DEFAULT_CHARSET, ERROR_HEADER);
        mos.close();
        
        final String mslMessage = destination.toString(MslConstants.DEFAULT_CHARSET.name());
        final JSONTokener tokener = new JSONTokener(mslMessage);
        
        // There should be one header.
        assertTrue(tokener.more());
        final Object first = tokener.nextValue();
        assertTrue(first instanceof JSONObject);
        final JSONObject headerJo = (JSONObject)first;

        // The reconstructed header should be equal to the original.
        final Header header = Header.parseHeader(ctx, headerJo, cryptoContexts);
        assertTrue(header instanceof ErrorHeader);
        assertEquals(ERROR_HEADER, header);
        
        // There should be no payloads.
        assertFalse(tokener.more());
        
        // Verify cached payloads.
        final List<PayloadChunk> payloads = mos.getPayloads();
        assertEquals(0, payloads.size());
    }
    
    @Test
    public void writeOffsets() throws IOException, JSONException, MslEncodingException, MslEntityAuthException, MslKeyExchangeException, MslUserAuthException, MslException {
        final byte[] data = new byte[32];
        random.nextBytes(data);
        final int from = 8;
        final int length = 8;
        final int to = from + length; // exclusive
        final MessageOutputStream mos = new MessageOutputStream(ctx, destination, MslConstants.DEFAULT_CHARSET, MESSAGE_HEADER, PAYLOAD_CRYPTO_CONTEXT);
        mos.write(data, from, length);
        mos.close();
        
        final String mslMessage = destination.toString(MslConstants.DEFAULT_CHARSET.name());
        final JSONTokener tokener = new JSONTokener(mslMessage);
        
        // There should be one header.
        assertTrue(tokener.more());
        final Object first = tokener.nextValue();
        assertTrue(first instanceof JSONObject);
        final JSONObject headerJo = (JSONObject)first;
        
        // We assume the reconstructed header is equal to the original.
        final Header header = Header.parseHeader(ctx, headerJo, cryptoContexts);
        assertTrue(header instanceof MessageHeader);
        final MessageHeader messageHeader = (MessageHeader)header;
        
        // There should be one payload.
        assertTrue(tokener.more());
        final Object second = tokener.nextValue();
        assertTrue(second instanceof JSONObject);
        final JSONObject payloadJo = (JSONObject)second;
        
        // Verify the payload.
        final ICryptoContext cryptoContext = messageHeader.getCryptoContext();
        assertNotNull(cryptoContext);
        final PayloadChunk payload = new PayloadChunk(payloadJo, cryptoContext);
        assertTrue(payload.isEndOfMessage());
        assertEquals(1, payload.getSequenceNumber());
        assertEquals(MESSAGE_HEADER.getMessageId(), payload.getMessageId());
        assertArrayEquals(Arrays.copyOfRange(data, from, to), payload.getData());
        
        // There should be nothing else.
        assertFalse(tokener.more());
        
        // Verify cached payloads.
        final List<PayloadChunk> payloads = mos.getPayloads();
        assertEquals(1, payloads.size());
        assertEquals(payload, payloads.get(0));
    }
    
    @Test
    public void writeBytes() throws IOException, JSONException, MslEncodingException, MslEntityAuthException, MslKeyExchangeException, MslUserAuthException, MslException {
        final byte[] data = new byte[32];
        random.nextBytes(data);
        final MessageOutputStream mos = new MessageOutputStream(ctx, destination, MslConstants.DEFAULT_CHARSET, MESSAGE_HEADER, PAYLOAD_CRYPTO_CONTEXT);
        mos.write(data);
        mos.close();
        
        final String mslMessage = destination.toString(MslConstants.DEFAULT_CHARSET.name());
        final JSONTokener tokener = new JSONTokener(mslMessage);
        
        // There should be one header.
        assertTrue(tokener.more());
        final Object first = tokener.nextValue();
        assertTrue(first instanceof JSONObject);
        final JSONObject headerJo = (JSONObject)first;
        
        // We assume the reconstructed header is equal to the original.
        final Header header = Header.parseHeader(ctx, headerJo, cryptoContexts);
        assertTrue(header instanceof MessageHeader);
        final MessageHeader messageHeader = (MessageHeader)header;
        
        // There should be one payload.
        assertTrue(tokener.more());
        final Object second = tokener.nextValue();
        assertTrue(second instanceof JSONObject);
        final JSONObject payloadJo = (JSONObject)second;
        
        // Verify the payload.
        final ICryptoContext cryptoContext = messageHeader.getCryptoContext();
        assertNotNull(cryptoContext);
        final PayloadChunk payload = new PayloadChunk(payloadJo, cryptoContext);
        assertTrue(payload.isEndOfMessage());
        assertEquals(1, payload.getSequenceNumber());
        assertEquals(MESSAGE_HEADER.getMessageId(), payload.getMessageId());
        assertArrayEquals(data, payload.getData());
        
        // There should be nothing else.
        assertFalse(tokener.more());
        
        // Verify cached payloads.
        final List<PayloadChunk> payloads = mos.getPayloads();
        assertEquals(1, payloads.size());
        assertEquals(payload, payloads.get(0));
    }
    
    @Test
    public void writeInt() throws IOException, JSONException, MslEncodingException, MslEntityAuthException, MslKeyExchangeException, MslUserAuthException, MslException {
        final int value = 1;
        final MessageOutputStream mos = new MessageOutputStream(ctx, destination, MslConstants.DEFAULT_CHARSET, MESSAGE_HEADER, PAYLOAD_CRYPTO_CONTEXT);
        mos.write(value);
        mos.close();
        
        final String mslMessage = destination.toString(MslConstants.DEFAULT_CHARSET.name());
        final JSONTokener tokener = new JSONTokener(mslMessage);
        
        // There should be one header.
        assertTrue(tokener.more());
        final Object first = tokener.nextValue();
        assertTrue(first instanceof JSONObject);
        final JSONObject headerJo = (JSONObject)first;
        
        // We assume the reconstructed header is equal to the original.
        final Header header = Header.parseHeader(ctx, headerJo, cryptoContexts);
        assertTrue(header instanceof MessageHeader);
        final MessageHeader messageHeader = (MessageHeader)header;
        
        // There should be one payload.
        assertTrue(tokener.more());
        final Object second = tokener.nextValue();
        assertTrue(second instanceof JSONObject);
        final JSONObject payloadJo = (JSONObject)second;
        
        // Verify the payload.
        final ICryptoContext cryptoContext = messageHeader.getCryptoContext();
        assertNotNull(cryptoContext);
        final PayloadChunk payload = new PayloadChunk(payloadJo, cryptoContext);
        assertTrue(payload.isEndOfMessage());
        assertEquals(1, payload.getSequenceNumber());
        assertEquals(MESSAGE_HEADER.getMessageId(), payload.getMessageId());
        assertArrayEquals(new byte[] { value }, payload.getData());
        
        // There should be nothing else.
        assertFalse(tokener.more());
        
        // Verify cached payloads.
        final List<PayloadChunk> payloads = mos.getPayloads();
        assertEquals(1, payloads.size());
        assertEquals(payload, payloads.get(0));
    }
    
    @Test
    public void compressed() throws IOException, JSONException, MslEncodingException, MslEntityAuthException, MslKeyExchangeException, MslUserAuthException, MslException {
        final MessageOutputStream mos = new MessageOutputStream(ctx, destination, MslConstants.DEFAULT_CHARSET, MESSAGE_HEADER, PAYLOAD_CRYPTO_CONTEXT);
        
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
        
        // Grab the JSON objects.
        final String mslMessage = destination.toString(MslConstants.DEFAULT_CHARSET.name());
        final JSONTokener tokener = new JSONTokener(mslMessage);
        final JSONObject headerJo = (JSONObject)tokener.nextValue();
        final List<JSONObject> payloadJos = new ArrayList<JSONObject>();
        while (tokener.more())
            payloadJos.add((JSONObject)tokener.nextValue());
        
        // Verify the number and contents of the payloads.
        final MessageHeader messageHeader = (MessageHeader)Header.parseHeader(ctx, headerJo, cryptoContexts);
        final ICryptoContext cryptoContext = messageHeader.getCryptoContext();
        assertEquals(3, payloadJos.size());
        final PayloadChunk firstPayload = new PayloadChunk(payloadJos.get(0), cryptoContext);
        assertArrayEquals(first, firstPayload.getData());
        final PayloadChunk secondPayload = new PayloadChunk(payloadJos.get(1), cryptoContext);
        assertArrayEquals(secondA, Arrays.copyOfRange(secondPayload.getData(), 0, secondA.length));
        assertArrayEquals(secondB, Arrays.copyOfRange(secondPayload.getData(), secondA.length, secondA.length + secondB.length));
        final PayloadChunk thirdPayload = new PayloadChunk(payloadJos.get(2), cryptoContext);
        assertEquals(0, thirdPayload.getData().length);
        assertTrue(thirdPayload.isEndOfMessage());
        
        // Verify cached payloads.
        final List<PayloadChunk> payloads = mos.getPayloads();
        assertEquals(payloadJos.size(), payloads.size());
        assertEquals(firstPayload, payloads.get(0));
        assertEquals(secondPayload, payloads.get(1));
        assertEquals(thirdPayload, payloads.get(2));
    }
    
    @Test
    public void flush() throws IOException, JSONException, MslEncodingException, MslEntityAuthException, MslKeyExchangeException, MslUserAuthException, MslException {
        final MessageOutputStream mos = new MessageOutputStream(ctx, destination, MslConstants.DEFAULT_CHARSET, MESSAGE_HEADER, PAYLOAD_CRYPTO_CONTEXT);
        
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
        
        // Grab the JSON objects.
        final String mslMessage = destination.toString(MslConstants.DEFAULT_CHARSET.name());
        final JSONTokener tokener = new JSONTokener(mslMessage);
        final JSONObject headerJo = (JSONObject)tokener.nextValue();
        final List<JSONObject> payloadJos = new ArrayList<JSONObject>();
        while (tokener.more())
            payloadJos.add((JSONObject)tokener.nextValue());
        
        // Verify the number and contents of the payloads.
        final MessageHeader messageHeader = (MessageHeader)Header.parseHeader(ctx, headerJo, cryptoContexts);
        final ICryptoContext cryptoContext = messageHeader.getCryptoContext();
        assertEquals(3, payloadJos.size());
        final PayloadChunk firstPayload = new PayloadChunk(payloadJos.get(0), cryptoContext);
        assertArrayEquals(first, firstPayload.getData());
        final PayloadChunk secondPayload = new PayloadChunk(payloadJos.get(1), cryptoContext);
        assertArrayEquals(secondA, Arrays.copyOfRange(secondPayload.getData(), 0, secondA.length));
        assertArrayEquals(secondB, Arrays.copyOfRange(secondPayload.getData(), secondA.length, secondA.length + secondB.length));
        final PayloadChunk thirdPayload = new PayloadChunk(payloadJos.get(2), cryptoContext);
        assertEquals(0, thirdPayload.getData().length);
        assertTrue(thirdPayload.isEndOfMessage());
        
        // Verify cached payloads.
        final List<PayloadChunk> payloads = mos.getPayloads();
        assertEquals(payloadJos.size(), payloads.size());
        assertEquals(firstPayload, payloads.get(0));
        assertEquals(secondPayload, payloads.get(1));
        assertEquals(thirdPayload, payloads.get(2));
    }
    
    @Test(expected = MslInternalException.class)
    public void writeErrorHeader() throws MslMasterTokenException, MslCryptoException, IOException {
        final MessageOutputStream mos = new MessageOutputStream(ctx, destination, MslConstants.DEFAULT_CHARSET, ERROR_HEADER);
        try {
            mos.write(new byte[0]);
        } finally {
            mos.close();
        }
    }
    
    @Test(expected = MslInternalException.class)
    public void writeHandshakeMessage() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslMessageException, IOException {
        final HeaderData headerData = new HeaderData(null, 1, null, false, true, ctx.getMessageCapabilities(), null, null, null, null, null);
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final MessageHeader messageHeader = new MessageHeader(ctx, ENTITY_AUTH_DATA, null, headerData, peerData);
        
        final MessageOutputStream mos = new MessageOutputStream(ctx, destination, MslConstants.DEFAULT_CHARSET, messageHeader, messageHeader.getCryptoContext());
        try {
            mos.write(new byte[0]);
        } finally {
            mos.close();
        }
    }
    
    @Test(expected = IOException.class)
    public void closed() throws MslMasterTokenException, MslCryptoException, IOException {
        final MessageOutputStream mos = new MessageOutputStream(ctx, destination, MslConstants.DEFAULT_CHARSET, MESSAGE_HEADER, PAYLOAD_CRYPTO_CONTEXT);
        mos.close();
        mos.write(new byte[0]);
    }
    
    @Test
    public void flushErrorHeader() throws IOException, MslMasterTokenException, MslCryptoException {
        final MessageOutputStream mos = new MessageOutputStream(ctx, destination, MslConstants.DEFAULT_CHARSET, ERROR_HEADER);
        try {
            // No data so this should be a no-op.
            mos.flush();
        } finally {
            mos.close();
        }
    }
    
    @Test
    public void stopCaching() throws IOException {
        final MessageOutputStream mos = new MessageOutputStream(ctx, destination, MslConstants.DEFAULT_CHARSET, MESSAGE_HEADER, PAYLOAD_CRYPTO_CONTEXT);
        
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
    public void multiClose() throws IOException, MslEncodingException, MslEntityAuthException, MslKeyExchangeException, MslUserAuthException, MslException, JSONException {
        final MessageOutputStream mos = new MessageOutputStream(ctx, destination, MslConstants.DEFAULT_CHARSET, MESSAGE_HEADER, PAYLOAD_CRYPTO_CONTEXT);
        mos.close();
        mos.close();
        
        final String mslMessage = destination.toString(MslConstants.DEFAULT_CHARSET.name());
        final JSONTokener tokener = new JSONTokener(mslMessage);
        
        // There should be one header.
        assertTrue(tokener.more());
        final Object first = tokener.nextValue();
        assertTrue(first instanceof JSONObject);
        final JSONObject headerJo = (JSONObject)first;
        
        // We assume the reconstructed header is equal to the original.
        final Header header = Header.parseHeader(ctx, headerJo, cryptoContexts);
        assertTrue(header instanceof MessageHeader);
        final MessageHeader messageHeader = (MessageHeader)header;
        
        // There should be one payload with no data indicating end of message.
        assertTrue(tokener.more());
        final Object second = tokener.nextValue();
        assertTrue(second instanceof JSONObject);
        final JSONObject payloadJo = (JSONObject)second;
        
        // Verify the payload.
        final ICryptoContext cryptoContext = messageHeader.getCryptoContext();
        assertNotNull(cryptoContext);
        final PayloadChunk payload = new PayloadChunk(payloadJo, cryptoContext);
        assertTrue(payload.isEndOfMessage());
        assertEquals(1, payload.getSequenceNumber());
        assertEquals(MESSAGE_HEADER.getMessageId(), payload.getMessageId());
        assertEquals(0, payload.getData().length);
        
        // There should be nothing else.
        assertFalse(tokener.more());
        
        // Verify cached payloads.
        final List<PayloadChunk> payloads = mos.getPayloads();
        assertEquals(1, payloads.size());
        assertEquals(payload, payloads.get(0));
    }
    
    @Test
    public void stressWrite() throws IOException, JSONException, MslEncodingException, MslEntityAuthException, MslKeyExchangeException, MslUserAuthException, MslException {
        final MessageOutputStream mos = new MessageOutputStream(ctx, destination, MslConstants.DEFAULT_CHARSET, MESSAGE_HEADER, PAYLOAD_CRYPTO_CONTEXT);
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
        final String mslMessage = destination.toString(MslConstants.DEFAULT_CHARSET.name());
        final JSONTokener tokener = new JSONTokener(mslMessage);
        final JSONObject headerJo = (JSONObject)tokener.nextValue();
        final List<JSONObject> payloadJos = new ArrayList<JSONObject>();
        while (tokener.more())
            payloadJos.add((JSONObject)tokener.nextValue());
        
        final Header header = Header.parseHeader(ctx, headerJo, cryptoContexts);
        assertTrue(header instanceof MessageHeader);
        final MessageHeader messageHeader = (MessageHeader)header;
        
        // Verify payloads, cached payloads, and aggregate data.
        int sequenceNumber = 1;
        final ByteArrayOutputStream data = new ByteArrayOutputStream();
        final ICryptoContext cryptoContext = messageHeader.getCryptoContext();
        final List<PayloadChunk> payloads = mos.getPayloads();
        assertEquals(payloadJos.size(), payloads.size());
        for (int i = 0; i < payloadJos.size(); ++i) {
            final PayloadChunk payload = new PayloadChunk(payloadJos.get(i), cryptoContext);
            assertEquals(sequenceNumber++, payload.getSequenceNumber());
            assertEquals(messageHeader.getMessageId(), payload.getMessageId());
            assertEquals(i == payloadJos.size() - 1, payload.isEndOfMessage());
            data.write(payload.getData());
            assertEquals(payload, payloads.get(i));
        }
        assertArrayEquals(message.toByteArray(), data.toByteArray());
    }
    
    @Test
    public void noCtxCompressionAlgorithm() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslMessageException, IOException {
        final MockMslContext ctx = new MockMslContext(EntityAuthenticationScheme.PSK, false);
        ctx.setMessageCapabilities(null);

        final MessageOutputStream mos = new MessageOutputStream(ctx, destination, MslConstants.DEFAULT_CHARSET, MESSAGE_HEADER, PAYLOAD_CRYPTO_CONTEXT);
        assertFalse(mos.setCompressionAlgorithm(CompressionAlgorithm.GZIP));
        assertFalse(mos.setCompressionAlgorithm(CompressionAlgorithm.LZW));
        mos.write(COMPRESSIBLE_DATA);
        mos.close();
        
        final List<PayloadChunk> payloads = mos.getPayloads();
        assertEquals(1, payloads.size());
        assertNull(payloads.get(0).getCompressionAlgorithm());
    }
    
    @Test
    public void noRequestCompressionAlgorithm() throws IOException, MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslMessageException {
        final HeaderData headerData = new HeaderData(null, 1, null, false, false, null, null, null, null, null, null);
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final MessageHeader messageHeader = new MessageHeader(ctx, ENTITY_AUTH_DATA, null, headerData, peerData);
        
        final MessageOutputStream mos = new MessageOutputStream(ctx, destination, MslConstants.DEFAULT_CHARSET, messageHeader, PAYLOAD_CRYPTO_CONTEXT);
        assertFalse(mos.setCompressionAlgorithm(CompressionAlgorithm.GZIP));
        assertFalse(mos.setCompressionAlgorithm(CompressionAlgorithm.LZW));
        mos.write(COMPRESSIBLE_DATA);
        mos.close();
        
        final List<PayloadChunk> payloads = mos.getPayloads();
        assertEquals(1, payloads.size());
        assertNull(payloads.get(0).getCompressionAlgorithm());
    }
    
    @Test
    public void bestCompressionAlgorithm() throws IOException, MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslMessageException {
        final MessageOutputStream mos = new MessageOutputStream(ctx, destination, MslConstants.DEFAULT_CHARSET, MESSAGE_HEADER, PAYLOAD_CRYPTO_CONTEXT);
        mos.write(COMPRESSIBLE_DATA);
        mos.close();
        
        final List<PayloadChunk> payloads = mos.getPayloads();
        assertEquals(1, payloads.size());
        
        final MessageCapabilities capabilities = ctx.getMessageCapabilities();
        final Set<CompressionAlgorithm> algos = capabilities.getCompressionAlgorithms();
        final CompressionAlgorithm bestAlgo = CompressionAlgorithm.getPreferredAlgorithm(algos);
        assertEquals(bestAlgo, payloads.get(0).getCompressionAlgorithm());
    }
    
    @Test
    public void setCompressionAlgorithm() throws IOException, MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslMessageException {
        final MessageOutputStream mos = new MessageOutputStream(ctx, destination, MslConstants.DEFAULT_CHARSET, MESSAGE_HEADER, PAYLOAD_CRYPTO_CONTEXT);
        assertTrue(mos.setCompressionAlgorithm(CompressionAlgorithm.GZIP));
        mos.write(COMPRESSIBLE_DATA);
        assertTrue(mos.setCompressionAlgorithm(CompressionAlgorithm.LZW));
        mos.write(COMPRESSIBLE_DATA);
        mos.close();
        
        final List<PayloadChunk> payloads = mos.getPayloads();
        assertEquals(2, payloads.size());
        assertEquals(CompressionAlgorithm.GZIP, payloads.get(0).getCompressionAlgorithm());
        assertEquals(CompressionAlgorithm.LZW, payloads.get(1).getCompressionAlgorithm());
    }
    
    @Test
    public void oneCompressionAlgorithm() throws IOException, MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslMessageException {
        final Set<CompressionAlgorithm> algos = new HashSet<CompressionAlgorithm>();
        algos.add(CompressionAlgorithm.GZIP);
        final MessageCapabilities capabilities = new MessageCapabilities(algos, null);

        final HeaderData headerData = new HeaderData(null, 1, null, false, false, capabilities, null, null, null, null, null);
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final MessageHeader messageHeader = new MessageHeader(ctx, ENTITY_AUTH_DATA, null, headerData, peerData);

        final MessageOutputStream mos = new MessageOutputStream(ctx, destination, MslConstants.DEFAULT_CHARSET, messageHeader, PAYLOAD_CRYPTO_CONTEXT);
        assertFalse(mos.setCompressionAlgorithm(CompressionAlgorithm.LZW));
        mos.write(COMPRESSIBLE_DATA);
        mos.close();

        final List<PayloadChunk> payloads = mos.getPayloads();
        assertEquals(1, payloads.size());
        assertEquals(CompressionAlgorithm.GZIP, payloads.get(0).getCompressionAlgorithm());
    }
}
