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
import java.util.Random;
import java.util.zip.GZIPInputStream;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.json.JSONException;
import org.json.JSONObject;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;

import com.netflix.msl.MslConstants;
import com.netflix.msl.MslConstants.CompressionAlgorithm;
import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslException;
import com.netflix.msl.MslInternalException;
import com.netflix.msl.MslMessageException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.crypto.JcaAlgorithm;
import com.netflix.msl.crypto.SymmetricCryptoContext;
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.io.LZWInputStream;
import com.netflix.msl.io.LZWOutputStreamTest;
import com.netflix.msl.test.ExpectedMslException;
import com.netflix.msl.util.Base64;
import com.netflix.msl.util.MockMslContext;
import com.netflix.msl.util.MslContext;

/**
 * Payload chunk unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class PayloadChunkTest {
    /** RAW data file. */
    private static final String DATAFILE = "pg1112.txt";
    
    /** JSON key payload. */
    private static final String KEY_PAYLOAD = "payload";
    /** JSON key signature. */
    private static final String KEY_SIGNATURE = "signature";
    
    // payload
    /** JSON key sequence number. */
    private static final String KEY_SEQUENCE_NUMBER = "sequencenumber";
    /** JSON key message ID. */
    private static final String KEY_MESSAGE_ID = "messageid";
    /** JSON key end of message. */
    private static final String KEY_END_OF_MESSAGE = "endofmsg";
    /** JSON key compression algorithm. */
    private static final String KEY_COMPRESSION_ALGORITHM = "compressionalgo";
    /** JSON key encrypted data. */
    private static final String KEY_DATA = "data";
    
    /**
     * Uncompress the provided data using the specified compression algorithm.
     * 
     * @param compressionAlgo the compression algorithm.
     * @param data the data to uncompress.
     * @return the uncompressed data.
     * @throws MslException if there is an error uncompressing the data.
     */
    private static byte[] uncompress(final CompressionAlgorithm compressionAlgo, final byte[] data) throws MslException {
        try {
            switch (compressionAlgo) {
                case GZIP:
                {
                    final ByteArrayInputStream bais = new ByteArrayInputStream(data);
                    final GZIPInputStream gzis = new GZIPInputStream(bais);
                    final byte[] buffer = new byte[data.length];
                    final ByteArrayOutputStream baos = new ByteArrayOutputStream(data.length);
                    do {
                        final int bytesRead = gzis.read(buffer);
                        if (bytesRead == -1) break;
                        baos.write(buffer, 0, bytesRead);
                    } while (true);
                    return baos.toByteArray();
                }
                case LZW:
                {
                    final ByteArrayInputStream bais = new ByteArrayInputStream(data);
                    final LZWInputStream lzwis = new LZWInputStream(bais);
                    try {
                        final byte[] buffer = new byte[data.length];
                        final ByteArrayOutputStream baos = new ByteArrayOutputStream(data.length);
                        do {
                            final int bytesRead = lzwis.read(buffer);
                            if (bytesRead == -1) break;
                            baos.write(buffer, 0, bytesRead);
                        } while (true);
                        return baos.toByteArray();
                    } finally {
                        lzwis.close();
                    }
                }
                default:
                    throw new MslException(MslError.UNSUPPORTED_COMPRESSION, compressionAlgo.name());
            }
        } catch (final IOException e) {
            throw new MslException(MslError.UNCOMPRESSION_ERROR, "algo " + compressionAlgo.name() + " data " + Base64.encode(data), e);
        }
    }
    
    private static final String CRYPTO_CONTEXT_ID = "cryptoContextId";
    private static SecretKey ENCRYPTION_KEY;
    private static SecretKey HMAC_KEY;
    
    /** MSL context. */
    private static MslContext ctx;
    /** Random. */
    private static final Random random = new Random();
    
    private static final long SEQ_NO = 1;
    private static final long MSG_ID = 42;
    private static final boolean END_OF_MSG = false;
    private static final byte[] DATA = "We have to use some data that is compressible, otherwise payloads will not always use the compression we request.".getBytes();
    private static ICryptoContext CRYPTO_CONTEXT;

    /** Raw data. */
    private static byte[] rawdata;

    @Rule
    public ExpectedMslException thrown = ExpectedMslException.none();
    
    @BeforeClass
    public static void setup() throws MslEncodingException, MslCryptoException, IOException {
        ctx = new MockMslContext(EntityAuthenticationScheme.PSK, false);

        final byte[] encryptionBytes = new byte[16];
        final byte[] hmacBytes = new byte[32];
        random.nextBytes(encryptionBytes);
        random.nextBytes(hmacBytes);
        ENCRYPTION_KEY = new SecretKeySpec(encryptionBytes, JcaAlgorithm.AES);
        HMAC_KEY = new SecretKeySpec(hmacBytes, JcaAlgorithm.HMAC_SHA256);
        CRYPTO_CONTEXT = new SymmetricCryptoContext(ctx, CRYPTO_CONTEXT_ID, ENCRYPTION_KEY, HMAC_KEY, null);
        
        // Load the raw file.
        final ClassLoader loader = LZWOutputStreamTest.class.getClassLoader();
        final InputStream raw = loader.getResourceAsStream(DATAFILE);
        try {
            final ByteArrayOutputStream rawos = new ByteArrayOutputStream();
            final byte[] data = new byte[256 * 1024];
            do {
                final int read = raw.read(data);
                if (read == -1) break;
                rawos.write(data, 0, read);
            } while (true);
            rawdata = rawos.toByteArray();
        } finally {
            raw.close();
        }
    }
    
    @AfterClass
    public static void teardown() {
        CRYPTO_CONTEXT = null;
        ctx = null;
    }

    @Test
    public void ctors() throws MslEncodingException, MslCryptoException, MslException, JSONException {
        final PayloadChunk chunk = new PayloadChunk(SEQ_NO, MSG_ID, END_OF_MSG, null, DATA, CRYPTO_CONTEXT);
        assertEquals(END_OF_MSG, chunk.isEndOfMessage());
        assertArrayEquals(DATA, chunk.getData());
        assertNull(chunk.getCompressionAlgo());
        assertEquals(MSG_ID, chunk.getMessageId());
        assertEquals(SEQ_NO, chunk.getSequenceNumber());
        final String jsonString = chunk.toJSONString();
        assertNotNull(jsonString);

        final PayloadChunk joChunk = new PayloadChunk(new JSONObject(jsonString), CRYPTO_CONTEXT);
        assertEquals(chunk.isEndOfMessage(), joChunk.isEndOfMessage());
        assertArrayEquals(chunk.getData(), joChunk.getData());
        assertEquals(chunk.getMessageId(), joChunk.getMessageId());
        assertEquals(chunk.getSequenceNumber(), joChunk.getSequenceNumber());
        final String joJsonString = joChunk.toJSONString();
        assertNotNull(joJsonString);
        assertEquals(jsonString, joJsonString);
    }
    
    @Test(expected = MslInternalException.class)
    public void negativeSequenceNumberCtor() throws MslEncodingException, MslCryptoException, MslException {
        final long sequenceNumber = -1;
        new PayloadChunk(sequenceNumber, MSG_ID, END_OF_MSG, null, DATA, CRYPTO_CONTEXT);
    }
    
    @Test(expected = MslInternalException.class)
    public void tooLargeSequenceNumberCtor() throws MslEncodingException, MslCryptoException, MslException {
        final long sequenceNumber = MslConstants.MAX_LONG_VALUE + 1;
        new PayloadChunk(sequenceNumber, MSG_ID, END_OF_MSG, null, DATA, CRYPTO_CONTEXT);
    }
    
    @Test(expected = MslInternalException.class)
    public void negativeMessageIdCtor() throws MslEncodingException, MslCryptoException, MslException {
        final long messageId = -1;
        new PayloadChunk(SEQ_NO, messageId, END_OF_MSG, null, DATA, CRYPTO_CONTEXT);
    }
    
    @Test(expected = MslInternalException.class)
    public void tooLargeMessageIdCtor() throws MslEncodingException, MslCryptoException, MslException {
        final long messageId = MslConstants.MAX_LONG_VALUE + 1;
        new PayloadChunk(SEQ_NO, messageId, END_OF_MSG, null, DATA, CRYPTO_CONTEXT);
    }
    
    @Test
    public void jsonString() throws MslEncodingException, MslException, JSONException {
        final PayloadChunk chunk = new PayloadChunk(SEQ_NO, MSG_ID, END_OF_MSG, null, DATA, CRYPTO_CONTEXT);
        final String jsonString = chunk.toJSONString();
        assertNotNull(jsonString);
        
        final JSONObject jo = new JSONObject(jsonString);
        final byte[] ciphertext = Base64.decode(jo.getString(KEY_PAYLOAD));
        final byte[] signature = Base64.decode(jo.getString(KEY_SIGNATURE));
        assertTrue(CRYPTO_CONTEXT.verify(ciphertext, signature));
        final byte[] payload = CRYPTO_CONTEXT.decrypt(ciphertext);
        
        final JSONObject payloadJo = new JSONObject(new String(payload, MslConstants.DEFAULT_CHARSET));
        assertEquals(SEQ_NO, payloadJo.getLong(KEY_SEQUENCE_NUMBER));
        assertEquals(MSG_ID, payloadJo.getLong(KEY_MESSAGE_ID));
        assertEquals(END_OF_MSG, payloadJo.optBoolean(KEY_END_OF_MESSAGE));
        assertFalse(payloadJo.has(KEY_COMPRESSION_ALGORITHM));
        assertArrayEquals(DATA, Base64.decode(payloadJo.getString(KEY_DATA)));
    }
    
    @Test
    public void gzipCtors() throws MslEncodingException, MslCryptoException, MslException, JSONException {
        final PayloadChunk chunk = new PayloadChunk(SEQ_NO, MSG_ID, END_OF_MSG, CompressionAlgorithm.GZIP, DATA, CRYPTO_CONTEXT);
        assertEquals(END_OF_MSG, chunk.isEndOfMessage());
        assertArrayEquals(DATA, chunk.getData());
        assertEquals(CompressionAlgorithm.GZIP, chunk.getCompressionAlgo());
        assertEquals(MSG_ID, chunk.getMessageId());
        assertEquals(SEQ_NO, chunk.getSequenceNumber());
        final String jsonString = chunk.toJSONString();
        assertNotNull(jsonString);

        final PayloadChunk joChunk = new PayloadChunk(new JSONObject(jsonString), CRYPTO_CONTEXT);
        assertEquals(chunk.isEndOfMessage(), joChunk.isEndOfMessage());
        assertArrayEquals(chunk.getData(), joChunk.getData());
        assertEquals(chunk.getMessageId(), joChunk.getMessageId());
        assertEquals(chunk.getSequenceNumber(), joChunk.getSequenceNumber());
        final String joJsonString = joChunk.toJSONString();
        assertNotNull(joJsonString);
        assertEquals(jsonString, joJsonString);
    }
    
    @Test
    public void gzipJsonString() throws JSONException, MslEncodingException, MslCryptoException, MslException {
        final PayloadChunk chunk = new PayloadChunk(SEQ_NO, MSG_ID, END_OF_MSG, CompressionAlgorithm.GZIP, DATA, CRYPTO_CONTEXT);
        final String jsonString = chunk.toJSONString();
        assertNotNull(jsonString);
        
        final JSONObject jo = new JSONObject(jsonString);
        final byte[] ciphertext = Base64.decode(jo.getString(KEY_PAYLOAD));
        final byte[] signature = Base64.decode(jo.getString(KEY_SIGNATURE));
        assertTrue(CRYPTO_CONTEXT.verify(ciphertext, signature));
        final byte[] payload = CRYPTO_CONTEXT.decrypt(ciphertext);
        
        final JSONObject payloadJo = new JSONObject(new String(payload, MslConstants.DEFAULT_CHARSET));
        assertEquals(SEQ_NO, payloadJo.getLong(KEY_SEQUENCE_NUMBER));
        assertEquals(MSG_ID, payloadJo.getLong(KEY_MESSAGE_ID));
        assertEquals(END_OF_MSG, payloadJo.optBoolean(KEY_END_OF_MESSAGE));
        assertEquals(CompressionAlgorithm.GZIP.toString(), payloadJo.getString(KEY_COMPRESSION_ALGORITHM));
        final byte[] gzipped = Base64.decode(payloadJo.getString(KEY_DATA));
        final byte[] plaintext = uncompress(CompressionAlgorithm.GZIP, gzipped);
        assertArrayEquals(DATA, plaintext);
    }
    
    @Test
    public void lzwCtors() throws MslEncodingException, MslCryptoException, MslException, JSONException {
        final PayloadChunk chunk = new PayloadChunk(SEQ_NO, MSG_ID, END_OF_MSG, CompressionAlgorithm.LZW, DATA, CRYPTO_CONTEXT);
        assertEquals(END_OF_MSG, chunk.isEndOfMessage());
        assertArrayEquals(DATA, chunk.getData());
        assertEquals(CompressionAlgorithm.LZW, chunk.getCompressionAlgo());
        assertEquals(MSG_ID, chunk.getMessageId());
        assertEquals(SEQ_NO, chunk.getSequenceNumber());
        final String jsonString = chunk.toJSONString();
        assertNotNull(jsonString);

        final PayloadChunk joChunk = new PayloadChunk(new JSONObject(jsonString), CRYPTO_CONTEXT);
        assertEquals(chunk.isEndOfMessage(), joChunk.isEndOfMessage());
        assertArrayEquals(chunk.getData(), joChunk.getData());
        assertEquals(chunk.getMessageId(), joChunk.getMessageId());
        assertEquals(chunk.getSequenceNumber(), joChunk.getSequenceNumber());
        final String joJsonString = joChunk.toJSONString();
        assertNotNull(joJsonString);
        assertEquals(jsonString, joJsonString);
    }
    
    @Test
    public void lzwJsonString() throws JSONException, MslEncodingException, MslCryptoException, MslException {
        final PayloadChunk chunk = new PayloadChunk(SEQ_NO, MSG_ID, END_OF_MSG, CompressionAlgorithm.LZW, DATA, CRYPTO_CONTEXT);
        final String jsonString = chunk.toJSONString();
        assertNotNull(jsonString);
        
        final JSONObject jo = new JSONObject(jsonString);
        final byte[] ciphertext = Base64.decode(jo.getString(KEY_PAYLOAD));
        final byte[] signature = Base64.decode(jo.getString(KEY_SIGNATURE));
        assertTrue(CRYPTO_CONTEXT.verify(ciphertext, signature));
        final byte[] payload = CRYPTO_CONTEXT.decrypt(ciphertext);
        
        final JSONObject payloadJo = new JSONObject(new String(payload, MslConstants.DEFAULT_CHARSET));
        assertEquals(SEQ_NO, payloadJo.getLong(KEY_SEQUENCE_NUMBER));
        assertEquals(MSG_ID, payloadJo.getLong(KEY_MESSAGE_ID));
        assertEquals(END_OF_MSG, payloadJo.optBoolean(KEY_END_OF_MESSAGE));
        assertEquals(CompressionAlgorithm.LZW.toString(), payloadJo.getString(KEY_COMPRESSION_ALGORITHM));
        final byte[] gzipped = Base64.decode(payloadJo.getString(KEY_DATA));
        final byte[] plaintext = uncompress(CompressionAlgorithm.LZW, gzipped);
        assertArrayEquals(DATA, plaintext);
    }
    
    @Test(expected = MslCryptoException.class)
    public void mismatchedCryptoContextId() throws MslEncodingException, MslCryptoException, MslException, JSONException {
        final ICryptoContext cryptoContextA = new SymmetricCryptoContext(ctx, CRYPTO_CONTEXT_ID + "A", ENCRYPTION_KEY, HMAC_KEY, null);
        final ICryptoContext cryptoContextB = new SymmetricCryptoContext(ctx, CRYPTO_CONTEXT_ID + "B", ENCRYPTION_KEY, HMAC_KEY, null);
        
        final PayloadChunk chunk = new PayloadChunk(SEQ_NO, MSG_ID, END_OF_MSG, CompressionAlgorithm.GZIP, DATA, cryptoContextA);
        final JSONObject jo = new JSONObject(chunk.toJSONString());
        new PayloadChunk(jo, cryptoContextB);
    }
    
    @Test(expected = MslCryptoException.class)
    public void mismatchedCryptoContextEncryptionKey() throws MslEncodingException, MslCryptoException, MslException, JSONException {
        final byte[] encryptionBytesA = new byte[16];
        final byte[] encryptionBytesB = new byte[16];
        random.nextBytes(encryptionBytesA);
        random.nextBytes(encryptionBytesB);
        final SecretKey encryptionKeyA = new SecretKeySpec(encryptionBytesA, JcaAlgorithm.AES);
        final SecretKey encryptionKeyB = new SecretKeySpec(encryptionBytesB, JcaAlgorithm.AES);
        final ICryptoContext cryptoContextA = new SymmetricCryptoContext(ctx, CRYPTO_CONTEXT_ID, encryptionKeyA, HMAC_KEY, null);
        final ICryptoContext cryptoContextB = new SymmetricCryptoContext(ctx, CRYPTO_CONTEXT_ID, encryptionKeyB, HMAC_KEY, null);
        
        // Mismatched encryption keys will just result in the wrong data.
        final PayloadChunk chunk = new PayloadChunk(SEQ_NO, MSG_ID, END_OF_MSG, CompressionAlgorithm.GZIP, DATA, cryptoContextA);
        final JSONObject jo = new JSONObject(chunk.toJSONString());
        // Sometimes decryption will succeed so check for a crypto exception
        // or encoding exception. Both are OK.
        try {
            new PayloadChunk(jo, cryptoContextB);
        } catch (final MslEncodingException e) {
            throw new MslCryptoException(MslError.DECRYPT_ERROR, e);
        }
    }
    
    @Test
    public void mismatchedCryptoContextSignKey() throws MslEncodingException, MslCryptoException, MslException, JSONException {
        thrown.expect(MslCryptoException.class);
        thrown.expectMslError(MslError.PAYLOAD_VERIFICATION_FAILED);

        final byte[] hmacBytesA = new byte[32];
        final byte[] hmacBytesB = new byte[32];
        random.nextBytes(hmacBytesA);
        random.nextBytes(hmacBytesB);
        final SecretKey hmacKeyA = new SecretKeySpec(hmacBytesA, JcaAlgorithm.HMAC_SHA256);
        final SecretKey hmacKeyB = new SecretKeySpec(hmacBytesB, JcaAlgorithm.HMAC_SHA256);
        final ICryptoContext cryptoContextA = new SymmetricCryptoContext(ctx, CRYPTO_CONTEXT_ID, ENCRYPTION_KEY, hmacKeyA, null);
        final ICryptoContext cryptoContextB = new SymmetricCryptoContext(ctx, CRYPTO_CONTEXT_ID, ENCRYPTION_KEY, hmacKeyB, null);
        
        final PayloadChunk chunk = new PayloadChunk(SEQ_NO, MSG_ID, END_OF_MSG, CompressionAlgorithm.GZIP, DATA, cryptoContextA);
        final JSONObject jo = new JSONObject(chunk.toJSONString());
        new PayloadChunk(jo, cryptoContextB);
    }
    
    @Test
    public void incorrectSignature() throws MslEncodingException, MslCryptoException, MslException, JSONException {
        thrown.expect(MslCryptoException.class);
        thrown.expectMslError(MslError.PAYLOAD_VERIFICATION_FAILED);

        final PayloadChunk chunk = new PayloadChunk(SEQ_NO, MSG_ID, END_OF_MSG, CompressionAlgorithm.GZIP, DATA, CRYPTO_CONTEXT);
        final JSONObject jo = new JSONObject(chunk.toJSONString());
        
        final byte[] signature = new byte[32];
        random.nextBytes(signature);
        jo.put(KEY_SIGNATURE, Base64.encode(signature));
        
        new PayloadChunk(jo, CRYPTO_CONTEXT);
    }
    
    @Test
    public void missingPayload() throws MslEncodingException, MslCryptoException, MslException, JSONException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.JSON_PARSE_ERROR);

        final PayloadChunk chunk = new PayloadChunk(SEQ_NO, MSG_ID, END_OF_MSG, CompressionAlgorithm.GZIP, DATA, CRYPTO_CONTEXT);
        final JSONObject jo = new JSONObject(chunk.toJSONString());
        
        assertNotNull(jo.remove(KEY_PAYLOAD));
        
        new PayloadChunk(jo, CRYPTO_CONTEXT);
    }
    
    @Test
    public void invalidPayload() throws MslEncodingException, MslCryptoException, MslException, JSONException {
        thrown.expect(MslMessageException.class);
        thrown.expectMslError(MslError.PAYLOAD_INVALID);

        final PayloadChunk chunk = new PayloadChunk(SEQ_NO, MSG_ID, END_OF_MSG, CompressionAlgorithm.GZIP, DATA, CRYPTO_CONTEXT);
        final JSONObject jo = new JSONObject(chunk.toJSONString());

        jo.put(KEY_PAYLOAD, "x");

        new PayloadChunk(jo, CRYPTO_CONTEXT);
    }
    
    @Test(expected = MslCryptoException.class)
    public void corruptPayload() throws JSONException, MslEncodingException, MslCryptoException, MslException {
        final PayloadChunk chunk = new PayloadChunk(SEQ_NO, MSG_ID, END_OF_MSG, CompressionAlgorithm.GZIP, DATA, CRYPTO_CONTEXT);
        final JSONObject jo = new JSONObject(chunk.toJSONString());

        final byte[] ciphertext = new byte[32];
        random.nextBytes(ciphertext);
        jo.put(KEY_PAYLOAD, Base64.encode(ciphertext));
        final byte[] signature = CRYPTO_CONTEXT.sign(ciphertext);
        jo.put(KEY_SIGNATURE, Base64.encode(signature));

        new PayloadChunk(jo, CRYPTO_CONTEXT);
    }
    
    @Test
    public void emptyPayloadEndOfMessage() throws JSONException, MslEncodingException, MslCryptoException, MslException {
        final byte[] data = new byte[0];
        final PayloadChunk chunk = new PayloadChunk(SEQ_NO, MSG_ID, true, CompressionAlgorithm.GZIP, data, CRYPTO_CONTEXT);
        final JSONObject jo = new JSONObject(chunk.toJSONString());
        
        final PayloadChunk joChunk = new PayloadChunk(jo, CRYPTO_CONTEXT);
        assertEquals(0, joChunk.getData().length);
    }
    
    @Test
    public void missingSequenceNumber() throws MslEncodingException, MslCryptoException, MslException, JSONException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.JSON_PARSE_ERROR);

        final PayloadChunk chunk = new PayloadChunk(SEQ_NO, MSG_ID, END_OF_MSG, CompressionAlgorithm.GZIP, DATA, CRYPTO_CONTEXT);
        final JSONObject jo = new JSONObject(chunk.toJSONString());

        final byte[] ciphertext = Base64.decode(jo.getString(KEY_PAYLOAD));
        final byte[] payload = CRYPTO_CONTEXT.decrypt(ciphertext);
        final JSONObject payloadJo = new JSONObject(new String(payload, MslConstants.DEFAULT_CHARSET));
        
        assertNotNull(payloadJo.remove(KEY_SEQUENCE_NUMBER));

        final byte[] plaintext = payloadJo.toString().getBytes(MslConstants.DEFAULT_CHARSET);
        final byte[] newPayload = CRYPTO_CONTEXT.encrypt(plaintext);
        final byte[] signature = CRYPTO_CONTEXT.sign(newPayload);
        jo.put(KEY_PAYLOAD, Base64.encode(newPayload));
        jo.put(KEY_SIGNATURE, Base64.encode(signature));
        
        new PayloadChunk(jo, CRYPTO_CONTEXT);
    }
    
    @Test
    public void invalidSequenceNumber() throws MslEncodingException, MslCryptoException, MslException, JSONException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.JSON_PARSE_ERROR);

        final PayloadChunk chunk = new PayloadChunk(SEQ_NO, MSG_ID, true, CompressionAlgorithm.GZIP, DATA, CRYPTO_CONTEXT);
        final JSONObject jo = new JSONObject(chunk.toJSONString());

        final byte[] ciphertext = Base64.decode(jo.getString(KEY_PAYLOAD));
        final byte[] payload = CRYPTO_CONTEXT.decrypt(ciphertext);
        final JSONObject payloadJo = new JSONObject(new String(payload, MslConstants.DEFAULT_CHARSET));
        
        payloadJo.put(KEY_SEQUENCE_NUMBER, "x");
        
        final byte[] plaintext = payloadJo.toString().getBytes(MslConstants.DEFAULT_CHARSET);
        final byte[] newPayload = CRYPTO_CONTEXT.encrypt(plaintext);
        final byte[] signature = CRYPTO_CONTEXT.sign(newPayload);
        jo.put(KEY_PAYLOAD, Base64.encode(newPayload));
        jo.put(KEY_SIGNATURE, Base64.encode(signature));
        
        new PayloadChunk(jo, CRYPTO_CONTEXT);
    }
    
    @Test
    public void negativeSequenceNumber() throws MslEncodingException, MslCryptoException, MslException, JSONException {
        thrown.expect(MslException.class);
        thrown.expectMslError(MslError.PAYLOAD_SEQUENCE_NUMBER_OUT_OF_RANGE);

        final PayloadChunk chunk = new PayloadChunk(SEQ_NO, MSG_ID, true, CompressionAlgorithm.GZIP, DATA, CRYPTO_CONTEXT);
        final JSONObject jo = new JSONObject(chunk.toJSONString());

        final byte[] ciphertext = Base64.decode(jo.getString(KEY_PAYLOAD));
        final byte[] payload = CRYPTO_CONTEXT.decrypt(ciphertext);
        final JSONObject payloadJo = new JSONObject(new String(payload, MslConstants.DEFAULT_CHARSET));
        
        payloadJo.put(KEY_SEQUENCE_NUMBER, -1);
        
        final byte[] plaintext = payloadJo.toString().getBytes(MslConstants.DEFAULT_CHARSET);
        final byte[] newPayload = CRYPTO_CONTEXT.encrypt(plaintext);
        final byte[] signature = CRYPTO_CONTEXT.sign(newPayload);
        jo.put(KEY_PAYLOAD, Base64.encode(newPayload));
        jo.put(KEY_SIGNATURE, Base64.encode(signature));
        
        new PayloadChunk(jo, CRYPTO_CONTEXT);
    }
    
    @Test
    public void tooLargeSequenceNumber() throws MslEncodingException, MslCryptoException, MslException, JSONException {
        thrown.expect(MslException.class);
        thrown.expectMslError(MslError.PAYLOAD_SEQUENCE_NUMBER_OUT_OF_RANGE);

        final PayloadChunk chunk = new PayloadChunk(SEQ_NO, MSG_ID, true, CompressionAlgorithm.GZIP, DATA, CRYPTO_CONTEXT);
        final JSONObject jo = new JSONObject(chunk.toJSONString());

        final byte[] ciphertext = Base64.decode(jo.getString(KEY_PAYLOAD));
        final byte[] payload = CRYPTO_CONTEXT.decrypt(ciphertext);
        final JSONObject payloadJo = new JSONObject(new String(payload, MslConstants.DEFAULT_CHARSET));
        
        payloadJo.put(KEY_SEQUENCE_NUMBER, MslConstants.MAX_LONG_VALUE + 1);
        
        final byte[] plaintext = payloadJo.toString().getBytes(MslConstants.DEFAULT_CHARSET);
        final byte[] newPayload = CRYPTO_CONTEXT.encrypt(plaintext);
        final byte[] signature = CRYPTO_CONTEXT.sign(newPayload);
        jo.put(KEY_PAYLOAD, Base64.encode(newPayload));
        jo.put(KEY_SIGNATURE, Base64.encode(signature));
        
        new PayloadChunk(jo, CRYPTO_CONTEXT);
    }
    
    @Test
    public void missingMessageId() throws MslEncodingException, MslCryptoException, MslException, JSONException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.JSON_PARSE_ERROR);

        final PayloadChunk chunk = new PayloadChunk(SEQ_NO, MSG_ID, END_OF_MSG, CompressionAlgorithm.GZIP, DATA, CRYPTO_CONTEXT);
        final JSONObject jo = new JSONObject(chunk.toJSONString());

        final byte[] ciphertext = Base64.decode(jo.getString(KEY_PAYLOAD));
        final byte[] payload = CRYPTO_CONTEXT.decrypt(ciphertext);
        final JSONObject payloadJo = new JSONObject(new String(payload, MslConstants.DEFAULT_CHARSET));
        
        assertNotNull(payloadJo.remove(KEY_MESSAGE_ID));

        final byte[] plaintext = payloadJo.toString().getBytes(MslConstants.DEFAULT_CHARSET);
        final byte[] newPayload = CRYPTO_CONTEXT.encrypt(plaintext);
        final byte[] signature = CRYPTO_CONTEXT.sign(newPayload);
        jo.put(KEY_PAYLOAD, Base64.encode(newPayload));
        jo.put(KEY_SIGNATURE, Base64.encode(signature));
        
        new PayloadChunk(jo, CRYPTO_CONTEXT);
    }
    
    @Test
    public void invalidMessageId() throws JSONException, MslEncodingException, MslCryptoException, MslException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.JSON_PARSE_ERROR);

        final PayloadChunk chunk = new PayloadChunk(SEQ_NO, MSG_ID, true, CompressionAlgorithm.GZIP, DATA, CRYPTO_CONTEXT);
        final JSONObject jo = new JSONObject(chunk.toJSONString());

        final byte[] ciphertext = Base64.decode(jo.getString(KEY_PAYLOAD));
        final byte[] payload = CRYPTO_CONTEXT.decrypt(ciphertext);
        final JSONObject payloadJo = new JSONObject(new String(payload, MslConstants.DEFAULT_CHARSET));
        
        payloadJo.put(KEY_MESSAGE_ID, "x");

        final byte[] plaintext = payloadJo.toString().getBytes(MslConstants.DEFAULT_CHARSET);
        final byte[] newPayload = CRYPTO_CONTEXT.encrypt(plaintext);
        final byte[] signature = CRYPTO_CONTEXT.sign(newPayload);
        jo.put(KEY_PAYLOAD, Base64.encode(newPayload));
        jo.put(KEY_SIGNATURE, Base64.encode(signature));
        
        new PayloadChunk(jo, CRYPTO_CONTEXT);
    }
    
    @Test
    public void invalidEndOfMessage() throws JSONException, MslEncodingException, MslCryptoException, MslException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.JSON_PARSE_ERROR);

        final PayloadChunk chunk = new PayloadChunk(SEQ_NO, MSG_ID, true, CompressionAlgorithm.GZIP, DATA, CRYPTO_CONTEXT);
        final JSONObject jo = new JSONObject(chunk.toJSONString());

        final byte[] ciphertext = Base64.decode(jo.getString(KEY_PAYLOAD));
        final byte[] payload = CRYPTO_CONTEXT.decrypt(ciphertext);
        final JSONObject payloadJo = new JSONObject(new String(payload, MslConstants.DEFAULT_CHARSET));
        
        payloadJo.put(KEY_END_OF_MESSAGE, "x");

        final byte[] plaintext = payloadJo.toString().getBytes(MslConstants.DEFAULT_CHARSET);
        final byte[] newPayload = CRYPTO_CONTEXT.encrypt(plaintext);
        final byte[] signature = CRYPTO_CONTEXT.sign(newPayload);
        jo.put(KEY_PAYLOAD, Base64.encode(newPayload));
        jo.put(KEY_SIGNATURE, Base64.encode(signature));
        
        new PayloadChunk(jo, CRYPTO_CONTEXT);
    }
    
    @Test
    public void invalidCompressionAlgorithm() throws MslEncodingException, MslCryptoException, MslException, JSONException {
        thrown.expect(MslMessageException.class);
        thrown.expectMslError(MslError.UNIDENTIFIED_COMPRESSION);

        final PayloadChunk chunk = new PayloadChunk(SEQ_NO, MSG_ID, true, CompressionAlgorithm.GZIP, DATA, CRYPTO_CONTEXT);
        final JSONObject jo = new JSONObject(chunk.toJSONString());

        final byte[] ciphertext = Base64.decode(jo.getString(KEY_PAYLOAD));
        final byte[] payload = CRYPTO_CONTEXT.decrypt(ciphertext);
        final JSONObject payloadJo = new JSONObject(new String(payload, MslConstants.DEFAULT_CHARSET));

        payloadJo.put(KEY_COMPRESSION_ALGORITHM, "x");

        final byte[] plaintext = payloadJo.toString().getBytes(MslConstants.DEFAULT_CHARSET);
        final byte[] newPayload = CRYPTO_CONTEXT.encrypt(plaintext);
        final byte[] signature = CRYPTO_CONTEXT.sign(newPayload);
        jo.put(KEY_PAYLOAD, Base64.encode(newPayload));
        jo.put(KEY_SIGNATURE, Base64.encode(signature));
        
        new PayloadChunk(jo, CRYPTO_CONTEXT);
    }
    
    @Test
    public void missingData() throws JSONException, MslEncodingException, MslCryptoException, MslException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.JSON_PARSE_ERROR);

        final PayloadChunk chunk = new PayloadChunk(SEQ_NO, MSG_ID, END_OF_MSG, CompressionAlgorithm.GZIP, DATA, CRYPTO_CONTEXT);
        final JSONObject jo = new JSONObject(chunk.toJSONString());

        final byte[] ciphertext = Base64.decode(jo.getString(KEY_PAYLOAD));
        final byte[] payload = CRYPTO_CONTEXT.decrypt(ciphertext);
        final JSONObject payloadJo = new JSONObject(new String(payload, MslConstants.DEFAULT_CHARSET));
        
        assertNotNull(payloadJo.remove(KEY_DATA));

        final byte[] plaintext = payloadJo.toString().getBytes(MslConstants.DEFAULT_CHARSET);
        final byte[] newPayload = CRYPTO_CONTEXT.encrypt(plaintext);
        final byte[] signature = CRYPTO_CONTEXT.sign(newPayload);
        jo.put(KEY_PAYLOAD, Base64.encode(newPayload));
        jo.put(KEY_SIGNATURE, Base64.encode(signature));
        
        new PayloadChunk(jo, CRYPTO_CONTEXT);
    }
    
    @Test
    public void emptyData() throws MslEncodingException, MslCryptoException, MslException, JSONException {
        thrown.expect(MslMessageException.class);
        thrown.expectMslError(MslError.PAYLOAD_DATA_MISSING);

        final PayloadChunk chunk = new PayloadChunk(SEQ_NO, MSG_ID, END_OF_MSG, CompressionAlgorithm.GZIP, DATA, CRYPTO_CONTEXT);
        final JSONObject jo = new JSONObject(chunk.toJSONString());

        final byte[] ciphertext = Base64.decode(jo.getString(KEY_PAYLOAD));
        final byte[] payload = CRYPTO_CONTEXT.decrypt(ciphertext);
        final JSONObject payloadJo = new JSONObject(new String(payload, MslConstants.DEFAULT_CHARSET));
        
        payloadJo.put(KEY_DATA, "");

        final byte[] plaintext = payloadJo.toString().getBytes(MslConstants.DEFAULT_CHARSET);
        final byte[] newPayload = CRYPTO_CONTEXT.encrypt(plaintext);
        final byte[] signature = CRYPTO_CONTEXT.sign(newPayload);
        jo.put(KEY_PAYLOAD, Base64.encode(newPayload));
        jo.put(KEY_SIGNATURE, Base64.encode(signature));
        
        new PayloadChunk(jo, CRYPTO_CONTEXT);
    }

    @Test
    public void invalidDataEndOfMessage() throws MslEncodingException, MslCryptoException, MslException, JSONException {
        thrown.expect(MslMessageException.class);
        thrown.expectMslError(MslError.PAYLOAD_DATA_CORRUPT);

        final PayloadChunk chunk = new PayloadChunk(SEQ_NO, MSG_ID, true, CompressionAlgorithm.GZIP, DATA, CRYPTO_CONTEXT);
        final JSONObject jo = new JSONObject(chunk.toJSONString());

        final byte[] ciphertext = Base64.decode(jo.getString(KEY_PAYLOAD));
        final byte[] payload = CRYPTO_CONTEXT.decrypt(ciphertext);
        final JSONObject payloadJo = new JSONObject(new String(payload, MslConstants.DEFAULT_CHARSET));
        
        payloadJo.put(KEY_DATA, "x");

        final byte[] plaintext = payloadJo.toString().getBytes(MslConstants.DEFAULT_CHARSET);
        final byte[] newPayload = CRYPTO_CONTEXT.encrypt(plaintext);
        final byte[] signature = CRYPTO_CONTEXT.sign(newPayload);
        jo.put(KEY_PAYLOAD, Base64.encode(newPayload));
        jo.put(KEY_SIGNATURE, Base64.encode(signature));
        
        new PayloadChunk(jo, CRYPTO_CONTEXT);
    }
    
    @Test
    public void largeData() throws MslEncodingException, MslCryptoException, MslException, JSONException {
        final byte[] data = new byte[10 * 1024 * 1024];
        random.nextBytes(data);
        final PayloadChunk chunk = new PayloadChunk(SEQ_NO, MSG_ID, true, null, data, CRYPTO_CONTEXT);
        assertArrayEquals(data, chunk.getData());
        
        final JSONObject jo = new JSONObject(chunk.toJSONString());
        final PayloadChunk joChunk = new PayloadChunk(jo, CRYPTO_CONTEXT);
        assertArrayEquals(chunk.getData(), joChunk.getData());
    }
    
    @Test
    public void gzipLargeData() throws MslEncodingException, MslCryptoException, MslException, JSONException {
        final byte[] data = new byte[10 * 1024 * 1024];
        random.nextBytes(data);
        final PayloadChunk chunk = new PayloadChunk(SEQ_NO, MSG_ID, true, CompressionAlgorithm.GZIP, data, CRYPTO_CONTEXT);
        assertArrayEquals(data, chunk.getData());
        
        // Random data will not compress.
        assertNull(chunk.getCompressionAlgo());
        
        final JSONObject jo = new JSONObject(chunk.toJSONString());
        final PayloadChunk joChunk = new PayloadChunk(jo, CRYPTO_CONTEXT);
        assertArrayEquals(chunk.getData(), joChunk.getData());
        assertEquals(chunk.getCompressionAlgo(), joChunk.getCompressionAlgo());
    }
    
    @Test
    public void gzipVerona() throws MslEncodingException, MslCryptoException, MslMessageException, MslException, JSONException {
        final PayloadChunk chunk = new PayloadChunk(SEQ_NO, MSG_ID, true, CompressionAlgorithm.GZIP, rawdata, CRYPTO_CONTEXT);
        assertArrayEquals(rawdata, chunk.getData());
        
        // Romeo and Juliet will compress.
        assertEquals(CompressionAlgorithm.GZIP, chunk.getCompressionAlgo());
        
        final JSONObject jo = new JSONObject(chunk.toJSONString());
        final PayloadChunk joChunk = new PayloadChunk(jo, CRYPTO_CONTEXT);
        assertArrayEquals(chunk.getData(), joChunk.getData());
        assertEquals(chunk.getCompressionAlgo(), joChunk.getCompressionAlgo());
    }
    
    @Test
    public void lzwRandomData() throws MslEncodingException, MslCryptoException, MslException, JSONException {
        final byte[] data = new byte[10 * 1024 * 1024];
        random.nextBytes(data);
        final PayloadChunk chunk = new PayloadChunk(SEQ_NO, MSG_ID, true, CompressionAlgorithm.LZW, data, CRYPTO_CONTEXT);
        assertArrayEquals(data, chunk.getData());
        
        // Random data will not compress.
        assertNull(chunk.getCompressionAlgo());
        
        final JSONObject jo = new JSONObject(chunk.toJSONString());
        final PayloadChunk joChunk = new PayloadChunk(jo, CRYPTO_CONTEXT);
        assertArrayEquals(chunk.getData(), joChunk.getData());
        assertEquals(chunk.getCompressionAlgo(), joChunk.getCompressionAlgo());
    }
    
    @Test
    public void lzwVerona() throws MslEncodingException, MslCryptoException, MslMessageException, MslException, JSONException {
        final PayloadChunk chunk = new PayloadChunk(SEQ_NO, MSG_ID, true, CompressionAlgorithm.LZW, rawdata, CRYPTO_CONTEXT);
        assertArrayEquals(rawdata, chunk.getData());
        
        // Romeo and Juliet will compress.
        assertEquals(CompressionAlgorithm.LZW, chunk.getCompressionAlgo());
        
        final JSONObject jo = new JSONObject(chunk.toJSONString());
        final PayloadChunk joChunk = new PayloadChunk(jo, CRYPTO_CONTEXT);
        assertArrayEquals(chunk.getData(), joChunk.getData());
        assertEquals(chunk.getCompressionAlgo(), joChunk.getCompressionAlgo());
    }
    
    @Test
    public void equalsSequenceNumber() throws MslEncodingException, MslCryptoException, MslException, JSONException {
        final long seqNoA = 1;
        final long seqNoB = 2;
        final PayloadChunk chunkA = new PayloadChunk(seqNoA, MSG_ID, false, null, DATA, CRYPTO_CONTEXT);
        final PayloadChunk chunkB = new PayloadChunk(seqNoB, MSG_ID, false, null, DATA, CRYPTO_CONTEXT);
        final PayloadChunk chunkA2 = new PayloadChunk(new JSONObject(chunkA.toJSONString()), CRYPTO_CONTEXT);
        
        assertTrue(chunkA.equals(chunkA));
        assertEquals(chunkA.hashCode(), chunkA.hashCode());
        
        assertFalse(chunkA.equals(chunkB));
        assertFalse(chunkB.equals(chunkA));
        assertTrue(chunkA.hashCode() != chunkB.hashCode());
        
        assertTrue(chunkA.equals(chunkA2));
        assertTrue(chunkA2.equals(chunkA));
        assertEquals(chunkA.hashCode(), chunkA2.hashCode());
    }
    
    @Test
    public void equalsMessageId() throws MslEncodingException, MslCryptoException, MslException, JSONException {
        final long msgIdA = 1;
        final long msgIdB = 2;
        final PayloadChunk chunkA = new PayloadChunk(SEQ_NO, msgIdA, false, null, DATA, CRYPTO_CONTEXT);
        final PayloadChunk chunkB = new PayloadChunk(SEQ_NO, msgIdB, false, null, DATA, CRYPTO_CONTEXT);
        final PayloadChunk chunkA2 = new PayloadChunk(new JSONObject(chunkA.toJSONString()), CRYPTO_CONTEXT);
        
        assertTrue(chunkA.equals(chunkA));
        assertEquals(chunkA.hashCode(), chunkA.hashCode());
        
        assertFalse(chunkA.equals(chunkB));
        assertFalse(chunkB.equals(chunkA));
        assertTrue(chunkA.hashCode() != chunkB.hashCode());
        
        assertTrue(chunkA.equals(chunkA2));
        assertTrue(chunkA2.equals(chunkA));
        assertEquals(chunkA.hashCode(), chunkA2.hashCode());
    }
    
    @Test
    public void equalsEndOfMessage() throws MslEncodingException, MslCryptoException, MslException, JSONException {
        final PayloadChunk chunkA = new PayloadChunk(SEQ_NO, MSG_ID, true, null, DATA, CRYPTO_CONTEXT);
        final PayloadChunk chunkB = new PayloadChunk(SEQ_NO, MSG_ID, false, null, DATA, CRYPTO_CONTEXT);
        final PayloadChunk chunkA2 = new PayloadChunk(new JSONObject(chunkA.toJSONString()), CRYPTO_CONTEXT);
        
        assertTrue(chunkA.equals(chunkA));
        assertEquals(chunkA.hashCode(), chunkA.hashCode());
        
        assertFalse(chunkA.equals(chunkB));
        assertFalse(chunkB.equals(chunkA));
        assertTrue(chunkA.hashCode() != chunkB.hashCode());
        
        assertTrue(chunkA.equals(chunkA2));
        assertTrue(chunkA2.equals(chunkA));
        assertEquals(chunkA.hashCode(), chunkA2.hashCode());
    }
    
    @Test
    public void equalsCompressionAlgorithm() throws MslEncodingException, MslCryptoException, MslException, JSONException {
        final PayloadChunk chunkA = new PayloadChunk(SEQ_NO, MSG_ID, true, CompressionAlgorithm.GZIP, DATA, CRYPTO_CONTEXT);
        final PayloadChunk chunkB = new PayloadChunk(SEQ_NO, MSG_ID, true, null, DATA, CRYPTO_CONTEXT);
        final PayloadChunk chunkA2 = new PayloadChunk(new JSONObject(chunkA.toJSONString()), CRYPTO_CONTEXT);
        
        assertTrue(chunkA.equals(chunkA));
        assertEquals(chunkA.hashCode(), chunkA.hashCode());
        
        assertFalse(chunkA.equals(chunkB));
        assertFalse(chunkB.equals(chunkA));
        assertTrue(chunkA.hashCode() != chunkB.hashCode());
        
        assertTrue(chunkA.equals(chunkA2));
        assertTrue(chunkA2.equals(chunkA));
        assertEquals(chunkA.hashCode(), chunkA2.hashCode());
    }
    
    @Test
    public void equalsData() throws MslEncodingException, MslCryptoException, MslException, JSONException {
        final byte[] dataA = new byte[32];
        random.nextBytes(dataA);
        final byte[] dataB = new byte[32];
        random.nextBytes(dataB);
        final byte[] dataC = new byte[0];
        final PayloadChunk chunkA = new PayloadChunk(SEQ_NO, MSG_ID, true, CompressionAlgorithm.GZIP, dataA, CRYPTO_CONTEXT);
        final PayloadChunk chunkB = new PayloadChunk(SEQ_NO, MSG_ID, true, CompressionAlgorithm.GZIP, dataB, CRYPTO_CONTEXT);
        final PayloadChunk chunkC = new PayloadChunk(SEQ_NO, MSG_ID, true, CompressionAlgorithm.GZIP, dataC, CRYPTO_CONTEXT);
        final PayloadChunk chunkA2 = new PayloadChunk(new JSONObject(chunkA.toJSONString()), CRYPTO_CONTEXT);
        
        assertTrue(chunkA.equals(chunkA));
        assertEquals(chunkA.hashCode(), chunkA.hashCode());
        
        assertFalse(chunkA.equals(chunkB));
        assertFalse(chunkB.equals(chunkA));
        assertTrue(chunkA.hashCode() != chunkB.hashCode());
        
        assertFalse(chunkA.equals(chunkC));
        assertFalse(chunkC.equals(chunkA));
        assertTrue(chunkA.hashCode() != chunkC.hashCode());
        
        assertTrue(chunkA.equals(chunkA2));
        assertTrue(chunkA2.equals(chunkA));
        assertEquals(chunkA.hashCode(), chunkA2.hashCode());
    }
    
    @Test
    public void equalsObject() throws MslEncodingException, MslCryptoException, MslException {
        final PayloadChunk chunk = new PayloadChunk(SEQ_NO, MSG_ID, true, CompressionAlgorithm.GZIP, DATA, CRYPTO_CONTEXT);
        
        assertFalse(chunk.equals(null));
        assertFalse(chunk.equals(CRYPTO_CONTEXT_ID));
        assertTrue(chunk.hashCode() != CRYPTO_CONTEXT_ID.hashCode());
    }
}
