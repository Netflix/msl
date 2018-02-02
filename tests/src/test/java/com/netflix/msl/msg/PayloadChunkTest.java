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
import java.io.IOException;
import java.util.Random;
import java.util.zip.GZIPInputStream;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

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
import com.netflix.msl.io.MslEncoderException;
import com.netflix.msl.io.MslEncoderFactory;
import com.netflix.msl.io.MslEncoderFormat;
import com.netflix.msl.io.MslObject;
import com.netflix.msl.test.ExpectedMslException;
import com.netflix.msl.util.Base64;
import com.netflix.msl.util.IOUtils;
import com.netflix.msl.util.MockMslContext;
import com.netflix.msl.util.MslContext;
import com.netflix.msl.util.MslTestUtils;

/**
 * Payload chunk unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class PayloadChunkTest {
	/** MSL encoder format. */
	private static final MslEncoderFormat ENCODER_FORMAT = MslEncoderFormat.JSON;

    /** RAW data file. */
    private static final String DATAFILE = "/pg1112.txt";
    
    /** Key payload. */
    private static final String KEY_PAYLOAD = "payload";
    /** Key signature. */
    private static final String KEY_SIGNATURE = "signature";
    
    // payload
    /** Key sequence number. */
    private static final String KEY_SEQUENCE_NUMBER = "sequencenumber";
    /** Key message ID. */
    private static final String KEY_MESSAGE_ID = "messageid";
    /** Key end of message. */
    private static final String KEY_END_OF_MESSAGE = "endofmsg";
    /** Key compression algorithm. */
    private static final String KEY_COMPRESSION_ALGORITHM = "compressionalgo";
    /** Key encrypted data. */
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
                    return IOUtils.readAllBytes(gzis);
                }
                case LZW:
                {
                    final ByteArrayInputStream bais = new ByteArrayInputStream(data);
                    final LZWInputStream lzwis = new LZWInputStream(bais);
                    return IOUtils.readAllBytes(lzwis);
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
    /** MSL encoder factory. */
    private static MslEncoderFactory encoder;
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
        encoder = ctx.getMslEncoderFactory();

        final byte[] encryptionBytes = new byte[16];
        final byte[] hmacBytes = new byte[32];
        random.nextBytes(encryptionBytes);
        random.nextBytes(hmacBytes);
        ENCRYPTION_KEY = new SecretKeySpec(encryptionBytes, JcaAlgorithm.AES);
        HMAC_KEY = new SecretKeySpec(hmacBytes, JcaAlgorithm.HMAC_SHA256);
        CRYPTO_CONTEXT = new SymmetricCryptoContext(ctx, CRYPTO_CONTEXT_ID, ENCRYPTION_KEY, HMAC_KEY, null);
        
        // Load the raw file.
        rawdata = IOUtils.readResource(DATAFILE);
    }
    
    @AfterClass
    public static void teardown() {
        CRYPTO_CONTEXT = null;
        encoder = null;
        ctx = null;
    }

    @Test
    public void ctors() throws MslEncodingException, MslCryptoException, MslException, MslEncoderException {
        final PayloadChunk chunk = new PayloadChunk(ctx, SEQ_NO, MSG_ID, END_OF_MSG, null, DATA, CRYPTO_CONTEXT);
        assertEquals(END_OF_MSG, chunk.isEndOfMessage());
        assertArrayEquals(DATA, chunk.getData());
        assertNull(chunk.getCompressionAlgo());
        assertEquals(MSG_ID, chunk.getMessageId());
        assertEquals(SEQ_NO, chunk.getSequenceNumber());
        final byte[] encode = chunk.toMslEncoding(encoder, ENCODER_FORMAT);
        assertNotNull(encode);

        final PayloadChunk moChunk = new PayloadChunk(ctx, encoder.parseObject(encode), CRYPTO_CONTEXT);
        assertEquals(chunk.isEndOfMessage(), moChunk.isEndOfMessage());
        assertArrayEquals(chunk.getData(), moChunk.getData());
        assertEquals(chunk.getMessageId(), moChunk.getMessageId());
        assertEquals(chunk.getSequenceNumber(), moChunk.getSequenceNumber());
        final byte[] moEncode = moChunk.toMslEncoding(encoder, ENCODER_FORMAT);
        assertNotNull(moEncode);
        // The two payload chunk encodings will not be equal because the
        // ciphertext and signature will be generated on-demand.
    }
    
    @Test(expected = MslInternalException.class)
    public void negativeSequenceNumberCtor() throws MslEncodingException, MslCryptoException, MslException {
        final long sequenceNumber = -1;
        new PayloadChunk(ctx, sequenceNumber, MSG_ID, END_OF_MSG, null, DATA, CRYPTO_CONTEXT);
    }
    
    @Test(expected = MslInternalException.class)
    public void tooLargeSequenceNumberCtor() throws MslEncodingException, MslCryptoException, MslException {
        final long sequenceNumber = MslConstants.MAX_LONG_VALUE + 1;
        new PayloadChunk(ctx, sequenceNumber, MSG_ID, END_OF_MSG, null, DATA, CRYPTO_CONTEXT);
    }
    
    @Test(expected = MslInternalException.class)
    public void negativeMessageIdCtor() throws MslEncodingException, MslCryptoException, MslException {
        final long messageId = -1;
        new PayloadChunk(ctx, SEQ_NO, messageId, END_OF_MSG, null, DATA, CRYPTO_CONTEXT);
    }
    
    @Test(expected = MslInternalException.class)
    public void tooLargeMessageIdCtor() throws MslEncodingException, MslCryptoException, MslException {
        final long messageId = MslConstants.MAX_LONG_VALUE + 1;
        new PayloadChunk(ctx, SEQ_NO, messageId, END_OF_MSG, null, DATA, CRYPTO_CONTEXT);
    }
    
    @Test
    public void mslObject() throws MslEncodingException, MslException, MslEncoderException {
        final PayloadChunk chunk = new PayloadChunk(ctx, SEQ_NO, MSG_ID, END_OF_MSG, null, DATA, CRYPTO_CONTEXT);
        final byte[] encode = chunk.toMslEncoding(encoder, ENCODER_FORMAT);
        assertNotNull(encode);
        
        final MslObject mo = encoder.parseObject(encode);
        final byte[] ciphertext = mo.getBytes(KEY_PAYLOAD);
        final byte[] signature = mo.getBytes(KEY_SIGNATURE);
        assertTrue(CRYPTO_CONTEXT.verify(ciphertext, signature, encoder));
        final byte[] payload = CRYPTO_CONTEXT.decrypt(ciphertext, encoder);
        
        final MslObject payloadMo = encoder.parseObject(payload);
        assertEquals(SEQ_NO, payloadMo.getLong(KEY_SEQUENCE_NUMBER));
        assertEquals(MSG_ID, payloadMo.getLong(KEY_MESSAGE_ID));
        assertEquals(END_OF_MSG, payloadMo.optBoolean(KEY_END_OF_MESSAGE));
        assertFalse(payloadMo.has(KEY_COMPRESSION_ALGORITHM));
        assertArrayEquals(DATA, payloadMo.getBytes(KEY_DATA));
    }
    
    @Test
    public void gzipCtors() throws MslEncodingException, MslCryptoException, MslException, MslEncoderException {
        final PayloadChunk chunk = new PayloadChunk(ctx, SEQ_NO, MSG_ID, END_OF_MSG, CompressionAlgorithm.GZIP, DATA, CRYPTO_CONTEXT);
        assertEquals(END_OF_MSG, chunk.isEndOfMessage());
        assertArrayEquals(DATA, chunk.getData());
        assertEquals(CompressionAlgorithm.GZIP, chunk.getCompressionAlgo());
        assertEquals(MSG_ID, chunk.getMessageId());
        assertEquals(SEQ_NO, chunk.getSequenceNumber());
        final byte[] encode = chunk.toMslEncoding(encoder, ENCODER_FORMAT);
        assertNotNull(encode);

        final PayloadChunk moChunk = new PayloadChunk(ctx, encoder.parseObject(encode), CRYPTO_CONTEXT);
        assertEquals(chunk.isEndOfMessage(), moChunk.isEndOfMessage());
        assertArrayEquals(chunk.getData(), moChunk.getData());
        assertEquals(chunk.getMessageId(), moChunk.getMessageId());
        assertEquals(chunk.getSequenceNumber(), moChunk.getSequenceNumber());
        final byte[] moEncode = moChunk.toMslEncoding(encoder, ENCODER_FORMAT);
        assertNotNull(moEncode);
        // The two payload chunk encodings will not be equal because the
        // ciphertext and signature will be generated on-demand.
    }
    
    @Test
    public void gzipMslObject() throws MslEncoderException, MslEncodingException, MslCryptoException, MslException {
        final PayloadChunk chunk = new PayloadChunk(ctx, SEQ_NO, MSG_ID, END_OF_MSG, CompressionAlgorithm.GZIP, DATA, CRYPTO_CONTEXT);
        final byte[] encode = chunk.toMslEncoding(encoder, ENCODER_FORMAT);
        assertNotNull(encode);
        
        final MslObject mo = encoder.parseObject(encode);
        final byte[] ciphertext = mo.getBytes(KEY_PAYLOAD);
        final byte[] signature = mo.getBytes(KEY_SIGNATURE);
        assertTrue(CRYPTO_CONTEXT.verify(ciphertext, signature, encoder));
        final byte[] payload = CRYPTO_CONTEXT.decrypt(ciphertext, encoder);
        
        final MslObject payloadMo = encoder.parseObject(payload);
        assertEquals(SEQ_NO, payloadMo.getLong(KEY_SEQUENCE_NUMBER));
        assertEquals(MSG_ID, payloadMo.getLong(KEY_MESSAGE_ID));
        assertEquals(END_OF_MSG, payloadMo.optBoolean(KEY_END_OF_MESSAGE));
        assertEquals(CompressionAlgorithm.GZIP.toString(), payloadMo.getString(KEY_COMPRESSION_ALGORITHM));
        final byte[] gzipped = payloadMo.getBytes(KEY_DATA);
        final byte[] plaintext = uncompress(CompressionAlgorithm.GZIP, gzipped);
        assertArrayEquals(DATA, plaintext);
    }
    
    @Test
    public void lzwCtors() throws MslEncodingException, MslCryptoException, MslException, MslEncoderException {
        final PayloadChunk chunk = new PayloadChunk(ctx, SEQ_NO, MSG_ID, END_OF_MSG, CompressionAlgorithm.LZW, DATA, CRYPTO_CONTEXT);
        assertEquals(END_OF_MSG, chunk.isEndOfMessage());
        assertArrayEquals(DATA, chunk.getData());
        assertEquals(CompressionAlgorithm.LZW, chunk.getCompressionAlgo());
        assertEquals(MSG_ID, chunk.getMessageId());
        assertEquals(SEQ_NO, chunk.getSequenceNumber());
        final byte[] encode = chunk.toMslEncoding(encoder, ENCODER_FORMAT);
        assertNotNull(encode);

        final PayloadChunk moChunk = new PayloadChunk(ctx, encoder.parseObject(encode), CRYPTO_CONTEXT);
        assertEquals(chunk.isEndOfMessage(), moChunk.isEndOfMessage());
        assertArrayEquals(chunk.getData(), moChunk.getData());
        assertEquals(chunk.getMessageId(), moChunk.getMessageId());
        assertEquals(chunk.getSequenceNumber(), moChunk.getSequenceNumber());
        final byte[] moEncode = moChunk.toMslEncoding(encoder, ENCODER_FORMAT);
        assertNotNull(moEncode);
        // The two payload chunk encodings will not be equal because the
        // ciphertext and signature will be generated on-demand.
    }
    
    @Test
    public void lzwMslObject() throws MslEncoderException, MslEncodingException, MslCryptoException, MslException {
        final PayloadChunk chunk = new PayloadChunk(ctx, SEQ_NO, MSG_ID, END_OF_MSG, CompressionAlgorithm.LZW, DATA, CRYPTO_CONTEXT);
        final byte[] encode = chunk.toMslEncoding(encoder, ENCODER_FORMAT);
        assertNotNull(encode);
        
        final MslObject mo = encoder.parseObject(encode);
        final byte[] ciphertext = mo.getBytes(KEY_PAYLOAD);
        final byte[] signature = mo.getBytes(KEY_SIGNATURE);
        assertTrue(CRYPTO_CONTEXT.verify(ciphertext, signature, encoder));
        final byte[] payload = CRYPTO_CONTEXT.decrypt(ciphertext, encoder);
        
        final MslObject payloadMo = encoder.parseObject(payload);
        assertEquals(SEQ_NO, payloadMo.getLong(KEY_SEQUENCE_NUMBER));
        assertEquals(MSG_ID, payloadMo.getLong(KEY_MESSAGE_ID));
        assertEquals(END_OF_MSG, payloadMo.optBoolean(KEY_END_OF_MESSAGE));
        assertEquals(CompressionAlgorithm.LZW.toString(), payloadMo.getString(KEY_COMPRESSION_ALGORITHM));
        final byte[] gzipped = payloadMo.getBytes(KEY_DATA);
        final byte[] plaintext = uncompress(CompressionAlgorithm.LZW, gzipped);
        assertArrayEquals(DATA, plaintext);
    }
    
    public void mismatchedCryptoContextId() throws MslEncodingException, MslCryptoException, MslException, MslEncoderException {
        final ICryptoContext cryptoContextA = new SymmetricCryptoContext(ctx, CRYPTO_CONTEXT_ID + "A", ENCRYPTION_KEY, HMAC_KEY, null);
        final ICryptoContext cryptoContextB = new SymmetricCryptoContext(ctx, CRYPTO_CONTEXT_ID + "B", ENCRYPTION_KEY, HMAC_KEY, null);
        
        final PayloadChunk chunk = new PayloadChunk(ctx, SEQ_NO, MSG_ID, END_OF_MSG, CompressionAlgorithm.GZIP, DATA, cryptoContextA);
        final MslObject mo = MslTestUtils.toMslObject(encoder, chunk);
        
        final PayloadChunk moChunk = new PayloadChunk(ctx, mo, cryptoContextB);
        assertEquals(chunk.isEndOfMessage(), moChunk.isEndOfMessage());
        assertArrayEquals(chunk.getData(), moChunk.getData());
        assertEquals(chunk.getMessageId(), moChunk.getMessageId());
        assertEquals(chunk.getSequenceNumber(), moChunk.getSequenceNumber());
        final byte[] moEncode = moChunk.toMslEncoding(encoder, ENCODER_FORMAT);
        assertNotNull(moEncode);
        // The two payload chunk encodings will not be equal because the
        // ciphertext and signature will be generated on-demand.
    }
    
    @Test(expected = MslCryptoException.class)
    public void mismatchedCryptoContextEncryptionKey() throws MslEncodingException, MslCryptoException, MslException, MslEncoderException {
        final byte[] encryptionBytesA = new byte[16];
        final byte[] encryptionBytesB = new byte[16];
        random.nextBytes(encryptionBytesA);
        random.nextBytes(encryptionBytesB);
        final SecretKey encryptionKeyA = new SecretKeySpec(encryptionBytesA, JcaAlgorithm.AES);
        final SecretKey encryptionKeyB = new SecretKeySpec(encryptionBytesB, JcaAlgorithm.AES);
        final ICryptoContext cryptoContextA = new SymmetricCryptoContext(ctx, CRYPTO_CONTEXT_ID, encryptionKeyA, HMAC_KEY, null);
        final ICryptoContext cryptoContextB = new SymmetricCryptoContext(ctx, CRYPTO_CONTEXT_ID, encryptionKeyB, HMAC_KEY, null);
        
        // Mismatched encryption keys will just result in the wrong data.
        final PayloadChunk chunk = new PayloadChunk(ctx, SEQ_NO, MSG_ID, END_OF_MSG, CompressionAlgorithm.GZIP, DATA, cryptoContextA);
        final MslObject mo = MslTestUtils.toMslObject(encoder, chunk);
        // Sometimes decryption will succeed so check for a crypto exception
        // or encoding exception. Both are OK.
        try {
            new PayloadChunk(ctx, mo, cryptoContextB);
        } catch (final MslEncodingException e) {
            throw new MslCryptoException(MslError.DECRYPT_ERROR, e);
        }
    }
    
    @Test
    public void mismatchedCryptoContextSignKey() throws MslEncodingException, MslCryptoException, MslException, MslEncoderException {
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
        
        final PayloadChunk chunk = new PayloadChunk(ctx, SEQ_NO, MSG_ID, END_OF_MSG, CompressionAlgorithm.GZIP, DATA, cryptoContextA);
        final MslObject mo = MslTestUtils.toMslObject(encoder, chunk);
        new PayloadChunk(ctx, mo, cryptoContextB);
    }
    
    @Test
    public void incorrectSignature() throws MslEncodingException, MslCryptoException, MslException, MslEncoderException {
        thrown.expect(MslCryptoException.class);
        thrown.expectMslError(MslError.PAYLOAD_VERIFICATION_FAILED);

        final PayloadChunk chunk = new PayloadChunk(ctx, SEQ_NO, MSG_ID, END_OF_MSG, CompressionAlgorithm.GZIP, DATA, CRYPTO_CONTEXT);
        final MslObject mo = MslTestUtils.toMslObject(encoder, chunk);
        
        final byte[] signature = new byte[32];
        random.nextBytes(signature);
        mo.put(KEY_SIGNATURE, signature);
        
        new PayloadChunk(ctx, mo, CRYPTO_CONTEXT);
    }
    
    @Test
    public void missingPayload() throws MslEncodingException, MslCryptoException, MslException, MslEncoderException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MSL_PARSE_ERROR);

        final PayloadChunk chunk = new PayloadChunk(ctx, SEQ_NO, MSG_ID, END_OF_MSG, CompressionAlgorithm.GZIP, DATA, CRYPTO_CONTEXT);
        final MslObject mo = MslTestUtils.toMslObject(encoder, chunk);
        
        assertNotNull(mo.remove(KEY_PAYLOAD));
        
        new PayloadChunk(ctx, mo, CRYPTO_CONTEXT);
    }
    
    @Test
    public void invalidPayload() throws MslEncodingException, MslCryptoException, MslException, MslEncoderException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MSL_PARSE_ERROR);

        final PayloadChunk chunk = new PayloadChunk(ctx, SEQ_NO, MSG_ID, END_OF_MSG, CompressionAlgorithm.GZIP, DATA, CRYPTO_CONTEXT);
        final MslObject mo = MslTestUtils.toMslObject(encoder, chunk);

        mo.put(KEY_PAYLOAD, "x");

        new PayloadChunk(ctx, mo, CRYPTO_CONTEXT);
    }
    
    @Test(expected = MslCryptoException.class)
    public void corruptPayload() throws MslEncoderException, MslEncodingException, MslCryptoException, MslException {
        final PayloadChunk chunk = new PayloadChunk(ctx, SEQ_NO, MSG_ID, END_OF_MSG, CompressionAlgorithm.GZIP, DATA, CRYPTO_CONTEXT);
        final MslObject mo = MslTestUtils.toMslObject(encoder, chunk);

        final byte[] ciphertext = new byte[32];
        random.nextBytes(ciphertext);
        mo.put(KEY_PAYLOAD, ciphertext);
        final byte[] signature = CRYPTO_CONTEXT.sign(ciphertext, encoder, ENCODER_FORMAT);
        mo.put(KEY_SIGNATURE, signature);

        new PayloadChunk(ctx, mo, CRYPTO_CONTEXT);
    }
    
    @Test
    public void emptyPayloadEndOfMessage() throws MslEncoderException, MslEncodingException, MslCryptoException, MslException {
        final byte[] data = new byte[0];
        final PayloadChunk chunk = new PayloadChunk(ctx, SEQ_NO, MSG_ID, true, CompressionAlgorithm.GZIP, data, CRYPTO_CONTEXT);
        final MslObject mo = MslTestUtils.toMslObject(encoder, chunk);
        
        final PayloadChunk moChunk = new PayloadChunk(ctx, mo, CRYPTO_CONTEXT);
        assertEquals(0, moChunk.getData().length);
    }
    
    @Test
    public void missingSequenceNumber() throws MslEncodingException, MslCryptoException, MslException, MslEncoderException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MSL_PARSE_ERROR);

        final PayloadChunk chunk = new PayloadChunk(ctx, SEQ_NO, MSG_ID, END_OF_MSG, CompressionAlgorithm.GZIP, DATA, CRYPTO_CONTEXT);
        final MslObject mo = MslTestUtils.toMslObject(encoder, chunk);

        final byte[] ciphertext = mo.getBytes(KEY_PAYLOAD);
        final byte[] payload = CRYPTO_CONTEXT.decrypt(ciphertext, encoder);
        final MslObject payloadMo = encoder.parseObject(payload);
        
        assertNotNull(payloadMo.remove(KEY_SEQUENCE_NUMBER));

        final byte[] plaintext = encoder.encodeObject(payloadMo, ENCODER_FORMAT);
        final byte[] newPayload = CRYPTO_CONTEXT.encrypt(plaintext, encoder, ENCODER_FORMAT);
        final byte[] signature = CRYPTO_CONTEXT.sign(newPayload, encoder, ENCODER_FORMAT);
        mo.put(KEY_PAYLOAD, newPayload);
        mo.put(KEY_SIGNATURE, signature);
        
        new PayloadChunk(ctx, mo, CRYPTO_CONTEXT);
    }
    
    @Test
    public void invalidSequenceNumber() throws MslEncodingException, MslCryptoException, MslException, MslEncoderException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MSL_PARSE_ERROR);

        final PayloadChunk chunk = new PayloadChunk(ctx, SEQ_NO, MSG_ID, true, CompressionAlgorithm.GZIP, DATA, CRYPTO_CONTEXT);
        final MslObject mo = MslTestUtils.toMslObject(encoder, chunk);

        final byte[] ciphertext = mo.getBytes(KEY_PAYLOAD);
        final byte[] payload = CRYPTO_CONTEXT.decrypt(ciphertext, encoder);
        final MslObject payloadMo = encoder.parseObject(payload);
        
        payloadMo.put(KEY_SEQUENCE_NUMBER, "x");
        
        final byte[] plaintext = encoder.encodeObject(payloadMo, ENCODER_FORMAT);
        final byte[] newPayload = CRYPTO_CONTEXT.encrypt(plaintext, encoder, ENCODER_FORMAT);
        final byte[] signature = CRYPTO_CONTEXT.sign(newPayload, encoder, ENCODER_FORMAT);
        mo.put(KEY_PAYLOAD, newPayload);
        mo.put(KEY_SIGNATURE, signature);
        
        new PayloadChunk(ctx, mo, CRYPTO_CONTEXT);
    }
    
    @Test
    public void negativeSequenceNumber() throws MslEncodingException, MslCryptoException, MslException, MslEncoderException {
        thrown.expect(MslException.class);
        thrown.expectMslError(MslError.PAYLOAD_SEQUENCE_NUMBER_OUT_OF_RANGE);

        final PayloadChunk chunk = new PayloadChunk(ctx, SEQ_NO, MSG_ID, true, CompressionAlgorithm.GZIP, DATA, CRYPTO_CONTEXT);
        final MslObject mo = MslTestUtils.toMslObject(encoder, chunk);

        final byte[] ciphertext = mo.getBytes(KEY_PAYLOAD);
        final byte[] payload = CRYPTO_CONTEXT.decrypt(ciphertext, encoder);
        final MslObject payloadMo = encoder.parseObject(payload);
        
        payloadMo.put(KEY_SEQUENCE_NUMBER, -1);
        
        final byte[] plaintext = encoder.encodeObject(payloadMo, ENCODER_FORMAT);
        final byte[] newPayload = CRYPTO_CONTEXT.encrypt(plaintext, encoder, ENCODER_FORMAT);
        final byte[] signature = CRYPTO_CONTEXT.sign(newPayload, encoder, ENCODER_FORMAT);
        mo.put(KEY_PAYLOAD, newPayload);
        mo.put(KEY_SIGNATURE, signature);
        
        new PayloadChunk(ctx, mo, CRYPTO_CONTEXT);
    }
    
    @Test
    public void tooLargeSequenceNumber() throws MslEncodingException, MslCryptoException, MslException, MslEncoderException {
        thrown.expect(MslException.class);
        thrown.expectMslError(MslError.PAYLOAD_SEQUENCE_NUMBER_OUT_OF_RANGE);

        final PayloadChunk chunk = new PayloadChunk(ctx, SEQ_NO, MSG_ID, true, CompressionAlgorithm.GZIP, DATA, CRYPTO_CONTEXT);
        final MslObject mo = MslTestUtils.toMslObject(encoder, chunk);

        final byte[] ciphertext = mo.getBytes(KEY_PAYLOAD);
        final byte[] payload = CRYPTO_CONTEXT.decrypt(ciphertext, encoder);
        final MslObject payloadMo = encoder.parseObject(payload);
        
        payloadMo.put(KEY_SEQUENCE_NUMBER, MslConstants.MAX_LONG_VALUE + 1);
        
        final byte[] plaintext = encoder.encodeObject(payloadMo, ENCODER_FORMAT);
        final byte[] newPayload = CRYPTO_CONTEXT.encrypt(plaintext, encoder, ENCODER_FORMAT);
        final byte[] signature = CRYPTO_CONTEXT.sign(newPayload, encoder, ENCODER_FORMAT);
        mo.put(KEY_PAYLOAD, newPayload);
        mo.put(KEY_SIGNATURE, signature);
        
        new PayloadChunk(ctx, mo, CRYPTO_CONTEXT);
    }
    
    @Test
    public void missingMessageId() throws MslEncodingException, MslCryptoException, MslException, MslEncoderException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MSL_PARSE_ERROR);

        final PayloadChunk chunk = new PayloadChunk(ctx, SEQ_NO, MSG_ID, END_OF_MSG, CompressionAlgorithm.GZIP, DATA, CRYPTO_CONTEXT);
        final MslObject mo = MslTestUtils.toMslObject(encoder, chunk);

        final byte[] ciphertext = mo.getBytes(KEY_PAYLOAD);
        final byte[] payload = CRYPTO_CONTEXT.decrypt(ciphertext, encoder);
        final MslObject payloadMo = encoder.parseObject(payload);
        
        assertNotNull(payloadMo.remove(KEY_MESSAGE_ID));

        final byte[] plaintext = encoder.encodeObject(payloadMo, ENCODER_FORMAT);
        final byte[] newPayload = CRYPTO_CONTEXT.encrypt(plaintext, encoder, ENCODER_FORMAT);
        final byte[] signature = CRYPTO_CONTEXT.sign(newPayload, encoder, ENCODER_FORMAT);
        mo.put(KEY_PAYLOAD, newPayload);
        mo.put(KEY_SIGNATURE, signature);
        
        new PayloadChunk(ctx, mo, CRYPTO_CONTEXT);
    }
    
    @Test
    public void invalidMessageId() throws MslEncoderException, MslEncodingException, MslCryptoException, MslException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MSL_PARSE_ERROR);

        final PayloadChunk chunk = new PayloadChunk(ctx, SEQ_NO, MSG_ID, true, CompressionAlgorithm.GZIP, DATA, CRYPTO_CONTEXT);
        final MslObject mo = MslTestUtils.toMslObject(encoder, chunk);

        final byte[] ciphertext = mo.getBytes(KEY_PAYLOAD);
        final byte[] payload = CRYPTO_CONTEXT.decrypt(ciphertext, encoder);
        final MslObject payloadMo = encoder.parseObject(payload);
        
        payloadMo.put(KEY_MESSAGE_ID, "x");

        final byte[] plaintext = encoder.encodeObject(payloadMo, ENCODER_FORMAT);
        final byte[] newPayload = CRYPTO_CONTEXT.encrypt(plaintext, encoder, ENCODER_FORMAT);
        final byte[] signature = CRYPTO_CONTEXT.sign(newPayload, encoder, ENCODER_FORMAT);
        mo.put(KEY_PAYLOAD, newPayload);
        mo.put(KEY_SIGNATURE, signature);
        
        new PayloadChunk(ctx, mo, CRYPTO_CONTEXT);
    }
    
    @Test
    public void invalidEndOfMessage() throws MslEncoderException, MslEncodingException, MslCryptoException, MslException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MSL_PARSE_ERROR);

        final PayloadChunk chunk = new PayloadChunk(ctx, SEQ_NO, MSG_ID, true, CompressionAlgorithm.GZIP, DATA, CRYPTO_CONTEXT);
        final MslObject mo = MslTestUtils.toMslObject(encoder, chunk);

        final byte[] ciphertext = mo.getBytes(KEY_PAYLOAD);
        final byte[] payload = CRYPTO_CONTEXT.decrypt(ciphertext, encoder);
        final MslObject payloadMo = encoder.parseObject(payload);
        
        payloadMo.put(KEY_END_OF_MESSAGE, "x");

        final byte[] plaintext = encoder.encodeObject(payloadMo, ENCODER_FORMAT);
        final byte[] newPayload = CRYPTO_CONTEXT.encrypt(plaintext, encoder, ENCODER_FORMAT);
        final byte[] signature = CRYPTO_CONTEXT.sign(newPayload, encoder, ENCODER_FORMAT);
        mo.put(KEY_PAYLOAD, newPayload);
        mo.put(KEY_SIGNATURE, signature);
        
        new PayloadChunk(ctx, mo, CRYPTO_CONTEXT);
    }
    
    @Test
    public void invalidCompressionAlgorithm() throws MslEncodingException, MslCryptoException, MslException, MslEncoderException {
        thrown.expect(MslMessageException.class);
        thrown.expectMslError(MslError.UNIDENTIFIED_COMPRESSION);

        final PayloadChunk chunk = new PayloadChunk(ctx, SEQ_NO, MSG_ID, true, CompressionAlgorithm.GZIP, DATA, CRYPTO_CONTEXT);
        final MslObject mo = MslTestUtils.toMslObject(encoder, chunk);

        final byte[] ciphertext = mo.getBytes(KEY_PAYLOAD);
        final byte[] payload = CRYPTO_CONTEXT.decrypt(ciphertext, encoder);
        final MslObject payloadMo = encoder.parseObject(payload);

        payloadMo.put(KEY_COMPRESSION_ALGORITHM, "x");

        final byte[] plaintext = encoder.encodeObject(payloadMo, ENCODER_FORMAT);
        final byte[] newPayload = CRYPTO_CONTEXT.encrypt(plaintext, encoder, ENCODER_FORMAT);
        final byte[] signature = CRYPTO_CONTEXT.sign(newPayload, encoder, ENCODER_FORMAT);
        mo.put(KEY_PAYLOAD, newPayload);
        mo.put(KEY_SIGNATURE, signature);
        
        new PayloadChunk(ctx, mo, CRYPTO_CONTEXT);
    }
    
    @Test
    public void missingData() throws MslEncoderException, MslEncodingException, MslCryptoException, MslException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MSL_PARSE_ERROR);

        final PayloadChunk chunk = new PayloadChunk(ctx, SEQ_NO, MSG_ID, END_OF_MSG, CompressionAlgorithm.GZIP, DATA, CRYPTO_CONTEXT);
        final MslObject mo = MslTestUtils.toMslObject(encoder, chunk);

        final byte[] ciphertext = mo.getBytes(KEY_PAYLOAD);
        final byte[] payload = CRYPTO_CONTEXT.decrypt(ciphertext, encoder);
        final MslObject payloadMo = encoder.parseObject(payload);
        
        assertNotNull(payloadMo.remove(KEY_DATA));

        final byte[] plaintext = encoder.encodeObject(payloadMo, ENCODER_FORMAT);
        final byte[] newPayload = CRYPTO_CONTEXT.encrypt(plaintext, encoder, ENCODER_FORMAT);
        final byte[] signature = CRYPTO_CONTEXT.sign(newPayload, encoder, ENCODER_FORMAT);
        mo.put(KEY_PAYLOAD, newPayload);
        mo.put(KEY_SIGNATURE, signature);
        
        new PayloadChunk(ctx, mo, CRYPTO_CONTEXT);
    }
    
    @Test
    public void emptyData() throws MslEncodingException, MslCryptoException, MslException, MslEncoderException {
        thrown.expect(MslMessageException.class);
        thrown.expectMslError(MslError.PAYLOAD_DATA_MISSING);

        final PayloadChunk chunk = new PayloadChunk(ctx, SEQ_NO, MSG_ID, END_OF_MSG, CompressionAlgorithm.GZIP, DATA, CRYPTO_CONTEXT);
        final MslObject mo = MslTestUtils.toMslObject(encoder, chunk);

        final byte[] ciphertext = mo.getBytes(KEY_PAYLOAD);
        final byte[] payload = CRYPTO_CONTEXT.decrypt(ciphertext, encoder);
        final MslObject payloadMo = encoder.parseObject(payload);
        
        payloadMo.put(KEY_DATA, "");

        final byte[] plaintext = encoder.encodeObject(payloadMo, ENCODER_FORMAT);
        final byte[] newPayload = CRYPTO_CONTEXT.encrypt(plaintext, encoder, ENCODER_FORMAT);
        final byte[] signature = CRYPTO_CONTEXT.sign(newPayload, encoder, ENCODER_FORMAT);
        mo.put(KEY_PAYLOAD, newPayload);
        mo.put(KEY_SIGNATURE, signature);
        
        new PayloadChunk(ctx, mo, CRYPTO_CONTEXT);
    }

    @Test
    public void invalidDataEndOfMessage() throws MslEncodingException, MslCryptoException, MslException, MslEncoderException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MSL_PARSE_ERROR);

        final PayloadChunk chunk = new PayloadChunk(ctx, SEQ_NO, MSG_ID, true, CompressionAlgorithm.GZIP, DATA, CRYPTO_CONTEXT);
        final MslObject mo = MslTestUtils.toMslObject(encoder, chunk);

        final byte[] ciphertext = mo.getBytes(KEY_PAYLOAD);
        final byte[] payload = CRYPTO_CONTEXT.decrypt(ciphertext, encoder);
        final MslObject payloadMo = encoder.parseObject(payload);
        
        payloadMo.put(KEY_DATA, false);

        final byte[] plaintext = encoder.encodeObject(payloadMo, ENCODER_FORMAT);
        final byte[] newPayload = CRYPTO_CONTEXT.encrypt(plaintext, encoder, ENCODER_FORMAT);
        final byte[] signature = CRYPTO_CONTEXT.sign(newPayload, encoder, ENCODER_FORMAT);
        mo.put(KEY_PAYLOAD, newPayload);
        mo.put(KEY_SIGNATURE, signature);
        
        new PayloadChunk(ctx, mo, CRYPTO_CONTEXT);
    }
    
    @Test
    public void largeData() throws MslEncodingException, MslCryptoException, MslException, MslEncoderException {
        final byte[] data = new byte[10 * 1024 * 1024];
        random.nextBytes(data);
        final PayloadChunk chunk = new PayloadChunk(ctx, SEQ_NO, MSG_ID, true, null, data, CRYPTO_CONTEXT);
        assertArrayEquals(data, chunk.getData());
        
        final MslObject mo = MslTestUtils.toMslObject(encoder, chunk);
        final PayloadChunk moChunk = new PayloadChunk(ctx, mo, CRYPTO_CONTEXT);
        assertArrayEquals(chunk.getData(), moChunk.getData());
    }
    
    @Test
    public void gzipLargeData() throws MslEncodingException, MslCryptoException, MslException, MslEncoderException {
        final byte[] data = new byte[10 * 1024 * 1024];
        random.nextBytes(data);
        final PayloadChunk chunk = new PayloadChunk(ctx, SEQ_NO, MSG_ID, true, CompressionAlgorithm.GZIP, data, CRYPTO_CONTEXT);
        assertArrayEquals(data, chunk.getData());
        
        // Random data will not compress.
        assertNull(chunk.getCompressionAlgo());
        
        final MslObject mo = MslTestUtils.toMslObject(encoder, chunk);
        final PayloadChunk moChunk = new PayloadChunk(ctx, mo, CRYPTO_CONTEXT);
        assertArrayEquals(chunk.getData(), moChunk.getData());
        assertEquals(chunk.getCompressionAlgo(), moChunk.getCompressionAlgo());
    }
    
    @Test
    public void gzipVerona() throws MslEncodingException, MslCryptoException, MslMessageException, MslException, MslEncoderException {
        final PayloadChunk chunk = new PayloadChunk(ctx, SEQ_NO, MSG_ID, true, CompressionAlgorithm.GZIP, rawdata, CRYPTO_CONTEXT);
        assertArrayEquals(rawdata, chunk.getData());
        
        // Romeo and Juliet will compress.
        assertEquals(CompressionAlgorithm.GZIP, chunk.getCompressionAlgo());
        
        final MslObject mo = MslTestUtils.toMslObject(encoder, chunk);
        final PayloadChunk moChunk = new PayloadChunk(ctx, mo, CRYPTO_CONTEXT);
        assertArrayEquals(chunk.getData(), moChunk.getData());
        assertEquals(chunk.getCompressionAlgo(), moChunk.getCompressionAlgo());
    }
    
    @Test
    public void lzwRandomData() throws MslEncodingException, MslCryptoException, MslException, MslEncoderException {
        final byte[] data = new byte[10 * 1024 * 1024];
        random.nextBytes(data);
        final PayloadChunk chunk = new PayloadChunk(ctx, SEQ_NO, MSG_ID, true, CompressionAlgorithm.LZW, data, CRYPTO_CONTEXT);
        assertArrayEquals(data, chunk.getData());
        
        // Random data will not compress.
        assertNull(chunk.getCompressionAlgo());
        
        final MslObject mo = MslTestUtils.toMslObject(encoder, chunk);
        final PayloadChunk moChunk = new PayloadChunk(ctx, mo, CRYPTO_CONTEXT);
        assertArrayEquals(chunk.getData(), moChunk.getData());
        assertEquals(chunk.getCompressionAlgo(), moChunk.getCompressionAlgo());
    }
    
    @Test
    public void lzwVerona() throws MslEncodingException, MslCryptoException, MslMessageException, MslException, MslEncoderException {
        final PayloadChunk chunk = new PayloadChunk(ctx, SEQ_NO, MSG_ID, true, CompressionAlgorithm.LZW, rawdata, CRYPTO_CONTEXT);
        assertArrayEquals(rawdata, chunk.getData());
        
        // Romeo and Juliet will compress.
        assertEquals(CompressionAlgorithm.LZW, chunk.getCompressionAlgo());
        
        final MslObject mo = MslTestUtils.toMslObject(encoder, chunk);
        final PayloadChunk moChunk = new PayloadChunk(ctx, mo, CRYPTO_CONTEXT);
        assertArrayEquals(chunk.getData(), moChunk.getData());
        assertEquals(chunk.getCompressionAlgo(), moChunk.getCompressionAlgo());
    }
    
    @Test
    public void equalsSequenceNumber() throws MslEncodingException, MslCryptoException, MslException, MslEncoderException {
        final long seqNoA = 1;
        final long seqNoB = 2;
        final PayloadChunk chunkA = new PayloadChunk(ctx, seqNoA, MSG_ID, false, null, DATA, CRYPTO_CONTEXT);
        final PayloadChunk chunkB = new PayloadChunk(ctx, seqNoB, MSG_ID, false, null, DATA, CRYPTO_CONTEXT);
        final PayloadChunk chunkA2 = new PayloadChunk(ctx, MslTestUtils.toMslObject(encoder, chunkA), CRYPTO_CONTEXT);
        
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
    public void equalsMessageId() throws MslEncodingException, MslCryptoException, MslException, MslEncoderException {
        final long msgIdA = 1;
        final long msgIdB = 2;
        final PayloadChunk chunkA = new PayloadChunk(ctx, SEQ_NO, msgIdA, false, null, DATA, CRYPTO_CONTEXT);
        final PayloadChunk chunkB = new PayloadChunk(ctx, SEQ_NO, msgIdB, false, null, DATA, CRYPTO_CONTEXT);
        final PayloadChunk chunkA2 = new PayloadChunk(ctx, MslTestUtils.toMslObject(encoder, chunkA), CRYPTO_CONTEXT);
        
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
    public void equalsEndOfMessage() throws MslEncodingException, MslCryptoException, MslException, MslEncoderException {
        final PayloadChunk chunkA = new PayloadChunk(ctx, SEQ_NO, MSG_ID, true, null, DATA, CRYPTO_CONTEXT);
        final PayloadChunk chunkB = new PayloadChunk(ctx, SEQ_NO, MSG_ID, false, null, DATA, CRYPTO_CONTEXT);
        final PayloadChunk chunkA2 = new PayloadChunk(ctx, MslTestUtils.toMslObject(encoder, chunkA), CRYPTO_CONTEXT);
        
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
    public void equalsCompressionAlgorithm() throws MslEncodingException, MslCryptoException, MslException, MslEncoderException {
        final PayloadChunk chunkA = new PayloadChunk(ctx, SEQ_NO, MSG_ID, true, CompressionAlgorithm.GZIP, DATA, CRYPTO_CONTEXT);
        final PayloadChunk chunkB = new PayloadChunk(ctx, SEQ_NO, MSG_ID, true, null, DATA, CRYPTO_CONTEXT);
        final PayloadChunk chunkA2 = new PayloadChunk(ctx, MslTestUtils.toMslObject(encoder, chunkA), CRYPTO_CONTEXT);
        
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
    public void equalsData() throws MslEncodingException, MslCryptoException, MslException, MslEncoderException {
        final byte[] dataA = new byte[32];
        random.nextBytes(dataA);
        final byte[] dataB = new byte[32];
        random.nextBytes(dataB);
        final byte[] dataC = new byte[0];
        final PayloadChunk chunkA = new PayloadChunk(ctx, SEQ_NO, MSG_ID, true, CompressionAlgorithm.GZIP, dataA, CRYPTO_CONTEXT);
        final PayloadChunk chunkB = new PayloadChunk(ctx, SEQ_NO, MSG_ID, true, CompressionAlgorithm.GZIP, dataB, CRYPTO_CONTEXT);
        final PayloadChunk chunkC = new PayloadChunk(ctx, SEQ_NO, MSG_ID, true, CompressionAlgorithm.GZIP, dataC, CRYPTO_CONTEXT);
        final PayloadChunk chunkA2 = new PayloadChunk(ctx, MslTestUtils.toMslObject(encoder, chunkA), CRYPTO_CONTEXT);
        
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
        final PayloadChunk chunk = new PayloadChunk(ctx, SEQ_NO, MSG_ID, true, CompressionAlgorithm.GZIP, DATA, CRYPTO_CONTEXT);
        
        assertFalse(chunk.equals(null));
        assertFalse(chunk.equals(CRYPTO_CONTEXT_ID));
        assertTrue(chunk.hashCode() != CRYPTO_CONTEXT_ID.hashCode());
    }
}
