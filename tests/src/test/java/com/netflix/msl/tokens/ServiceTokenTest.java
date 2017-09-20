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
package com.netflix.msl.tokens;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.CryptoException;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import com.netflix.msl.MslConstants;
import com.netflix.msl.MslConstants.CompressionAlgorithm;
import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslException;
import com.netflix.msl.MslInternalException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.crypto.JcaAlgorithm;
import com.netflix.msl.crypto.SymmetricCryptoContext;
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.io.MslEncoderException;
import com.netflix.msl.io.MslEncoderFactory;
import com.netflix.msl.io.MslEncoderFormat;
import com.netflix.msl.io.MslObject;
import com.netflix.msl.test.ExpectedMslException;
import com.netflix.msl.userauth.MockEmailPasswordAuthenticationFactory;
import com.netflix.msl.util.MockMslContext;
import com.netflix.msl.util.MslContext;
import com.netflix.msl.util.MslTestUtils;

/**
 * Service token unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
@RunWith(Parameterized.class)
public class ServiceTokenTest {
	/** MSL encoder format. */
	private static final MslEncoderFormat ENCODER_FORMAT = MslEncoderFormat.JSON;

    /** Key token data. */
    private static final String KEY_TOKENDATA = "tokendata";
    /** Key signature. */
    private static final String KEY_SIGNATURE = "signature";
    
    // tokendata
    /** Key token name. */
    private static final String KEY_NAME = "name";
    /** Key master token serial number. */
    private static final String KEY_MASTER_TOKEN_SERIAL_NUMBER = "mtserialnumber";
    /** Key user ID token serial number. */
    private static final String KEY_USER_ID_TOKEN_SERIAL_NUMBER = "uitserialnumber";
    /** Key encrypted. */
    private static final String KEY_ENCRYPTED = "encrypted";
    /** Key compression algorithm. */
    private static final String KEY_COMPRESSION_ALGORITHM = "compressionalgo";
    /** Key service data. */
    private static final String KEY_SERVICEDATA = "servicedata";
    
    private static final String NAME = "tokenName";
    private static final byte[] DATA = "We have to use some data that is compressible, otherwise service tokens will not always use the compression we request.".getBytes();
    private static MasterToken MASTER_TOKEN;
    private static UserIdToken USER_ID_TOKEN;
    private static final boolean ENCRYPTED = true;
    private static ICryptoContext CRYPTO_CONTEXT;
    
    /**
     * @param ctx MSL context.
     * @return a new crypto context.
     * @throws CryptoException if there is an error creating the crypto
     *         context.
     */
    private static ICryptoContext getCryptoContext(final MslContext ctx) {
        final String keysetId = "keysetId";
        final byte[] encryptionBytes = new byte[16];
        random.nextBytes(encryptionBytes);
        final SecretKey encryptionKey = new SecretKeySpec(encryptionBytes, JcaAlgorithm.AES);
        final byte[] hmacBytes = new byte[32];
        random.nextBytes(hmacBytes);
        final SecretKey hmacKey = new SecretKeySpec(hmacBytes, JcaAlgorithm.HMAC_SHA256);
        final ICryptoContext cryptoContext = new SymmetricCryptoContext(ctx, keysetId, encryptionKey, hmacKey, null);
        return cryptoContext;
    }

    @Rule
    public ExpectedMslException thrown = ExpectedMslException.none();
    
    @BeforeClass
    public static void setup() throws MslEncodingException, MslCryptoException {
        random = new Random();
        ctx = new MockMslContext(EntityAuthenticationScheme.PSK, false);
        encoder = ctx.getMslEncoderFactory();
        MASTER_TOKEN = MslTestUtils.getMasterToken(ctx, 1, 1);
        USER_ID_TOKEN = MslTestUtils.getUserIdToken(ctx, MASTER_TOKEN, 1, MockEmailPasswordAuthenticationFactory.USER);
        CRYPTO_CONTEXT = getCryptoContext(ctx);
    }
    
    @AfterClass
    public static void teardown() {
        CRYPTO_CONTEXT = null;
        USER_ID_TOKEN = null;
        MASTER_TOKEN = null;
        encoder = null;
        ctx = null;
        random = null;
    }
    
    @Parameters
    public static List<Object[]> data() {
        return Arrays.asList(new Object[][] {
            { null },
            { CompressionAlgorithm.LZW },
            { CompressionAlgorithm.GZIP },
        });
    }
    
    /** Compression algorithm. */
    private final CompressionAlgorithm compressionAlgo;
    
    /**
     * Create a new master token test instance.
     * 
     * @param compressionAlgo compression algorithm.
     */
    public ServiceTokenTest(final CompressionAlgorithm compressionAlgo) {
        this.compressionAlgo = compressionAlgo;
    }
    
    @Test
    public void ctors() throws MslEncoderException, MslException {
        final ServiceToken serviceToken = new ServiceToken(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        assertTrue(serviceToken.isDecrypted());
        assertFalse(serviceToken.isDeleted());
        assertTrue(serviceToken.isVerified());
        assertTrue(serviceToken.isBoundTo(MASTER_TOKEN));
        assertTrue(serviceToken.isBoundTo(USER_ID_TOKEN));
        assertTrue(serviceToken.isMasterTokenBound());
        assertTrue(serviceToken.isUserIdTokenBound());
        assertFalse(serviceToken.isUnbound());
        assertEquals(MASTER_TOKEN.getSerialNumber(), serviceToken.getMasterTokenSerialNumber());
        assertEquals(USER_ID_TOKEN.getSerialNumber(), serviceToken.getUserIdTokenSerialNumber());
        assertEquals(NAME, serviceToken.getName());
        assertEquals(compressionAlgo, serviceToken.getCompressionAlgo());
        assertArrayEquals(DATA, serviceToken.getData());
        final byte[] encode = serviceToken.toMslEncoding(encoder, ENCODER_FORMAT);
        assertNotNull(encode);
        final MslObject mo = encoder.parseObject(encode);

        final ServiceToken moServiceToken = new ServiceToken(ctx, mo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT);
        assertEquals(serviceToken.isDecrypted(), moServiceToken.isDecrypted());
        assertEquals(serviceToken.isDeleted(), moServiceToken.isDeleted());
        assertEquals(serviceToken.isVerified(), moServiceToken.isVerified());
        assertEquals(serviceToken.isBoundTo(MASTER_TOKEN), moServiceToken.isBoundTo(MASTER_TOKEN));
        assertEquals(serviceToken.isBoundTo(USER_ID_TOKEN), moServiceToken.isBoundTo(USER_ID_TOKEN));
        assertEquals(serviceToken.isMasterTokenBound(), moServiceToken.isMasterTokenBound());
        assertEquals(serviceToken.isUserIdTokenBound(), moServiceToken.isUserIdTokenBound());
        assertEquals(serviceToken.isUnbound(), moServiceToken.isUnbound());
        assertEquals(serviceToken.getMasterTokenSerialNumber(), moServiceToken.getMasterTokenSerialNumber());
        assertEquals(serviceToken.getUserIdTokenSerialNumber(), moServiceToken.getUserIdTokenSerialNumber());
        assertEquals(serviceToken.getName(), moServiceToken.getName());
        assertEquals(serviceToken.getCompressionAlgo(), moServiceToken.getCompressionAlgo());
        assertArrayEquals(serviceToken.getData(), moServiceToken.getData());
        final byte[] moEncode = moServiceToken.toMslEncoding(encoder, ENCODER_FORMAT);
        assertNotNull(moEncode);
        assertArrayEquals(encode, moEncode);
    }
    
    @Test
    public void cryptoContextMismatch() throws MslEncoderException, MslException {
        final ServiceToken serviceToken = new ServiceToken(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        final byte[] encode = serviceToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);
        
        final ICryptoContext moCryptoContext = getCryptoContext(ctx);
        final ServiceToken moServiceToken = new ServiceToken(ctx, mo, MASTER_TOKEN, USER_ID_TOKEN, moCryptoContext);
        assertFalse(moServiceToken.isDecrypted());
        assertFalse(serviceToken.isDeleted());
        assertFalse(moServiceToken.isVerified());
        assertNull(moServiceToken.getData());
        assertEquals(serviceToken.isBoundTo(MASTER_TOKEN), moServiceToken.isBoundTo(MASTER_TOKEN));
        assertEquals(serviceToken.isBoundTo(USER_ID_TOKEN), moServiceToken.isBoundTo(USER_ID_TOKEN));
        assertEquals(serviceToken.isMasterTokenBound(), moServiceToken.isMasterTokenBound());
        assertEquals(serviceToken.isUserIdTokenBound(), moServiceToken.isUserIdTokenBound());
        assertEquals(serviceToken.isUnbound(), moServiceToken.isUnbound());
        assertEquals(serviceToken.getMasterTokenSerialNumber(), moServiceToken.getMasterTokenSerialNumber());
        assertEquals(serviceToken.getUserIdTokenSerialNumber(), moServiceToken.getUserIdTokenSerialNumber());
        assertEquals(serviceToken.getName(), moServiceToken.getName());
        assertEquals(serviceToken.getCompressionAlgo(), moServiceToken.getCompressionAlgo());
        final byte[] moEncode = moServiceToken.toMslEncoding(encoder, ENCODER_FORMAT);
        assertNotNull(moEncode);
        assertArrayEquals(encode, moEncode);
    }
    
    @Test
    public void mappedCryptoContext() throws MslEncoderException, MslException {
        final ServiceToken serviceToken = new ServiceToken(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        final byte[] encode = serviceToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);
        
        final Map<String,ICryptoContext> cryptoContexts = new HashMap<String,ICryptoContext>();
        cryptoContexts.put(NAME, CRYPTO_CONTEXT);
        cryptoContexts.put(NAME + "1", getCryptoContext(ctx));
        cryptoContexts.put(NAME + "2", getCryptoContext(ctx));
        
        final ServiceToken moServiceToken = new ServiceToken(ctx, mo, MASTER_TOKEN, USER_ID_TOKEN, cryptoContexts);
        assertEquals(serviceToken.isDecrypted(), moServiceToken.isDecrypted());
        assertEquals(serviceToken.isDeleted(), moServiceToken.isDeleted());
        assertEquals(serviceToken.isVerified(), moServiceToken.isVerified());
        assertEquals(serviceToken.isBoundTo(MASTER_TOKEN), moServiceToken.isBoundTo(MASTER_TOKEN));
        assertEquals(serviceToken.isBoundTo(USER_ID_TOKEN), moServiceToken.isBoundTo(USER_ID_TOKEN));
        assertEquals(serviceToken.isMasterTokenBound(), moServiceToken.isMasterTokenBound());
        assertEquals(serviceToken.isUserIdTokenBound(), moServiceToken.isUserIdTokenBound());
        assertEquals(serviceToken.isUnbound(), moServiceToken.isUnbound());
        assertEquals(serviceToken.getMasterTokenSerialNumber(), moServiceToken.getMasterTokenSerialNumber());
        assertEquals(serviceToken.getUserIdTokenSerialNumber(), moServiceToken.getUserIdTokenSerialNumber());
        assertEquals(serviceToken.getName(), moServiceToken.getName());
        assertEquals(serviceToken.getCompressionAlgo(), moServiceToken.getCompressionAlgo());
        assertArrayEquals(serviceToken.getData(), moServiceToken.getData());
        final byte[] moEncode = moServiceToken.toMslEncoding(encoder, ENCODER_FORMAT);
        assertNotNull(moEncode);
        assertArrayEquals(encode, moEncode);
    }
    
    @Test
    public void unmappedCryptoContext() throws MslEncoderException, MslException {
        final ServiceToken serviceToken = new ServiceToken(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        final byte[] encode = serviceToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);
        
        final Map<String,ICryptoContext> cryptoContexts = new HashMap<String,ICryptoContext>();
        cryptoContexts.put(NAME + "0", CRYPTO_CONTEXT);
        cryptoContexts.put(NAME + "1", getCryptoContext(ctx));
        cryptoContexts.put(NAME + "2", getCryptoContext(ctx));
        
        final ServiceToken moServiceToken = new ServiceToken(ctx, mo, MASTER_TOKEN, USER_ID_TOKEN, cryptoContexts);
        assertFalse(moServiceToken.isDecrypted());
        assertFalse(moServiceToken.isDeleted());
        assertFalse(moServiceToken.isVerified());
        assertNull(moServiceToken.getData());
        assertEquals(serviceToken.isBoundTo(MASTER_TOKEN), moServiceToken.isBoundTo(MASTER_TOKEN));
        assertEquals(serviceToken.isBoundTo(USER_ID_TOKEN), moServiceToken.isBoundTo(USER_ID_TOKEN));
        assertEquals(serviceToken.isMasterTokenBound(), moServiceToken.isMasterTokenBound());
        assertEquals(serviceToken.isUserIdTokenBound(), moServiceToken.isUserIdTokenBound());
        assertEquals(serviceToken.isUnbound(), moServiceToken.isUnbound());
        assertEquals(serviceToken.getMasterTokenSerialNumber(), moServiceToken.getMasterTokenSerialNumber());
        assertEquals(serviceToken.getUserIdTokenSerialNumber(), moServiceToken.getUserIdTokenSerialNumber());
        assertEquals(serviceToken.getName(), moServiceToken.getName());
        assertEquals(serviceToken.getCompressionAlgo(), moServiceToken.getCompressionAlgo());
        final byte[] moEncode = moServiceToken.toMslEncoding(encoder, ENCODER_FORMAT);
        assertNotNull(moEncode);
        assertArrayEquals(encode, moEncode);
    }
    
    @Test
    public void masterTokenMismatch() throws MslException, MslEncoderException {
        thrown.expect(MslException.class);
        thrown.expectMslError(MslError.SERVICETOKEN_MASTERTOKEN_MISMATCH);

        final MasterToken masterToken = MslTestUtils.getMasterToken(ctx, 1, 1);
        final ServiceToken serviceToken = new ServiceToken(ctx, NAME, DATA, masterToken, null, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        final byte[] encode = serviceToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);
        
        final MasterToken moMasterToken = MslTestUtils.getMasterToken(ctx, 1, 2);
        new ServiceToken(ctx, mo, moMasterToken, null, CRYPTO_CONTEXT);
    }
    
    @Test
    public void masterTokenMissing() throws MslEncoderException, MslException {
        thrown.expect(MslException.class);
        thrown.expectMslError(MslError.SERVICETOKEN_MASTERTOKEN_MISMATCH);

        final ServiceToken serviceToken = new ServiceToken(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        final byte[] encode = serviceToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);
        
        new ServiceToken(ctx, mo, null, USER_ID_TOKEN, CRYPTO_CONTEXT);
    }
    
    @Test
    public void userIdTokenMismatch() throws MslException, MslEncoderException {
        thrown.expect(MslException.class);
        thrown.expectMslError(MslError.SERVICETOKEN_USERIDTOKEN_MISMATCH);

        final UserIdToken userIdToken = MslTestUtils.getUserIdToken(ctx, MASTER_TOKEN, 1, MockEmailPasswordAuthenticationFactory.USER);
        final ServiceToken serviceToken = new ServiceToken(ctx, NAME, DATA, MASTER_TOKEN, userIdToken, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        final byte[] encode = serviceToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);
        
        final UserIdToken moUserIdToken = MslTestUtils.getUserIdToken(ctx, MASTER_TOKEN, 2, MockEmailPasswordAuthenticationFactory.USER);
        new ServiceToken(ctx, mo, MASTER_TOKEN, moUserIdToken, CRYPTO_CONTEXT);
    }
    
    @Test
    public void userIdTokenMissing() throws MslCryptoException, MslEncodingException, MslException, MslEncoderException {
        thrown.expect(MslException.class);
        thrown.expectMslError(MslError.SERVICETOKEN_USERIDTOKEN_MISMATCH);

        final ServiceToken serviceToken = new ServiceToken(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        final byte[] encode = serviceToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);
        
        new ServiceToken(ctx, mo, MASTER_TOKEN, null, CRYPTO_CONTEXT);
    }
    
    @Test(expected = MslInternalException.class)
    public void tokenMismatch() throws MslInternalException, MslException {
        final MasterToken masterTokenA = MslTestUtils.getMasterToken(ctx, 1, 1);
        final MasterToken masterTokenB = MslTestUtils.getMasterToken(ctx, 1, 2);
        final UserIdToken userIdToken = MslTestUtils.getUserIdToken(ctx, masterTokenB, 1, MockEmailPasswordAuthenticationFactory.USER);
        new ServiceToken(ctx, NAME, DATA, masterTokenA, userIdToken, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
    }
    
    @Test
    public void missingTokendata() throws MslEncoderException, MslException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MSL_PARSE_ERROR);

        final ServiceToken serviceToken = new ServiceToken(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        final byte[] encode = serviceToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);
        
        assertNotNull(mo.remove(KEY_TOKENDATA));
        
        new ServiceToken(ctx, mo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT);
    }
    
    @Test
    public void invalidTokendata() throws MslException, MslEncoderException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MSL_PARSE_ERROR);

        final ServiceToken serviceToken = new ServiceToken(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        final byte[] encode = serviceToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);

        final byte[] tokendata = mo.getBytes(KEY_TOKENDATA);
        ++tokendata[0];
        mo.put(KEY_TOKENDATA, tokendata);
        
        new ServiceToken(ctx, mo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT);
    }
    
    @Test
    public void missingSignature() throws MslEncoderException, MslCryptoException, MslEncodingException, MslException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MSL_PARSE_ERROR);

        final ServiceToken serviceToken = new ServiceToken(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        final byte[] encode = serviceToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);
        
        assertNotNull(mo.remove(KEY_SIGNATURE));
        
        new ServiceToken(ctx, mo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT);
    }
    
    @Test
    public void missingName() throws MslCryptoException, MslEncodingException, MslException, MslEncoderException, UnsupportedEncodingException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MSL_PARSE_ERROR);

        final ServiceToken serviceToken = new ServiceToken(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        final byte[] encode = serviceToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);
        
        final byte[] tokendata = mo.getBytes(KEY_TOKENDATA);
        final MslObject tokendataMo = encoder.parseObject(tokendata);;
        assertNotNull(tokendataMo.remove(KEY_NAME));
        mo.put(KEY_TOKENDATA, encoder.encodeObject(tokendataMo, ENCODER_FORMAT));
        
        new ServiceToken(ctx, mo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT);
    }
    
    @Test
    public void missingMasterTokenSerialNumber() throws MslEncoderException, MslException, UnsupportedEncodingException {
        final ServiceToken serviceToken = new ServiceToken(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        final byte[] encode = serviceToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);
        
        final byte[] tokendata = mo.getBytes(KEY_TOKENDATA);
        final MslObject tokendataMo = encoder.parseObject(tokendata);;
        assertNotNull(tokendataMo.remove(KEY_MASTER_TOKEN_SERIAL_NUMBER));
        mo.put(KEY_TOKENDATA, encoder.encodeObject(tokendataMo, ENCODER_FORMAT));
        
        final ServiceToken moServiceToken = new ServiceToken(ctx, mo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT);
        assertEquals(-1, moServiceToken.getMasterTokenSerialNumber());
        assertFalse(moServiceToken.isBoundTo(MASTER_TOKEN));
    }
    
    @Test
    public void invalidMasterTokenSerialNumber() throws MslEncoderException, MslCryptoException, MslEncodingException, MslException, UnsupportedEncodingException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MSL_PARSE_ERROR);

        final ServiceToken serviceToken = new ServiceToken(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        final byte[] encode = serviceToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);
        
        final byte[] tokendata = mo.getBytes(KEY_TOKENDATA);
        final MslObject tokendataMo = encoder.parseObject(tokendata);;
        tokendataMo.put(KEY_MASTER_TOKEN_SERIAL_NUMBER, "x");
        mo.put(KEY_TOKENDATA, encoder.encodeObject(tokendataMo, ENCODER_FORMAT));
        
        new ServiceToken(ctx, mo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT);
    }
    
    @Test
    public void negativeMasterTokenSerialNumber() throws MslEncoderException, MslCryptoException, MslEncodingException, MslException, UnsupportedEncodingException {
        thrown.expect(MslException.class);
        thrown.expectMslError(MslError.SERVICETOKEN_MASTERTOKEN_SERIAL_NUMBER_OUT_OF_RANGE);

        final ServiceToken serviceToken = new ServiceToken(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        final byte[] encode = serviceToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);
        
        final byte[] tokendata = mo.getBytes(KEY_TOKENDATA);
        final MslObject tokendataMo = encoder.parseObject(tokendata);;
        tokendataMo.put(KEY_MASTER_TOKEN_SERIAL_NUMBER, -1);
        mo.put(KEY_TOKENDATA, encoder.encodeObject(tokendataMo, ENCODER_FORMAT));
        
        new ServiceToken(ctx, mo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT);
    }
    
    @Test
    public void tooLargeMasterTokenSerialNumber() throws MslEncoderException, MslCryptoException, MslEncodingException, MslException, UnsupportedEncodingException {
        thrown.expect(MslException.class);
        thrown.expectMslError(MslError.SERVICETOKEN_MASTERTOKEN_SERIAL_NUMBER_OUT_OF_RANGE);

        final ServiceToken serviceToken = new ServiceToken(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        final byte[] encode = serviceToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);
        
        final byte[] tokendata = mo.getBytes(KEY_TOKENDATA);
        final MslObject tokendataMo = encoder.parseObject(tokendata);;
        tokendataMo.put(KEY_MASTER_TOKEN_SERIAL_NUMBER, MslConstants.MAX_LONG_VALUE + 1);
        mo.put(KEY_TOKENDATA, encoder.encodeObject(tokendataMo, ENCODER_FORMAT));
        
        new ServiceToken(ctx, mo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT);
    }
    
    @Test
    public void missingUserIdTokenSerialNumber() throws MslEncoderException, MslCryptoException, MslEncodingException, MslException, UnsupportedEncodingException {
        final ServiceToken serviceToken = new ServiceToken(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        final byte[] encode = serviceToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);
        
        final byte[] tokendata = mo.getBytes(KEY_TOKENDATA);
        final MslObject tokendataMo = encoder.parseObject(tokendata);;
        assertNotNull(tokendataMo.remove(KEY_USER_ID_TOKEN_SERIAL_NUMBER));
        mo.put(KEY_TOKENDATA, encoder.encodeObject(tokendataMo, ENCODER_FORMAT));
        
        final ServiceToken moServiceToken = new ServiceToken(ctx, mo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT);
        assertEquals(-1, moServiceToken.getUserIdTokenSerialNumber());
        assertFalse(moServiceToken.isBoundTo(USER_ID_TOKEN));
    }
    
    @Test
    public void invalidUserIdTokenSerialNumber() throws MslEncoderException, MslException, UnsupportedEncodingException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MSL_PARSE_ERROR);

        final ServiceToken serviceToken = new ServiceToken(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        final byte[] encode = serviceToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);
        
        final byte[] tokendata = mo.getBytes(KEY_TOKENDATA);
        final MslObject tokendataMo = encoder.parseObject(tokendata);;
        tokendataMo.put(KEY_USER_ID_TOKEN_SERIAL_NUMBER, "x");
        mo.put(KEY_TOKENDATA, encoder.encodeObject(tokendataMo, ENCODER_FORMAT));
        
        new ServiceToken(ctx, mo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT);
    }
    
    @Test
    public void negativeUserIdTokenSerialNumber() throws MslEncoderException, MslCryptoException, MslEncodingException, MslException, UnsupportedEncodingException {
        thrown.expect(MslException.class);
        thrown.expectMslError(MslError.SERVICETOKEN_USERIDTOKEN_SERIAL_NUMBER_OUT_OF_RANGE);

        final ServiceToken serviceToken = new ServiceToken(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        final byte[] encode = serviceToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);
        
        final byte[] tokendata = mo.getBytes(KEY_TOKENDATA);
        final MslObject tokendataMo = encoder.parseObject(tokendata);;
        tokendataMo.put(KEY_USER_ID_TOKEN_SERIAL_NUMBER, -1);
        mo.put(KEY_TOKENDATA, encoder.encodeObject(tokendataMo, ENCODER_FORMAT));
        
        new ServiceToken(ctx, mo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT);
    }
    
    @Test
    public void tooLargeUserIdTokenSerialNumber() throws MslEncoderException, MslCryptoException, MslEncodingException, MslException, UnsupportedEncodingException {
        thrown.expect(MslException.class);
        thrown.expectMslError(MslError.SERVICETOKEN_USERIDTOKEN_SERIAL_NUMBER_OUT_OF_RANGE);

        final ServiceToken serviceToken = new ServiceToken(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        final byte[] encode = serviceToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);
        
        final byte[] tokendata = mo.getBytes(KEY_TOKENDATA);
        final MslObject tokendataMo = encoder.parseObject(tokendata);;
        tokendataMo.put(KEY_USER_ID_TOKEN_SERIAL_NUMBER, MslConstants.MAX_LONG_VALUE + 1);
        mo.put(KEY_TOKENDATA, encoder.encodeObject(tokendataMo, ENCODER_FORMAT));
        
        new ServiceToken(ctx, mo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT);
    }
    
    @Test
    public void missingEncrypted() throws MslEncoderException, MslCryptoException, MslEncodingException, MslException, UnsupportedEncodingException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MSL_PARSE_ERROR);

        final ServiceToken serviceToken = new ServiceToken(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        final byte[] encode = serviceToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);
        
        final byte[] tokendata = mo.getBytes(KEY_TOKENDATA);
        final MslObject tokendataMo = encoder.parseObject(tokendata);;
        assertNotNull(tokendataMo.remove(KEY_ENCRYPTED));
        mo.put(KEY_TOKENDATA, encoder.encodeObject(tokendataMo, ENCODER_FORMAT));
        
        new ServiceToken(ctx, mo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT);
    }
    
    @Test
    public void invalidEncrypted() throws MslEncoderException, MslCryptoException, MslEncodingException, MslException, UnsupportedEncodingException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MSL_PARSE_ERROR);

        final ServiceToken serviceToken = new ServiceToken(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        final byte[] encode = serviceToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);
        
        final byte[] tokendata = mo.getBytes(KEY_TOKENDATA);
        final MslObject tokendataMo = encoder.parseObject(tokendata);;
        tokendataMo.put(KEY_ENCRYPTED, "x");
        mo.put(KEY_TOKENDATA, encoder.encodeObject(tokendataMo, ENCODER_FORMAT));
        
        new ServiceToken(ctx, mo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT);
    }
    
    @Test
    public void invalidCompressionAlgorithm() throws MslEncodingException, MslCryptoException, MslException, MslEncoderException {
        thrown.expect(MslException.class);
        thrown.expectMslError(MslError.UNIDENTIFIED_COMPRESSION);

        final ServiceToken serviceToken = new ServiceToken(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        final byte[] encode = serviceToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);
        
        final byte[] tokendata = mo.getBytes(KEY_TOKENDATA);
        final MslObject tokendataMo = encoder.parseObject(tokendata);;
        tokendataMo.put(KEY_COMPRESSION_ALGORITHM, "x");
        mo.put(KEY_TOKENDATA, encoder.encodeObject(tokendataMo, ENCODER_FORMAT));
        
        new ServiceToken(ctx, mo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT);
    }
    
    @Test
    public void missingServicedata() throws MslEncoderException, MslCryptoException, MslEncodingException, MslException, UnsupportedEncodingException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MSL_PARSE_ERROR);

        final ServiceToken serviceToken = new ServiceToken(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        final byte[] encode = serviceToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);
        
        final byte[] tokendata = mo.getBytes(KEY_TOKENDATA);
        final MslObject tokendataMo = encoder.parseObject(tokendata);;
        assertNotNull(tokendataMo.remove(KEY_SERVICEDATA));
        mo.put(KEY_TOKENDATA, encoder.encodeObject(tokendataMo, ENCODER_FORMAT));
        
        new ServiceToken(ctx, mo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT);
    }
    
    @Test
    public void invalidServicedata() throws MslCryptoException, MslEncodingException, MslException, UnsupportedEncodingException, MslEncoderException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MSL_PARSE_ERROR);

        final ServiceToken serviceToken = new ServiceToken(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        final byte[] encode = serviceToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);
        
        final byte[] tokendata = mo.getBytes(KEY_TOKENDATA);
        final MslObject tokendataMo = encoder.parseObject(tokendata);;
        tokendataMo.put(KEY_SERVICEDATA, false);
        
        final byte[] modifiedTokendata = encoder.encodeObject(tokendataMo, ENCODER_FORMAT);
        final byte[] signature = CRYPTO_CONTEXT.sign(modifiedTokendata, encoder, ENCODER_FORMAT);
        mo.put(KEY_TOKENDATA, modifiedTokendata);
        mo.put(KEY_SIGNATURE, signature);
        
        new ServiceToken(ctx, mo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT);
    }
    
    @Test
    public void emptyServicedata() throws MslCryptoException, MslEncodingException, MslException, UnsupportedEncodingException, MslEncoderException {
        final ServiceToken serviceToken = new ServiceToken(ctx, NAME, new byte[0], MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        assertTrue(serviceToken.isDeleted());
        final byte[] encode = serviceToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);
        
        final ServiceToken moServiceToken = new ServiceToken(ctx, mo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT);
        assertTrue(moServiceToken.isDeleted());
        assertEquals(0, moServiceToken.getData().length);
    }
    
    @Test
    public void emptyServicedataNotVerified() throws MslCryptoException, MslEncodingException, MslException, UnsupportedEncodingException, MslEncoderException {
        final ServiceToken serviceToken = new ServiceToken(ctx, NAME, new byte[0], MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        final byte[] encode = serviceToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);
        
        final byte[] signature = mo.getBytes(KEY_SIGNATURE);
        ++signature[0];
        mo.put(KEY_SIGNATURE, signature);
        
        final ServiceToken moServiceToken = new ServiceToken(ctx, mo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT);
        assertTrue(moServiceToken.isDeleted());
        assertEquals(0, moServiceToken.getData().length);
    }
    
    @Test(expected = MslCryptoException.class)
    public void corruptServicedata() throws MslEncoderException, MslCryptoException, MslEncodingException, MslException, UnsupportedEncodingException {
        final ServiceToken serviceToken = new ServiceToken(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        final byte[] encode = serviceToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);
        
        // This is testing service data that is verified but corrupt.
        final byte[] tokendata = mo.getBytes(KEY_TOKENDATA);
        final MslObject tokendataMo = encoder.parseObject(tokendata);;
        final byte[] servicedata = tokendataMo.getBytes(KEY_SERVICEDATA);
        ++servicedata[servicedata.length-1];
        tokendataMo.put(KEY_SERVICEDATA, servicedata);
        
        final byte[] modifiedTokendata = encoder.encodeObject(tokendataMo, ENCODER_FORMAT);
        final byte[] signature = CRYPTO_CONTEXT.sign(modifiedTokendata, encoder, ENCODER_FORMAT);
        mo.put(KEY_TOKENDATA, modifiedTokendata);
        mo.put(KEY_SIGNATURE, signature);
        
        new ServiceToken(ctx, mo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT);
    }
    
    @Test
    public void notVerified() throws MslEncoderException, MslException {
        final ServiceToken serviceToken = new ServiceToken(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        final byte[] encode = serviceToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);
        
        final byte[] signature = mo.getBytes(KEY_SIGNATURE);
        ++signature[0];
        mo.put(KEY_SIGNATURE, signature);
        
        final ServiceToken moServiceToken = new ServiceToken(ctx, mo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT);
        assertFalse(moServiceToken.isDecrypted());
        assertFalse(moServiceToken.isDeleted());
        assertFalse(moServiceToken.isVerified());
        assertNull(moServiceToken.getData());
        assertEquals(serviceToken.isBoundTo(MASTER_TOKEN), moServiceToken.isBoundTo(MASTER_TOKEN));
        assertEquals(serviceToken.isBoundTo(USER_ID_TOKEN), moServiceToken.isBoundTo(USER_ID_TOKEN));
        assertEquals(serviceToken.isMasterTokenBound(), moServiceToken.isMasterTokenBound());
        assertEquals(serviceToken.isUserIdTokenBound(), moServiceToken.isUserIdTokenBound());
        assertEquals(serviceToken.isUnbound(), moServiceToken.isUnbound());
        assertEquals(serviceToken.getMasterTokenSerialNumber(), moServiceToken.getMasterTokenSerialNumber());
        assertEquals(serviceToken.getUserIdTokenSerialNumber(), moServiceToken.getUserIdTokenSerialNumber());
        assertEquals(serviceToken.getName(), moServiceToken.getName());
        final byte[] moEncode = moServiceToken.toMslEncoding(encoder, ENCODER_FORMAT);
        assertNotNull(moEncode);
        assertFalse(encode.equals(moEncode));
    }
    
    @Test
    public void notEncrypted() throws MslEncoderException, MslException {
        final ServiceToken serviceToken = new ServiceToken(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, !ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        assertArrayEquals(DATA, serviceToken.getData());
        final byte[] encode = serviceToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);
        
        final ServiceToken moServiceToken = new ServiceToken(ctx, mo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT);
        assertTrue(moServiceToken.isVerified());
        assertFalse(moServiceToken.isDeleted());
        assertTrue(moServiceToken.isDecrypted());
        assertArrayEquals(serviceToken.getData(), moServiceToken.getData());
        assertEquals(serviceToken.isBoundTo(MASTER_TOKEN), moServiceToken.isBoundTo(MASTER_TOKEN));
        assertEquals(serviceToken.isBoundTo(USER_ID_TOKEN), moServiceToken.isBoundTo(USER_ID_TOKEN));
        assertEquals(serviceToken.isMasterTokenBound(), moServiceToken.isMasterTokenBound());
        assertEquals(serviceToken.isUserIdTokenBound(), moServiceToken.isUserIdTokenBound());
        assertEquals(serviceToken.isUnbound(), moServiceToken.isUnbound());
        assertEquals(serviceToken.getMasterTokenSerialNumber(), moServiceToken.getMasterTokenSerialNumber());
        assertEquals(serviceToken.getUserIdTokenSerialNumber(), moServiceToken.getUserIdTokenSerialNumber());
        assertEquals(serviceToken.getName(), moServiceToken.getName());
        final byte[] moEncode = moServiceToken.toMslEncoding(encoder, ENCODER_FORMAT);
        assertNotNull(moEncode);
        assertArrayEquals(encode, moEncode);
    }
    
    @Test
    public void cryptoContextNull() throws MslException, MslEncoderException {
        final ServiceToken serviceToken = new ServiceToken(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        final byte[] encode = serviceToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);
        
        final ServiceToken moServiceToken = new ServiceToken(ctx, mo, MASTER_TOKEN, USER_ID_TOKEN, (ICryptoContext)null);
        assertFalse(moServiceToken.isDecrypted());
        assertFalse(moServiceToken.isDeleted());
        assertFalse(moServiceToken.isVerified());
        assertNull(moServiceToken.getData());
        assertEquals(serviceToken.isBoundTo(MASTER_TOKEN), moServiceToken.isBoundTo(MASTER_TOKEN));
        assertEquals(serviceToken.isBoundTo(USER_ID_TOKEN), moServiceToken.isBoundTo(USER_ID_TOKEN));
        assertEquals(serviceToken.isMasterTokenBound(), moServiceToken.isMasterTokenBound());
        assertEquals(serviceToken.isUserIdTokenBound(), moServiceToken.isUserIdTokenBound());
        assertEquals(serviceToken.isUnbound(), moServiceToken.isUnbound());
        assertEquals(serviceToken.getMasterTokenSerialNumber(), moServiceToken.getMasterTokenSerialNumber());
        assertEquals(serviceToken.getUserIdTokenSerialNumber(), moServiceToken.getUserIdTokenSerialNumber());
        assertEquals(serviceToken.getName(), moServiceToken.getName());
        final byte[] moEncode = moServiceToken.toMslEncoding(encoder, ENCODER_FORMAT);
        assertNotNull(moEncode);
        assertArrayEquals(encode, moEncode);
    }
    
    @Test
    public void notEncryptedCryptoContextNull() throws MslCryptoException, MslEncodingException, MslException, MslEncoderException, MslEncoderException {
        final ServiceToken serviceToken = new ServiceToken(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, !ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        final byte[] encode = serviceToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);
        
        final ServiceToken moServiceToken = new ServiceToken(ctx, mo, MASTER_TOKEN, USER_ID_TOKEN, (ICryptoContext)null);
        assertFalse(moServiceToken.isDecrypted());
        assertFalse(moServiceToken.isDeleted());
        assertFalse(moServiceToken.isVerified());
        assertNull(moServiceToken.getData());
        assertEquals(serviceToken.isBoundTo(MASTER_TOKEN), moServiceToken.isBoundTo(MASTER_TOKEN));
        assertEquals(serviceToken.isBoundTo(USER_ID_TOKEN), moServiceToken.isBoundTo(USER_ID_TOKEN));
        assertEquals(serviceToken.isMasterTokenBound(), moServiceToken.isMasterTokenBound());
        assertEquals(serviceToken.isUserIdTokenBound(), moServiceToken.isUserIdTokenBound());
        assertEquals(serviceToken.isUnbound(), moServiceToken.isUnbound());
        assertEquals(serviceToken.getMasterTokenSerialNumber(), moServiceToken.getMasterTokenSerialNumber());
        assertEquals(serviceToken.getUserIdTokenSerialNumber(), moServiceToken.getUserIdTokenSerialNumber());
        assertEquals(serviceToken.getName(), moServiceToken.getName());
        final byte[] moEncode = moServiceToken.toMslEncoding(encoder, ENCODER_FORMAT);
        assertNotNull(moEncode);
        assertArrayEquals(encode, moEncode);
    }
    
    @Test
    public void isBoundToMasterToken() throws MslException {
        final MasterToken masterTokenA = MslTestUtils.getMasterToken(ctx, 1, 1);
        final MasterToken masterTokenB = MslTestUtils.getMasterToken(ctx, 1, 2);
        final ServiceToken serviceTokenA = new ServiceToken(ctx, NAME, DATA, masterTokenA, null, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        final ServiceToken serviceTokenB = new ServiceToken(ctx, NAME, DATA, masterTokenB, null, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        
        assertTrue(serviceTokenA.isBoundTo(masterTokenA));
        assertFalse(serviceTokenA.isBoundTo(masterTokenB));
        assertFalse(serviceTokenA.isBoundTo((MasterToken)null));
        assertTrue(serviceTokenB.isBoundTo(masterTokenB));
        assertFalse(serviceTokenB.isBoundTo(masterTokenA));
        assertFalse(serviceTokenA.isBoundTo((MasterToken)null));
    }
    
    @Test
    public void isBoundToUserIdToken() throws MslException {
        final UserIdToken userIdTokenA = MslTestUtils.getUserIdToken(ctx, MASTER_TOKEN, 1, MockEmailPasswordAuthenticationFactory.USER);
        final UserIdToken userIdTokenB = MslTestUtils.getUserIdToken(ctx, MASTER_TOKEN, 2, MockEmailPasswordAuthenticationFactory.USER);
        final ServiceToken serviceTokenA = new ServiceToken(ctx, NAME, DATA, MASTER_TOKEN, userIdTokenA, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        final ServiceToken serviceTokenB = new ServiceToken(ctx, NAME, DATA, MASTER_TOKEN, userIdTokenB, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        
        assertTrue(serviceTokenA.isBoundTo(userIdTokenA));
        assertFalse(serviceTokenA.isBoundTo(userIdTokenB));
        assertFalse(serviceTokenA.isBoundTo((UserIdToken)null));
        assertTrue(serviceTokenB.isBoundTo(userIdTokenB));
        assertFalse(serviceTokenB.isBoundTo(userIdTokenA));
        assertFalse(serviceTokenA.isBoundTo((UserIdToken)null));
    }
    
    @Test
    public void isUnbound() throws MslException {
        final ServiceToken serviceToken = new ServiceToken(ctx, NAME, DATA, null, null, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        assertTrue(serviceToken.isUnbound());
        assertFalse(serviceToken.isBoundTo(MASTER_TOKEN));
        assertFalse(serviceToken.isBoundTo(USER_ID_TOKEN));
        assertFalse(serviceToken.isBoundTo((MasterToken)null));
        assertFalse(serviceToken.isBoundTo((UserIdToken)null));
    }
    
    @Test
    public void equalsName() throws MslException, MslEncoderException {
        final String nameA = NAME + "A";
        final String nameB = NAME + "B";
        final ServiceToken serviceTokenA = new ServiceToken(ctx, nameA, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        final ServiceToken serviceTokenB = new ServiceToken(ctx, nameB, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        final ServiceToken serviceTokenA2 = new ServiceToken(ctx, MslTestUtils.toMslObject(encoder, serviceTokenA), MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT);

        assertTrue(serviceTokenA.equals(serviceTokenA));
        assertEquals(serviceTokenA.hashCode(), serviceTokenA.hashCode());
        
        assertFalse(serviceTokenA.equals(serviceTokenB));
        assertFalse(serviceTokenB.equals(serviceTokenA));
        assertTrue(serviceTokenA.hashCode() != serviceTokenB.hashCode());
        
        assertTrue(serviceTokenA.equals(serviceTokenA2));
        assertTrue(serviceTokenA2.equals(serviceTokenA));
        assertEquals(serviceTokenA.hashCode(), serviceTokenA2.hashCode());
    }
    
    @Test
    public void equalsMasterTokenSerialNumber() throws MslException, MslEncoderException {
        final MasterToken masterTokenA = MslTestUtils.getMasterToken(ctx, 1, 1);
        final MasterToken masterTokenB = MslTestUtils.getMasterToken(ctx, 1, 2);
        final ServiceToken serviceTokenA = new ServiceToken(ctx, NAME, DATA, masterTokenA, null, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        final ServiceToken serviceTokenB = new ServiceToken(ctx, NAME, DATA, masterTokenB, null, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        final ServiceToken serviceTokenA2 = new ServiceToken(ctx, MslTestUtils.toMslObject(encoder, serviceTokenA), masterTokenA, null, CRYPTO_CONTEXT);

        assertTrue(serviceTokenA.equals(serviceTokenA));
        assertEquals(serviceTokenA.hashCode(), serviceTokenA.hashCode());
        
        assertFalse(serviceTokenA.equals(serviceTokenB));
        assertFalse(serviceTokenB.equals(serviceTokenA));
        assertTrue(serviceTokenA.hashCode() != serviceTokenB.hashCode());
        
        assertTrue(serviceTokenA.equals(serviceTokenA2));
        assertTrue(serviceTokenA2.equals(serviceTokenA));
        assertEquals(serviceTokenA.hashCode(), serviceTokenA2.hashCode());
    }
    
    @Test
    public void equalsUserIdTokenSerialNumber() throws MslException, MslEncoderException {
        final UserIdToken userIdTokenA = MslTestUtils.getUserIdToken(ctx, MASTER_TOKEN, 1, MockEmailPasswordAuthenticationFactory.USER);
        final UserIdToken userIdTokenB = MslTestUtils.getUserIdToken(ctx, MASTER_TOKEN, 2, MockEmailPasswordAuthenticationFactory.USER);
        final ServiceToken serviceTokenA = new ServiceToken(ctx, NAME, DATA, MASTER_TOKEN, userIdTokenA, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        final ServiceToken serviceTokenB = new ServiceToken(ctx, NAME, DATA, MASTER_TOKEN, userIdTokenB, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        final ServiceToken serviceTokenA2 = new ServiceToken(ctx, MslTestUtils.toMslObject(encoder, serviceTokenA), MASTER_TOKEN, userIdTokenA, CRYPTO_CONTEXT);
        
        assertTrue(serviceTokenA.equals(serviceTokenA));
        assertEquals(serviceTokenA.hashCode(), serviceTokenA.hashCode());
        
        assertFalse(serviceTokenA.equals(serviceTokenB));
        assertFalse(serviceTokenB.equals(serviceTokenA));
        assertTrue(serviceTokenA.hashCode() != serviceTokenB.hashCode());
        
        assertTrue(serviceTokenA.equals(serviceTokenA2));
        assertTrue(serviceTokenA2.equals(serviceTokenA));
        assertEquals(serviceTokenA.hashCode(), serviceTokenA2.hashCode());
    }
    
    @Test
    public void equalsObject() throws MslException {
        final ServiceToken serviceToken = new ServiceToken(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        assertFalse(serviceToken.equals(null));
        assertFalse(serviceToken.equals(DATA));
        assertTrue(serviceToken.hashCode() != Arrays.hashCode(DATA));
    }
    
    /** MSL context. */
    private static MslContext ctx;
    /** MSL encoder factory. */
    private static MslEncoderFactory encoder;
    /** Random. */
    private static Random random;
}
