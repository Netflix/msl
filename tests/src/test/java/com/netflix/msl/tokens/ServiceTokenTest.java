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
import javax.xml.bind.DatatypeConverter;

import org.json.JSONException;
import org.json.JSONObject;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Ignore;
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
    /** JSON key token data. */
    private static final String KEY_TOKENDATA = "tokendata";
    /** JSON key signature. */
    private static final String KEY_SIGNATURE = "signature";
    
    // tokendata
    /** JSON key token name. */
    private static final String KEY_NAME = "name";
    /** JSON key master token serial number. */
    private static final String KEY_MASTER_TOKEN_SERIAL_NUMBER = "mtserialnumber";
    /** JSON key user ID token serial number. */
    private static final String KEY_USER_ID_TOKEN_SERIAL_NUMBER = "uitserialnumber";
    /** JSON key encrypted. */
    private static final String KEY_ENCRYPTED = "encrypted";
    /** JSON key compression algorithm. */
    private static final String KEY_COMPRESSION_ALGORITHM = "compressionalgo";
    /** JSON key service data. */
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
        MASTER_TOKEN = MslTestUtils.getMasterToken(ctx, 1, 1);
        USER_ID_TOKEN = MslTestUtils.getUserIdToken(ctx, MASTER_TOKEN, 1, MockEmailPasswordAuthenticationFactory.USER);
        CRYPTO_CONTEXT = getCryptoContext(ctx);
    }
    
    @AfterClass
    public static void teardown() {
        CRYPTO_CONTEXT = null;
        USER_ID_TOKEN = null;
        MASTER_TOKEN = null;
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
    private CompressionAlgorithm compressionAlgo;
    
    /**
     * Create a new master token test instance.
     * 
     * @param compressionAlgo compression algorithm.
     */
    public ServiceTokenTest(final CompressionAlgorithm compressionAlgo) {
        this.compressionAlgo = compressionAlgo;
    }
    
    @Test
    public void ctors() throws JSONException, MslException {
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
        final String jsonString = serviceToken.toJSONString();
        assertNotNull(jsonString);
        final JSONObject jo = new JSONObject(jsonString);

        final ServiceToken joServiceToken = new ServiceToken(ctx, jo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT);
        assertEquals(serviceToken.isDecrypted(), joServiceToken.isDecrypted());
        assertEquals(serviceToken.isDeleted(), joServiceToken.isDeleted());
        assertEquals(serviceToken.isVerified(), joServiceToken.isVerified());
        assertEquals(serviceToken.isBoundTo(MASTER_TOKEN), joServiceToken.isBoundTo(MASTER_TOKEN));
        assertEquals(serviceToken.isBoundTo(USER_ID_TOKEN), joServiceToken.isBoundTo(USER_ID_TOKEN));
        assertEquals(serviceToken.isMasterTokenBound(), joServiceToken.isMasterTokenBound());
        assertEquals(serviceToken.isUserIdTokenBound(), joServiceToken.isUserIdTokenBound());
        assertEquals(serviceToken.isUnbound(), joServiceToken.isUnbound());
        assertEquals(serviceToken.getMasterTokenSerialNumber(), joServiceToken.getMasterTokenSerialNumber());
        assertEquals(serviceToken.getUserIdTokenSerialNumber(), joServiceToken.getUserIdTokenSerialNumber());
        assertEquals(serviceToken.getName(), joServiceToken.getName());
        assertEquals(serviceToken.getCompressionAlgo(), joServiceToken.getCompressionAlgo());
        assertArrayEquals(serviceToken.getData(), joServiceToken.getData());
        final String joJsonString = joServiceToken.toJSONString();
        assertNotNull(joJsonString);
        assertEquals(jsonString, joJsonString);
    }
    
    @Test
    public void cryptoContextMismatch() throws JSONException, MslException {
        final ServiceToken serviceToken = new ServiceToken(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        final String jsonString = serviceToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);
        
        final ICryptoContext joCryptoContext = getCryptoContext(ctx);
        final ServiceToken joServiceToken = new ServiceToken(ctx, jo, MASTER_TOKEN, USER_ID_TOKEN, joCryptoContext);
        assertFalse(joServiceToken.isDecrypted());
        assertFalse(serviceToken.isDeleted());
        assertFalse(joServiceToken.isVerified());
        assertNull(joServiceToken.getData());
        assertEquals(serviceToken.isBoundTo(MASTER_TOKEN), joServiceToken.isBoundTo(MASTER_TOKEN));
        assertEquals(serviceToken.isBoundTo(USER_ID_TOKEN), joServiceToken.isBoundTo(USER_ID_TOKEN));
        assertEquals(serviceToken.isMasterTokenBound(), joServiceToken.isMasterTokenBound());
        assertEquals(serviceToken.isUserIdTokenBound(), joServiceToken.isUserIdTokenBound());
        assertEquals(serviceToken.isUnbound(), joServiceToken.isUnbound());
        assertEquals(serviceToken.getMasterTokenSerialNumber(), joServiceToken.getMasterTokenSerialNumber());
        assertEquals(serviceToken.getUserIdTokenSerialNumber(), joServiceToken.getUserIdTokenSerialNumber());
        assertEquals(serviceToken.getName(), joServiceToken.getName());
        assertEquals(serviceToken.getCompressionAlgo(), joServiceToken.getCompressionAlgo());
        final String joJsonString = joServiceToken.toJSONString();
        assertNotNull(joJsonString);
        assertEquals(jsonString, joJsonString);
    }
    
    @Test
    public void mappedCryptoContext() throws JSONException, MslException {
        final ServiceToken serviceToken = new ServiceToken(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        final String jsonString = serviceToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);
        
        final Map<String,ICryptoContext> cryptoContexts = new HashMap<String,ICryptoContext>();
        cryptoContexts.put(NAME, CRYPTO_CONTEXT);
        cryptoContexts.put(NAME + "1", getCryptoContext(ctx));
        cryptoContexts.put(NAME + "2", getCryptoContext(ctx));
        
        final ServiceToken joServiceToken = new ServiceToken(ctx, jo, MASTER_TOKEN, USER_ID_TOKEN, cryptoContexts);
        assertEquals(serviceToken.isDecrypted(), joServiceToken.isDecrypted());
        assertEquals(serviceToken.isDeleted(), joServiceToken.isDeleted());
        assertEquals(serviceToken.isVerified(), joServiceToken.isVerified());
        assertEquals(serviceToken.isBoundTo(MASTER_TOKEN), joServiceToken.isBoundTo(MASTER_TOKEN));
        assertEquals(serviceToken.isBoundTo(USER_ID_TOKEN), joServiceToken.isBoundTo(USER_ID_TOKEN));
        assertEquals(serviceToken.isMasterTokenBound(), joServiceToken.isMasterTokenBound());
        assertEquals(serviceToken.isUserIdTokenBound(), joServiceToken.isUserIdTokenBound());
        assertEquals(serviceToken.isUnbound(), joServiceToken.isUnbound());
        assertEquals(serviceToken.getMasterTokenSerialNumber(), joServiceToken.getMasterTokenSerialNumber());
        assertEquals(serviceToken.getUserIdTokenSerialNumber(), joServiceToken.getUserIdTokenSerialNumber());
        assertEquals(serviceToken.getName(), joServiceToken.getName());
        assertEquals(serviceToken.getCompressionAlgo(), joServiceToken.getCompressionAlgo());
        assertArrayEquals(serviceToken.getData(), joServiceToken.getData());
        final String joJsonString = joServiceToken.toJSONString();
        assertNotNull(joJsonString);
        assertEquals(jsonString, joJsonString);
    }
    
    @Test
    public void unmappedCryptoContext() throws JSONException, MslException {
        final ServiceToken serviceToken = new ServiceToken(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        final String jsonString = serviceToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);
        
        final Map<String,ICryptoContext> cryptoContexts = new HashMap<String,ICryptoContext>();
        cryptoContexts.put(NAME + "0", CRYPTO_CONTEXT);
        cryptoContexts.put(NAME + "1", getCryptoContext(ctx));
        cryptoContexts.put(NAME + "2", getCryptoContext(ctx));
        
        final ServiceToken joServiceToken = new ServiceToken(ctx, jo, MASTER_TOKEN, USER_ID_TOKEN, cryptoContexts);
        assertFalse(joServiceToken.isDecrypted());
        assertFalse(joServiceToken.isDeleted());
        assertFalse(joServiceToken.isVerified());
        assertNull(joServiceToken.getData());
        assertEquals(serviceToken.isBoundTo(MASTER_TOKEN), joServiceToken.isBoundTo(MASTER_TOKEN));
        assertEquals(serviceToken.isBoundTo(USER_ID_TOKEN), joServiceToken.isBoundTo(USER_ID_TOKEN));
        assertEquals(serviceToken.isMasterTokenBound(), joServiceToken.isMasterTokenBound());
        assertEquals(serviceToken.isUserIdTokenBound(), joServiceToken.isUserIdTokenBound());
        assertEquals(serviceToken.isUnbound(), joServiceToken.isUnbound());
        assertEquals(serviceToken.getMasterTokenSerialNumber(), joServiceToken.getMasterTokenSerialNumber());
        assertEquals(serviceToken.getUserIdTokenSerialNumber(), joServiceToken.getUserIdTokenSerialNumber());
        assertEquals(serviceToken.getName(), joServiceToken.getName());
        assertEquals(serviceToken.getCompressionAlgo(), joServiceToken.getCompressionAlgo());
        final String joJsonString = joServiceToken.toJSONString();
        assertNotNull(joJsonString);
        assertEquals(jsonString, joJsonString);
    }
    
    @Test
    public void masterTokenMismatch() throws MslException, JSONException {
        thrown.expect(MslException.class);
        thrown.expectMslError(MslError.SERVICETOKEN_MASTERTOKEN_MISMATCH);

        final MasterToken masterToken = MslTestUtils.getMasterToken(ctx, 1, 1);
        final ServiceToken serviceToken = new ServiceToken(ctx, NAME, DATA, masterToken, null, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        final String jsonString = serviceToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);
        
        final MasterToken joMasterToken = MslTestUtils.getMasterToken(ctx, 1, 2);
        new ServiceToken(ctx, jo, joMasterToken, null, CRYPTO_CONTEXT);
    }
    
    @Test
    public void masterTokenMissing() throws JSONException, MslException {
        thrown.expect(MslException.class);
        thrown.expectMslError(MslError.SERVICETOKEN_MASTERTOKEN_MISMATCH);

        final ServiceToken serviceToken = new ServiceToken(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        final String jsonString = serviceToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);
        
        new ServiceToken(ctx, jo, null, USER_ID_TOKEN, CRYPTO_CONTEXT);
    }
    
    @Test
    public void userIdTokenMismatch() throws MslException, JSONException {
        thrown.expect(MslException.class);
        thrown.expectMslError(MslError.SERVICETOKEN_USERIDTOKEN_MISMATCH);

        final UserIdToken userIdToken = MslTestUtils.getUserIdToken(ctx, MASTER_TOKEN, 1, MockEmailPasswordAuthenticationFactory.USER);
        final ServiceToken serviceToken = new ServiceToken(ctx, NAME, DATA, MASTER_TOKEN, userIdToken, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        final String jsonString = serviceToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);
        
        final UserIdToken joUserIdToken = MslTestUtils.getUserIdToken(ctx, MASTER_TOKEN, 2, MockEmailPasswordAuthenticationFactory.USER);
        new ServiceToken(ctx, jo, MASTER_TOKEN, joUserIdToken, CRYPTO_CONTEXT);
    }
    
    @Test
    public void userIdTokenMissing() throws MslCryptoException, MslEncodingException, MslException, JSONException {
        thrown.expect(MslException.class);
        thrown.expectMslError(MslError.SERVICETOKEN_USERIDTOKEN_MISMATCH);

        final ServiceToken serviceToken = new ServiceToken(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        final String jsonString = serviceToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);
        
        new ServiceToken(ctx, jo, MASTER_TOKEN, null, CRYPTO_CONTEXT);
    }
    
    @Test(expected = MslInternalException.class)
    public void tokenMismatch() throws MslInternalException, MslException {
        final MasterToken masterTokenA = MslTestUtils.getMasterToken(ctx, 1, 1);
        final MasterToken masterTokenB = MslTestUtils.getMasterToken(ctx, 1, 2);
        final UserIdToken userIdToken = MslTestUtils.getUserIdToken(ctx, masterTokenB, 1, MockEmailPasswordAuthenticationFactory.USER);
        new ServiceToken(ctx, NAME, DATA, masterTokenA, userIdToken, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
    }
    
    @Test
    public void missingTokendata() throws JSONException, MslException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.JSON_PARSE_ERROR);

        final ServiceToken serviceToken = new ServiceToken(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        final String jsonString = serviceToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);
        
        assertNotNull(jo.remove(KEY_TOKENDATA));
        
        new ServiceToken(ctx, jo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT);
    }
    
    @Test
    public void invalidTokendata() throws MslException, JSONException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.JSON_PARSE_ERROR);

        final ServiceToken serviceToken = new ServiceToken(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        final String jsonString = serviceToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);

        final byte[] tokendata = DatatypeConverter.parseBase64Binary(jo.getString(KEY_TOKENDATA));
        ++tokendata[0];
        jo.put(KEY_TOKENDATA, DatatypeConverter.printBase64Binary(tokendata));
        
        new ServiceToken(ctx, jo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT);
    }
    
    @Test
    public void missingSignature() throws JSONException, MslCryptoException, MslEncodingException, MslException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.JSON_PARSE_ERROR);

        final ServiceToken serviceToken = new ServiceToken(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        final String jsonString = serviceToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);
        
        assertNotNull(jo.remove(KEY_SIGNATURE));
        
        new ServiceToken(ctx, jo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT);
    }
    
    @Test
    public void missingName() throws MslCryptoException, MslEncodingException, MslException, JSONException, UnsupportedEncodingException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.JSON_PARSE_ERROR);

        final ServiceToken serviceToken = new ServiceToken(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        final String jsonString = serviceToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);
        
        final byte[] tokendata = DatatypeConverter.parseBase64Binary(jo.getString(KEY_TOKENDATA));
        final JSONObject tokendataJo = new JSONObject(new String(tokendata, MslConstants.DEFAULT_CHARSET));
        assertNotNull(tokendataJo.remove(KEY_NAME));
        jo.put(KEY_TOKENDATA, DatatypeConverter.printBase64Binary(tokendataJo.toString().getBytes()));
        
        new ServiceToken(ctx, jo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT);
    }
    
    @Test
    public void missingMasterTokenSerialNumber() throws JSONException, MslException, UnsupportedEncodingException {
        final ServiceToken serviceToken = new ServiceToken(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        final String jsonString = serviceToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);
        
        final byte[] tokendata = DatatypeConverter.parseBase64Binary(jo.getString(KEY_TOKENDATA));
        final JSONObject tokendataJo = new JSONObject(new String(tokendata, MslConstants.DEFAULT_CHARSET));
        assertNotNull(tokendataJo.remove(KEY_MASTER_TOKEN_SERIAL_NUMBER));
        jo.put(KEY_TOKENDATA, DatatypeConverter.printBase64Binary(tokendataJo.toString().getBytes()));
        
        final ServiceToken joServiceToken = new ServiceToken(ctx, jo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT);
        assertEquals(-1, joServiceToken.getMasterTokenSerialNumber());
        assertFalse(joServiceToken.isBoundTo(MASTER_TOKEN));
    }
    
    @Test
    public void invalidMasterTokenSerialNumber() throws JSONException, MslCryptoException, MslEncodingException, MslException, UnsupportedEncodingException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.JSON_PARSE_ERROR);

        final ServiceToken serviceToken = new ServiceToken(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        final String jsonString = serviceToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);
        
        final byte[] tokendata = DatatypeConverter.parseBase64Binary(jo.getString(KEY_TOKENDATA));
        final JSONObject tokendataJo = new JSONObject(new String(tokendata, MslConstants.DEFAULT_CHARSET));
        tokendataJo.put(KEY_MASTER_TOKEN_SERIAL_NUMBER, "x");
        jo.put(KEY_TOKENDATA, DatatypeConverter.printBase64Binary(tokendataJo.toString().getBytes()));
        
        new ServiceToken(ctx, jo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT);
    }
    
    @Test
    public void negativeMasterTokenSerialNumber() throws JSONException, MslCryptoException, MslEncodingException, MslException, UnsupportedEncodingException {
        thrown.expect(MslException.class);
        thrown.expectMslError(MslError.SERVICETOKEN_MASTERTOKEN_SERIAL_NUMBER_OUT_OF_RANGE);

        final ServiceToken serviceToken = new ServiceToken(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        final String jsonString = serviceToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);
        
        final byte[] tokendata = DatatypeConverter.parseBase64Binary(jo.getString(KEY_TOKENDATA));
        final JSONObject tokendataJo = new JSONObject(new String(tokendata, MslConstants.DEFAULT_CHARSET));
        tokendataJo.put(KEY_MASTER_TOKEN_SERIAL_NUMBER, -1);
        jo.put(KEY_TOKENDATA, DatatypeConverter.printBase64Binary(tokendataJo.toString().getBytes()));
        
        new ServiceToken(ctx, jo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT);
    }
    
    @Test
    public void tooLargeMasterTokenSerialNumber() throws JSONException, MslCryptoException, MslEncodingException, MslException, UnsupportedEncodingException {
        thrown.expect(MslException.class);
        thrown.expectMslError(MslError.SERVICETOKEN_MASTERTOKEN_SERIAL_NUMBER_OUT_OF_RANGE);

        final ServiceToken serviceToken = new ServiceToken(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        final String jsonString = serviceToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);
        
        final byte[] tokendata = DatatypeConverter.parseBase64Binary(jo.getString(KEY_TOKENDATA));
        final JSONObject tokendataJo = new JSONObject(new String(tokendata, MslConstants.DEFAULT_CHARSET));
        tokendataJo.put(KEY_MASTER_TOKEN_SERIAL_NUMBER, MslConstants.MAX_LONG_VALUE + 1);
        jo.put(KEY_TOKENDATA, DatatypeConverter.printBase64Binary(tokendataJo.toString().getBytes()));
        
        new ServiceToken(ctx, jo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT);
    }
    
    @Test
    public void missingUserIdTokenSerialNumber() throws JSONException, MslCryptoException, MslEncodingException, MslException, UnsupportedEncodingException {
        final ServiceToken serviceToken = new ServiceToken(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        final String jsonString = serviceToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);
        
        final byte[] tokendata = DatatypeConverter.parseBase64Binary(jo.getString(KEY_TOKENDATA));
        final JSONObject tokendataJo = new JSONObject(new String(tokendata, MslConstants.DEFAULT_CHARSET));
        assertNotNull(tokendataJo.remove(KEY_USER_ID_TOKEN_SERIAL_NUMBER));
        jo.put(KEY_TOKENDATA, DatatypeConverter.printBase64Binary(tokendataJo.toString().getBytes()));
        
        final ServiceToken joServiceToken = new ServiceToken(ctx, jo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT);
        assertEquals(-1, joServiceToken.getUserIdTokenSerialNumber());
        assertFalse(joServiceToken.isBoundTo(USER_ID_TOKEN));
    }
    
    @Test
    public void invalidUserIdTokenSerialNumber() throws JSONException, MslException, UnsupportedEncodingException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.JSON_PARSE_ERROR);

        final ServiceToken serviceToken = new ServiceToken(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        final String jsonString = serviceToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);
        
        final byte[] tokendata = DatatypeConverter.parseBase64Binary(jo.getString(KEY_TOKENDATA));
        final JSONObject tokendataJo = new JSONObject(new String(tokendata, MslConstants.DEFAULT_CHARSET));
        tokendataJo.put(KEY_USER_ID_TOKEN_SERIAL_NUMBER, "x");
        jo.put(KEY_TOKENDATA, DatatypeConverter.printBase64Binary(tokendataJo.toString().getBytes()));
        
        new ServiceToken(ctx, jo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT);
    }
    
    @Test
    public void negativeUserIdTokenSerialNumber() throws JSONException, MslCryptoException, MslEncodingException, MslException, UnsupportedEncodingException {
        thrown.expect(MslException.class);
        thrown.expectMslError(MslError.SERVICETOKEN_USERIDTOKEN_SERIAL_NUMBER_OUT_OF_RANGE);

        final ServiceToken serviceToken = new ServiceToken(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        final String jsonString = serviceToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);
        
        final byte[] tokendata = DatatypeConverter.parseBase64Binary(jo.getString(KEY_TOKENDATA));
        final JSONObject tokendataJo = new JSONObject(new String(tokendata, MslConstants.DEFAULT_CHARSET));
        tokendataJo.put(KEY_USER_ID_TOKEN_SERIAL_NUMBER, -1);
        jo.put(KEY_TOKENDATA, DatatypeConverter.printBase64Binary(tokendataJo.toString().getBytes()));
        
        new ServiceToken(ctx, jo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT);
    }
    
    @Test
    public void tooLargeUserIdTokenSerialNumber() throws JSONException, MslCryptoException, MslEncodingException, MslException, UnsupportedEncodingException {
        thrown.expect(MslException.class);
        thrown.expectMslError(MslError.SERVICETOKEN_USERIDTOKEN_SERIAL_NUMBER_OUT_OF_RANGE);

        final ServiceToken serviceToken = new ServiceToken(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        final String jsonString = serviceToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);
        
        final byte[] tokendata = DatatypeConverter.parseBase64Binary(jo.getString(KEY_TOKENDATA));
        final JSONObject tokendataJo = new JSONObject(new String(tokendata, MslConstants.DEFAULT_CHARSET));
        tokendataJo.put(KEY_USER_ID_TOKEN_SERIAL_NUMBER, MslConstants.MAX_LONG_VALUE + 1);
        jo.put(KEY_TOKENDATA, DatatypeConverter.printBase64Binary(tokendataJo.toString().getBytes()));
        
        new ServiceToken(ctx, jo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT);
    }
    
    @Test
    public void missingEncrypted() throws JSONException, MslCryptoException, MslEncodingException, MslException, UnsupportedEncodingException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.JSON_PARSE_ERROR);

        final ServiceToken serviceToken = new ServiceToken(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        final String jsonString = serviceToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);
        
        final byte[] tokendata = DatatypeConverter.parseBase64Binary(jo.getString(KEY_TOKENDATA));
        final JSONObject tokendataJo = new JSONObject(new String(tokendata, MslConstants.DEFAULT_CHARSET));
        assertNotNull(tokendataJo.remove(KEY_ENCRYPTED));
        jo.put(KEY_TOKENDATA, DatatypeConverter.printBase64Binary(tokendataJo.toString().getBytes()));
        
        new ServiceToken(ctx, jo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT);
    }
    
    @Test
    public void invalidEncrypted() throws JSONException, MslCryptoException, MslEncodingException, MslException, UnsupportedEncodingException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.JSON_PARSE_ERROR);

        final ServiceToken serviceToken = new ServiceToken(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        final String jsonString = serviceToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);
        
        final byte[] tokendata = DatatypeConverter.parseBase64Binary(jo.getString(KEY_TOKENDATA));
        final JSONObject tokendataJo = new JSONObject(new String(tokendata, MslConstants.DEFAULT_CHARSET));
        tokendataJo.put(KEY_ENCRYPTED, "x");
        jo.put(KEY_TOKENDATA, DatatypeConverter.printBase64Binary(tokendataJo.toString().getBytes()));
        
        new ServiceToken(ctx, jo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT);
    }
    
    @Test
    public void invalidCompressionAlgorithm() throws MslEncodingException, MslCryptoException, MslException, JSONException {
        thrown.expect(MslException.class);
        thrown.expectMslError(MslError.UNIDENTIFIED_COMPRESSION);

        final ServiceToken serviceToken = new ServiceToken(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        final String jsonString = serviceToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);
        
        final byte[] tokendata = DatatypeConverter.parseBase64Binary(jo.getString(KEY_TOKENDATA));
        final JSONObject tokendataJo = new JSONObject(new String(tokendata, MslConstants.DEFAULT_CHARSET));
        tokendataJo.put(KEY_COMPRESSION_ALGORITHM, "x");
        jo.put(KEY_TOKENDATA, DatatypeConverter.printBase64Binary(tokendataJo.toString().getBytes()));
        
        new ServiceToken(ctx, jo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT);
    }
    
    @Test
    public void missingServicedata() throws JSONException, MslCryptoException, MslEncodingException, MslException, UnsupportedEncodingException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.JSON_PARSE_ERROR);

        final ServiceToken serviceToken = new ServiceToken(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        final String jsonString = serviceToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);
        
        final byte[] tokendata = DatatypeConverter.parseBase64Binary(jo.getString(KEY_TOKENDATA));
        final JSONObject tokendataJo = new JSONObject(new String(tokendata, MslConstants.DEFAULT_CHARSET));
        assertNotNull(tokendataJo.remove(KEY_SERVICEDATA));
        jo.put(KEY_TOKENDATA, DatatypeConverter.printBase64Binary(tokendataJo.toString().getBytes()));
        
        new ServiceToken(ctx, jo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT);
    }
    
    // This test no longer passes because DataConverter.parseBase64Binary()
    // does not error when presented with invalid Base64-encoded data.
    @Ignore
    @Test
    public void invalidServicedata() throws MslCryptoException, MslEncodingException, MslException, UnsupportedEncodingException, JSONException {
        thrown.expect(MslException.class);
        thrown.expectMslError(MslError.SERVICETOKEN_SERVICEDATA_INVALID);

        final ServiceToken serviceToken = new ServiceToken(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        final String jsonString = serviceToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);
        
        final byte[] tokendata = DatatypeConverter.parseBase64Binary(jo.getString(KEY_TOKENDATA));
        final JSONObject tokendataJo = new JSONObject(new String(tokendata, MslConstants.DEFAULT_CHARSET));
        tokendataJo.put(KEY_SERVICEDATA, "x");
        
        final byte[] modifiedTokendata = tokendataJo.toString().getBytes(MslConstants.DEFAULT_CHARSET);
        final byte[] signature = CRYPTO_CONTEXT.sign(modifiedTokendata);
        jo.put(KEY_TOKENDATA, DatatypeConverter.printBase64Binary(modifiedTokendata));
        jo.put(KEY_SIGNATURE, DatatypeConverter.printBase64Binary(signature));
        
        new ServiceToken(ctx, jo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT);
    }
    
    @Test
    public void emptyServicedata() throws MslCryptoException, MslEncodingException, MslException, UnsupportedEncodingException, JSONException {
        final ServiceToken serviceToken = new ServiceToken(ctx, NAME, new byte[0], MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        assertTrue(serviceToken.isDeleted());
        final String jsonString = serviceToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);
        
        final ServiceToken joServiceToken = new ServiceToken(ctx, jo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT);
        assertTrue(joServiceToken.isDeleted());
        assertEquals(0, joServiceToken.getData().length);
    }
    
    @Test
    public void emptyServicedataNotVerified() throws MslCryptoException, MslEncodingException, MslException, UnsupportedEncodingException, JSONException {
        final ServiceToken serviceToken = new ServiceToken(ctx, NAME, new byte[0], MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        final String jsonString = serviceToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);
        
        final byte[] signature = DatatypeConverter.parseBase64Binary(jo.getString(KEY_SIGNATURE));
        ++signature[0];
        jo.put(KEY_SIGNATURE, DatatypeConverter.printBase64Binary(signature));
        
        final ServiceToken joServiceToken = new ServiceToken(ctx, jo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT);
        assertTrue(joServiceToken.isDeleted());
        assertEquals(0, joServiceToken.getData().length);
    }
    
    @Test(expected = MslCryptoException.class)
    public void corruptServicedata() throws JSONException, MslCryptoException, MslEncodingException, MslException, UnsupportedEncodingException {
        final ServiceToken serviceToken = new ServiceToken(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        final String jsonString = serviceToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);
        
        // This is testing service data that is verified but corrupt.
        final byte[] tokendata = DatatypeConverter.parseBase64Binary(jo.getString(KEY_TOKENDATA));
        final JSONObject tokendataJo = new JSONObject(new String(tokendata, MslConstants.DEFAULT_CHARSET));
        final byte[] servicedata = DatatypeConverter.parseBase64Binary(tokendataJo.getString(KEY_SERVICEDATA));
        ++servicedata[servicedata.length-1];
        tokendataJo.put(KEY_SERVICEDATA, DatatypeConverter.printBase64Binary(servicedata));
        
        final byte[] modifiedTokendata = tokendataJo.toString().getBytes(MslConstants.DEFAULT_CHARSET);
        final byte[] signature = CRYPTO_CONTEXT.sign(modifiedTokendata);
        jo.put(KEY_TOKENDATA, DatatypeConverter.printBase64Binary(modifiedTokendata));
        jo.put(KEY_SIGNATURE, DatatypeConverter.printBase64Binary(signature));
        
        new ServiceToken(ctx, jo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT);
    }
    
    @Test
    public void notVerified() throws JSONException, MslException {
        final ServiceToken serviceToken = new ServiceToken(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        final String jsonString = serviceToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);
        
        final byte[] signature = DatatypeConverter.parseBase64Binary(jo.getString(KEY_SIGNATURE));
        ++signature[0];
        jo.put(KEY_SIGNATURE, DatatypeConverter.printBase64Binary(signature));
        
        final ServiceToken joServiceToken = new ServiceToken(ctx, jo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT);
        assertFalse(joServiceToken.isDecrypted());
        assertFalse(joServiceToken.isDeleted());
        assertFalse(joServiceToken.isVerified());
        assertNull(joServiceToken.getData());
        assertEquals(serviceToken.isBoundTo(MASTER_TOKEN), joServiceToken.isBoundTo(MASTER_TOKEN));
        assertEquals(serviceToken.isBoundTo(USER_ID_TOKEN), joServiceToken.isBoundTo(USER_ID_TOKEN));
        assertEquals(serviceToken.isMasterTokenBound(), joServiceToken.isMasterTokenBound());
        assertEquals(serviceToken.isUserIdTokenBound(), joServiceToken.isUserIdTokenBound());
        assertEquals(serviceToken.isUnbound(), joServiceToken.isUnbound());
        assertEquals(serviceToken.getMasterTokenSerialNumber(), joServiceToken.getMasterTokenSerialNumber());
        assertEquals(serviceToken.getUserIdTokenSerialNumber(), joServiceToken.getUserIdTokenSerialNumber());
        assertEquals(serviceToken.getName(), joServiceToken.getName());
        final String joJsonString = joServiceToken.toJSONString();
        assertNotNull(joJsonString);
        assertFalse(jsonString.equals(joJsonString));
    }
    
    @Test
    public void notEncrypted() throws JSONException, MslException {
        final ServiceToken serviceToken = new ServiceToken(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, !ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        assertArrayEquals(DATA, serviceToken.getData());
        final String jsonString = serviceToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);
        
        final ServiceToken joServiceToken = new ServiceToken(ctx, jo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT);
        assertTrue(joServiceToken.isVerified());
        assertFalse(joServiceToken.isDeleted());
        assertTrue(joServiceToken.isDecrypted());
        assertArrayEquals(serviceToken.getData(), joServiceToken.getData());
        assertEquals(serviceToken.isBoundTo(MASTER_TOKEN), joServiceToken.isBoundTo(MASTER_TOKEN));
        assertEquals(serviceToken.isBoundTo(USER_ID_TOKEN), joServiceToken.isBoundTo(USER_ID_TOKEN));
        assertEquals(serviceToken.isMasterTokenBound(), joServiceToken.isMasterTokenBound());
        assertEquals(serviceToken.isUserIdTokenBound(), joServiceToken.isUserIdTokenBound());
        assertEquals(serviceToken.isUnbound(), joServiceToken.isUnbound());
        assertEquals(serviceToken.getMasterTokenSerialNumber(), joServiceToken.getMasterTokenSerialNumber());
        assertEquals(serviceToken.getUserIdTokenSerialNumber(), joServiceToken.getUserIdTokenSerialNumber());
        assertEquals(serviceToken.getName(), joServiceToken.getName());
        final String joJsonString = joServiceToken.toJSONString();
        assertNotNull(joJsonString);
        assertEquals(jsonString, joJsonString);
    }
    
    @Test
    public void cryptoContextNull() throws MslException, JSONException {
        final ServiceToken serviceToken = new ServiceToken(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        final String jsonString = serviceToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);
        
        final ServiceToken joServiceToken = new ServiceToken(ctx, jo, MASTER_TOKEN, USER_ID_TOKEN, (ICryptoContext)null);
        assertFalse(joServiceToken.isDecrypted());
        assertFalse(joServiceToken.isDeleted());
        assertFalse(joServiceToken.isVerified());
        assertNull(joServiceToken.getData());
        assertEquals(serviceToken.isBoundTo(MASTER_TOKEN), joServiceToken.isBoundTo(MASTER_TOKEN));
        assertEquals(serviceToken.isBoundTo(USER_ID_TOKEN), joServiceToken.isBoundTo(USER_ID_TOKEN));
        assertEquals(serviceToken.isMasterTokenBound(), joServiceToken.isMasterTokenBound());
        assertEquals(serviceToken.isUserIdTokenBound(), joServiceToken.isUserIdTokenBound());
        assertEquals(serviceToken.isUnbound(), joServiceToken.isUnbound());
        assertEquals(serviceToken.getMasterTokenSerialNumber(), joServiceToken.getMasterTokenSerialNumber());
        assertEquals(serviceToken.getUserIdTokenSerialNumber(), joServiceToken.getUserIdTokenSerialNumber());
        assertEquals(serviceToken.getName(), joServiceToken.getName());
        final String joJsonString = joServiceToken.toJSONString();
        assertNotNull(joJsonString);
        assertEquals(jsonString, joJsonString);
    }
    
    @Test
    public void notEncryptedCryptoContextNull() throws MslCryptoException, MslEncodingException, MslException, JSONException {
        final ServiceToken serviceToken = new ServiceToken(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, !ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        final String jsonString = serviceToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);
        
        final ServiceToken joServiceToken = new ServiceToken(ctx, jo, MASTER_TOKEN, USER_ID_TOKEN, (ICryptoContext)null);
        assertFalse(joServiceToken.isDecrypted());
        assertFalse(joServiceToken.isDeleted());
        assertFalse(joServiceToken.isVerified());
        assertNull(joServiceToken.getData());
        assertEquals(serviceToken.isBoundTo(MASTER_TOKEN), joServiceToken.isBoundTo(MASTER_TOKEN));
        assertEquals(serviceToken.isBoundTo(USER_ID_TOKEN), joServiceToken.isBoundTo(USER_ID_TOKEN));
        assertEquals(serviceToken.isMasterTokenBound(), joServiceToken.isMasterTokenBound());
        assertEquals(serviceToken.isUserIdTokenBound(), joServiceToken.isUserIdTokenBound());
        assertEquals(serviceToken.isUnbound(), joServiceToken.isUnbound());
        assertEquals(serviceToken.getMasterTokenSerialNumber(), joServiceToken.getMasterTokenSerialNumber());
        assertEquals(serviceToken.getUserIdTokenSerialNumber(), joServiceToken.getUserIdTokenSerialNumber());
        assertEquals(serviceToken.getName(), joServiceToken.getName());
        final String joJsonString = joServiceToken.toJSONString();
        assertNotNull(joJsonString);
        assertEquals(jsonString, joJsonString);
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
    public void equalsName() throws MslException, JSONException {
        final String nameA = NAME + "A";
        final String nameB = NAME + "B";
        final ServiceToken serviceTokenA = new ServiceToken(ctx, nameA, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        final ServiceToken serviceTokenB = new ServiceToken(ctx, nameB, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        final ServiceToken serviceTokenA2 = new ServiceToken(ctx, new JSONObject(serviceTokenA.toJSONString()), MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT);

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
    public void equalsMasterTokenSerialNumber() throws MslException, JSONException {
        final MasterToken masterTokenA = MslTestUtils.getMasterToken(ctx, 1, 1);
        final MasterToken masterTokenB = MslTestUtils.getMasterToken(ctx, 1, 2);
        final ServiceToken serviceTokenA = new ServiceToken(ctx, NAME, DATA, masterTokenA, null, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        final ServiceToken serviceTokenB = new ServiceToken(ctx, NAME, DATA, masterTokenB, null, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        final ServiceToken serviceTokenA2 = new ServiceToken(ctx, new JSONObject(serviceTokenA.toJSONString()), masterTokenA, null, CRYPTO_CONTEXT);

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
    public void equalsUserIdTokenSerialNumber() throws MslException, JSONException {
        final UserIdToken userIdTokenA = MslTestUtils.getUserIdToken(ctx, MASTER_TOKEN, 1, MockEmailPasswordAuthenticationFactory.USER);
        final UserIdToken userIdTokenB = MslTestUtils.getUserIdToken(ctx, MASTER_TOKEN, 2, MockEmailPasswordAuthenticationFactory.USER);
        final ServiceToken serviceTokenA = new ServiceToken(ctx, NAME, DATA, MASTER_TOKEN, userIdTokenA, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        final ServiceToken serviceTokenB = new ServiceToken(ctx, NAME, DATA, MASTER_TOKEN, userIdTokenB, ENCRYPTED, compressionAlgo, CRYPTO_CONTEXT);
        final ServiceToken serviceTokenA2 = new ServiceToken(ctx, new JSONObject(serviceTokenA.toJSONString()), MASTER_TOKEN, userIdTokenA, CRYPTO_CONTEXT);
        
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
    /** Random. */
    private static Random random;
}
