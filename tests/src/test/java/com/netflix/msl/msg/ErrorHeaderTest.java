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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.UnsupportedEncodingException;
import java.util.Collections;
import java.util.Date;
import java.util.Map;

import org.json.JSONException;
import org.json.JSONObject;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;

import com.netflix.msl.MslConstants;
import com.netflix.msl.MslConstants.ResponseCode;
import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslEntityAuthException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslException;
import com.netflix.msl.MslInternalException;
import com.netflix.msl.MslKeyExchangeException;
import com.netflix.msl.MslMessageException;
import com.netflix.msl.MslUserAuthException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.entityauth.EntityAuthenticationData;
import com.netflix.msl.entityauth.EntityAuthenticationFactory;
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.test.ExpectedMslException;
import com.netflix.msl.util.Base64;
import com.netflix.msl.util.JsonUtils;
import com.netflix.msl.util.MockMslContext;
import com.netflix.msl.util.MslContext;

/**
 * Error header unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class ErrorHeaderTest {
    /** Milliseconds per second. */
    private static final long MILLISECONDS_PER_SECOND = 1000;
    
    /** JSON key entity authentication data. */
    private static final String KEY_ENTITY_AUTHENTICATION_DATA = "entityauthdata";
    /** JSON key error data. */
    private static final String KEY_ERRORDATA = "errordata";
    /** JSON key error data signature. */
    private static final String KEY_SIGNATURE = "signature";
    
    // Message error data.
    /** JSON key recipient. */
    private static final String KEY_RECIPIENT = "recipient";
    /** JSON key timestamp. */
    private static final String KEY_TIMESTAMP = "timestamp";
    /** JSON key message ID. */
    private static final String KEY_MESSAGE_ID = "messageid";
    /** JSON key error code. */
    private static final String KEY_ERROR_CODE = "errorcode";
    /** JSON key internal code. */
    private static final String KEY_INTERNAL_CODE = "internalcode";
    /** JSON key error message. */
    private static final String KEY_ERROR_MESSAGE = "errormsg";
    /** JSON key user message. */
    private static final String KEY_USER_MESSAGE = "usermsg";
    
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
    
    @Rule
    public ExpectedMslException thrown = ExpectedMslException.none();
    
    /** MSL context. */
    private static MslContext ctx;
    /** Header crypto context. */
    private static ICryptoContext cryptoContext;
    
    private static EntityAuthenticationData ENTITY_AUTH_DATA;
    private static final String RECIPIENT = "recipient";
    private static final long MESSAGE_ID = 17;
    private static final ResponseCode ERROR_CODE = ResponseCode.FAIL;
    private static final int INTERNAL_CODE = 621;
    private static final String ERROR_MSG = "Error message.";
    private static final String USER_MSG = "User message.";
    private static final Map<String,ICryptoContext> CRYPTO_CONTEXTS = Collections.emptyMap();
    
    @BeforeClass
    public static void setup() throws MslEntityAuthException, MslEncodingException, MslCryptoException {
        ctx = new MockMslContext(EntityAuthenticationScheme.PSK, false);
        ENTITY_AUTH_DATA = ctx.getEntityAuthenticationData(null);

        final EntityAuthenticationScheme scheme = ENTITY_AUTH_DATA.getScheme();
        final EntityAuthenticationFactory factory = ctx.getEntityAuthenticationFactory(scheme);
        cryptoContext = factory.getCryptoContext(ctx, ENTITY_AUTH_DATA);
    }
    
    @AfterClass
    public static void teardown() {
        ENTITY_AUTH_DATA = null;
        ctx = null;
    }

    @Test
    public void ctors() throws MslEncodingException, MslEntityAuthException, MslMessageException, MslCryptoException {
        final ErrorHeader errorHeader = new ErrorHeader(ctx, ENTITY_AUTH_DATA, RECIPIENT, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
        assertEquals(ENTITY_AUTH_DATA, errorHeader.getEntityAuthenticationData());
        assertEquals(ERROR_CODE, errorHeader.getErrorCode());
        assertEquals(ERROR_MSG, errorHeader.getErrorMessage());
        assertEquals(INTERNAL_CODE, errorHeader.getInternalCode());
        assertEquals(MESSAGE_ID, errorHeader.getMessageId());
        assertEquals(USER_MSG, errorHeader.getUserMessage());
        assertEquals(RECIPIENT, errorHeader.getRecipient());
        assertTrue(isAboutNow(errorHeader.getTimestamp()));
    }
    
    @Test
    public void jsonString() throws MslEncodingException, MslEntityAuthException, JSONException, UnsupportedEncodingException, MslMessageException, MslCryptoException {
        final ErrorHeader errorHeader = new ErrorHeader(ctx, ENTITY_AUTH_DATA, RECIPIENT, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
        final String jsonString = errorHeader.toJSONString();
        assertNotNull(jsonString);
        
        final JSONObject jo = new JSONObject(jsonString);
        final JSONObject entityAuthDataJo = jo.getJSONObject(KEY_ENTITY_AUTHENTICATION_DATA);
        assertTrue(JsonUtils.equals(new JSONObject(ENTITY_AUTH_DATA.toJSONString()), entityAuthDataJo));
        final byte[] ciphertext = Base64.decode(jo.getString(KEY_ERRORDATA));
        final byte[] plaintext = cryptoContext.decrypt(ciphertext);
        final JSONObject errordata = new JSONObject(new String(plaintext, MslConstants.DEFAULT_CHARSET));
        final byte[] signature = Base64.decode(jo.getString(KEY_SIGNATURE));
        assertTrue(cryptoContext.verify(ciphertext, signature));

        assertEquals(RECIPIENT, errordata.getString(KEY_RECIPIENT));
        assertEquals(MESSAGE_ID, errordata.getLong(KEY_MESSAGE_ID));
        assertEquals(ERROR_CODE.intValue(), errordata.getInt(KEY_ERROR_CODE));
        assertEquals(INTERNAL_CODE, errordata.getInt(KEY_INTERNAL_CODE));
        assertEquals(ERROR_MSG, errordata.getString(KEY_ERROR_MESSAGE));
        assertEquals(USER_MSG, errordata.getString(KEY_USER_MESSAGE));
        assertTrue(isAboutNowSeconds(errordata.getLong(KEY_TIMESTAMP)));
    }
    
    @Test
    public void negativeInternalCodeJson() throws MslEncodingException, MslEntityAuthException, JSONException, MslMessageException, MslCryptoException {
        final ErrorHeader errorHeader = new ErrorHeader(ctx, ENTITY_AUTH_DATA, RECIPIENT, MESSAGE_ID, ERROR_CODE, -17, ERROR_MSG, USER_MSG);
        assertEquals(-1, errorHeader.getInternalCode());
        final String jsonString = errorHeader.toJSONString();
        assertNotNull(jsonString);
        
        final JSONObject jo = new JSONObject(jsonString);
        final JSONObject entityAuthDataJo = jo.getJSONObject(KEY_ENTITY_AUTHENTICATION_DATA);
        assertTrue(JsonUtils.equals(new JSONObject(ENTITY_AUTH_DATA.toJSONString()), entityAuthDataJo));
        final byte[] ciphertext = Base64.decode(jo.getString(KEY_ERRORDATA));
        final byte[] plaintext = cryptoContext.decrypt(ciphertext);
        final JSONObject errordata = new JSONObject(new String(plaintext, MslConstants.DEFAULT_CHARSET));
        final byte[] signature = Base64.decode(jo.getString(KEY_SIGNATURE));
        assertTrue(cryptoContext.verify(ciphertext, signature));

        assertEquals(RECIPIENT, errordata.getString(KEY_RECIPIENT));
        assertTrue(isAboutNowSeconds(errordata.getLong(KEY_TIMESTAMP)));
        assertEquals(MESSAGE_ID, errordata.getLong(KEY_MESSAGE_ID));
        assertEquals(ERROR_CODE.intValue(), errordata.getInt(KEY_ERROR_CODE));
        assertFalse(errordata.has(KEY_INTERNAL_CODE));
        assertEquals(ERROR_MSG, errordata.getString(KEY_ERROR_MESSAGE));
        assertEquals(USER_MSG, errordata.getString(KEY_USER_MESSAGE));
    }
    
    @Test
    public void nullRecipientJson() throws MslEncodingException, MslEntityAuthException, MslMessageException, JSONException, MslCryptoException {
        final ErrorHeader errorHeader = new ErrorHeader(ctx, ENTITY_AUTH_DATA, null, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
        assertNull(errorHeader.getRecipient());
        final String jsonString = errorHeader.toJSONString();
        assertNotNull(jsonString);
        
        final JSONObject jo = new JSONObject(jsonString);
        final JSONObject entityAuthDataJo = jo.getJSONObject(KEY_ENTITY_AUTHENTICATION_DATA);
        assertTrue(JsonUtils.equals(new JSONObject(ENTITY_AUTH_DATA.toJSONString()), entityAuthDataJo));
        final byte[] ciphertext = Base64.decode(jo.getString(KEY_ERRORDATA));
        final byte[] plaintext = cryptoContext.decrypt(ciphertext);
        final JSONObject errordata = new JSONObject(new String(plaintext, MslConstants.DEFAULT_CHARSET));
        final byte[] signature = Base64.decode(jo.getString(KEY_SIGNATURE));
        assertTrue(cryptoContext.verify(ciphertext, signature));

        assertFalse(errordata.has(KEY_RECIPIENT));
        assertTrue(isAboutNowSeconds(errordata.getLong(KEY_TIMESTAMP)));
        assertEquals(MESSAGE_ID, errordata.getLong(KEY_MESSAGE_ID));
        assertEquals(ERROR_CODE.intValue(), errordata.getInt(KEY_ERROR_CODE));
        assertEquals(INTERNAL_CODE, errordata.getInt(KEY_INTERNAL_CODE));
        assertEquals(ERROR_MSG, errordata.getString(KEY_ERROR_MESSAGE));
        assertEquals(USER_MSG, errordata.getString(KEY_USER_MESSAGE));
    }
    
    @Test
    public void nullErrorMessageJson() throws MslEncodingException, MslEntityAuthException, JSONException, MslMessageException, MslCryptoException {
        final ErrorHeader errorHeader = new ErrorHeader(ctx, ENTITY_AUTH_DATA, RECIPIENT, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, null, USER_MSG);
        assertNull(errorHeader.getErrorMessage());
        final String jsonString = errorHeader.toJSONString();
        assertNotNull(jsonString);
        
        final JSONObject jo = new JSONObject(jsonString);
        final JSONObject entityAuthDataJo = jo.getJSONObject(KEY_ENTITY_AUTHENTICATION_DATA);
        assertTrue(JsonUtils.equals(new JSONObject(ENTITY_AUTH_DATA.toJSONString()), entityAuthDataJo));
        final byte[] ciphertext = Base64.decode(jo.getString(KEY_ERRORDATA));
        final byte[] plaintext = cryptoContext.decrypt(ciphertext);
        final JSONObject errordata = new JSONObject(new String(plaintext, MslConstants.DEFAULT_CHARSET));
        final byte[] signature = Base64.decode(jo.getString(KEY_SIGNATURE));
        assertTrue(cryptoContext.verify(ciphertext, signature));

        assertEquals(RECIPIENT, errordata.getString(KEY_RECIPIENT));
        assertTrue(isAboutNowSeconds(errordata.getLong(KEY_TIMESTAMP)));
        assertEquals(MESSAGE_ID, errordata.getLong(KEY_MESSAGE_ID));
        assertEquals(ERROR_CODE.intValue(), errordata.getInt(KEY_ERROR_CODE));
        assertEquals(INTERNAL_CODE, errordata.getInt(KEY_INTERNAL_CODE));
        assertFalse(errordata.has(KEY_ERROR_MESSAGE));
        assertEquals(USER_MSG, errordata.getString(KEY_USER_MESSAGE));
    }
    
    @Test
    public void nullUserMessageJson() throws MslEncodingException, MslEntityAuthException, JSONException, MslMessageException, MslCryptoException {
        final ErrorHeader errorHeader = new ErrorHeader(ctx, ENTITY_AUTH_DATA, RECIPIENT, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, null);
        assertNull(errorHeader.getUserMessage());
        final String jsonString = errorHeader.toJSONString();
        assertNotNull(jsonString);
        
        final JSONObject jo = new JSONObject(jsonString);
        final JSONObject entityAuthDataJo = jo.getJSONObject(KEY_ENTITY_AUTHENTICATION_DATA);
        assertTrue(JsonUtils.equals(new JSONObject(ENTITY_AUTH_DATA.toJSONString()), entityAuthDataJo));
        final byte[] ciphertext = Base64.decode(jo.getString(KEY_ERRORDATA));
        final byte[] plaintext = cryptoContext.decrypt(ciphertext);
        final JSONObject errordata = new JSONObject(new String(plaintext, MslConstants.DEFAULT_CHARSET));
        final byte[] signature = Base64.decode(jo.getString(KEY_SIGNATURE));
        assertTrue(cryptoContext.verify(ciphertext, signature));

        assertEquals(RECIPIENT, errordata.getString(KEY_RECIPIENT));
        assertTrue(isAboutNowSeconds(errordata.getLong(KEY_TIMESTAMP)));
        assertEquals(MESSAGE_ID, errordata.getLong(KEY_MESSAGE_ID));
        assertEquals(ERROR_CODE.intValue(), errordata.getInt(KEY_ERROR_CODE));
        assertEquals(INTERNAL_CODE, errordata.getInt(KEY_INTERNAL_CODE));
        assertEquals(ERROR_MSG, errordata.getString(KEY_ERROR_MESSAGE));
        assertFalse(errordata.has(KEY_USER_MESSAGE));
    }
    
    @Test
    public void parseHeader() throws JSONException, MslKeyExchangeException, MslUserAuthException, MslException {
        final ErrorHeader errorHeader = new ErrorHeader(ctx, ENTITY_AUTH_DATA, RECIPIENT, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
        final JSONObject errorHeaderJo = new JSONObject(errorHeader.toJSONString());
        final Header header = Header.parseHeader(ctx, errorHeaderJo, CRYPTO_CONTEXTS);
        assertNotNull(header);
        assertTrue(header instanceof ErrorHeader);
        final ErrorHeader joErrorHeader = (ErrorHeader)header;
        
        assertEquals(errorHeader.getEntityAuthenticationData(), joErrorHeader.getEntityAuthenticationData());
        assertEquals(errorHeader.getTimestamp(), joErrorHeader.getTimestamp());
        assertEquals(errorHeader.getErrorCode(), joErrorHeader.getErrorCode());
        assertEquals(errorHeader.getErrorMessage(), joErrorHeader.getErrorMessage());
        assertEquals(errorHeader.getInternalCode(), joErrorHeader.getInternalCode());
        assertEquals(errorHeader.getMessageId(), joErrorHeader.getMessageId());
        assertEquals(errorHeader.getRecipient(), joErrorHeader.getRecipient());
        assertEquals(errorHeader.getUserMessage(), joErrorHeader.getUserMessage());
    }
    
    @Test
    public void missingEntityAuthDataCtor() throws MslEncodingException, MslEntityAuthException, MslMessageException, MslCryptoException {
        thrown.expect(MslMessageException.class);
        thrown.expectMslError(MslError.MESSAGE_ENTITY_NOT_FOUND);

        new ErrorHeader(ctx, null, RECIPIENT, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
    }
    
    @Test
    public void missingEntityAuthDataParseHeader() throws MslEncodingException, MslEntityAuthException, MslCryptoException, MslKeyExchangeException, MslUserAuthException, MslException, JSONException {
        thrown.expect(MslMessageException.class);
        thrown.expectMslError(MslError.MESSAGE_ENTITY_NOT_FOUND);

        final ErrorHeader errorHeader = new ErrorHeader(ctx, ENTITY_AUTH_DATA, RECIPIENT, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
        final JSONObject errorHeaderJo = new JSONObject(errorHeader.toJSONString());
        
        assertNotNull(errorHeaderJo.remove(KEY_ENTITY_AUTHENTICATION_DATA));
        
        Header.parseHeader(ctx, errorHeaderJo, CRYPTO_CONTEXTS);
    }
    
    @Test
    public void invalidEntityAuthData() throws MslEncodingException, MslEntityAuthException, MslCryptoException, MslKeyExchangeException, MslUserAuthException, MslException, JSONException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.JSON_PARSE_ERROR);

        final ErrorHeader errorHeader = new ErrorHeader(ctx, ENTITY_AUTH_DATA, RECIPIENT, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
        final JSONObject errorHeaderJo = new JSONObject(errorHeader.toJSONString());
        
        errorHeaderJo.put(KEY_ENTITY_AUTHENTICATION_DATA, "x");

        Header.parseHeader(ctx, errorHeaderJo, CRYPTO_CONTEXTS);
    }
    
    @Test
    public void missingSignature() throws JSONException, MslEncodingException, MslEntityAuthException, MslCryptoException, MslKeyExchangeException, MslUserAuthException, MslException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.JSON_PARSE_ERROR);

        final ErrorHeader errorHeader = new ErrorHeader(ctx, ENTITY_AUTH_DATA, RECIPIENT, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
        final JSONObject errorHeaderJo = new JSONObject(errorHeader.toJSONString());
        
        assertNotNull(errorHeaderJo.remove(KEY_SIGNATURE));

        Header.parseHeader(ctx, errorHeaderJo, CRYPTO_CONTEXTS);
    }
    
    // This unit test no longer passes because
    // Base64.decode() does not error when given invalid
    // Base64-encoded data.
    @Ignore
    @Test
    public void invalidSignature() throws JSONException, MslKeyExchangeException, MslUserAuthException, MslException {
        thrown.expect(MslMessageException.class);
        thrown.expectMslError(MslError.HEADER_SIGNATURE_INVALID);

        final ErrorHeader errorHeader = new ErrorHeader(ctx, ENTITY_AUTH_DATA, RECIPIENT, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
        final JSONObject errorHeaderJo = new JSONObject(errorHeader.toJSONString());
        
        errorHeaderJo.put(KEY_SIGNATURE, "x");

        Header.parseHeader(ctx, errorHeaderJo, CRYPTO_CONTEXTS);
    }
    
    @Test
    public void incorrectSignature() throws JSONException, MslKeyExchangeException, MslUserAuthException, MslException {
        thrown.expect(MslCryptoException.class);
        thrown.expectMslError(MslError.MESSAGE_VERIFICATION_FAILED);

        final ErrorHeader errorHeader = new ErrorHeader(ctx, ENTITY_AUTH_DATA, RECIPIENT, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
        final JSONObject errorHeaderJo = new JSONObject(errorHeader.toJSONString());
        
        errorHeaderJo.put(KEY_SIGNATURE, "AAA=");

        Header.parseHeader(ctx, errorHeaderJo, CRYPTO_CONTEXTS);
    }
    
    @Test
    public void missingErrordata() throws JSONException, MslKeyExchangeException, MslUserAuthException, MslException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.JSON_PARSE_ERROR);

        final ErrorHeader errorHeader = new ErrorHeader(ctx, ENTITY_AUTH_DATA, RECIPIENT, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
        final JSONObject errorHeaderJo = new JSONObject(errorHeader.toJSONString());
        
        assertNotNull(errorHeaderJo.remove(KEY_ERRORDATA));
        
        Header.parseHeader(ctx, errorHeaderJo, CRYPTO_CONTEXTS);
    }
    
    @Test
    public void invalidErrordata() throws MslEncodingException, MslEntityAuthException, MslCryptoException, MslKeyExchangeException, MslUserAuthException, MslException, JSONException {
        thrown.expect(MslCryptoException.class);

        final ErrorHeader errorHeader = new ErrorHeader(ctx, ENTITY_AUTH_DATA, RECIPIENT, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
        final JSONObject errorHeaderJo = new JSONObject(errorHeader.toJSONString());
        
        // This tests invalid but trusted error data so we must sign it.
        errorHeaderJo.put(KEY_ERRORDATA, "AA==");
        final byte[] ciphertext = Base64.decode(errorHeaderJo.getString(KEY_ERRORDATA));
        final byte[] signature = cryptoContext.sign(ciphertext);
        errorHeaderJo.put(KEY_SIGNATURE, Base64.encode(signature));
        
        Header.parseHeader(ctx, errorHeaderJo, CRYPTO_CONTEXTS);
    }
    
    @Test
    public void emptyErrordata() throws JSONException, MslKeyExchangeException, MslUserAuthException, MslException {
        thrown.expect(MslMessageException.class);
        thrown.expectMslError(MslError.HEADER_DATA_MISSING);

        final ErrorHeader errorHeader = new ErrorHeader(ctx, ENTITY_AUTH_DATA, RECIPIENT, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
        final JSONObject errorHeaderJo = new JSONObject(errorHeader.toJSONString());
        
        // This tests empty but trusted error data so we must sign it.
        final byte[] ciphertext = new byte[0];
        errorHeaderJo.put(KEY_ERRORDATA, Base64.encode(ciphertext));
        final byte[] signature = cryptoContext.sign(ciphertext);
        errorHeaderJo.put(KEY_SIGNATURE, Base64.encode(signature));
        
        Header.parseHeader(ctx, errorHeaderJo, CRYPTO_CONTEXTS);
    }
    
    @Test
    public void missingTimestamp() throws MslKeyExchangeException, MslUserAuthException, MslException {
        final ErrorHeader errorHeader = new ErrorHeader(ctx, ENTITY_AUTH_DATA, RECIPIENT, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
        final JSONObject errorHeaderJo = new JSONObject(errorHeader.toJSONString());

        // Before modifying the error data we need to decrypt it.
        final byte[] ciphertext = Base64.decode(errorHeaderJo.getString(KEY_ERRORDATA));
        final byte[] plaintext = cryptoContext.decrypt(ciphertext);
        final JSONObject errordata = new JSONObject(new String(plaintext, MslConstants.DEFAULT_CHARSET));
        
        // After modifying the error data we need to encrypt it.
        assertNotNull(errordata.remove(KEY_TIMESTAMP));
        final byte[] modifiedPlaintext = errordata.toString().getBytes(MslConstants.DEFAULT_CHARSET);
        final byte[] modifiedCiphertext = cryptoContext.encrypt(modifiedPlaintext);
        errorHeaderJo.put(KEY_ERRORDATA, Base64.encode(modifiedCiphertext));
        
        // The error data must be signed otherwise the error data will not be
        // processed.
        final byte[] modifiedSignature = cryptoContext.sign(modifiedCiphertext);
        errorHeaderJo.put(KEY_SIGNATURE, Base64.encode(modifiedSignature));

        Header.parseHeader(ctx, errorHeaderJo, CRYPTO_CONTEXTS);
    }
    
    @Test
    public void invalidTimestamp() throws MslKeyExchangeException, MslUserAuthException, MslException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.JSON_PARSE_ERROR);

        final ErrorHeader errorHeader = new ErrorHeader(ctx, ENTITY_AUTH_DATA, RECIPIENT, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
        final JSONObject errorHeaderJo = new JSONObject(errorHeader.toJSONString());

        // Before modifying the error data we need to decrypt it.
        final byte[] ciphertext = Base64.decode(errorHeaderJo.getString(KEY_ERRORDATA));
        final byte[] plaintext = cryptoContext.decrypt(ciphertext);
        final JSONObject errordata = new JSONObject(new String(plaintext, MslConstants.DEFAULT_CHARSET));

        // After modifying the error data we need to encrypt it.
        errordata.put(KEY_TIMESTAMP, "x");
        final byte[] modifiedPlaintext = errordata.toString().getBytes(MslConstants.DEFAULT_CHARSET);
        final byte[] modifiedCiphertext = cryptoContext.encrypt(modifiedPlaintext);
        errorHeaderJo.put(KEY_ERRORDATA, Base64.encode(modifiedCiphertext));

        // The error data must be signed otherwise the error data will not be
        // processed.
        final byte[] modifiedSignature = cryptoContext.sign(modifiedCiphertext);
        errorHeaderJo.put(KEY_SIGNATURE, Base64.encode(modifiedSignature));
        
        Header.parseHeader(ctx, errorHeaderJo, CRYPTO_CONTEXTS);
    }
    
    @Test
    public void missingMessageId() throws JSONException, UnsupportedEncodingException, MslKeyExchangeException, MslUserAuthException, MslException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.JSON_PARSE_ERROR);

        final ErrorHeader errorHeader = new ErrorHeader(ctx, ENTITY_AUTH_DATA, RECIPIENT, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
        final JSONObject errorHeaderJo = new JSONObject(errorHeader.toJSONString());
        
        // Before modifying the error data we need to decrypt it.
        final byte[] ciphertext = Base64.decode(errorHeaderJo.getString(KEY_ERRORDATA));
        final byte[] plaintext = cryptoContext.decrypt(ciphertext);
        final JSONObject errordata = new JSONObject(new String(plaintext, MslConstants.DEFAULT_CHARSET));
        
        // After modifying the error data we need to encrypt it.
        assertNotNull(errordata.remove(KEY_MESSAGE_ID));
        final byte[] modifiedPlaintext = errordata.toString().getBytes(MslConstants.DEFAULT_CHARSET);
        final byte[] modifiedCiphertext = cryptoContext.encrypt(modifiedPlaintext);
        errorHeaderJo.put(KEY_ERRORDATA, Base64.encode(modifiedCiphertext));
        
        // The error data must be signed otherwise the error data will not be
        // processed.
        final byte[] modifiedSignature = cryptoContext.sign(modifiedCiphertext);
        errorHeaderJo.put(KEY_SIGNATURE, Base64.encode(modifiedSignature));
        
        Header.parseHeader(ctx, errorHeaderJo, CRYPTO_CONTEXTS);
    }
    
    @Test
    public void invalidMessageId() throws UnsupportedEncodingException, JSONException, MslKeyExchangeException, MslUserAuthException, MslException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.JSON_PARSE_ERROR);

        final ErrorHeader errorHeader = new ErrorHeader(ctx, ENTITY_AUTH_DATA, RECIPIENT, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
        final JSONObject errorHeaderJo = new JSONObject(errorHeader.toJSONString());

        // Before modifying the error data we need to decrypt it.
        final byte[] ciphertext = Base64.decode(errorHeaderJo.getString(KEY_ERRORDATA));
        final byte[] plaintext = cryptoContext.decrypt(ciphertext);
        final JSONObject errordata = new JSONObject(new String(plaintext, MslConstants.DEFAULT_CHARSET));

        // After modifying the error data we need to encrypt it.
        errordata.put(KEY_MESSAGE_ID, "x");
        final byte[] modifiedPlaintext = errordata.toString().getBytes(MslConstants.DEFAULT_CHARSET);
        final byte[] modifiedCiphertext = cryptoContext.encrypt(modifiedPlaintext);
        errorHeaderJo.put(KEY_ERRORDATA, Base64.encode(modifiedCiphertext));

        // The error data must be signed otherwise the error data will not be
        // processed.
        final byte[] modifiedSignature = cryptoContext.sign(modifiedCiphertext);
        errorHeaderJo.put(KEY_SIGNATURE, Base64.encode(modifiedSignature));
        
        Header.parseHeader(ctx, errorHeaderJo, CRYPTO_CONTEXTS);
    }
    
    @Test(expected = MslInternalException.class)
    public void negativeMessageIdCtor() throws MslEncodingException, MslEntityAuthException, MslMessageException, MslCryptoException {
        new ErrorHeader(ctx, ENTITY_AUTH_DATA, RECIPIENT, -1, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
    }
    
    @Test(expected = MslInternalException.class)
    public void tooLargeMessageIdCtor() throws MslEncodingException, MslEntityAuthException, MslMessageException, MslCryptoException {
        new ErrorHeader(ctx, ENTITY_AUTH_DATA, RECIPIENT, MslConstants.MAX_LONG_VALUE + 1, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
    }
    
    @Test
    public void negativeMessageIdParseHeader() throws MslEncodingException, MslEntityAuthException, MslKeyExchangeException, MslUserAuthException, JSONException, MslException {
        thrown.expect(MslMessageException.class);
        thrown.expectMslError(MslError.MESSAGE_ID_OUT_OF_RANGE);

        final ErrorHeader errorHeader = new ErrorHeader(ctx, ENTITY_AUTH_DATA, RECIPIENT, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
        final JSONObject errorHeaderJo = new JSONObject(errorHeader.toJSONString());

        // Before modifying the error data we need to decrypt it.
        final byte[] ciphertext = Base64.decode(errorHeaderJo.getString(KEY_ERRORDATA));
        final byte[] plaintext = cryptoContext.decrypt(ciphertext);
        final JSONObject errordata = new JSONObject(new String(plaintext, MslConstants.DEFAULT_CHARSET));

        // After modifying the error data we need to encrypt it.
        errordata.put(KEY_MESSAGE_ID, -1L);
        final byte[] modifiedPlaintext = errordata.toString().getBytes(MslConstants.DEFAULT_CHARSET);
        final byte[] modifiedCiphertext = cryptoContext.encrypt(modifiedPlaintext);
        errorHeaderJo.put(KEY_ERRORDATA, Base64.encode(modifiedCiphertext));

        // The error data must be signed otherwise the error data will not be
        // processed.
        final byte[] modifiedSignature = cryptoContext.sign(modifiedCiphertext);
        errorHeaderJo.put(KEY_SIGNATURE, Base64.encode(modifiedSignature));
        
        Header.parseHeader(ctx, errorHeaderJo, CRYPTO_CONTEXTS);
    }
    
    @Test
    public void tooLargeMessageIdParseHeader() throws MslEncodingException, MslEntityAuthException, MslKeyExchangeException, MslUserAuthException, JSONException, MslException {
        thrown.expect(MslMessageException.class);
        thrown.expectMslError(MslError.MESSAGE_ID_OUT_OF_RANGE);

        final ErrorHeader errorHeader = new ErrorHeader(ctx, ENTITY_AUTH_DATA, RECIPIENT, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
        final JSONObject errorHeaderJo = new JSONObject(errorHeader.toJSONString());

        // Before modifying the error data we need to decrypt it.
        final byte[] ciphertext = Base64.decode(errorHeaderJo.getString(KEY_ERRORDATA));
        final byte[] plaintext = cryptoContext.decrypt(ciphertext);
        final JSONObject errordata = new JSONObject(new String(plaintext, MslConstants.DEFAULT_CHARSET));

        // After modifying the error data we need to encrypt it.
        errordata.put(KEY_MESSAGE_ID, MslConstants.MAX_LONG_VALUE + 1);
        final byte[] modifiedPlaintext = errordata.toString().getBytes(MslConstants.DEFAULT_CHARSET);
        final byte[] modifiedCiphertext = cryptoContext.encrypt(modifiedPlaintext);
        errorHeaderJo.put(KEY_ERRORDATA, Base64.encode(modifiedCiphertext));

        // The error data must be signed otherwise the error data will not be
        // processed.
        final byte[] modifiedSignature = cryptoContext.sign(modifiedCiphertext);
        errorHeaderJo.put(KEY_SIGNATURE, Base64.encode(modifiedSignature));
        
        Header.parseHeader(ctx, errorHeaderJo, CRYPTO_CONTEXTS);
    }
    
    @Test
    public void missingErrorCode() throws MslEncodingException, MslEntityAuthException, MslCryptoException, MslKeyExchangeException, MslUserAuthException, MslException, JSONException, UnsupportedEncodingException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.JSON_PARSE_ERROR);
        thrown.expectMessageId(MESSAGE_ID);

        final ErrorHeader errorHeader = new ErrorHeader(ctx, ENTITY_AUTH_DATA, RECIPIENT, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
        final JSONObject errorHeaderJo = new JSONObject(errorHeader.toJSONString());
        
        // Before modifying the error data we need to decrypt it.
        final byte[] ciphertext = Base64.decode(errorHeaderJo.getString(KEY_ERRORDATA));
        final byte[] plaintext = cryptoContext.decrypt(ciphertext);
        final JSONObject errordata = new JSONObject(new String(plaintext, MslConstants.DEFAULT_CHARSET));
        
        // After modifying the error data we need to encrypt it.
        assertNotNull(errordata.remove(KEY_ERROR_CODE));
        final byte[] modifiedPlaintext = errordata.toString().getBytes(MslConstants.DEFAULT_CHARSET);
        final byte[] modifiedCiphertext = cryptoContext.encrypt(modifiedPlaintext);
        errorHeaderJo.put(KEY_ERRORDATA, Base64.encode(modifiedCiphertext));
        
        // The error data must be signed otherwise the error data will not be
        // processed.
        final byte[] modifiedSignature = cryptoContext.sign(modifiedCiphertext);
        errorHeaderJo.put(KEY_SIGNATURE, Base64.encode(modifiedSignature));
        
        Header.parseHeader(ctx, errorHeaderJo, CRYPTO_CONTEXTS);
    }
    
    @Test
    public void invalidErrorCode() throws MslEncodingException, MslEntityAuthException, MslCryptoException, MslKeyExchangeException, MslUserAuthException, MslException, JSONException, UnsupportedEncodingException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.JSON_PARSE_ERROR);
        thrown.expectMessageId(MESSAGE_ID);

        final ErrorHeader errorHeader = new ErrorHeader(ctx, ENTITY_AUTH_DATA, RECIPIENT, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
        final JSONObject errorHeaderJo = new JSONObject(errorHeader.toJSONString());

        // Before modifying the error data we need to decrypt it.
        final byte[] ciphertext = Base64.decode(errorHeaderJo.getString(KEY_ERRORDATA));
        final byte[] plaintext = cryptoContext.decrypt(ciphertext);
        final JSONObject errordata = new JSONObject(new String(plaintext, MslConstants.DEFAULT_CHARSET));

        // After modifying the error data we need to encrypt it.
        errordata.put(KEY_ERROR_CODE, "x");
        final byte[] modifiedPlaintext = errordata.toString().getBytes(MslConstants.DEFAULT_CHARSET);
        final byte[] modifiedCiphertext = cryptoContext.encrypt(modifiedPlaintext);
        errorHeaderJo.put(KEY_ERRORDATA, Base64.encode(modifiedCiphertext));

        // The error data must be signed otherwise the error data will not be
        // processed.
        final byte[] modifiedSignature = cryptoContext.sign(modifiedCiphertext);
        errorHeaderJo.put(KEY_SIGNATURE, Base64.encode(modifiedSignature));
        
        Header.parseHeader(ctx, errorHeaderJo, CRYPTO_CONTEXTS);
    }
    
    @Test
    public void missingInternalCode() throws JSONException, MslKeyExchangeException, MslUserAuthException, MslException {
        final ErrorHeader errorHeader = new ErrorHeader(ctx, ENTITY_AUTH_DATA, RECIPIENT, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
        final JSONObject errorHeaderJo = new JSONObject(errorHeader.toJSONString());
        
        // Before modifying the error data we need to decrypt it.
        final byte[] ciphertext = Base64.decode(errorHeaderJo.getString(KEY_ERRORDATA));
        final byte[] plaintext = cryptoContext.decrypt(ciphertext);
        final JSONObject errordata = new JSONObject(new String(plaintext, MslConstants.DEFAULT_CHARSET));
        
        // After modifying the error data we need to encrypt it.
        assertNotNull(errordata.remove(KEY_INTERNAL_CODE));
        final byte[] modifiedPlaintext = errordata.toString().getBytes(MslConstants.DEFAULT_CHARSET);
        final byte[] modifiedCiphertext = cryptoContext.encrypt(modifiedPlaintext);
        errorHeaderJo.put(KEY_ERRORDATA, Base64.encode(modifiedCiphertext));
        
        // The error data must be signed otherwise the error data will not be
        // processed.
        final byte[] modifiedSignature = cryptoContext.sign(modifiedCiphertext);
        errorHeaderJo.put(KEY_SIGNATURE, Base64.encode(modifiedSignature));
        
        final ErrorHeader joErrorHeader = (ErrorHeader)Header.parseHeader(ctx, errorHeaderJo, CRYPTO_CONTEXTS);
        assertEquals(-1, joErrorHeader.getInternalCode());
    }
    
    @Test
    public void invalidInternalCode() throws JSONException, MslKeyExchangeException, MslUserAuthException, MslException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.JSON_PARSE_ERROR);
        thrown.expectMessageId(MESSAGE_ID);

        final ErrorHeader errorHeader = new ErrorHeader(ctx, ENTITY_AUTH_DATA, RECIPIENT, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
        final JSONObject errorHeaderJo = new JSONObject(errorHeader.toJSONString());
        
        // Before modifying the error data we need to decrypt it.
        final byte[] ciphertext = Base64.decode(errorHeaderJo.getString(KEY_ERRORDATA));
        final byte[] plaintext = cryptoContext.decrypt(ciphertext);
        final JSONObject errordata = new JSONObject(new String(plaintext, MslConstants.DEFAULT_CHARSET));
        
        // After modifying the error data we need to encrypt it.
        errordata.put(KEY_INTERNAL_CODE, "x");
        final byte[] modifiedPlaintext = errordata.toString().getBytes(MslConstants.DEFAULT_CHARSET);
        final byte[] modifiedCiphertext = cryptoContext.encrypt(modifiedPlaintext);
        errorHeaderJo.put(KEY_ERRORDATA, Base64.encode(modifiedCiphertext));
        
        // The error data must be signed otherwise the error data will not be
        // processed.
        final byte[] modifiedSignature = cryptoContext.sign(modifiedCiphertext);
        errorHeaderJo.put(KEY_SIGNATURE, Base64.encode(modifiedSignature));
        
        Header.parseHeader(ctx, errorHeaderJo, CRYPTO_CONTEXTS);
    }
    
    @Test
    public void negativeInternalCode() throws JSONException, MslKeyExchangeException, MslUserAuthException, MslException {
        thrown.expect(MslMessageException.class);
        thrown.expectMslError(MslError.INTERNAL_CODE_NEGATIVE);
        thrown.expectMessageId(MESSAGE_ID);

        final ErrorHeader errorHeader = new ErrorHeader(ctx, ENTITY_AUTH_DATA, RECIPIENT, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
        final JSONObject errorHeaderJo = new JSONObject(errorHeader.toJSONString());
        
        // Before modifying the error data we need to decrypt it.
        final byte[] ciphertext = Base64.decode(errorHeaderJo.getString(KEY_ERRORDATA));
        final byte[] plaintext = cryptoContext.decrypt(ciphertext);
        final JSONObject errordata = new JSONObject(new String(plaintext, MslConstants.DEFAULT_CHARSET));
        
        // After modifying the error data we need to encrypt it.
        errordata.put(KEY_INTERNAL_CODE, -17);
        final byte[] modifiedPlaintext = errordata.toString().getBytes(MslConstants.DEFAULT_CHARSET);
        final byte[] modifiedCiphertext = cryptoContext.encrypt(modifiedPlaintext);
        errorHeaderJo.put(KEY_ERRORDATA, Base64.encode(modifiedCiphertext));
        
        // The error data must be signed otherwise the error data will not be
        // processed.
        final byte[] modifiedSignature = cryptoContext.sign(modifiedCiphertext);
        errorHeaderJo.put(KEY_SIGNATURE, Base64.encode(modifiedSignature));
        
        Header.parseHeader(ctx, errorHeaderJo, CRYPTO_CONTEXTS);
    }
    
    @Test
    public void missingErrorMessage() throws UnsupportedEncodingException, JSONException, MslKeyExchangeException, MslUserAuthException, MslException {
        final ErrorHeader errorHeader = new ErrorHeader(ctx, ENTITY_AUTH_DATA, RECIPIENT, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
        final JSONObject errorHeaderJo = new JSONObject(errorHeader.toJSONString());
        
        // Before modifying the error data we need to decrypt it.
        final byte[] ciphertext = Base64.decode(errorHeaderJo.getString(KEY_ERRORDATA));
        final byte[] plaintext = cryptoContext.decrypt(ciphertext);
        final JSONObject errordata = new JSONObject(new String(plaintext, MslConstants.DEFAULT_CHARSET));
        
        // After modifying the error data we need to encrypt it.
        assertNotNull(errordata.remove(KEY_ERROR_MESSAGE));
        final byte[] modifiedPlaintext = errordata.toString().getBytes(MslConstants.DEFAULT_CHARSET);
        final byte[] modifiedCiphertext = cryptoContext.encrypt(modifiedPlaintext);
        errorHeaderJo.put(KEY_ERRORDATA, Base64.encode(modifiedCiphertext));
        
        // The error data must be signed otherwise the error data will not be
        // processed.
        final byte[] modifiedSignature = cryptoContext.sign(modifiedCiphertext);
        errorHeaderJo.put(KEY_SIGNATURE, Base64.encode(modifiedSignature));
        
        final ErrorHeader joErrorHeader = (ErrorHeader)Header.parseHeader(ctx, errorHeaderJo, CRYPTO_CONTEXTS);
        assertNull(joErrorHeader.getErrorMessage());
    }
    
    @Test
    public void missingUserMessage() throws MslEncodingException, MslEntityAuthException, MslMessageException, MslKeyExchangeException, MslUserAuthException, JSONException, MslException {
        final ErrorHeader errorHeader = new ErrorHeader(ctx, ENTITY_AUTH_DATA, RECIPIENT, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
        final JSONObject errorHeaderJo = new JSONObject(errorHeader.toJSONString());
        
        // Before modifying the error data we need to decrypt it.
        final byte[] ciphertext = Base64.decode(errorHeaderJo.getString(KEY_ERRORDATA));
        final byte[] plaintext = cryptoContext.decrypt(ciphertext);
        final JSONObject errordata = new JSONObject(new String(plaintext, MslConstants.DEFAULT_CHARSET));
        
        // After modifying the error data we need to encrypt it.
        assertNotNull(errordata.remove(KEY_USER_MESSAGE));
        final byte[] modifiedPlaintext = errordata.toString().getBytes(MslConstants.DEFAULT_CHARSET);
        final byte[] modifiedCiphertext = cryptoContext.encrypt(modifiedPlaintext);
        errorHeaderJo.put(KEY_ERRORDATA, Base64.encode(modifiedCiphertext));
        
        // The error data must be signed otherwise the error data will not be
        // processed.
        final byte[] modifiedSignature = cryptoContext.sign(modifiedCiphertext);
        errorHeaderJo.put(KEY_SIGNATURE, Base64.encode(modifiedSignature));
        
        final ErrorHeader joErrorHeader = (ErrorHeader)Header.parseHeader(ctx, errorHeaderJo, CRYPTO_CONTEXTS);
        assertNull(joErrorHeader.getUserMessage());
    }
    
    @Test
    public void equalsRecipient() throws MslKeyExchangeException, MslUserAuthException, MslException, JSONException {
        final String recipientA = "A";
        final String recipientB = "B";
        final ErrorHeader errorHeaderA = new ErrorHeader(ctx, ENTITY_AUTH_DATA, recipientA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
        final ErrorHeader errorHeaderB = new ErrorHeader(ctx, ENTITY_AUTH_DATA, recipientB, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
        final ErrorHeader errorHeaderA2 = (ErrorHeader)Header.parseHeader(ctx, new JSONObject(errorHeaderA.toJSONString()), CRYPTO_CONTEXTS);

        assertTrue(errorHeaderA.equals(errorHeaderA));
        assertEquals(errorHeaderA.hashCode(), errorHeaderA.hashCode());
        
        assertFalse(errorHeaderA.equals(errorHeaderB));
        assertFalse(errorHeaderB.equals(errorHeaderA));
        assertTrue(errorHeaderA.hashCode() != errorHeaderB.hashCode());
        
        assertTrue(errorHeaderA.equals(errorHeaderA2));
        assertTrue(errorHeaderA2.equals(errorHeaderA));
        assertEquals(errorHeaderA.hashCode(), errorHeaderA2.hashCode());
    }
    
    @Test
    public void equalsTimestamp() throws InterruptedException, MslKeyExchangeException, MslUserAuthException, JSONException, MslException {
        final ErrorHeader errorHeaderA = new ErrorHeader(ctx, ENTITY_AUTH_DATA, RECIPIENT, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
        Thread.sleep(MILLISECONDS_PER_SECOND);
        final ErrorHeader errorHeaderB = new ErrorHeader(ctx, ENTITY_AUTH_DATA, RECIPIENT, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
        final ErrorHeader errorHeaderA2 = (ErrorHeader)Header.parseHeader(ctx, new JSONObject(errorHeaderA.toJSONString()), CRYPTO_CONTEXTS);

        assertTrue(errorHeaderA.equals(errorHeaderA));
        assertEquals(errorHeaderA.hashCode(), errorHeaderA.hashCode());
        
        assertFalse(errorHeaderA.equals(errorHeaderB));
        assertFalse(errorHeaderB.equals(errorHeaderA));
        assertTrue(errorHeaderA.hashCode() != errorHeaderB.hashCode());
        
        assertTrue(errorHeaderA.equals(errorHeaderA2));
        assertTrue(errorHeaderA2.equals(errorHeaderA));
        assertEquals(errorHeaderA.hashCode(), errorHeaderA2.hashCode());
    }
    
    @Test
    public void equalsMessageId() throws MslKeyExchangeException, MslUserAuthException, MslException, JSONException {
        final long messageIdA = 1;
        final long messageIdB = 2;
        final ErrorHeader errorHeaderA = new ErrorHeader(ctx, ENTITY_AUTH_DATA, RECIPIENT, messageIdA, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
        final ErrorHeader errorHeaderB = new ErrorHeader(ctx, ENTITY_AUTH_DATA, RECIPIENT, messageIdB, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
        final ErrorHeader errorHeaderA2 = (ErrorHeader)Header.parseHeader(ctx, new JSONObject(errorHeaderA.toJSONString()), CRYPTO_CONTEXTS);

        assertTrue(errorHeaderA.equals(errorHeaderA));
        assertEquals(errorHeaderA.hashCode(), errorHeaderA.hashCode());
        
        assertFalse(errorHeaderA.equals(errorHeaderB));
        assertFalse(errorHeaderB.equals(errorHeaderA));
        assertTrue(errorHeaderA.hashCode() != errorHeaderB.hashCode());
        
        assertTrue(errorHeaderA.equals(errorHeaderA2));
        assertTrue(errorHeaderA2.equals(errorHeaderA));
        assertEquals(errorHeaderA.hashCode(), errorHeaderA2.hashCode());
    }
    
    @Test
    public void equalsErrorCode() throws MslKeyExchangeException, MslUserAuthException, MslException, JSONException {
        final ResponseCode errorCodeA = ResponseCode.FAIL;
        final ResponseCode errorCodeB = ResponseCode.TRANSIENT_FAILURE;
        final ErrorHeader errorHeaderA = new ErrorHeader(ctx, ENTITY_AUTH_DATA, RECIPIENT, MESSAGE_ID, errorCodeA, INTERNAL_CODE, ERROR_MSG, USER_MSG);
        final ErrorHeader errorHeaderB = new ErrorHeader(ctx, ENTITY_AUTH_DATA, RECIPIENT, MESSAGE_ID, errorCodeB, INTERNAL_CODE, ERROR_MSG, USER_MSG);
        final ErrorHeader errorHeaderA2 = (ErrorHeader)Header.parseHeader(ctx, new JSONObject(errorHeaderA.toJSONString()), CRYPTO_CONTEXTS);
        
        assertTrue(errorHeaderA.equals(errorHeaderA));
        assertEquals(errorHeaderA.hashCode(), errorHeaderA.hashCode());
        
        assertFalse(errorHeaderA.equals(errorHeaderB));
        assertFalse(errorHeaderB.equals(errorHeaderA));
        assertTrue(errorHeaderA.hashCode() != errorHeaderB.hashCode());
        
        assertTrue(errorHeaderA.equals(errorHeaderA2));
        assertTrue(errorHeaderA2.equals(errorHeaderA));
        assertEquals(errorHeaderA.hashCode(), errorHeaderA2.hashCode());
    }
    
    @Test
    public void equalsInternalCode() throws MslKeyExchangeException, MslUserAuthException, MslException, JSONException {
        final int internalCodeA = 1;
        final int internalCodeB = 2;
        final ErrorHeader errorHeaderA = new ErrorHeader(ctx, ENTITY_AUTH_DATA, RECIPIENT, MESSAGE_ID, ERROR_CODE, internalCodeA, ERROR_MSG, USER_MSG);
        final ErrorHeader errorHeaderB = new ErrorHeader(ctx, ENTITY_AUTH_DATA, RECIPIENT, MESSAGE_ID, ERROR_CODE, internalCodeB, ERROR_MSG, USER_MSG);
        final ErrorHeader errorHeaderA2 = (ErrorHeader)Header.parseHeader(ctx, new JSONObject(errorHeaderA.toJSONString()), CRYPTO_CONTEXTS);
        
        assertTrue(errorHeaderA.equals(errorHeaderA));
        assertEquals(errorHeaderA.hashCode(), errorHeaderA.hashCode());
        
        assertFalse(errorHeaderA.equals(errorHeaderB));
        assertFalse(errorHeaderB.equals(errorHeaderA));
        assertTrue(errorHeaderA.hashCode() != errorHeaderB.hashCode());
        
        assertTrue(errorHeaderA.equals(errorHeaderA2));
        assertTrue(errorHeaderA2.equals(errorHeaderA));
        assertEquals(errorHeaderA.hashCode(), errorHeaderA2.hashCode());
    }
    
    @Test
    public void equalsErrorMessage() throws MslKeyExchangeException, MslUserAuthException, MslException, JSONException {
        final String errorMsgA = "A";
        final String errorMsgB = "B";
        final ErrorHeader errorHeaderA = new ErrorHeader(ctx, ENTITY_AUTH_DATA, RECIPIENT, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, errorMsgA, USER_MSG);
        final ErrorHeader errorHeaderB = new ErrorHeader(ctx, ENTITY_AUTH_DATA, RECIPIENT, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, errorMsgB, USER_MSG);
        final ErrorHeader errorHeaderC = new ErrorHeader(ctx, ENTITY_AUTH_DATA, RECIPIENT, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, null, USER_MSG);
        final ErrorHeader errorHeaderA2 = (ErrorHeader)Header.parseHeader(ctx, new JSONObject(errorHeaderA.toJSONString()), CRYPTO_CONTEXTS);
        
        assertTrue(errorHeaderA.equals(errorHeaderA));
        assertEquals(errorHeaderA.hashCode(), errorHeaderA.hashCode());
        
        assertFalse(errorHeaderA.equals(errorHeaderB));
        assertFalse(errorHeaderB.equals(errorHeaderA));
        assertTrue(errorHeaderA.hashCode() != errorHeaderB.hashCode());
        
        assertFalse(errorHeaderA.equals(errorHeaderC));
        assertFalse(errorHeaderC.equals(errorHeaderA));
        assertTrue(errorHeaderA.hashCode() != errorHeaderC.hashCode());
        
        assertTrue(errorHeaderA.equals(errorHeaderA2));
        assertTrue(errorHeaderA2.equals(errorHeaderA));
        assertEquals(errorHeaderA.hashCode(), errorHeaderA2.hashCode());
    }
    
    @Test
    public void equalsUserMessage() throws MslKeyExchangeException, MslUserAuthException, MslException, JSONException {
        final String userMsgA = "A";
        final String userMsgB = "B";
        final ErrorHeader errorHeaderA = new ErrorHeader(ctx, ENTITY_AUTH_DATA, RECIPIENT, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, userMsgA);
        final ErrorHeader errorHeaderB = new ErrorHeader(ctx, ENTITY_AUTH_DATA, RECIPIENT, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, userMsgB);
        final ErrorHeader errorHeaderC = new ErrorHeader(ctx, ENTITY_AUTH_DATA, RECIPIENT, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, null);
        final ErrorHeader errorHeaderA2 = (ErrorHeader)Header.parseHeader(ctx, new JSONObject(errorHeaderA.toJSONString()), CRYPTO_CONTEXTS);
        
        assertTrue(errorHeaderA.equals(errorHeaderA));
        assertEquals(errorHeaderA.hashCode(), errorHeaderA.hashCode());
        
        assertFalse(errorHeaderA.equals(errorHeaderB));
        assertFalse(errorHeaderB.equals(errorHeaderA));
        assertTrue(errorHeaderA.hashCode() != errorHeaderB.hashCode());
        
        assertFalse(errorHeaderA.equals(errorHeaderC));
        assertFalse(errorHeaderC.equals(errorHeaderA));
        assertTrue(errorHeaderA.hashCode() != errorHeaderC.hashCode());
        
        assertTrue(errorHeaderA.equals(errorHeaderA2));
        assertTrue(errorHeaderA2.equals(errorHeaderA));
        assertEquals(errorHeaderA.hashCode(), errorHeaderA2.hashCode());
    }
    
    @Test
    public void equalsObject() throws MslEncodingException, MslEntityAuthException, MslMessageException, MslCryptoException {
        final ErrorHeader errorHeader = new ErrorHeader(ctx, ENTITY_AUTH_DATA, RECIPIENT, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
        assertFalse(errorHeader.equals(null));
        assertFalse(errorHeader.equals(ERROR_MSG));
        assertTrue(errorHeader.hashCode() != ERROR_MSG.hashCode());
    }
}
