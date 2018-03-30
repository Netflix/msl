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
import java.util.Collections;
import java.util.Date;
import java.util.Map;

import org.bouncycastle.util.encoders.Base64;
import org.junit.AfterClass;
import org.junit.BeforeClass;
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
import com.netflix.msl.io.MslEncoderException;
import com.netflix.msl.io.MslEncoderFactory;
import com.netflix.msl.io.MslEncoderFormat;
import com.netflix.msl.io.MslEncoderUtils;
import com.netflix.msl.io.MslObject;
import com.netflix.msl.test.ExpectedMslException;
import com.netflix.msl.util.MockMslContext;
import com.netflix.msl.util.MslContext;
import com.netflix.msl.util.MslTestUtils;

/**
 * Error header unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class ErrorHeaderTest {
	/** MSL encoder format. */
	private static final MslEncoderFormat ENCODER_FORMAT = MslEncoderFormat.JSON;

    /** Milliseconds per second. */
    private static final long MILLISECONDS_PER_SECOND = 1000;
    
    /** Key entity authentication data. */
    private static final String KEY_ENTITY_AUTHENTICATION_DATA = "entityauthdata";
    /** Key error data. */
    private static final String KEY_ERRORDATA = "errordata";
    /** Key error data signature. */
    private static final String KEY_SIGNATURE = "signature";
    
    // Message error data.
    /** Key timestamp. */
    private static final String KEY_TIMESTAMP = "timestamp";
    /** Key message ID. */
    private static final String KEY_MESSAGE_ID = "messageid";
    /** Key error code. */
    private static final String KEY_ERROR_CODE = "errorcode";
    /** Key internal code. */
    private static final String KEY_INTERNAL_CODE = "internalcode";
    /** Key error message. */
    private static final String KEY_ERROR_MESSAGE = "errormsg";
    /** Key user message. */
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
    /** MSL encoder factory. */
    private static MslEncoderFactory encoder;
    /** Header crypto context. */
    private static ICryptoContext cryptoContext;
    
    private static EntityAuthenticationData ENTITY_AUTH_DATA;
    private static final long MESSAGE_ID = 17;
    private static final ResponseCode ERROR_CODE = ResponseCode.FAIL;
    private static final int INTERNAL_CODE = 621;
    private static final String ERROR_MSG = "Error message.";
    private static final String USER_MSG = "User message.";
    private static final Map<String,ICryptoContext> CRYPTO_CONTEXTS = Collections.emptyMap();
    
    @BeforeClass
    public static void setup() throws MslEntityAuthException, MslEncodingException, MslCryptoException {
        ctx = new MockMslContext(EntityAuthenticationScheme.PSK, false);
        encoder = ctx.getMslEncoderFactory();
        ENTITY_AUTH_DATA = ctx.getEntityAuthenticationData(null);

        final EntityAuthenticationScheme scheme = ENTITY_AUTH_DATA.getScheme();
        final EntityAuthenticationFactory factory = ctx.getEntityAuthenticationFactory(scheme);
        cryptoContext = factory.getCryptoContext(ctx, ENTITY_AUTH_DATA);
    }
    
    @AfterClass
    public static void teardown() {
        ENTITY_AUTH_DATA = null;
        encoder = null;
        ctx = null;
    }

    @Test
    public void ctors() throws MslEncodingException, MslEntityAuthException, MslMessageException, MslCryptoException {
        final ErrorHeader errorHeader = new ErrorHeader(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
        assertEquals(ENTITY_AUTH_DATA, errorHeader.getEntityAuthenticationData());
        assertEquals(ERROR_CODE, errorHeader.getErrorCode());
        assertEquals(ERROR_MSG, errorHeader.getErrorMessage());
        assertEquals(INTERNAL_CODE, errorHeader.getInternalCode());
        assertEquals(MESSAGE_ID, errorHeader.getMessageId());
        assertEquals(USER_MSG, errorHeader.getUserMessage());
        assertTrue(isAboutNow(errorHeader.getTimestamp()));
    }
    
    @Test
    public void mslObject() throws MslEncodingException, MslEntityAuthException, MslEncoderException, UnsupportedEncodingException, MslMessageException, MslCryptoException {
        final ErrorHeader errorHeader = new ErrorHeader(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
        
        final MslObject mo = MslTestUtils.toMslObject(encoder, errorHeader);
        final MslObject entityAuthDataMo = mo.getMslObject(KEY_ENTITY_AUTHENTICATION_DATA, encoder);
        assertTrue(MslEncoderUtils.equalObjects(MslTestUtils.toMslObject(encoder, ENTITY_AUTH_DATA), entityAuthDataMo));
        final byte[] ciphertext = mo.getBytes(KEY_ERRORDATA);
        final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
        final MslObject errordata = encoder.parseObject(plaintext);
        final byte[] signature = mo.getBytes(KEY_SIGNATURE);
        assertTrue(cryptoContext.verify(ciphertext, signature, encoder));

        assertEquals(MESSAGE_ID, errordata.getLong(KEY_MESSAGE_ID));
        assertEquals(ERROR_CODE.intValue(), errordata.getInt(KEY_ERROR_CODE));
        assertEquals(INTERNAL_CODE, errordata.getInt(KEY_INTERNAL_CODE));
        assertEquals(ERROR_MSG, errordata.getString(KEY_ERROR_MESSAGE));
        assertEquals(USER_MSG, errordata.getString(KEY_USER_MESSAGE));
        assertTrue(isAboutNowSeconds(errordata.getLong(KEY_TIMESTAMP)));
    }
    
    @Test
    public void negativeInternalCodeMslObject() throws MslEncodingException, MslEntityAuthException, MslEncoderException, MslMessageException, MslCryptoException {
        final ErrorHeader errorHeader = new ErrorHeader(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, -17, ERROR_MSG, USER_MSG);
        assertEquals(-1, errorHeader.getInternalCode());
        
        final MslObject mo = MslTestUtils.toMslObject(encoder, errorHeader);
        final MslObject entityAuthDataMo = mo.getMslObject(KEY_ENTITY_AUTHENTICATION_DATA, encoder);
        assertTrue(MslEncoderUtils.equalObjects(MslTestUtils.toMslObject(encoder, ENTITY_AUTH_DATA), entityAuthDataMo));
        final byte[] ciphertext = mo.getBytes(KEY_ERRORDATA);
        final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
        final MslObject errordata = encoder.parseObject(plaintext);
        final byte[] signature = mo.getBytes(KEY_SIGNATURE);
        assertTrue(cryptoContext.verify(ciphertext, signature, encoder));

        assertTrue(isAboutNowSeconds(errordata.getLong(KEY_TIMESTAMP)));
        assertEquals(MESSAGE_ID, errordata.getLong(KEY_MESSAGE_ID));
        assertEquals(ERROR_CODE.intValue(), errordata.getInt(KEY_ERROR_CODE));
        assertFalse(errordata.has(KEY_INTERNAL_CODE));
        assertEquals(ERROR_MSG, errordata.getString(KEY_ERROR_MESSAGE));
        assertEquals(USER_MSG, errordata.getString(KEY_USER_MESSAGE));
    }
    
    @Test
    public void nullErrorMessageMslObject() throws MslEncodingException, MslEntityAuthException, MslEncoderException, MslMessageException, MslCryptoException {
        final ErrorHeader errorHeader = new ErrorHeader(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, null, USER_MSG);
        assertNull(errorHeader.getErrorMessage());
        
        final MslObject mo = MslTestUtils.toMslObject(encoder, errorHeader);
        final MslObject entityAuthDataMo = mo.getMslObject(KEY_ENTITY_AUTHENTICATION_DATA, encoder);
        assertTrue(MslEncoderUtils.equalObjects(MslTestUtils.toMslObject(encoder, ENTITY_AUTH_DATA), entityAuthDataMo));
        final byte[] ciphertext = mo.getBytes(KEY_ERRORDATA);
        final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
        final MslObject errordata = encoder.parseObject(plaintext);
        final byte[] signature = mo.getBytes(KEY_SIGNATURE);
        assertTrue(cryptoContext.verify(ciphertext, signature, encoder));

        assertTrue(isAboutNowSeconds(errordata.getLong(KEY_TIMESTAMP)));
        assertEquals(MESSAGE_ID, errordata.getLong(KEY_MESSAGE_ID));
        assertEquals(ERROR_CODE.intValue(), errordata.getInt(KEY_ERROR_CODE));
        assertEquals(INTERNAL_CODE, errordata.getInt(KEY_INTERNAL_CODE));
        assertFalse(errordata.has(KEY_ERROR_MESSAGE));
        assertEquals(USER_MSG, errordata.getString(KEY_USER_MESSAGE));
    }
    
    @Test
    public void nullUserMessageMslObject() throws MslEncodingException, MslEntityAuthException, MslEncoderException, MslMessageException, MslCryptoException {
        final ErrorHeader errorHeader = new ErrorHeader(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, null);
        assertNull(errorHeader.getUserMessage());
        
        final MslObject mo = MslTestUtils.toMslObject(encoder, errorHeader);
        final MslObject entityAuthDataMo = mo.getMslObject(KEY_ENTITY_AUTHENTICATION_DATA, encoder);
        assertTrue(MslEncoderUtils.equalObjects(MslTestUtils.toMslObject(encoder, ENTITY_AUTH_DATA), entityAuthDataMo));
        final byte[] ciphertext = mo.getBytes(KEY_ERRORDATA);
        final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
        final MslObject errordata = encoder.parseObject(plaintext);
        final byte[] signature = mo.getBytes(KEY_SIGNATURE);
        assertTrue(cryptoContext.verify(ciphertext, signature, encoder));

        assertTrue(isAboutNowSeconds(errordata.getLong(KEY_TIMESTAMP)));
        assertEquals(MESSAGE_ID, errordata.getLong(KEY_MESSAGE_ID));
        assertEquals(ERROR_CODE.intValue(), errordata.getInt(KEY_ERROR_CODE));
        assertEquals(INTERNAL_CODE, errordata.getInt(KEY_INTERNAL_CODE));
        assertEquals(ERROR_MSG, errordata.getString(KEY_ERROR_MESSAGE));
        assertFalse(errordata.has(KEY_USER_MESSAGE));
    }
    
    @Test
    public void parseHeader() throws MslEncoderException, MslKeyExchangeException, MslUserAuthException, MslException {
        final ErrorHeader errorHeader = new ErrorHeader(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
        final MslObject errorHeaderMo = MslTestUtils.toMslObject(encoder, errorHeader);
        final Header header = Header.parseHeader(ctx, errorHeaderMo, CRYPTO_CONTEXTS);
        assertNotNull(header);
        assertTrue(header instanceof ErrorHeader);
        final ErrorHeader moErrorHeader = (ErrorHeader)header;
        
        assertEquals(errorHeader.getEntityAuthenticationData(), moErrorHeader.getEntityAuthenticationData());
        assertEquals(errorHeader.getTimestamp(), moErrorHeader.getTimestamp());
        assertEquals(errorHeader.getErrorCode(), moErrorHeader.getErrorCode());
        assertEquals(errorHeader.getErrorMessage(), moErrorHeader.getErrorMessage());
        assertEquals(errorHeader.getInternalCode(), moErrorHeader.getInternalCode());
        assertEquals(errorHeader.getMessageId(), moErrorHeader.getMessageId());
        assertEquals(errorHeader.getUserMessage(), moErrorHeader.getUserMessage());
    }
    
    @Test
    public void missingEntityAuthDataCtor() throws MslEncodingException, MslEntityAuthException, MslMessageException, MslCryptoException {
        thrown.expect(MslMessageException.class);
        thrown.expectMslError(MslError.MESSAGE_ENTITY_NOT_FOUND);

        new ErrorHeader(ctx, null, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
    }
    
    @Test
    public void missingEntityAuthDataParseHeader() throws MslEncodingException, MslEntityAuthException, MslCryptoException, MslKeyExchangeException, MslUserAuthException, MslException, MslEncoderException {
        thrown.expect(MslMessageException.class);
        thrown.expectMslError(MslError.MESSAGE_ENTITY_NOT_FOUND);

        final ErrorHeader errorHeader = new ErrorHeader(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
        final MslObject errorHeaderMo = MslTestUtils.toMslObject(encoder, errorHeader);
        
        assertNotNull(errorHeaderMo.remove(KEY_ENTITY_AUTHENTICATION_DATA));
        
        Header.parseHeader(ctx, errorHeaderMo, CRYPTO_CONTEXTS);
    }
    
    @Test
    public void invalidEntityAuthData() throws MslEncodingException, MslEntityAuthException, MslCryptoException, MslKeyExchangeException, MslUserAuthException, MslException, MslEncoderException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MSL_PARSE_ERROR);

        final ErrorHeader errorHeader = new ErrorHeader(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
        final MslObject errorHeaderMo = MslTestUtils.toMslObject(encoder, errorHeader);
        
        errorHeaderMo.put(KEY_ENTITY_AUTHENTICATION_DATA, "x");

        Header.parseHeader(ctx, errorHeaderMo, CRYPTO_CONTEXTS);
    }
    
    @Test
    public void missingSignature() throws MslEncoderException, MslEncodingException, MslEntityAuthException, MslCryptoException, MslKeyExchangeException, MslUserAuthException, MslException, MslEncoderException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MSL_PARSE_ERROR);

        final ErrorHeader errorHeader = new ErrorHeader(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
        final MslObject errorHeaderMo = MslTestUtils.toMslObject(encoder, errorHeader);
        
        assertNotNull(errorHeaderMo.remove(KEY_SIGNATURE));

        Header.parseHeader(ctx, errorHeaderMo, CRYPTO_CONTEXTS);
    }
    
    @Test
    public void invalidSignature() throws MslEncoderException, MslKeyExchangeException, MslUserAuthException, MslException, MslEncoderException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MSL_PARSE_ERROR);

        final ErrorHeader errorHeader = new ErrorHeader(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
        final MslObject errorHeaderMo = MslTestUtils.toMslObject(encoder, errorHeader);
        
        errorHeaderMo.put(KEY_SIGNATURE, false);

        Header.parseHeader(ctx, errorHeaderMo, CRYPTO_CONTEXTS);
    }
    
    @Test
    public void incorrectSignature() throws MslEncoderException, MslKeyExchangeException, MslUserAuthException, MslException, MslEncoderException {
        thrown.expect(MslCryptoException.class);
        thrown.expectMslError(MslError.MESSAGE_VERIFICATION_FAILED);

        final ErrorHeader errorHeader = new ErrorHeader(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
        final MslObject errorHeaderMo = MslTestUtils.toMslObject(encoder, errorHeader);
        
        errorHeaderMo.put(KEY_SIGNATURE, Base64.decode("AAA="));

        Header.parseHeader(ctx, errorHeaderMo, CRYPTO_CONTEXTS);
    }
    
    @Test
    public void missingErrordata() throws MslEncoderException, MslKeyExchangeException, MslUserAuthException, MslException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MSL_PARSE_ERROR);

        final ErrorHeader errorHeader = new ErrorHeader(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
        final MslObject errorHeaderMo = MslTestUtils.toMslObject(encoder, errorHeader);
        
        assertNotNull(errorHeaderMo.remove(KEY_ERRORDATA));
        
        Header.parseHeader(ctx, errorHeaderMo, CRYPTO_CONTEXTS);
    }
    
    @Test
    public void invalidErrordata() throws MslEncodingException, MslEntityAuthException, MslCryptoException, MslKeyExchangeException, MslUserAuthException, MslException, MslEncoderException {
        thrown.expect(MslCryptoException.class);
        thrown.expectMslError(MslError.CIPHERTEXT_ENVELOPE_PARSE_ERROR);

        final ErrorHeader errorHeader = new ErrorHeader(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
        final MslObject errorHeaderMo = MslTestUtils.toMslObject(encoder, errorHeader);
        
        // This tests invalid but trusted error data so we must sign it.
        final byte[] errordata = new byte[1];
        errordata[0] = 'x';
        errorHeaderMo.put(KEY_ERRORDATA, errordata);
        final byte[] signature = cryptoContext.sign(errordata, encoder, ENCODER_FORMAT);
        errorHeaderMo.put(KEY_SIGNATURE, signature);
        
        Header.parseHeader(ctx, errorHeaderMo, CRYPTO_CONTEXTS);
    }
    
    @Test
    public void emptyErrordata() throws MslEncoderException, MslKeyExchangeException, MslUserAuthException, MslException {
        thrown.expect(MslMessageException.class);
        thrown.expectMslError(MslError.HEADER_DATA_MISSING);

        final ErrorHeader errorHeader = new ErrorHeader(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
        final MslObject errorHeaderMo = MslTestUtils.toMslObject(encoder, errorHeader);
        
        // This tests empty but trusted error data so we must sign it.
        final byte[] ciphertext = new byte[0];
        errorHeaderMo.put(KEY_ERRORDATA, ciphertext);
        final byte[] signature = cryptoContext.sign(ciphertext, encoder, ENCODER_FORMAT);
        errorHeaderMo.put(KEY_SIGNATURE, signature);
        
        Header.parseHeader(ctx, errorHeaderMo, CRYPTO_CONTEXTS);
    }
    
    @Test
    public void missingTimestamp() throws MslKeyExchangeException, MslUserAuthException, MslException, MslEncoderException {
        final ErrorHeader errorHeader = new ErrorHeader(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
        final MslObject errorHeaderMo = MslTestUtils.toMslObject(encoder, errorHeader);

        // Before modifying the error data we need to decrypt it.
        final byte[] ciphertext = errorHeaderMo.getBytes(KEY_ERRORDATA);
        final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
        final MslObject errordata = encoder.parseObject(plaintext);
        
        // After modifying the error data we need to encrypt it.
        assertNotNull(errordata.remove(KEY_TIMESTAMP));
        final byte[] modifiedPlaintext = encoder.encodeObject(errordata, ENCODER_FORMAT);
        final byte[] modifiedCiphertext = cryptoContext.encrypt(modifiedPlaintext, encoder, ENCODER_FORMAT);
        errorHeaderMo.put(KEY_ERRORDATA, modifiedCiphertext);
        
        // The error data must be signed otherwise the error data will not be
        // processed.
        final byte[] modifiedSignature = cryptoContext.sign(modifiedCiphertext, encoder, ENCODER_FORMAT);
        errorHeaderMo.put(KEY_SIGNATURE, modifiedSignature);

        Header.parseHeader(ctx, errorHeaderMo, CRYPTO_CONTEXTS);
    }
    
    @Test
    public void invalidTimestamp() throws MslKeyExchangeException, MslUserAuthException, MslException, MslEncoderException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MSL_PARSE_ERROR);

        final ErrorHeader errorHeader = new ErrorHeader(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
        final MslObject errorHeaderMo = MslTestUtils.toMslObject(encoder, errorHeader);

        // Before modifying the error data we need to decrypt it.
        final byte[] ciphertext = errorHeaderMo.getBytes(KEY_ERRORDATA);
        final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
        final MslObject errordata = encoder.parseObject(plaintext);

        // After modifying the error data we need to encrypt it.
        errordata.put(KEY_TIMESTAMP, "x");
        final byte[] modifiedPlaintext = errordata.toString().getBytes(MslConstants.DEFAULT_CHARSET);
        final byte[] modifiedCiphertext = cryptoContext.encrypt(modifiedPlaintext, encoder, ENCODER_FORMAT);
        errorHeaderMo.put(KEY_ERRORDATA, modifiedCiphertext);

        // The error data must be signed otherwise the error data will not be
        // processed.
        final byte[] modifiedSignature = cryptoContext.sign(modifiedCiphertext, encoder, ENCODER_FORMAT);
        errorHeaderMo.put(KEY_SIGNATURE, modifiedSignature);
        
        Header.parseHeader(ctx, errorHeaderMo, CRYPTO_CONTEXTS);
    }
    
    @Test
    public void missingMessageId() throws MslEncoderException, UnsupportedEncodingException, MslKeyExchangeException, MslUserAuthException, MslException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MSL_PARSE_ERROR);

        final ErrorHeader errorHeader = new ErrorHeader(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
        final MslObject errorHeaderMo = MslTestUtils.toMslObject(encoder, errorHeader);
        
        // Before modifying the error data we need to decrypt it.
        final byte[] ciphertext = errorHeaderMo.getBytes(KEY_ERRORDATA);
        final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
        final MslObject errordata = encoder.parseObject(plaintext);
        
        // After modifying the error data we need to encrypt it.
        assertNotNull(errordata.remove(KEY_MESSAGE_ID));
        final byte[] modifiedPlaintext = errordata.toString().getBytes(MslConstants.DEFAULT_CHARSET);
        final byte[] modifiedCiphertext = cryptoContext.encrypt(modifiedPlaintext, encoder, ENCODER_FORMAT);
        errorHeaderMo.put(KEY_ERRORDATA, modifiedCiphertext);
        
        // The error data must be signed otherwise the error data will not be
        // processed.
        final byte[] modifiedSignature = cryptoContext.sign(modifiedCiphertext, encoder, ENCODER_FORMAT);
        errorHeaderMo.put(KEY_SIGNATURE, modifiedSignature);
        
        Header.parseHeader(ctx, errorHeaderMo, CRYPTO_CONTEXTS);
    }
    
    @Test
    public void invalidMessageId() throws UnsupportedEncodingException, MslEncoderException, MslKeyExchangeException, MslUserAuthException, MslException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MSL_PARSE_ERROR);

        final ErrorHeader errorHeader = new ErrorHeader(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
        final MslObject errorHeaderMo = MslTestUtils.toMslObject(encoder, errorHeader);

        // Before modifying the error data we need to decrypt it.
        final byte[] ciphertext = errorHeaderMo.getBytes(KEY_ERRORDATA);
        final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
        final MslObject errordata = encoder.parseObject(plaintext);

        // After modifying the error data we need to encrypt it.
        errordata.put(KEY_MESSAGE_ID, "x");
        final byte[] modifiedPlaintext = errordata.toString().getBytes(MslConstants.DEFAULT_CHARSET);
        final byte[] modifiedCiphertext = cryptoContext.encrypt(modifiedPlaintext, encoder, ENCODER_FORMAT);
        errorHeaderMo.put(KEY_ERRORDATA, modifiedCiphertext);

        // The error data must be signed otherwise the error data will not be
        // processed.
        final byte[] modifiedSignature = cryptoContext.sign(modifiedCiphertext, encoder, ENCODER_FORMAT);
        errorHeaderMo.put(KEY_SIGNATURE, modifiedSignature);
        
        Header.parseHeader(ctx, errorHeaderMo, CRYPTO_CONTEXTS);
    }
    
    @Test(expected = MslInternalException.class)
    public void negativeMessageIdCtor() throws MslEncodingException, MslEntityAuthException, MslMessageException, MslCryptoException {
        new ErrorHeader(ctx, ENTITY_AUTH_DATA, -1, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
    }
    
    @Test(expected = MslInternalException.class)
    public void tooLargeMessageIdCtor() throws MslEncodingException, MslEntityAuthException, MslMessageException, MslCryptoException {
        new ErrorHeader(ctx, ENTITY_AUTH_DATA, MslConstants.MAX_LONG_VALUE + 1, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
    }
    
    @Test
    public void negativeMessageIdParseHeader() throws MslEncodingException, MslEntityAuthException, MslKeyExchangeException, MslUserAuthException, MslEncoderException, MslException {
        thrown.expect(MslMessageException.class);
        thrown.expectMslError(MslError.MESSAGE_ID_OUT_OF_RANGE);

        final ErrorHeader errorHeader = new ErrorHeader(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
        final MslObject errorHeaderMo = MslTestUtils.toMslObject(encoder, errorHeader);

        // Before modifying the error data we need to decrypt it.
        final byte[] ciphertext = errorHeaderMo.getBytes(KEY_ERRORDATA);
        final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
        final MslObject errordata = encoder.parseObject(plaintext);

        // After modifying the error data we need to encrypt it.
        errordata.put(KEY_MESSAGE_ID, -1L);
        final byte[] modifiedPlaintext = errordata.toString().getBytes(MslConstants.DEFAULT_CHARSET);
        final byte[] modifiedCiphertext = cryptoContext.encrypt(modifiedPlaintext, encoder, ENCODER_FORMAT);
        errorHeaderMo.put(KEY_ERRORDATA, modifiedCiphertext);

        // The error data must be signed otherwise the error data will not be
        // processed.
        final byte[] modifiedSignature = cryptoContext.sign(modifiedCiphertext, encoder, ENCODER_FORMAT);
        errorHeaderMo.put(KEY_SIGNATURE, modifiedSignature);
        
        Header.parseHeader(ctx, errorHeaderMo, CRYPTO_CONTEXTS);
    }
    
    @Test
    public void tooLargeMessageIdParseHeader() throws MslEncodingException, MslEntityAuthException, MslKeyExchangeException, MslUserAuthException, MslEncoderException, MslException {
        thrown.expect(MslMessageException.class);
        thrown.expectMslError(MslError.MESSAGE_ID_OUT_OF_RANGE);

        final ErrorHeader errorHeader = new ErrorHeader(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
        final MslObject errorHeaderMo = MslTestUtils.toMslObject(encoder, errorHeader);

        // Before modifying the error data we need to decrypt it.
        final byte[] ciphertext = errorHeaderMo.getBytes(KEY_ERRORDATA);
        final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
        final MslObject errordata = encoder.parseObject(plaintext);

        // After modifying the error data we need to encrypt it.
        errordata.put(KEY_MESSAGE_ID, MslConstants.MAX_LONG_VALUE + 1);
        final byte[] modifiedPlaintext = errordata.toString().getBytes(MslConstants.DEFAULT_CHARSET);
        final byte[] modifiedCiphertext = cryptoContext.encrypt(modifiedPlaintext, encoder, ENCODER_FORMAT);
        errorHeaderMo.put(KEY_ERRORDATA, modifiedCiphertext);

        // The error data must be signed otherwise the error data will not be
        // processed.
        final byte[] modifiedSignature = cryptoContext.sign(modifiedCiphertext, encoder, ENCODER_FORMAT);
        errorHeaderMo.put(KEY_SIGNATURE, modifiedSignature);
        
        Header.parseHeader(ctx, errorHeaderMo, CRYPTO_CONTEXTS);
    }
    
    @Test
    public void missingErrorCode() throws MslEncodingException, MslEntityAuthException, MslCryptoException, MslKeyExchangeException, MslUserAuthException, MslException, MslEncoderException, UnsupportedEncodingException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MSL_PARSE_ERROR);
        thrown.expectMessageId(MESSAGE_ID);

        final ErrorHeader errorHeader = new ErrorHeader(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
        final MslObject errorHeaderMo = MslTestUtils.toMslObject(encoder, errorHeader);
        
        // Before modifying the error data we need to decrypt it.
        final byte[] ciphertext = errorHeaderMo.getBytes(KEY_ERRORDATA);
        final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
        final MslObject errordata = encoder.parseObject(plaintext);
        
        // After modifying the error data we need to encrypt it.
        assertNotNull(errordata.remove(KEY_ERROR_CODE));
        final byte[] modifiedPlaintext = errordata.toString().getBytes(MslConstants.DEFAULT_CHARSET);
        final byte[] modifiedCiphertext = cryptoContext.encrypt(modifiedPlaintext, encoder, ENCODER_FORMAT);
        errorHeaderMo.put(KEY_ERRORDATA, modifiedCiphertext);
        
        // The error data must be signed otherwise the error data will not be
        // processed.
        final byte[] modifiedSignature = cryptoContext.sign(modifiedCiphertext, encoder, ENCODER_FORMAT);
        errorHeaderMo.put(KEY_SIGNATURE, modifiedSignature);
        
        Header.parseHeader(ctx, errorHeaderMo, CRYPTO_CONTEXTS);
    }
    
    @Test
    public void invalidErrorCode() throws MslEncodingException, MslEntityAuthException, MslCryptoException, MslKeyExchangeException, MslUserAuthException, MslException, MslEncoderException, UnsupportedEncodingException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MSL_PARSE_ERROR);
        thrown.expectMessageId(MESSAGE_ID);

        final ErrorHeader errorHeader = new ErrorHeader(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
        final MslObject errorHeaderMo = MslTestUtils.toMslObject(encoder, errorHeader);

        // Before modifying the error data we need to decrypt it.
        final byte[] ciphertext = errorHeaderMo.getBytes(KEY_ERRORDATA);
        final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
        final MslObject errordata = encoder.parseObject(plaintext);

        // After modifying the error data we need to encrypt it.
        errordata.put(KEY_ERROR_CODE, "x");
        final byte[] modifiedPlaintext = errordata.toString().getBytes(MslConstants.DEFAULT_CHARSET);
        final byte[] modifiedCiphertext = cryptoContext.encrypt(modifiedPlaintext, encoder, ENCODER_FORMAT);
        errorHeaderMo.put(KEY_ERRORDATA, modifiedCiphertext);

        // The error data must be signed otherwise the error data will not be
        // processed.
        final byte[] modifiedSignature = cryptoContext.sign(modifiedCiphertext, encoder, ENCODER_FORMAT);
        errorHeaderMo.put(KEY_SIGNATURE, modifiedSignature);
        
        Header.parseHeader(ctx, errorHeaderMo, CRYPTO_CONTEXTS);
    }
    
    @Test
    public void missingInternalCode() throws MslEncoderException, MslKeyExchangeException, MslUserAuthException, MslException {
        final ErrorHeader errorHeader = new ErrorHeader(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
        final MslObject errorHeaderMo = MslTestUtils.toMslObject(encoder, errorHeader);
        
        // Before modifying the error data we need to decrypt it.
        final byte[] ciphertext = errorHeaderMo.getBytes(KEY_ERRORDATA);
        final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
        final MslObject errordata = encoder.parseObject(plaintext);
        
        // After modifying the error data we need to encrypt it.
        assertNotNull(errordata.remove(KEY_INTERNAL_CODE));
        final byte[] modifiedPlaintext = errordata.toString().getBytes(MslConstants.DEFAULT_CHARSET);
        final byte[] modifiedCiphertext = cryptoContext.encrypt(modifiedPlaintext, encoder, ENCODER_FORMAT);
        errorHeaderMo.put(KEY_ERRORDATA, modifiedCiphertext);
        
        // The error data must be signed otherwise the error data will not be
        // processed.
        final byte[] modifiedSignature = cryptoContext.sign(modifiedCiphertext, encoder, ENCODER_FORMAT);
        errorHeaderMo.put(KEY_SIGNATURE, modifiedSignature);
        
        final ErrorHeader moErrorHeader = (ErrorHeader)Header.parseHeader(ctx, errorHeaderMo, CRYPTO_CONTEXTS);
        assertEquals(-1, moErrorHeader.getInternalCode());
    }
    
    @Test
    public void invalidInternalCode() throws MslEncoderException, MslKeyExchangeException, MslUserAuthException, MslException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MSL_PARSE_ERROR);
        thrown.expectMessageId(MESSAGE_ID);

        final ErrorHeader errorHeader = new ErrorHeader(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
        final MslObject errorHeaderMo = MslTestUtils.toMslObject(encoder, errorHeader);
        
        // Before modifying the error data we need to decrypt it.
        final byte[] ciphertext = errorHeaderMo.getBytes(KEY_ERRORDATA);
        final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
        final MslObject errordata = encoder.parseObject(plaintext);
        
        // After modifying the error data we need to encrypt it.
        errordata.put(KEY_INTERNAL_CODE, "x");
        final byte[] modifiedPlaintext = errordata.toString().getBytes(MslConstants.DEFAULT_CHARSET);
        final byte[] modifiedCiphertext = cryptoContext.encrypt(modifiedPlaintext, encoder, ENCODER_FORMAT);
        errorHeaderMo.put(KEY_ERRORDATA, modifiedCiphertext);
        
        // The error data must be signed otherwise the error data will not be
        // processed.
        final byte[] modifiedSignature = cryptoContext.sign(modifiedCiphertext, encoder, ENCODER_FORMAT);
        errorHeaderMo.put(KEY_SIGNATURE, modifiedSignature);
        
        Header.parseHeader(ctx, errorHeaderMo, CRYPTO_CONTEXTS);
    }
    
    @Test
    public void negativeInternalCode() throws MslEncoderException, MslKeyExchangeException, MslUserAuthException, MslException {
        thrown.expect(MslMessageException.class);
        thrown.expectMslError(MslError.INTERNAL_CODE_NEGATIVE);
        thrown.expectMessageId(MESSAGE_ID);

        final ErrorHeader errorHeader = new ErrorHeader(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
        final MslObject errorHeaderMo = MslTestUtils.toMslObject(encoder, errorHeader);
        
        // Before modifying the error data we need to decrypt it.
        final byte[] ciphertext = errorHeaderMo.getBytes(KEY_ERRORDATA);
        final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
        final MslObject errordata = encoder.parseObject(plaintext);
        
        // After modifying the error data we need to encrypt it.
        errordata.put(KEY_INTERNAL_CODE, -17);
        final byte[] modifiedPlaintext = errordata.toString().getBytes(MslConstants.DEFAULT_CHARSET);
        final byte[] modifiedCiphertext = cryptoContext.encrypt(modifiedPlaintext, encoder, ENCODER_FORMAT);
        errorHeaderMo.put(KEY_ERRORDATA, modifiedCiphertext);
        
        // The error data must be signed otherwise the error data will not be
        // processed.
        final byte[] modifiedSignature = cryptoContext.sign(modifiedCiphertext, encoder, ENCODER_FORMAT);
        errorHeaderMo.put(KEY_SIGNATURE, modifiedSignature);
        
        Header.parseHeader(ctx, errorHeaderMo, CRYPTO_CONTEXTS);
    }
    
    @Test
    public void missingErrorMessage() throws UnsupportedEncodingException, MslEncoderException, MslKeyExchangeException, MslUserAuthException, MslException {
        final ErrorHeader errorHeader = new ErrorHeader(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
        final MslObject errorHeaderMo = MslTestUtils.toMslObject(encoder, errorHeader);
        
        // Before modifying the error data we need to decrypt it.
        final byte[] ciphertext = errorHeaderMo.getBytes(KEY_ERRORDATA);
        final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
        final MslObject errordata = encoder.parseObject(plaintext);
        
        // After modifying the error data we need to encrypt it.
        assertNotNull(errordata.remove(KEY_ERROR_MESSAGE));
        final byte[] modifiedPlaintext = errordata.toString().getBytes(MslConstants.DEFAULT_CHARSET);
        final byte[] modifiedCiphertext = cryptoContext.encrypt(modifiedPlaintext, encoder, ENCODER_FORMAT);
        errorHeaderMo.put(KEY_ERRORDATA, modifiedCiphertext);
        
        // The error data must be signed otherwise the error data will not be
        // processed.
        final byte[] modifiedSignature = cryptoContext.sign(modifiedCiphertext, encoder, ENCODER_FORMAT);
        errorHeaderMo.put(KEY_SIGNATURE, modifiedSignature);
        
        final ErrorHeader moErrorHeader = (ErrorHeader)Header.parseHeader(ctx, errorHeaderMo, CRYPTO_CONTEXTS);
        assertNull(moErrorHeader.getErrorMessage());
    }
    
    @Test
    public void missingUserMessage() throws MslEncodingException, MslEntityAuthException, MslMessageException, MslKeyExchangeException, MslUserAuthException, MslEncoderException, MslException {
        final ErrorHeader errorHeader = new ErrorHeader(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
        final MslObject errorHeaderMo = MslTestUtils.toMslObject(encoder, errorHeader);
        
        // Before modifying the error data we need to decrypt it.
        final byte[] ciphertext = errorHeaderMo.getBytes(KEY_ERRORDATA);
        final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
        final MslObject errordata = encoder.parseObject(plaintext);
        
        // After modifying the error data we need to encrypt it.
        assertNotNull(errordata.remove(KEY_USER_MESSAGE));
        final byte[] modifiedPlaintext = errordata.toString().getBytes(MslConstants.DEFAULT_CHARSET);
        final byte[] modifiedCiphertext = cryptoContext.encrypt(modifiedPlaintext, encoder, ENCODER_FORMAT);
        errorHeaderMo.put(KEY_ERRORDATA, modifiedCiphertext);
        
        // The error data must be signed otherwise the error data will not be
        // processed.
        final byte[] modifiedSignature = cryptoContext.sign(modifiedCiphertext, encoder, ENCODER_FORMAT);
        errorHeaderMo.put(KEY_SIGNATURE, modifiedSignature);
        
        final ErrorHeader moErrorHeader = (ErrorHeader)Header.parseHeader(ctx, errorHeaderMo, CRYPTO_CONTEXTS);
        assertNull(moErrorHeader.getUserMessage());
    }
    
    @Test
    public void equalsTimestamp() throws InterruptedException, MslKeyExchangeException, MslUserAuthException, MslEncoderException, MslException {
        final ErrorHeader errorHeaderA = new ErrorHeader(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
        Thread.sleep(MILLISECONDS_PER_SECOND);
        final ErrorHeader errorHeaderB = new ErrorHeader(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
        final ErrorHeader errorHeaderA2 = (ErrorHeader)Header.parseHeader(ctx, MslTestUtils.toMslObject(encoder, errorHeaderA), CRYPTO_CONTEXTS);

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
    public void equalsMessageId() throws MslKeyExchangeException, MslUserAuthException, MslException, MslEncoderException {
        final long messageIdA = 1;
        final long messageIdB = 2;
        final ErrorHeader errorHeaderA = new ErrorHeader(ctx, ENTITY_AUTH_DATA, messageIdA, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
        final ErrorHeader errorHeaderB = new ErrorHeader(ctx, ENTITY_AUTH_DATA, messageIdB, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
        final ErrorHeader errorHeaderA2 = (ErrorHeader)Header.parseHeader(ctx, MslTestUtils.toMslObject(encoder, errorHeaderA), CRYPTO_CONTEXTS);

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
    public void equalsErrorCode() throws MslKeyExchangeException, MslUserAuthException, MslException, MslEncoderException {
        final ResponseCode errorCodeA = ResponseCode.FAIL;
        final ResponseCode errorCodeB = ResponseCode.TRANSIENT_FAILURE;
        final ErrorHeader errorHeaderA = new ErrorHeader(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, errorCodeA, INTERNAL_CODE, ERROR_MSG, USER_MSG);
        final ErrorHeader errorHeaderB = new ErrorHeader(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, errorCodeB, INTERNAL_CODE, ERROR_MSG, USER_MSG);
        final ErrorHeader errorHeaderA2 = (ErrorHeader)Header.parseHeader(ctx, MslTestUtils.toMslObject(encoder, errorHeaderA), CRYPTO_CONTEXTS);
        
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
    public void equalsInternalCode() throws MslKeyExchangeException, MslUserAuthException, MslException, MslEncoderException {
        final int internalCodeA = 1;
        final int internalCodeB = 2;
        final ErrorHeader errorHeaderA = new ErrorHeader(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, internalCodeA, ERROR_MSG, USER_MSG);
        final ErrorHeader errorHeaderB = new ErrorHeader(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, internalCodeB, ERROR_MSG, USER_MSG);
        final ErrorHeader errorHeaderA2 = (ErrorHeader)Header.parseHeader(ctx, MslTestUtils.toMslObject(encoder, errorHeaderA), CRYPTO_CONTEXTS);
        
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
    public void equalsErrorMessage() throws MslKeyExchangeException, MslUserAuthException, MslException, MslEncoderException {
        final String errorMsgA = "A";
        final String errorMsgB = "B";
        final ErrorHeader errorHeaderA = new ErrorHeader(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, errorMsgA, USER_MSG);
        final ErrorHeader errorHeaderB = new ErrorHeader(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, errorMsgB, USER_MSG);
        final ErrorHeader errorHeaderC = new ErrorHeader(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, null, USER_MSG);
        final ErrorHeader errorHeaderA2 = (ErrorHeader)Header.parseHeader(ctx, MslTestUtils.toMslObject(encoder, errorHeaderA), CRYPTO_CONTEXTS);
        
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
    public void equalsUserMessage() throws MslKeyExchangeException, MslUserAuthException, MslException, MslEncoderException {
        final String userMsgA = "A";
        final String userMsgB = "B";
        final ErrorHeader errorHeaderA = new ErrorHeader(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, userMsgA);
        final ErrorHeader errorHeaderB = new ErrorHeader(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, userMsgB);
        final ErrorHeader errorHeaderC = new ErrorHeader(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, null);
        final ErrorHeader errorHeaderA2 = (ErrorHeader)Header.parseHeader(ctx, MslTestUtils.toMslObject(encoder, errorHeaderA), CRYPTO_CONTEXTS);
        
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
        final ErrorHeader errorHeader = new ErrorHeader(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
        assertFalse(errorHeader.equals(null));
        assertFalse(errorHeader.equals(ERROR_MSG));
        assertTrue(errorHeader.hashCode() != ERROR_MSG.hashCode());
    }
}
