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
import static org.junit.Assert.assertTrue;

import java.io.UnsupportedEncodingException;
import java.util.Date;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;

import com.netflix.msl.MslConstants;
import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslException;
import com.netflix.msl.MslInternalException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.io.MslEncoderException;
import com.netflix.msl.io.MslEncoderFactory;
import com.netflix.msl.io.MslEncoderFormat;
import com.netflix.msl.io.MslEncoderUtils;
import com.netflix.msl.io.MslObject;
import com.netflix.msl.test.ExpectedMslException;
import com.netflix.msl.userauth.MockEmailPasswordAuthenticationFactory;
import com.netflix.msl.util.MockMslContext;
import com.netflix.msl.util.MslContext;
import com.netflix.msl.util.MslTestUtils;

/**
 * User ID token unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class UserIdTokenTest {
	/** MSL encoder format. */
	private static final MslEncoderFormat ENCODER_FORMAT = MslEncoderFormat.JSON;

    /** Milliseconds per second. */
    private static final long MILLISECONDS_PER_SECOND = 1000;
    
    /** Key token data. */
    private static final String KEY_TOKENDATA = "tokendata";
    /** Key signature. */
    private static final String KEY_SIGNATURE = "signature";
    
    // tokendata
    /** Key renewal window timestamp. */
    private static final String KEY_RENEWAL_WINDOW = "renewalwindow";
    /** Key expiration timestamp. */
    private static final String KEY_EXPIRATION = "expiration";
    /** Key master token serial number. */
    private static final String KEY_MASTER_TOKEN_SERIAL_NUMBER = "mtserialnumber";
    /** Key user ID token serial number. */
    private static final String KEY_SERIAL_NUMBER = "serialnumber";
    /** Key token user identification data. */
    private static final String KEY_USERDATA = "userdata";
    
    // userdata
    /** Key issuer data. */
    private static final String KEY_ISSUER_DATA = "issuerdata";
    /** Key identity. */
    private static final String KEY_IDENTITY = "identity";
    
    private static final Date RENEWAL_WINDOW = new Date(System.currentTimeMillis() + 60000);
    private static final Date EXPIRATION = new Date(System.currentTimeMillis() + 120000);
    private static MasterToken MASTER_TOKEN;
    private static final long SERIAL_NUMBER = 42;
    private static MslObject ISSUER_DATA;
    private static MslUser USER;

    @Rule
    public ExpectedMslException thrown = ExpectedMslException.none();
    
    @BeforeClass
    public static void setup() throws MslEncodingException, MslCryptoException, MslEncoderException {
        ctx = new MockMslContext(EntityAuthenticationScheme.PSK, false);
        encoder = ctx.getMslEncoderFactory();
        MASTER_TOKEN = MslTestUtils.getMasterToken(ctx, 1, 1);
        ISSUER_DATA = encoder.parseObject("{ 'issuerid' : 17 }".getBytes());
        USER = MockEmailPasswordAuthenticationFactory.USER;
    }
    
    @AfterClass
    public static void teardown() {
        USER = null;
        MASTER_TOKEN = null;
        encoder = null;
        ctx = null;
    }
    
    @Test
    public void ctors() throws MslEncoderException, MslException {
        final UserIdToken userIdToken = new UserIdToken(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
        assertTrue(userIdToken.isDecrypted());
        assertTrue(userIdToken.isVerified());
        assertFalse(userIdToken.isRenewable(null));
        assertFalse(userIdToken.isExpired(null));
        assertTrue(userIdToken.isBoundTo(MASTER_TOKEN));
        assertTrue(MslEncoderUtils.equalObjects(ISSUER_DATA, userIdToken.getIssuerData()));
        assertEquals(USER, userIdToken.getUser());
        assertEquals(EXPIRATION.getTime() / MILLISECONDS_PER_SECOND, userIdToken.getExpiration().getTime() / MILLISECONDS_PER_SECOND);
        assertEquals(MASTER_TOKEN.getSerialNumber(), userIdToken.getMasterTokenSerialNumber());
        assertEquals(RENEWAL_WINDOW.getTime() / MILLISECONDS_PER_SECOND, userIdToken.getRenewalWindow().getTime() / MILLISECONDS_PER_SECOND);
        assertEquals(SERIAL_NUMBER, userIdToken.getSerialNumber());
        final byte[] encode = userIdToken.toMslEncoding(encoder, ENCODER_FORMAT);
        assertNotNull(encode);
        
        final MslObject mo = encoder.parseObject(encode);
        final UserIdToken moUserIdToken = new UserIdToken(ctx, mo, MASTER_TOKEN);
        assertEquals(userIdToken.isDecrypted(), moUserIdToken.isDecrypted());
        assertEquals(userIdToken.isVerified(), moUserIdToken.isVerified());
        assertEquals(userIdToken.isRenewable(null), moUserIdToken.isRenewable(null));
        assertEquals(userIdToken.isExpired(null), moUserIdToken.isExpired(null));
        assertTrue(moUserIdToken.isBoundTo(MASTER_TOKEN));
        assertTrue(MslEncoderUtils.equalObjects(userIdToken.getIssuerData(), moUserIdToken.getIssuerData()));
        assertEquals(userIdToken.getUser(), moUserIdToken.getUser());
        assertEquals(userIdToken.getExpiration().getTime() / MILLISECONDS_PER_SECOND, moUserIdToken.getExpiration().getTime() / MILLISECONDS_PER_SECOND);
        assertEquals(userIdToken.getMasterTokenSerialNumber(), moUserIdToken.getMasterTokenSerialNumber());
        assertEquals(userIdToken.getRenewalWindow().getTime() / MILLISECONDS_PER_SECOND, moUserIdToken.getRenewalWindow().getTime() / MILLISECONDS_PER_SECOND);
        assertEquals(userIdToken.getSerialNumber(), moUserIdToken.getSerialNumber());
        final byte[] moEncode = moUserIdToken.toMslEncoding(encoder, ENCODER_FORMAT);
        assertNotNull(moEncode);
        assertArrayEquals(encode, moEncode);
    }
    
    @Test(expected = MslInternalException.class)
    public void negativeSerialNumberCtor() throws MslEncodingException, MslCryptoException {
        final long serialNumber = -1;
        new UserIdToken(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, serialNumber, ISSUER_DATA, USER);
    }
    
    @Test(expected = MslInternalException.class)
    public void tooLargeSerialNumberCtor() throws MslEncodingException, MslCryptoException {
        final long serialNumber = MslConstants.MAX_LONG_VALUE + 1;
        new UserIdToken(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, serialNumber, ISSUER_DATA, USER);
    }
    
    @Test(expected = MslInternalException.class)
    public void nullMasterToken() throws MslEncodingException, MslCryptoException {
        new UserIdToken(ctx, RENEWAL_WINDOW, EXPIRATION, null, SERIAL_NUMBER, ISSUER_DATA, USER);
    }
    
    @Test
    public void masterTokenMismatch() throws MslException, MslEncoderException {
        thrown.expect(MslException.class);
        thrown.expectMslError(MslError.USERIDTOKEN_MASTERTOKEN_MISMATCH);

        final MasterToken masterToken = MslTestUtils.getMasterToken(ctx, 1, 1);
        final UserIdToken userIdToken = new UserIdToken(ctx, RENEWAL_WINDOW, EXPIRATION, masterToken, SERIAL_NUMBER, ISSUER_DATA, USER);
        
        final MasterToken moMasterToken = MslTestUtils.getMasterToken(ctx, 1, 2);
        new UserIdToken(ctx, MslTestUtils.toMslObject(encoder, userIdToken), moMasterToken);
    }
    
    @Test
    public void masterTokenNull() throws MslException, MslEncoderException {
        thrown.expect(MslException.class);
        thrown.expectMslError(MslError.USERIDTOKEN_MASTERTOKEN_MISMATCH);

        final MasterToken masterToken = MslTestUtils.getMasterToken(ctx, 1, 1);
        final UserIdToken userIdToken = new UserIdToken(ctx, RENEWAL_WINDOW, EXPIRATION, masterToken, SERIAL_NUMBER, ISSUER_DATA, USER);
        
        new UserIdToken(ctx, MslTestUtils.toMslObject(encoder, userIdToken), null);
    }
    
    @Test(expected = MslInternalException.class)
    public void inconsistentExpiration() throws MslEncodingException, MslCryptoException {
        final Date expiration = new Date(System.currentTimeMillis() - 1);
        final Date renewalWindow = new Date();
        assertTrue(expiration.before(renewalWindow));
        new UserIdToken(ctx, renewalWindow, expiration, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
    }
    
    @Test
    public void inconsistentExpirationJson() throws MslEncoderException, MslException, UnsupportedEncodingException {
        thrown.expect(MslException.class);
        thrown.expectMslError(MslError.USERIDTOKEN_EXPIRES_BEFORE_RENEWAL);

        final UserIdToken userIdToken = new UserIdToken(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
        final byte[] encode = userIdToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);
        
        final byte[] tokendata = mo.getBytes(KEY_TOKENDATA);
        final MslObject tokendataMo = encoder.parseObject(tokendata);
        tokendataMo.put(KEY_EXPIRATION, System.currentTimeMillis() / MILLISECONDS_PER_SECOND - 1);
        tokendataMo.put(KEY_RENEWAL_WINDOW, System.currentTimeMillis() / MILLISECONDS_PER_SECOND);
        mo.put(KEY_TOKENDATA, encoder.encodeObject(tokendataMo, ENCODER_FORMAT));
        
        new UserIdToken(ctx, mo, MASTER_TOKEN);
    }
    
    @Test
    public void missingTokendata() throws MslException, MslEncoderException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MSL_PARSE_ERROR);

        final UserIdToken userIdToken = new UserIdToken(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
        final byte[] encode = userIdToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);
        
        assertNotNull(mo.remove(KEY_TOKENDATA));
        
        new UserIdToken(ctx, mo, MASTER_TOKEN);
    }
    
    @Test(expected = MslEncodingException.class)
    public void invalidTokendata() throws MslEncodingException, MslCryptoException, MslException, MslEncoderException {
        final UserIdToken userIdToken = new UserIdToken(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
        final byte[] encode = userIdToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);
        
        final byte[] tokendata = mo.getBytes(KEY_TOKENDATA);
        ++tokendata[0];
        mo.put(KEY_TOKENDATA, tokendata);
        
        new UserIdToken(ctx, mo, MASTER_TOKEN);
    }
    
    @Test
    public void missingSignature() throws MslEncodingException, MslCryptoException, MslException, MslEncoderException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MSL_PARSE_ERROR);

        final UserIdToken userIdToken = new UserIdToken(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
        final byte[] encode = userIdToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);
        
        assertNotNull(mo.remove(KEY_SIGNATURE));
        
        new UserIdToken(ctx, mo, MASTER_TOKEN);
    }
    
    @Test
    public void missingRenewalWindow() throws MslEncoderException, MslException, UnsupportedEncodingException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.USERIDTOKEN_TOKENDATA_PARSE_ERROR);

        final UserIdToken userIdToken = new UserIdToken(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
        final byte[] encode = userIdToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);

        final byte[] tokendata = mo.getBytes(KEY_TOKENDATA);
        final MslObject tokendataMo = encoder.parseObject(tokendata);
        assertNotNull(tokendataMo.remove(KEY_RENEWAL_WINDOW));
        mo.put(KEY_TOKENDATA, encoder.encodeObject(tokendataMo, ENCODER_FORMAT));
        
        new UserIdToken(ctx, mo, MASTER_TOKEN);
    }
    
    @Test
    public void invalidRenewalWindow() throws MslEncoderException, MslException, UnsupportedEncodingException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.USERIDTOKEN_TOKENDATA_PARSE_ERROR);

        final UserIdToken userIdToken = new UserIdToken(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
        final byte[] encode = userIdToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);

        final byte[] tokendata = mo.getBytes(KEY_TOKENDATA);
        final MslObject tokendataMo = encoder.parseObject(tokendata);
        tokendataMo.put(KEY_RENEWAL_WINDOW, "x");
        mo.put(KEY_TOKENDATA, encoder.encodeObject(tokendataMo, ENCODER_FORMAT));
        
        new UserIdToken(ctx, mo, MASTER_TOKEN);
    }
    
    @Test
    public void missingExpiration() throws MslEncoderException, MslException, UnsupportedEncodingException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.USERIDTOKEN_TOKENDATA_PARSE_ERROR);

        final UserIdToken userIdToken = new UserIdToken(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
        final byte[] encode = userIdToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);

        final byte[] tokendata = mo.getBytes(KEY_TOKENDATA);
        final MslObject tokendataMo = encoder.parseObject(tokendata);
        assertNotNull(tokendataMo.remove(KEY_EXPIRATION));
        mo.put(KEY_TOKENDATA, encoder.encodeObject(tokendataMo, ENCODER_FORMAT));
        
        new UserIdToken(ctx, mo, MASTER_TOKEN);
    }
    
    @Test
    public void invalidExpiration() throws MslEncoderException, MslException, UnsupportedEncodingException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.USERIDTOKEN_TOKENDATA_PARSE_ERROR);

        final UserIdToken userIdToken = new UserIdToken(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
        final byte[] encode = userIdToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);

        final byte[] tokendata = mo.getBytes(KEY_TOKENDATA);
        final MslObject tokendataMo = encoder.parseObject(tokendata);
        tokendataMo.put(KEY_EXPIRATION, "x");
        mo.put(KEY_TOKENDATA, encoder.encodeObject(tokendataMo, ENCODER_FORMAT));
        
        new UserIdToken(ctx, mo, MASTER_TOKEN);
    }
    
    @Test
    public void missingSerialNumber() throws MslEncoderException, MslException, UnsupportedEncodingException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.USERIDTOKEN_TOKENDATA_PARSE_ERROR);

        final UserIdToken userIdToken = new UserIdToken(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
        final byte[] encode = userIdToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);

        final byte[] tokendata = mo.getBytes(KEY_TOKENDATA);
        final MslObject tokendataMo = encoder.parseObject(tokendata);
        assertNotNull(tokendataMo.remove(KEY_SERIAL_NUMBER));
        mo.put(KEY_TOKENDATA, encoder.encodeObject(tokendataMo, ENCODER_FORMAT));
        
        new UserIdToken(ctx, mo, MASTER_TOKEN);
    }
    
    @Test
    public void invalidSerialNumber() throws MslEncoderException, MslException, UnsupportedEncodingException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.USERIDTOKEN_TOKENDATA_PARSE_ERROR);

        final UserIdToken userIdToken = new UserIdToken(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
        final byte[] encode = userIdToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);

        final byte[] tokendata = mo.getBytes(KEY_TOKENDATA);
        final MslObject tokendataMo = encoder.parseObject(tokendata);
        tokendataMo.put(KEY_SERIAL_NUMBER, "x");
        mo.put(KEY_TOKENDATA, encoder.encodeObject(tokendataMo, ENCODER_FORMAT));
        
        new UserIdToken(ctx, mo, MASTER_TOKEN);
    }
    
    @Test
    public void negativeSerialNumber() throws MslEncodingException, MslCryptoException, MslEncoderException, MslException {
        thrown.expect(MslException.class);
        thrown.expectMslError(MslError.USERIDTOKEN_SERIAL_NUMBER_OUT_OF_RANGE);

        final UserIdToken userIdToken = new UserIdToken(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
        final byte[] encode = userIdToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);

        final byte[] tokendata = mo.getBytes(KEY_TOKENDATA);
        final MslObject tokendataMo = encoder.parseObject(tokendata);
        tokendataMo.put(KEY_SERIAL_NUMBER, -1);
        mo.put(KEY_TOKENDATA, encoder.encodeObject(tokendataMo, ENCODER_FORMAT));
        
        new UserIdToken(ctx, mo, MASTER_TOKEN);
    }
    
    @Test
    public void tooLargeSerialNumber() throws MslEncodingException, MslCryptoException, MslEncoderException, MslException {
        thrown.expect(MslException.class);
        thrown.expectMslError(MslError.USERIDTOKEN_SERIAL_NUMBER_OUT_OF_RANGE);

        final UserIdToken userIdToken = new UserIdToken(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
        final byte[] encode = userIdToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);

        final byte[] tokendata = mo.getBytes(KEY_TOKENDATA);
        final MslObject tokendataMo = encoder.parseObject(tokendata);
        tokendataMo.put(KEY_SERIAL_NUMBER, MslConstants.MAX_LONG_VALUE + 1);
        mo.put(KEY_TOKENDATA, encoder.encodeObject(tokendataMo, ENCODER_FORMAT));
        
        new UserIdToken(ctx, mo, MASTER_TOKEN);
    }
    
    @Test
    public void missingMasterTokenSerialNumber() throws MslEncoderException, MslException, UnsupportedEncodingException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.USERIDTOKEN_TOKENDATA_PARSE_ERROR);

        final UserIdToken userIdToken = new UserIdToken(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
        final byte[] encode = userIdToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);

        final byte[] tokendata = mo.getBytes(KEY_TOKENDATA);
        final MslObject tokendataMo = encoder.parseObject(tokendata);
        assertNotNull(tokendataMo.remove(KEY_MASTER_TOKEN_SERIAL_NUMBER));
        mo.put(KEY_TOKENDATA, encoder.encodeObject(tokendataMo, ENCODER_FORMAT));
        
        new UserIdToken(ctx, mo, MASTER_TOKEN);
    }
    
    @Test
    public void invalidMasterTokenSerialNumber() throws MslEncoderException, MslException, UnsupportedEncodingException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.USERIDTOKEN_TOKENDATA_PARSE_ERROR);

        final UserIdToken userIdToken = new UserIdToken(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
        final byte[] encode = userIdToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);

        final byte[] tokendata = mo.getBytes(KEY_TOKENDATA);
        final MslObject tokendataMo = encoder.parseObject(tokendata);
        tokendataMo.put(KEY_MASTER_TOKEN_SERIAL_NUMBER, "x");
        mo.put(KEY_TOKENDATA, encoder.encodeObject(tokendataMo, ENCODER_FORMAT));
        
        new UserIdToken(ctx, mo, MASTER_TOKEN);
    }
    
    @Test
    public void negativeMasterTokenSerialNumber() throws MslEncodingException, MslCryptoException, MslEncoderException, MslException {
        thrown.expect(MslException.class);
        thrown.expectMslError(MslError.USERIDTOKEN_MASTERTOKEN_SERIAL_NUMBER_OUT_OF_RANGE);

        final UserIdToken userIdToken = new UserIdToken(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
        final byte[] encode = userIdToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);

        final byte[] tokendata = mo.getBytes(KEY_TOKENDATA);
        final MslObject tokendataMo = encoder.parseObject(tokendata);
        tokendataMo.put(KEY_MASTER_TOKEN_SERIAL_NUMBER, -1);
        mo.put(KEY_TOKENDATA, encoder.encodeObject(tokendataMo, ENCODER_FORMAT));
        
        new UserIdToken(ctx, mo, MASTER_TOKEN);
    }
    
    @Test
    public void tooLargeMasterTokenSerialNumber() throws MslEncodingException, MslCryptoException, MslEncoderException, MslException {
        thrown.expect(MslException.class);
        thrown.expectMslError(MslError.USERIDTOKEN_MASTERTOKEN_SERIAL_NUMBER_OUT_OF_RANGE);

        final UserIdToken userIdToken = new UserIdToken(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
        final byte[] encode = userIdToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);

        final byte[] tokendata = mo.getBytes(KEY_TOKENDATA);
        final MslObject tokendataMo = encoder.parseObject(tokendata);
        tokendataMo.put(KEY_MASTER_TOKEN_SERIAL_NUMBER, MslConstants.MAX_LONG_VALUE + 1);
        mo.put(KEY_TOKENDATA, encoder.encodeObject(tokendataMo, ENCODER_FORMAT));
        
        new UserIdToken(ctx, mo, MASTER_TOKEN);
    }
    
    @Test
    public void missingUserdata() throws MslEncoderException, MslException, UnsupportedEncodingException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.USERIDTOKEN_TOKENDATA_PARSE_ERROR);

        final UserIdToken userIdToken = new UserIdToken(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
        final byte[] encode = userIdToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);

        final byte[] tokendata = mo.getBytes(KEY_TOKENDATA);
        final MslObject tokendataMo = encoder.parseObject(tokendata);
        assertNotNull(tokendataMo.remove(KEY_USERDATA));
        mo.put(KEY_TOKENDATA, encoder.encodeObject(tokendataMo, ENCODER_FORMAT));
        
        new UserIdToken(ctx, mo, MASTER_TOKEN);
    }
    
    @Test
    public void invalidUserdata() throws MslEncodingException, MslCryptoException, MslException, UnsupportedEncodingException, MslEncoderException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.USERIDTOKEN_TOKENDATA_PARSE_ERROR);

        final UserIdToken userIdToken = new UserIdToken(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
        final byte[] encode = userIdToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);

        final byte[] tokendata = mo.getBytes(KEY_TOKENDATA);
        final MslObject tokendataMo = encoder.parseObject(tokendata);
        tokendataMo.put(KEY_USERDATA, "x");
        
        final ICryptoContext cryptoContext = ctx.getMslCryptoContext();
        final byte[] modifiedTokendata = encoder.encodeObject(tokendataMo, ENCODER_FORMAT);
        final byte[] signature = cryptoContext.sign(modifiedTokendata, encoder, ENCODER_FORMAT);
        mo.put(KEY_TOKENDATA, modifiedTokendata);
        mo.put(KEY_SIGNATURE, signature);
        
        new UserIdToken(ctx, mo, MASTER_TOKEN);
    }
    
    @Test
    public void emptyUserdata() throws MslEncodingException, MslCryptoException, MslException, UnsupportedEncodingException, MslEncoderException {
        thrown.expect(MslException.class);
        thrown.expectMslError(MslError.USERIDTOKEN_USERDATA_MISSING);

        final UserIdToken userIdToken = new UserIdToken(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
        final byte[] encode = userIdToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);

        final byte[] tokendata = mo.getBytes(KEY_TOKENDATA);
        final MslObject tokendataMo = encoder.parseObject(tokendata);

        final ICryptoContext cryptoContext = ctx.getMslCryptoContext();
        final byte[] ciphertext = new byte[0];
        tokendataMo.put(KEY_USERDATA, ciphertext);
        final byte[] modifiedTokendata = encoder.encodeObject(tokendataMo, ENCODER_FORMAT);
        final byte[] signature = cryptoContext.sign(modifiedTokendata, encoder, ENCODER_FORMAT);
        mo.put(KEY_TOKENDATA, modifiedTokendata);
        mo.put(KEY_SIGNATURE, signature);
        
        new UserIdToken(ctx, mo, MASTER_TOKEN);
    }
    
    @Test(expected = MslCryptoException.class)
    public void corruptUserdata() throws MslEncoderException, MslException, UnsupportedEncodingException {
        final UserIdToken userIdToken = new UserIdToken(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
        final byte[] encode = userIdToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);

        // This is testing user data that is verified but corrupt.
        final byte[] tokendata = mo.getBytes(KEY_TOKENDATA);
        final MslObject tokendataMo = encoder.parseObject(tokendata);
        final byte[] userdata = tokendataMo.getBytes(KEY_USERDATA);
        ++userdata[userdata.length-1];
        tokendataMo.put(KEY_USERDATA, userdata);
        
        final ICryptoContext cryptoContext = ctx.getMslCryptoContext();
        final byte[] modifiedTokendata = encoder.encodeObject(tokendataMo, ENCODER_FORMAT);
        final byte[] signature = cryptoContext.sign(modifiedTokendata, encoder, ENCODER_FORMAT);
        mo.put(KEY_TOKENDATA, modifiedTokendata);
        mo.put(KEY_SIGNATURE, signature);
        
        new UserIdToken(ctx, mo, MASTER_TOKEN);
    }
    
    @Test
    public void invalidUser() throws MslEncoderException, MslException {
        thrown.expect(MslException.class);
        thrown.expectMslError(MslError.USERIDTOKEN_IDENTITY_INVALID);

        final UserIdToken userIdToken = new UserIdToken(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
        final byte[] encode = userIdToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);

        final ICryptoContext cryptoContext = ctx.getMslCryptoContext();

        // Before modifying the user data we need to decrypt it.
        final byte[] tokendata = mo.getBytes(KEY_TOKENDATA);
        final MslObject tokendataMo = encoder.parseObject(tokendata);
        final byte[] ciphertext = tokendataMo.getBytes(KEY_USERDATA);
        final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
        final MslObject userdataMo = encoder.parseObject(plaintext);
        
        // After modifying the user data we need to encrypt it.
        userdataMo.put(KEY_IDENTITY, "x");
        final byte[] userdata = cryptoContext.encrypt(encoder.encodeObject(userdataMo, ENCODER_FORMAT), encoder, ENCODER_FORMAT);
        tokendataMo.put(KEY_USERDATA, userdata);

        // The tokendata must be signed otherwise the user data will not be
        // processed.
        final byte[] modifiedTokendata = encoder.encodeObject(tokendataMo, ENCODER_FORMAT);
        final byte[] signature = cryptoContext.sign(modifiedTokendata, encoder, ENCODER_FORMAT);
        mo.put(KEY_TOKENDATA, modifiedTokendata);
        mo.put(KEY_SIGNATURE, signature);
        
        new UserIdToken(ctx, mo, MASTER_TOKEN);
    }
    
    @Test
    public void emptyUser() throws MslEncoderException, MslException {
        thrown.expect(MslException.class);
        thrown.expectMslError(MslError.USERIDTOKEN_IDENTITY_INVALID);

        final UserIdToken userIdToken = new UserIdToken(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
        final byte[] encode = userIdToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);

        final ICryptoContext cryptoContext = ctx.getMslCryptoContext();

        // Before modifying the user data we need to decrypt it.
        final byte[] tokendata = mo.getBytes(KEY_TOKENDATA);
        final MslObject tokendataMo = encoder.parseObject(tokendata);
        final byte[] ciphertext = tokendataMo.getBytes(KEY_USERDATA);
        final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
        final MslObject userdataMo = encoder.parseObject(plaintext);
        
        // After modifying the user data we need to encrypt it.
        userdataMo.put(KEY_IDENTITY, "");
        final byte[] userdata = cryptoContext.encrypt(encoder.encodeObject(userdataMo, ENCODER_FORMAT), encoder, ENCODER_FORMAT);
        tokendataMo.put(KEY_USERDATA, userdata);

        // The tokendata must be signed otherwise the user data will not be
        // processed.
        final byte[] modifiedTokendata = encoder.encodeObject(tokendataMo, ENCODER_FORMAT);
        final byte[] signature = cryptoContext.sign(modifiedTokendata, encoder, ENCODER_FORMAT);
        mo.put(KEY_TOKENDATA, modifiedTokendata);
        mo.put(KEY_SIGNATURE, signature);
        
        new UserIdToken(ctx, mo, MASTER_TOKEN);
    }
    
    @Test
    public void missingUser() throws MslEncoderException, MslException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.USERIDTOKEN_USERDATA_PARSE_ERROR);

        final UserIdToken userIdToken = new UserIdToken(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
        final byte[] encode = userIdToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);

        final ICryptoContext cryptoContext = ctx.getMslCryptoContext();

        // Before modifying the user data we need to decrypt it.
        final byte[] tokendata = mo.getBytes(KEY_TOKENDATA);
        final MslObject tokendataMo = encoder.parseObject(tokendata);
        final byte[] ciphertext = tokendataMo.getBytes(KEY_USERDATA);
        final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
        final MslObject userdataMo = encoder.parseObject(plaintext);
        
        // After modifying the user data we need to encrypt it.
        userdataMo.remove(KEY_IDENTITY);
        final byte[] userdata = cryptoContext.encrypt(encoder.encodeObject(userdataMo, ENCODER_FORMAT), encoder, ENCODER_FORMAT);
        tokendataMo.put(KEY_USERDATA, userdata);

        // The tokendata must be signed otherwise the user data will not be
        // processed.
        final byte[] modifiedTokendata = encoder.encodeObject(tokendataMo, ENCODER_FORMAT);
        final byte[] signature = cryptoContext.sign(modifiedTokendata, encoder, ENCODER_FORMAT);
        mo.put(KEY_TOKENDATA, modifiedTokendata);
        mo.put(KEY_SIGNATURE, signature);
        
        new UserIdToken(ctx, mo, MASTER_TOKEN);
    }
    
    @Test
    public void invalidIssuerData() throws MslEncodingException, MslCryptoException, MslEncoderException, MslException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.USERIDTOKEN_USERDATA_PARSE_ERROR);

        final UserIdToken userIdToken = new UserIdToken(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
        final byte[] encode = userIdToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);

        final ICryptoContext cryptoContext = ctx.getMslCryptoContext();

        // Before modifying the user data we need to decrypt it.
        final byte[] tokendata = mo.getBytes(KEY_TOKENDATA);
        final MslObject tokendataMo = encoder.parseObject(tokendata);
        final byte[] ciphertext = tokendataMo.getBytes(KEY_USERDATA);
        final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
        final MslObject userdataMo = encoder.parseObject(plaintext);
        
        // After modifying the user data we need to encrypt it.
        userdataMo.put(KEY_ISSUER_DATA, "x");
        final byte[] userdata = cryptoContext.encrypt(encoder.encodeObject(userdataMo, ENCODER_FORMAT), encoder, ENCODER_FORMAT);
        tokendataMo.put(KEY_USERDATA, userdata);

        // The tokendata must be signed otherwise the user data will not be
        // processed.
        final byte[] modifiedTokendata = encoder.encodeObject(tokendataMo, ENCODER_FORMAT);
        final byte[] signature = cryptoContext.sign(modifiedTokendata, encoder, ENCODER_FORMAT);
        mo.put(KEY_TOKENDATA, modifiedTokendata);
        mo.put(KEY_SIGNATURE, signature);
        
        new UserIdToken(ctx, mo, MASTER_TOKEN);
    }
    
    @Test
    public void notVerified() throws MslEncoderException, MslException {
        final UserIdToken userIdToken = new UserIdToken(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
        final byte[] encode = userIdToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);

        final byte[] signature = mo.getBytes(KEY_SIGNATURE);
        ++signature[0];
        mo.put(KEY_SIGNATURE, signature);
        
        final UserIdToken moUserIdToken = new UserIdToken(ctx, mo, MASTER_TOKEN);
        assertFalse(moUserIdToken.isDecrypted());
        assertFalse(moUserIdToken.isVerified());
        assertTrue(moUserIdToken.isRenewable(null));
        assertFalse(moUserIdToken.isExpired(null));
        assertEquals(userIdToken.isBoundTo(MASTER_TOKEN), moUserIdToken.isBoundTo(MASTER_TOKEN));
        assertEquals(null, moUserIdToken.getUser());
        assertEquals(userIdToken.getExpiration().getTime() / MILLISECONDS_PER_SECOND, moUserIdToken.getExpiration().getTime() / MILLISECONDS_PER_SECOND);
        assertEquals(userIdToken.getMasterTokenSerialNumber(), moUserIdToken.getMasterTokenSerialNumber());
        assertEquals(userIdToken.getRenewalWindow().getTime() / MILLISECONDS_PER_SECOND, moUserIdToken.getRenewalWindow().getTime() / MILLISECONDS_PER_SECOND);
        assertEquals(userIdToken.getSerialNumber(), moUserIdToken.getSerialNumber());
        final byte[] moEncode = moUserIdToken.toMslEncoding(encoder, ENCODER_FORMAT);
        assertNotNull(moEncode);
        assertFalse(encode.equals(moEncode));
    }
    
    @Test
    public void isRenewable() throws MslEncodingException, MslCryptoException {
        final Date renewalWindow = new Date();
        final Date expiration = new Date(System.currentTimeMillis() + 1000);
        final UserIdToken userIdToken = new UserIdToken(ctx, renewalWindow, expiration, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);

        final Date now = new Date();
        assertTrue(userIdToken.isRenewable(null));
        assertTrue(userIdToken.isRenewable(now));
        assertFalse(userIdToken.isExpired(null));
        assertFalse(userIdToken.isExpired(now));
        
        final Date before = new Date(renewalWindow.getTime() - 1000);
        assertFalse(userIdToken.isRenewable(before));
        assertFalse(userIdToken.isExpired(before));
        
        final Date after = new Date(expiration.getTime() + 1000);
        assertTrue(userIdToken.isRenewable(after));
        assertTrue(userIdToken.isExpired(after));
    }
    
    @Test
    public void isExpired() throws MslEncodingException, MslCryptoException {
        final Date renewalWindow = new Date(System.currentTimeMillis() - 1000);
        final Date expiration = new Date();
        final UserIdToken userIdToken = new UserIdToken(ctx, renewalWindow, expiration, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);

        final Date now = new Date();
        assertTrue(userIdToken.isRenewable(null));
        assertTrue(userIdToken.isRenewable(now));
        assertTrue(userIdToken.isExpired(null));
        assertTrue(userIdToken.isExpired(now));
        
        final Date before = new Date(renewalWindow.getTime() - 1000);
        assertFalse(userIdToken.isRenewable(before));
        assertFalse(userIdToken.isExpired(before));
        
        final Date after = new Date(expiration.getTime() + 1000);
        assertTrue(userIdToken.isRenewable(after));
        assertTrue(userIdToken.isExpired(after));
    }
    
    @Test
    public void notRenewableOrExpired() throws MslEncodingException, MslCryptoException {
        final Date renewalWindow = new Date(System.currentTimeMillis() + 1000);
        final Date expiration = new Date(System.currentTimeMillis() + 2000);
        final UserIdToken userIdToken = new UserIdToken(ctx, renewalWindow, expiration, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);

        final Date now = new Date();
        assertFalse(userIdToken.isRenewable(null));
        assertFalse(userIdToken.isRenewable(now));
        assertFalse(userIdToken.isExpired(null));
        assertFalse(userIdToken.isExpired(now));
        
        final Date before = new Date(renewalWindow.getTime() - 1000);
        assertFalse(userIdToken.isRenewable(before));
        assertFalse(userIdToken.isExpired(before));
        
        final Date after = new Date(expiration.getTime() + 1000);
        assertTrue(userIdToken.isRenewable(after));
        assertTrue(userIdToken.isExpired(after));
    }
    
    @Test
    public void isBoundTo() throws MslEncodingException, MslCryptoException {
        final MasterToken masterTokenA = MslTestUtils.getMasterToken(ctx, 1, 1);
        final UserIdToken userIdTokenA = new UserIdToken(ctx, RENEWAL_WINDOW, EXPIRATION, masterTokenA, SERIAL_NUMBER, ISSUER_DATA, USER);
        final MasterToken masterTokenB = MslTestUtils.getMasterToken(ctx, 1, 2);
        final UserIdToken userIdTokenB = new UserIdToken(ctx, RENEWAL_WINDOW, EXPIRATION, masterTokenB, SERIAL_NUMBER, ISSUER_DATA, USER);
        
        assertTrue(userIdTokenA.isBoundTo(masterTokenA));
        assertFalse(userIdTokenA.isBoundTo(masterTokenB));
        assertFalse(userIdTokenA.isBoundTo(null));
        assertTrue(userIdTokenB.isBoundTo(masterTokenB));
        assertFalse(userIdTokenB.isBoundTo(masterTokenA));
        assertFalse(userIdTokenB.isBoundTo(null));
    }
    
    @Test
    public void equalsSerialNumber() throws MslException, MslEncoderException {
        final long serialNumberA = 1;
        final long serialNumberB = 2;
        final UserIdToken userIdTokenA = new UserIdToken(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, serialNumberA, ISSUER_DATA, USER);
        final UserIdToken userIdTokenB = new UserIdToken(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, serialNumberB, ISSUER_DATA, USER);
        final UserIdToken userIdTokenA2 = new UserIdToken(ctx, MslTestUtils.toMslObject(encoder, userIdTokenA), MASTER_TOKEN);
        
        assertTrue(userIdTokenA.equals(userIdTokenA));
        assertEquals(userIdTokenA.hashCode(), userIdTokenA.hashCode());
        
        assertFalse(userIdTokenA.equals(userIdTokenB));
        assertFalse(userIdTokenB.equals(userIdTokenA));
        assertTrue(userIdTokenA.hashCode() != userIdTokenB.hashCode());
        
        assertTrue(userIdTokenA.equals(userIdTokenA2));
        assertTrue(userIdTokenA2.equals(userIdTokenA));
        assertEquals(userIdTokenA.hashCode(), userIdTokenA2.hashCode());
    }
    
    @Test
    public void equalsMasterTokenSerialNumber() throws MslException, MslEncoderException {
        final MasterToken masterTokenA = MslTestUtils.getMasterToken(ctx, 1, 1);
        final MasterToken masterTokenB = MslTestUtils.getMasterToken(ctx, 1, 2);
        final UserIdToken userIdTokenA = new UserIdToken(ctx, RENEWAL_WINDOW, EXPIRATION, masterTokenA, SERIAL_NUMBER, ISSUER_DATA, USER);
        final UserIdToken userIdTokenB = new UserIdToken(ctx, RENEWAL_WINDOW, EXPIRATION, masterTokenB, SERIAL_NUMBER, ISSUER_DATA, USER);
        final UserIdToken userIdTokenA2 = new UserIdToken(ctx, MslTestUtils.toMslObject(encoder, userIdTokenA), masterTokenA);
        
        assertTrue(userIdTokenA.equals(userIdTokenA));
        assertEquals(userIdTokenA.hashCode(), userIdTokenA.hashCode());
        
        assertFalse(userIdTokenA.equals(userIdTokenB));
        assertFalse(userIdTokenB.equals(userIdTokenA));
        assertTrue(userIdTokenA.hashCode() != userIdTokenB.hashCode());
        
        assertTrue(userIdTokenA.equals(userIdTokenA2));
        assertTrue(userIdTokenA2.equals(userIdTokenA));
        assertEquals(userIdTokenA.hashCode(), userIdTokenA2.hashCode());
    }
    
    @Test
    public void equalsObject() throws MslEncodingException, MslCryptoException {
        final UserIdToken userIdToken = new UserIdToken(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
        assertFalse(userIdToken.equals(null));
        assertFalse(userIdToken.equals(RENEWAL_WINDOW));
        assertTrue(userIdToken.hashCode() != RENEWAL_WINDOW.hashCode());
    }
    
    /** MSL context. */
    private static MslContext ctx;
    /** MSL encoder factory. */
    private static MslEncoderFactory encoder;
}
