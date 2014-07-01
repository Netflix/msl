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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.UnsupportedEncodingException;
import java.util.Date;

import javax.xml.bind.DatatypeConverter;

import org.json.JSONException;
import org.json.JSONObject;
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
import com.netflix.msl.test.ExpectedMslException;
import com.netflix.msl.userauth.MockEmailPasswordAuthenticationFactory;
import com.netflix.msl.util.JsonUtils;
import com.netflix.msl.util.MockMslContext;
import com.netflix.msl.util.MslContext;
import com.netflix.msl.util.MslTestUtils;

/**
 * User ID token unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class UserIdTokenTest {
    /** Milliseconds per second. */
    private static final long MILLISECONDS_PER_SECOND = 1000;
    
    /** JSON key token data. */
    private static final String KEY_TOKENDATA = "tokendata";
    /** JSON key signature. */
    private static final String KEY_SIGNATURE = "signature";
    
    // tokendata
    /** JSON key renewal window timestamp. */
    private static final String KEY_RENEWAL_WINDOW = "renewalwindow";
    /** JSON key expiration timestamp. */
    private static final String KEY_EXPIRATION = "expiration";
    /** JSON key master token serial number. */
    private static final String KEY_MASTER_TOKEN_SERIAL_NUMBER = "mtserialnumber";
    /** JSON key user ID token serial number. */
    private static final String KEY_SERIAL_NUMBER = "serialnumber";
    /** JSON key token user identification data. */
    private static final String KEY_USERDATA = "userdata";
    
    // userdata
    /** JSON key issuer data. */
    private static final String KEY_ISSUER_DATA = "issuerdata";
    /** JSON key identity. */
    private static final String KEY_IDENTITY = "identity";
    
    private static final Date RENEWAL_WINDOW = new Date(System.currentTimeMillis() + 60000);
    private static final Date EXPIRATION = new Date(System.currentTimeMillis() + 120000);
    private static MasterToken MASTER_TOKEN;
    private static final long SERIAL_NUMBER = 42;
    private static JSONObject ISSUER_DATA;
    private static MslUser USER;

    @Rule
    public ExpectedMslException thrown = ExpectedMslException.none();
    
    @BeforeClass
    public static void setup() throws MslEncodingException, MslCryptoException, JSONException {
        ctx = new MockMslContext(EntityAuthenticationScheme.PSK, false);
        MASTER_TOKEN = MslTestUtils.getMasterToken(ctx, 1, 1);
        ISSUER_DATA = new JSONObject("{ issuerid = 17 }");
        USER = MockEmailPasswordAuthenticationFactory.USER;
    }
    
    @AfterClass
    public static void teardown() {
        USER = null;
        MASTER_TOKEN = null;
        ctx = null;
    }
    
    @Test
    public void ctors() throws JSONException, MslException {
        final UserIdToken userIdToken = new UserIdToken(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
        assertTrue(userIdToken.isDecrypted());
        assertTrue(userIdToken.isVerified());
        assertFalse(userIdToken.isRenewable());
        assertFalse(userIdToken.isExpired());
        assertTrue(userIdToken.isBoundTo(MASTER_TOKEN));
        assertTrue(JsonUtils.equals(ISSUER_DATA, userIdToken.getIssuerData()));
        assertEquals(USER, userIdToken.getUser());
        assertEquals(EXPIRATION.getTime() / MILLISECONDS_PER_SECOND, userIdToken.getExpiration().getTime() / MILLISECONDS_PER_SECOND);
        assertEquals(MASTER_TOKEN.getSerialNumber(), userIdToken.getMasterTokenSerialNumber());
        assertEquals(RENEWAL_WINDOW.getTime() / MILLISECONDS_PER_SECOND, userIdToken.getRenewalWindow().getTime() / MILLISECONDS_PER_SECOND);
        assertEquals(SERIAL_NUMBER, userIdToken.getSerialNumber());
        final String jsonString = userIdToken.toJSONString();
        assertNotNull(jsonString);
        
        final JSONObject jo = new JSONObject(jsonString);
        final UserIdToken joUserIdToken = new UserIdToken(ctx, jo, MASTER_TOKEN);
        assertEquals(userIdToken.isDecrypted(), joUserIdToken.isDecrypted());
        assertEquals(userIdToken.isVerified(), joUserIdToken.isVerified());
        assertEquals(userIdToken.isRenewable(), joUserIdToken.isRenewable());
        assertEquals(userIdToken.isExpired(), joUserIdToken.isExpired());
        assertTrue(joUserIdToken.isBoundTo(MASTER_TOKEN));
        assertTrue(JsonUtils.equals(userIdToken.getIssuerData(), joUserIdToken.getIssuerData()));
        assertEquals(userIdToken.getUser(), joUserIdToken.getUser());
        assertEquals(userIdToken.getExpiration().getTime() / MILLISECONDS_PER_SECOND, joUserIdToken.getExpiration().getTime() / MILLISECONDS_PER_SECOND);
        assertEquals(userIdToken.getMasterTokenSerialNumber(), joUserIdToken.getMasterTokenSerialNumber());
        assertEquals(userIdToken.getRenewalWindow().getTime() / MILLISECONDS_PER_SECOND, joUserIdToken.getRenewalWindow().getTime() / MILLISECONDS_PER_SECOND);
        assertEquals(userIdToken.getSerialNumber(), joUserIdToken.getSerialNumber());
        final String joJsonString = joUserIdToken.toJSONString();
        assertNotNull(joJsonString);
        assertEquals(jsonString, joJsonString);
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
    public void masterTokenMismatch() throws MslException, JSONException {
        thrown.expect(MslException.class);
        thrown.expectMslError(MslError.USERIDTOKEN_MASTERTOKEN_MISMATCH);

        final MasterToken masterToken = MslTestUtils.getMasterToken(ctx, 1, 1);
        final UserIdToken userIdToken = new UserIdToken(ctx, RENEWAL_WINDOW, EXPIRATION, masterToken, SERIAL_NUMBER, ISSUER_DATA, USER);
        
        final MasterToken joMasterToken = MslTestUtils.getMasterToken(ctx, 1, 2);
        new UserIdToken(ctx, new JSONObject(userIdToken.toJSONString()), joMasterToken);
    }
    
    @Test
    public void masterTokenNull() throws MslException, JSONException {
        thrown.expect(MslException.class);
        thrown.expectMslError(MslError.USERIDTOKEN_MASTERTOKEN_MISMATCH);

        final MasterToken masterToken = MslTestUtils.getMasterToken(ctx, 1, 1);
        final UserIdToken userIdToken = new UserIdToken(ctx, RENEWAL_WINDOW, EXPIRATION, masterToken, SERIAL_NUMBER, ISSUER_DATA, USER);
        
        new UserIdToken(ctx, new JSONObject(userIdToken.toJSONString()), null);
    }
    
    @Test(expected = MslInternalException.class)
    public void inconsistentExpiration() throws MslEncodingException, MslCryptoException {
        final Date expiration = new Date(System.currentTimeMillis() - 1);
        final Date renewalWindow = new Date();
        assertTrue(expiration.before(renewalWindow));
        new UserIdToken(ctx, renewalWindow, expiration, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
    }
    
    @Test
    public void inconsistentExpirationJson() throws JSONException, MslException, UnsupportedEncodingException {
        thrown.expect(MslException.class);
        thrown.expectMslError(MslError.USERIDTOKEN_EXPIRES_BEFORE_RENEWAL);

        final UserIdToken userIdToken = new UserIdToken(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
        final String jsonString = userIdToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);
        
        final byte[] tokendata = DatatypeConverter.parseBase64Binary(jo.getString(KEY_TOKENDATA));
        final JSONObject tokendataJo = new JSONObject(new String(tokendata, MslConstants.DEFAULT_CHARSET));
        tokendataJo.put(KEY_EXPIRATION, System.currentTimeMillis() / MILLISECONDS_PER_SECOND - 1);
        tokendataJo.put(KEY_RENEWAL_WINDOW, System.currentTimeMillis() / MILLISECONDS_PER_SECOND);
        jo.put(KEY_TOKENDATA, DatatypeConverter.printBase64Binary(tokendataJo.toString().getBytes()));
        
        new UserIdToken(ctx, jo, MASTER_TOKEN);
    }
    
    @Test
    public void missingTokendata() throws MslException, JSONException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.JSON_PARSE_ERROR);

        final UserIdToken userIdToken = new UserIdToken(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
        final String jsonString = userIdToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);
        
        assertNotNull(jo.remove(KEY_TOKENDATA));
        
        new UserIdToken(ctx, jo, MASTER_TOKEN);
    }
    
    @Test(expected = MslEncodingException.class)
    public void invalidTokendata() throws MslEncodingException, MslCryptoException, MslException, JSONException {
        final UserIdToken userIdToken = new UserIdToken(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
        final String jsonString = userIdToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);
        
        final byte[] tokendata = DatatypeConverter.parseBase64Binary(jo.getString(KEY_TOKENDATA));
        ++tokendata[0];
        jo.put(KEY_TOKENDATA, DatatypeConverter.printBase64Binary(tokendata));
        
        new UserIdToken(ctx, jo, MASTER_TOKEN);
    }
    
    @Test
    public void missingSignature() throws MslEncodingException, MslCryptoException, MslException, JSONException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.JSON_PARSE_ERROR);

        final UserIdToken userIdToken = new UserIdToken(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
        final String jsonString = userIdToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);
        
        assertNotNull(jo.remove(KEY_SIGNATURE));
        
        new UserIdToken(ctx, jo, MASTER_TOKEN);
    }
    
    @Test
    public void missingRenewalWindow() throws JSONException, MslException, UnsupportedEncodingException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.USERIDTOKEN_TOKENDATA_PARSE_ERROR);

        final UserIdToken userIdToken = new UserIdToken(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
        final String jsonString = userIdToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);

        final byte[] tokendata = DatatypeConverter.parseBase64Binary(jo.getString(KEY_TOKENDATA));
        final JSONObject tokendataJo = new JSONObject(new String(tokendata, MslConstants.DEFAULT_CHARSET));
        assertNotNull(tokendataJo.remove(KEY_RENEWAL_WINDOW));
        jo.put(KEY_TOKENDATA, DatatypeConverter.printBase64Binary(tokendataJo.toString().getBytes()));
        
        new UserIdToken(ctx, jo, MASTER_TOKEN);
    }
    
    @Test
    public void invalidRenewalWindow() throws JSONException, MslException, UnsupportedEncodingException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.USERIDTOKEN_TOKENDATA_PARSE_ERROR);

        final UserIdToken userIdToken = new UserIdToken(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
        final String jsonString = userIdToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);

        final byte[] tokendata = DatatypeConverter.parseBase64Binary(jo.getString(KEY_TOKENDATA));
        final JSONObject tokendataJo = new JSONObject(new String(tokendata, MslConstants.DEFAULT_CHARSET));
        tokendataJo.put(KEY_RENEWAL_WINDOW, "x");
        jo.put(KEY_TOKENDATA, DatatypeConverter.printBase64Binary(tokendataJo.toString().getBytes()));
        
        new UserIdToken(ctx, jo, MASTER_TOKEN);
    }
    
    @Test
    public void missingExpiration() throws JSONException, MslException, UnsupportedEncodingException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.USERIDTOKEN_TOKENDATA_PARSE_ERROR);

        final UserIdToken userIdToken = new UserIdToken(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
        final String jsonString = userIdToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);

        final byte[] tokendata = DatatypeConverter.parseBase64Binary(jo.getString(KEY_TOKENDATA));
        final JSONObject tokendataJo = new JSONObject(new String(tokendata, MslConstants.DEFAULT_CHARSET));
        assertNotNull(tokendataJo.remove(KEY_EXPIRATION));
        jo.put(KEY_TOKENDATA, DatatypeConverter.printBase64Binary(tokendataJo.toString().getBytes()));
        
        new UserIdToken(ctx, jo, MASTER_TOKEN);
    }
    
    @Test
    public void invalidExpiration() throws JSONException, MslException, UnsupportedEncodingException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.USERIDTOKEN_TOKENDATA_PARSE_ERROR);

        final UserIdToken userIdToken = new UserIdToken(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
        final String jsonString = userIdToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);

        final byte[] tokendata = DatatypeConverter.parseBase64Binary(jo.getString(KEY_TOKENDATA));
        final JSONObject tokendataJo = new JSONObject(new String(tokendata, MslConstants.DEFAULT_CHARSET));
        tokendataJo.put(KEY_EXPIRATION, "x");
        jo.put(KEY_TOKENDATA, DatatypeConverter.printBase64Binary(tokendataJo.toString().getBytes()));
        
        new UserIdToken(ctx, jo, MASTER_TOKEN);
    }
    
    @Test
    public void missingSerialNumber() throws JSONException, MslException, UnsupportedEncodingException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.USERIDTOKEN_TOKENDATA_PARSE_ERROR);

        final UserIdToken userIdToken = new UserIdToken(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
        final String jsonString = userIdToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);

        final byte[] tokendata = DatatypeConverter.parseBase64Binary(jo.getString(KEY_TOKENDATA));
        final JSONObject tokendataJo = new JSONObject(new String(tokendata, MslConstants.DEFAULT_CHARSET));
        assertNotNull(tokendataJo.remove(KEY_SERIAL_NUMBER));
        jo.put(KEY_TOKENDATA, DatatypeConverter.printBase64Binary(tokendataJo.toString().getBytes()));
        
        new UserIdToken(ctx, jo, MASTER_TOKEN);
    }
    
    @Test
    public void invalidSerialNumber() throws JSONException, MslException, UnsupportedEncodingException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.USERIDTOKEN_TOKENDATA_PARSE_ERROR);

        final UserIdToken userIdToken = new UserIdToken(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
        final String jsonString = userIdToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);

        final byte[] tokendata = DatatypeConverter.parseBase64Binary(jo.getString(KEY_TOKENDATA));
        final JSONObject tokendataJo = new JSONObject(new String(tokendata, MslConstants.DEFAULT_CHARSET));
        tokendataJo.put(KEY_SERIAL_NUMBER, "x");
        jo.put(KEY_TOKENDATA, DatatypeConverter.printBase64Binary(tokendataJo.toString().getBytes()));
        
        new UserIdToken(ctx, jo, MASTER_TOKEN);
    }
    
    @Test
    public void negativeSerialNumber() throws MslEncodingException, MslCryptoException, JSONException, MslException {
        thrown.expect(MslException.class);
        thrown.expectMslError(MslError.USERIDTOKEN_SERIAL_NUMBER_OUT_OF_RANGE);

        final UserIdToken userIdToken = new UserIdToken(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
        final String jsonString = userIdToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);

        final byte[] tokendata = DatatypeConverter.parseBase64Binary(jo.getString(KEY_TOKENDATA));
        final JSONObject tokendataJo = new JSONObject(new String(tokendata, MslConstants.DEFAULT_CHARSET));
        tokendataJo.put(KEY_SERIAL_NUMBER, -1);
        jo.put(KEY_TOKENDATA, DatatypeConverter.printBase64Binary(tokendataJo.toString().getBytes()));
        
        new UserIdToken(ctx, jo, MASTER_TOKEN);
    }
    
    @Test
    public void tooLargeSerialNumber() throws MslEncodingException, MslCryptoException, JSONException, MslException {
        thrown.expect(MslException.class);
        thrown.expectMslError(MslError.USERIDTOKEN_SERIAL_NUMBER_OUT_OF_RANGE);

        final UserIdToken userIdToken = new UserIdToken(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
        final String jsonString = userIdToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);

        final byte[] tokendata = DatatypeConverter.parseBase64Binary(jo.getString(KEY_TOKENDATA));
        final JSONObject tokendataJo = new JSONObject(new String(tokendata, MslConstants.DEFAULT_CHARSET));
        tokendataJo.put(KEY_SERIAL_NUMBER, MslConstants.MAX_LONG_VALUE + 1);
        jo.put(KEY_TOKENDATA, DatatypeConverter.printBase64Binary(tokendataJo.toString().getBytes()));
        
        new UserIdToken(ctx, jo, MASTER_TOKEN);
    }
    
    @Test
    public void missingMasterTokenSerialNumber() throws JSONException, MslException, UnsupportedEncodingException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.USERIDTOKEN_TOKENDATA_PARSE_ERROR);

        final UserIdToken userIdToken = new UserIdToken(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
        final String jsonString = userIdToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);

        final byte[] tokendata = DatatypeConverter.parseBase64Binary(jo.getString(KEY_TOKENDATA));
        final JSONObject tokendataJo = new JSONObject(new String(tokendata, MslConstants.DEFAULT_CHARSET));
        assertNotNull(tokendataJo.remove(KEY_MASTER_TOKEN_SERIAL_NUMBER));
        jo.put(KEY_TOKENDATA, DatatypeConverter.printBase64Binary(tokendataJo.toString().getBytes()));
        
        new UserIdToken(ctx, jo, MASTER_TOKEN);
    }
    
    @Test
    public void invalidMasterTokenSerialNumber() throws JSONException, MslException, UnsupportedEncodingException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.USERIDTOKEN_TOKENDATA_PARSE_ERROR);

        final UserIdToken userIdToken = new UserIdToken(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
        final String jsonString = userIdToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);

        final byte[] tokendata = DatatypeConverter.parseBase64Binary(jo.getString(KEY_TOKENDATA));
        final JSONObject tokendataJo = new JSONObject(new String(tokendata, MslConstants.DEFAULT_CHARSET));
        tokendataJo.put(KEY_MASTER_TOKEN_SERIAL_NUMBER, "x");
        jo.put(KEY_TOKENDATA, DatatypeConverter.printBase64Binary(tokendataJo.toString().getBytes()));
        
        new UserIdToken(ctx, jo, MASTER_TOKEN);
    }
    
    @Test
    public void negativeMasterTokenSerialNumber() throws MslEncodingException, MslCryptoException, JSONException, MslException {
        thrown.expect(MslException.class);
        thrown.expectMslError(MslError.USERIDTOKEN_MASTERTOKEN_SERIAL_NUMBER_OUT_OF_RANGE);

        final UserIdToken userIdToken = new UserIdToken(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
        final String jsonString = userIdToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);

        final byte[] tokendata = DatatypeConverter.parseBase64Binary(jo.getString(KEY_TOKENDATA));
        final JSONObject tokendataJo = new JSONObject(new String(tokendata, MslConstants.DEFAULT_CHARSET));
        tokendataJo.put(KEY_MASTER_TOKEN_SERIAL_NUMBER, -1);
        jo.put(KEY_TOKENDATA, DatatypeConverter.printBase64Binary(tokendataJo.toString().getBytes()));
        
        new UserIdToken(ctx, jo, MASTER_TOKEN);
    }
    
    @Test
    public void tooLargeMasterTokenSerialNumber() throws MslEncodingException, MslCryptoException, JSONException, MslException {
        thrown.expect(MslException.class);
        thrown.expectMslError(MslError.USERIDTOKEN_MASTERTOKEN_SERIAL_NUMBER_OUT_OF_RANGE);

        final UserIdToken userIdToken = new UserIdToken(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
        final String jsonString = userIdToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);

        final byte[] tokendata = DatatypeConverter.parseBase64Binary(jo.getString(KEY_TOKENDATA));
        final JSONObject tokendataJo = new JSONObject(new String(tokendata, MslConstants.DEFAULT_CHARSET));
        tokendataJo.put(KEY_MASTER_TOKEN_SERIAL_NUMBER, MslConstants.MAX_LONG_VALUE + 1);
        jo.put(KEY_TOKENDATA, DatatypeConverter.printBase64Binary(tokendataJo.toString().getBytes()));
        
        new UserIdToken(ctx, jo, MASTER_TOKEN);
    }
    
    @Test
    public void missingUserdata() throws JSONException, MslException, UnsupportedEncodingException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.USERIDTOKEN_TOKENDATA_PARSE_ERROR);

        final UserIdToken userIdToken = new UserIdToken(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
        final String jsonString = userIdToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);

        final byte[] tokendata = DatatypeConverter.parseBase64Binary(jo.getString(KEY_TOKENDATA));
        final JSONObject tokendataJo = new JSONObject(new String(tokendata, MslConstants.DEFAULT_CHARSET));
        assertNotNull(tokendataJo.remove(KEY_USERDATA));
        jo.put(KEY_TOKENDATA, DatatypeConverter.printBase64Binary(tokendataJo.toString().getBytes()));
        
        new UserIdToken(ctx, jo, MASTER_TOKEN);
    }
    
    @Test
    public void invalidUserdata() throws MslEncodingException, MslCryptoException, MslException, UnsupportedEncodingException, JSONException {
        thrown.expect(MslException.class);
        thrown.expectMslError(MslError.USERIDTOKEN_USERDATA_MISSING);

        final UserIdToken userIdToken = new UserIdToken(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
        final String jsonString = userIdToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);

        final byte[] tokendata = DatatypeConverter.parseBase64Binary(jo.getString(KEY_TOKENDATA));
        final JSONObject tokendataJo = new JSONObject(new String(tokendata, MslConstants.DEFAULT_CHARSET));
        tokendataJo.put(KEY_USERDATA, "x");
        
        final ICryptoContext cryptoContext = ctx.getMslCryptoContext();
        final byte[] modifiedTokendata = tokendataJo.toString().getBytes(MslConstants.DEFAULT_CHARSET);
        final byte[] signature = cryptoContext.sign(modifiedTokendata);
        jo.put(KEY_TOKENDATA, DatatypeConverter.printBase64Binary(modifiedTokendata));
        jo.put(KEY_SIGNATURE, DatatypeConverter.printBase64Binary(signature));
        
        new UserIdToken(ctx, jo, MASTER_TOKEN);
    }
    
    @Test
    public void emptyUserdata() throws MslEncodingException, MslCryptoException, MslException, UnsupportedEncodingException, JSONException {
        thrown.expect(MslException.class);
        thrown.expectMslError(MslError.USERIDTOKEN_USERDATA_MISSING);

        final UserIdToken userIdToken = new UserIdToken(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
        final String jsonString = userIdToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);

        final byte[] tokendata = DatatypeConverter.parseBase64Binary(jo.getString(KEY_TOKENDATA));
        final JSONObject tokendataJo = new JSONObject(new String(tokendata, MslConstants.DEFAULT_CHARSET));

        final ICryptoContext cryptoContext = ctx.getMslCryptoContext();
        final byte[] ciphertext = new byte[0];
        tokendataJo.put(KEY_USERDATA, DatatypeConverter.printBase64Binary(ciphertext));
        final byte[] modifiedTokendata = tokendataJo.toString().getBytes(MslConstants.DEFAULT_CHARSET);
        final byte[] signature = cryptoContext.sign(modifiedTokendata);
        jo.put(KEY_TOKENDATA, DatatypeConverter.printBase64Binary(modifiedTokendata));
        jo.put(KEY_SIGNATURE, DatatypeConverter.printBase64Binary(signature));
        
        new UserIdToken(ctx, jo, MASTER_TOKEN);
    }
    
    @Test(expected = MslCryptoException.class)
    public void corruptUserdata() throws JSONException, MslException, UnsupportedEncodingException {
        final UserIdToken userIdToken = new UserIdToken(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
        final String jsonString = userIdToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);

        // This is testing user data that is verified but corrupt.
        final byte[] tokendata = DatatypeConverter.parseBase64Binary(jo.getString(KEY_TOKENDATA));
        final JSONObject tokendataJo = new JSONObject(new String(tokendata, MslConstants.DEFAULT_CHARSET));
        final byte[] userdata = DatatypeConverter.parseBase64Binary(tokendataJo.getString(KEY_USERDATA));
        ++userdata[userdata.length-1];
        tokendataJo.put(KEY_USERDATA, DatatypeConverter.printBase64Binary(userdata));
        
        final ICryptoContext cryptoContext = ctx.getMslCryptoContext();
        final byte[] modifiedTokendata = tokendataJo.toString().getBytes(MslConstants.DEFAULT_CHARSET);
        final byte[] signature = cryptoContext.sign(modifiedTokendata);
        jo.put(KEY_TOKENDATA, DatatypeConverter.printBase64Binary(modifiedTokendata));
        jo.put(KEY_SIGNATURE, DatatypeConverter.printBase64Binary(signature));
        
        new UserIdToken(ctx, jo, MASTER_TOKEN);
    }
    
    @Test
    public void invalidUser() throws JSONException, MslException {
        thrown.expect(MslException.class);
        thrown.expectMslError(MslError.USERIDTOKEN_IDENTITY_INVALID);

        final UserIdToken userIdToken = new UserIdToken(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
        final String jsonString = userIdToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);

        final ICryptoContext cryptoContext = ctx.getMslCryptoContext();

        // Before modifying the user data we need to decrypt it.
        final byte[] tokendata = DatatypeConverter.parseBase64Binary(jo.getString(KEY_TOKENDATA));
        final JSONObject tokendataJo = new JSONObject(new String(tokendata, MslConstants.DEFAULT_CHARSET));
        final byte[] ciphertext = DatatypeConverter.parseBase64Binary(tokendataJo.getString(KEY_USERDATA));
        final byte[] plaintext = cryptoContext.decrypt(ciphertext);
        final JSONObject userdataJo = new JSONObject(new String(plaintext, MslConstants.DEFAULT_CHARSET));
        
        // After modifying the user data we need to encrypt it.
        userdataJo.put(KEY_IDENTITY, "x");
        final byte[] userdata = cryptoContext.encrypt(userdataJo.toString().getBytes(MslConstants.DEFAULT_CHARSET));
        tokendataJo.put(KEY_USERDATA, DatatypeConverter.printBase64Binary(userdata));

        // The tokendata must be signed otherwise the user data will not be
        // processed.
        final byte[] modifiedTokendata = tokendataJo.toString().getBytes(MslConstants.DEFAULT_CHARSET);
        final byte[] signature = cryptoContext.sign(modifiedTokendata);
        jo.put(KEY_TOKENDATA, DatatypeConverter.printBase64Binary(modifiedTokendata));
        jo.put(KEY_SIGNATURE, DatatypeConverter.printBase64Binary(signature));
        
        new UserIdToken(ctx, jo, MASTER_TOKEN);
    }
    
    @Test
    public void emptyUser() throws JSONException, MslException {
        thrown.expect(MslException.class);
        thrown.expectMslError(MslError.USERIDTOKEN_IDENTITY_INVALID);

        final UserIdToken userIdToken = new UserIdToken(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
        final String jsonString = userIdToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);

        final ICryptoContext cryptoContext = ctx.getMslCryptoContext();

        // Before modifying the user data we need to decrypt it.
        final byte[] tokendata = DatatypeConverter.parseBase64Binary(jo.getString(KEY_TOKENDATA));
        final JSONObject tokendataJo = new JSONObject(new String(tokendata, MslConstants.DEFAULT_CHARSET));
        final byte[] ciphertext = DatatypeConverter.parseBase64Binary(tokendataJo.getString(KEY_USERDATA));
        final byte[] plaintext = cryptoContext.decrypt(ciphertext);
        final JSONObject userdataJo = new JSONObject(new String(plaintext, MslConstants.DEFAULT_CHARSET));
        
        // After modifying the user data we need to encrypt it.
        userdataJo.put(KEY_IDENTITY, "");
        final byte[] userdata = cryptoContext.encrypt(userdataJo.toString().getBytes(MslConstants.DEFAULT_CHARSET));
        tokendataJo.put(KEY_USERDATA, DatatypeConverter.printBase64Binary(userdata));

        // The tokendata must be signed otherwise the user data will not be
        // processed.
        final byte[] modifiedTokendata = tokendataJo.toString().getBytes(MslConstants.DEFAULT_CHARSET);
        final byte[] signature = cryptoContext.sign(modifiedTokendata);
        jo.put(KEY_TOKENDATA, DatatypeConverter.printBase64Binary(modifiedTokendata));
        jo.put(KEY_SIGNATURE, DatatypeConverter.printBase64Binary(signature));
        
        new UserIdToken(ctx, jo, MASTER_TOKEN);
    }
    
    @Test
    public void missingUser() throws JSONException, MslException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.USERIDTOKEN_USERDATA_PARSE_ERROR);

        final UserIdToken userIdToken = new UserIdToken(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
        final String jsonString = userIdToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);

        final ICryptoContext cryptoContext = ctx.getMslCryptoContext();

        // Before modifying the user data we need to decrypt it.
        final byte[] tokendata = DatatypeConverter.parseBase64Binary(jo.getString(KEY_TOKENDATA));
        final JSONObject tokendataJo = new JSONObject(new String(tokendata, MslConstants.DEFAULT_CHARSET));
        final byte[] ciphertext = DatatypeConverter.parseBase64Binary(tokendataJo.getString(KEY_USERDATA));
        final byte[] plaintext = cryptoContext.decrypt(ciphertext);
        final JSONObject userdataJo = new JSONObject(new String(plaintext, MslConstants.DEFAULT_CHARSET));
        
        // After modifying the user data we need to encrypt it.
        userdataJo.remove(KEY_IDENTITY);
        final byte[] userdata = cryptoContext.encrypt(userdataJo.toString().getBytes(MslConstants.DEFAULT_CHARSET));
        tokendataJo.put(KEY_USERDATA, DatatypeConverter.printBase64Binary(userdata));

        // The tokendata must be signed otherwise the user data will not be
        // processed.
        final byte[] modifiedTokendata = tokendataJo.toString().getBytes(MslConstants.DEFAULT_CHARSET);
        final byte[] signature = cryptoContext.sign(modifiedTokendata);
        jo.put(KEY_TOKENDATA, DatatypeConverter.printBase64Binary(modifiedTokendata));
        jo.put(KEY_SIGNATURE, DatatypeConverter.printBase64Binary(signature));
        
        new UserIdToken(ctx, jo, MASTER_TOKEN);
    }
    
    @Test
    public void invalidIssuerData() throws MslEncodingException, MslCryptoException, JSONException, MslException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.USERIDTOKEN_USERDATA_PARSE_ERROR);

        final UserIdToken userIdToken = new UserIdToken(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
        final String jsonString = userIdToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);

        final ICryptoContext cryptoContext = ctx.getMslCryptoContext();

        // Before modifying the user data we need to decrypt it.
        final byte[] tokendata = DatatypeConverter.parseBase64Binary(jo.getString(KEY_TOKENDATA));
        final JSONObject tokendataJo = new JSONObject(new String(tokendata, MslConstants.DEFAULT_CHARSET));
        final byte[] ciphertext = DatatypeConverter.parseBase64Binary(tokendataJo.getString(KEY_USERDATA));
        final byte[] plaintext = cryptoContext.decrypt(ciphertext);
        final JSONObject userdataJo = new JSONObject(new String(plaintext, MslConstants.DEFAULT_CHARSET));
        
        // After modifying the user data we need to encrypt it.
        userdataJo.put(KEY_ISSUER_DATA, "x");
        final byte[] userdata = cryptoContext.encrypt(userdataJo.toString().getBytes(MslConstants.DEFAULT_CHARSET));
        tokendataJo.put(KEY_USERDATA, DatatypeConverter.printBase64Binary(userdata));

        // The tokendata must be signed otherwise the user data will not be
        // processed.
        final byte[] modifiedTokendata = tokendataJo.toString().getBytes(MslConstants.DEFAULT_CHARSET);
        final byte[] signature = cryptoContext.sign(modifiedTokendata);
        jo.put(KEY_TOKENDATA, DatatypeConverter.printBase64Binary(modifiedTokendata));
        jo.put(KEY_SIGNATURE, DatatypeConverter.printBase64Binary(signature));
        
        new UserIdToken(ctx, jo, MASTER_TOKEN);
    }
    
    @Test
    public void notVerified() throws JSONException, MslException {
        final UserIdToken userIdToken = new UserIdToken(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
        final String jsonString = userIdToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);

        final byte[] signature = DatatypeConverter.parseBase64Binary(jo.getString(KEY_SIGNATURE));
        ++signature[0];
        jo.put(KEY_SIGNATURE, DatatypeConverter.printBase64Binary(signature));
        
        final UserIdToken joUserIdToken = new UserIdToken(ctx, jo, MASTER_TOKEN);
        assertFalse(joUserIdToken.isDecrypted());
        assertFalse(joUserIdToken.isVerified());
        assertEquals(userIdToken.isRenewable(), joUserIdToken.isRenewable());
        assertEquals(userIdToken.isExpired(), joUserIdToken.isExpired());
        assertEquals(userIdToken.isBoundTo(MASTER_TOKEN), joUserIdToken.isBoundTo(MASTER_TOKEN));
        assertEquals(null, joUserIdToken.getUser());
        assertEquals(userIdToken.getExpiration().getTime() / MILLISECONDS_PER_SECOND, joUserIdToken.getExpiration().getTime() / MILLISECONDS_PER_SECOND);
        assertEquals(userIdToken.getMasterTokenSerialNumber(), joUserIdToken.getMasterTokenSerialNumber());
        assertEquals(userIdToken.getRenewalWindow().getTime() / MILLISECONDS_PER_SECOND, joUserIdToken.getRenewalWindow().getTime() / MILLISECONDS_PER_SECOND);
        assertEquals(userIdToken.getSerialNumber(), joUserIdToken.getSerialNumber());
        final String joJsonString = joUserIdToken.toJSONString();
        assertNotNull(joJsonString);
        assertFalse(jsonString.equals(joJsonString));
    }
    
    @Test
    public void isRenewable() throws MslEncodingException, MslCryptoException {
        final Date renewalWindow = new Date();
        final Date expiration = new Date(System.currentTimeMillis() + 1000);
        final UserIdToken userIdToken = new UserIdToken(ctx, renewalWindow, expiration, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
        
        assertTrue(userIdToken.isRenewable());
        assertFalse(userIdToken.isExpired());
    }
    
    @Test
    public void isExpired() throws MslEncodingException, MslCryptoException {
        final Date renewalWindow = new Date(System.currentTimeMillis() - 1000);
        final Date expiration = new Date();
        final UserIdToken userIdToken = new UserIdToken(ctx, renewalWindow, expiration, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
        
        assertTrue(userIdToken.isRenewable());
        assertTrue(userIdToken.isExpired());
    }
    
    @Test
    public void notRenewableOrExpired() throws MslEncodingException, MslCryptoException {
        final Date renewalWindow = new Date(System.currentTimeMillis() + 1000);
        final Date expiration = new Date(System.currentTimeMillis() + 2000);
        final UserIdToken userIdToken = new UserIdToken(ctx, renewalWindow, expiration, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
        
        assertFalse(userIdToken.isRenewable());
        assertFalse(userIdToken.isExpired());
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
    public void equalsSerialNumber() throws MslException, JSONException {
        final long serialNumberA = 1;
        final long serialNumberB = 2;
        final UserIdToken userIdTokenA = new UserIdToken(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, serialNumberA, ISSUER_DATA, USER);
        final UserIdToken userIdTokenB = new UserIdToken(ctx, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, serialNumberB, ISSUER_DATA, USER);
        final UserIdToken userIdTokenA2 = new UserIdToken(ctx, new JSONObject(userIdTokenA.toJSONString()), MASTER_TOKEN);
        
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
    public void equalsMasterTokenSerialNumber() throws MslException, JSONException {
        final MasterToken masterTokenA = MslTestUtils.getMasterToken(ctx, 1, 1);
        final MasterToken masterTokenB = MslTestUtils.getMasterToken(ctx, 1, 2);
        final UserIdToken userIdTokenA = new UserIdToken(ctx, RENEWAL_WINDOW, EXPIRATION, masterTokenA, SERIAL_NUMBER, ISSUER_DATA, USER);
        final UserIdToken userIdTokenB = new UserIdToken(ctx, RENEWAL_WINDOW, EXPIRATION, masterTokenB, SERIAL_NUMBER, ISSUER_DATA, USER);
        final UserIdToken userIdTokenA2 = new UserIdToken(ctx, new JSONObject(userIdTokenA.toJSONString()), masterTokenA);
        
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
}
