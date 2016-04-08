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
import java.util.Date;

import javax.crypto.SecretKey;

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
import com.netflix.msl.crypto.JcaAlgorithm;
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.entityauth.MockPresharedAuthenticationFactory;
import com.netflix.msl.test.ExpectedMslException;
import com.netflix.msl.util.Base64;
import com.netflix.msl.util.JsonUtils;
import com.netflix.msl.util.MockMslContext;
import com.netflix.msl.util.MslContext;

/**
 * Master token unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class MasterTokenTest {
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
    /** JSON key sequence number. */
    private static final String KEY_SEQUENCE_NUMBER = "sequencenumber";
    /** JSON key serial number. */
    private static final String KEY_SERIAL_NUMBER = "serialnumber";
    /** JSON key session data. */
    private static final String KEY_SESSIONDATA = "sessiondata";
    
    // sessiondata
    /** JSON key issuer data. */
    private static final String KEY_ISSUER_DATA = "issuerdata";
    /** JSON key identity. */
    private static final String KEY_IDENTITY = "identity";
    /** JSON key symmetric encryption key. */
    private static final String KEY_ENCRYPTION_KEY = "encryptionkey";
    /** JSON key encryption algorithm. */
    private static final String KEY_ENCRYPTION_ALGORITHM = "encryptionalgorithm";
    /** JSON key symmetric HMAC key. */
    private static final String KEY_HMAC_KEY = "hmackey";
    /** JSON key signature key. */
    private static final String KEY_SIGNATURE_KEY = "signaturekey";
    /** JSON key signature algorithm. */
    private static final String KEY_SIGNATURE_ALGORITHM = "signaturealgorithm";
    
    private static final Date RENEWAL_WINDOW = new Date(System.currentTimeMillis() + 60000);
    private static final Date EXPIRATION = new Date(System.currentTimeMillis() + 120000);
    private static final long SEQUENCE_NUMBER = 1;
    private static final long SERIAL_NUMBER = 42;
    private static JSONObject ISSUER_DATA;
    private static final String IDENTITY = MockPresharedAuthenticationFactory.PSK_ESN;
    private static final SecretKey ENCRYPTION_KEY = MockPresharedAuthenticationFactory.KPE;
    private static final SecretKey SIGNATURE_KEY = MockPresharedAuthenticationFactory.KPH;
    
    private static long incrementSequenceNumber(final long seqNo, final long amount) {
        if (seqNo - MslConstants.MAX_LONG_VALUE + amount <= 0)
            return seqNo + amount;
        return seqNo - MslConstants.MAX_LONG_VALUE - 1 + amount;
    }
    
    private static long decrementSequenceNumber(final long seqNo, final long amount) {
        if (seqNo - amount >= 0)
            return seqNo - amount;
        return MslConstants.MAX_LONG_VALUE - amount - 1 + seqNo;
    }

    @Rule
    public ExpectedMslException thrown = ExpectedMslException.none();
    
    @BeforeClass
    public static void setup() throws MslEncodingException, MslCryptoException, JSONException {
        ctx = new MockMslContext(EntityAuthenticationScheme.PSK, false);
        ISSUER_DATA = new JSONObject("{ 'issuerid' : 17 }");
    }
    
    @AfterClass
    public static void teardown() {
        ctx = null;
    }
    
    @Test
    public void ctors() throws JSONException, MslException {
        final MasterToken masterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        assertTrue(masterToken.isDecrypted());
        assertTrue(masterToken.isVerified());
        assertFalse(masterToken.isRenewable(null));
        assertFalse(masterToken.isExpired(null));
        assertFalse(masterToken.isNewerThan(masterToken));
        assertArrayEquals(ENCRYPTION_KEY.getEncoded(), masterToken.getEncryptionKey().getEncoded());
        assertEquals(EXPIRATION.getTime() / MILLISECONDS_PER_SECOND, masterToken.getExpiration().getTime() / MILLISECONDS_PER_SECOND);
        assertArrayEquals(SIGNATURE_KEY.getEncoded(), masterToken.getSignatureKey().getEncoded());
        assertEquals(IDENTITY, masterToken.getIdentity());
        assertTrue(JsonUtils.equals(ISSUER_DATA, masterToken.getIssuerData()));
        assertEquals(RENEWAL_WINDOW.getTime() / MILLISECONDS_PER_SECOND, masterToken.getRenewalWindow().getTime() / MILLISECONDS_PER_SECOND);
        assertEquals(SEQUENCE_NUMBER, masterToken.getSequenceNumber());
        assertEquals(SERIAL_NUMBER, masterToken.getSerialNumber());
        final String jsonString = masterToken.toJSONString();
        assertNotNull(jsonString);
        
        final JSONObject jo = new JSONObject(jsonString);
        final MasterToken joMasterToken = new MasterToken(ctx, jo);
        assertEquals(masterToken.isDecrypted(), joMasterToken.isDecrypted());
        assertEquals(masterToken.isVerified(), joMasterToken.isVerified());
        assertEquals(masterToken.isRenewable(null), joMasterToken.isRenewable(null));
        assertEquals(masterToken.isExpired(null), joMasterToken.isExpired(null));
        assertFalse(joMasterToken.isNewerThan(masterToken));
        assertFalse(masterToken.isNewerThan(joMasterToken));
        assertArrayEquals(masterToken.getEncryptionKey().getEncoded(), joMasterToken.getEncryptionKey().getEncoded());
        assertEquals(masterToken.getExpiration().getTime() / MILLISECONDS_PER_SECOND, joMasterToken.getExpiration().getTime() / MILLISECONDS_PER_SECOND);
        assertArrayEquals(masterToken.getSignatureKey().getEncoded(), joMasterToken.getSignatureKey().getEncoded());
        assertEquals(masterToken.getIdentity(), joMasterToken.getIdentity());
        assertTrue(JsonUtils.equals(masterToken.getIssuerData(), joMasterToken.getIssuerData()));
        assertEquals(masterToken.getRenewalWindow().getTime() / MILLISECONDS_PER_SECOND, joMasterToken.getRenewalWindow().getTime() / MILLISECONDS_PER_SECOND);
        assertEquals(masterToken.getSequenceNumber(), joMasterToken.getSequenceNumber());
        assertEquals(masterToken.getSerialNumber(), joMasterToken.getSerialNumber());
        final String joJsonString = joMasterToken.toJSONString();
        assertNotNull(joJsonString);
        assertEquals(jsonString, joJsonString);
    }
    
    @Test(expected = MslInternalException.class)
    public void negativeSequenceNumberCtor() throws MslEncodingException, MslCryptoException {
        final long sequenceNumber = -1;
        new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, sequenceNumber, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
    }
    
    @Test(expected = MslInternalException.class)
    public void tooLargeSequenceNumberCtor() throws MslEncodingException, MslCryptoException {
        final long sequenceNumber = MslConstants.MAX_LONG_VALUE + 1;
        new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, sequenceNumber, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
    }
    
    @Test(expected = MslInternalException.class)
    public void negativeSerialNumberCtor() throws MslEncodingException, MslCryptoException {
        final long serialNumber = -1;
        new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, serialNumber, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
    }
    
    @Test(expected = MslInternalException.class)
    public void tooLargeSerialNumberCtor() throws MslEncodingException, MslCryptoException {
        final long serialNumber = MslConstants.MAX_LONG_VALUE + 1;
        new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, serialNumber, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
    }
    
    @Test(expected = MslInternalException.class)
    public void inconsistentExpiration() throws MslException, JSONException {
        final Date expiration = new Date(System.currentTimeMillis() - 1);
        final Date renewalWindow = new Date();
        assertTrue(expiration.before(renewalWindow));
        new MasterToken(ctx, renewalWindow, expiration, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
    }
    
    @Test
    public void inconsistentExpirationJson() throws MslException, JSONException, UnsupportedEncodingException {
        thrown.expect(MslException.class);
        thrown.expectMslError(MslError.MASTERTOKEN_EXPIRES_BEFORE_RENEWAL);

        final MasterToken masterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final String jsonString = masterToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);
        
        final byte[] tokendata = Base64.decode(jo.getString(KEY_TOKENDATA));
        final JSONObject tokendataJo = new JSONObject(new String(tokendata, MslConstants.DEFAULT_CHARSET));
        tokendataJo.put(KEY_EXPIRATION, System.currentTimeMillis() / MILLISECONDS_PER_SECOND - 1);
        tokendataJo.put(KEY_RENEWAL_WINDOW, System.currentTimeMillis() / MILLISECONDS_PER_SECOND);
        jo.put(KEY_TOKENDATA, Base64.encode(tokendataJo.toString().getBytes()));
        
        new MasterToken(ctx, jo);
    }
    
    @Test
    public void nullIssuerData() throws JSONException, MslException {
        final MasterToken masterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, null, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        assertNull(masterToken.getIssuerData());
        
        final String jsonString = masterToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);
        
        final MasterToken joMasterToken = new MasterToken(ctx, jo);
        assertNull(joMasterToken.getIssuerData());
    }
    
    @Test
    public void missingTokendata() throws JSONException, MslException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.JSON_PARSE_ERROR);

        final MasterToken masterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final String jsonString = masterToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);

        assertNotNull(jo.remove(KEY_TOKENDATA));

        new MasterToken(ctx, jo);
    }
    
    @Test(expected = MslEncodingException.class)
    public void invalidTokendata() throws JSONException, MslException {
        final MasterToken masterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final String jsonString = masterToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);
        
        final byte[] tokendata = Base64.decode(jo.getString(KEY_TOKENDATA));
        ++tokendata[0];
        jo.put(KEY_TOKENDATA, Base64.encode(tokendata));
        
        new MasterToken(ctx, jo);
    }
    
    @Test
    public void missingSignature() throws JSONException, MslException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.JSON_PARSE_ERROR);

        final MasterToken masterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final String jsonString = masterToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);
        
        assertNotNull(jo.remove(KEY_SIGNATURE));
        
        new MasterToken(ctx, jo);
    }
    
    @Test
    public void missingRenewalWindow() throws JSONException, MslException, UnsupportedEncodingException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MASTERTOKEN_TOKENDATA_PARSE_ERROR);

        final MasterToken masterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final String jsonString = masterToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);
        
        final byte[] tokendata = Base64.decode(jo.getString(KEY_TOKENDATA));
        final JSONObject tokendataJo = new JSONObject(new String(tokendata, MslConstants.DEFAULT_CHARSET));
        assertNotNull(tokendataJo.remove(KEY_RENEWAL_WINDOW));
        jo.put(KEY_TOKENDATA, Base64.encode(tokendataJo.toString().getBytes()));
        
        new MasterToken(ctx, jo);
    }
    
    @Test
    public void invalidRenewalWindow() throws JSONException, MslException, UnsupportedEncodingException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MASTERTOKEN_TOKENDATA_PARSE_ERROR);

        final MasterToken masterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final String jsonString = masterToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);
        
        final byte[] tokendata = Base64.decode(jo.getString(KEY_TOKENDATA));
        final JSONObject tokendataJo = new JSONObject(new String(tokendata, MslConstants.DEFAULT_CHARSET));
        tokendataJo.put(KEY_RENEWAL_WINDOW, "x");
        jo.put(KEY_TOKENDATA, Base64.encode(tokendataJo.toString().getBytes()));
        
        new MasterToken(ctx, jo);
    }
    
    @Test
    public void missingExpiration() throws JSONException, MslException, UnsupportedEncodingException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MASTERTOKEN_TOKENDATA_PARSE_ERROR);

        final MasterToken masterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final String jsonString = masterToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);
        
        final byte[] tokendata = Base64.decode(jo.getString(KEY_TOKENDATA));
        final JSONObject tokendataJo = new JSONObject(new String(tokendata, MslConstants.DEFAULT_CHARSET));
        assertNotNull(tokendataJo.remove(KEY_EXPIRATION));
        jo.put(KEY_TOKENDATA, Base64.encode(tokendataJo.toString().getBytes()));
        
        new MasterToken(ctx, jo);
    }
    
    @Test
    public void invalidExpiration() throws JSONException, MslException, UnsupportedEncodingException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MASTERTOKEN_TOKENDATA_PARSE_ERROR);

        final MasterToken masterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final String jsonString = masterToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);
        
        final byte[] tokendata = Base64.decode(jo.getString(KEY_TOKENDATA));
        final JSONObject tokendataJo = new JSONObject(new String(tokendata, MslConstants.DEFAULT_CHARSET));
        tokendataJo.put(KEY_EXPIRATION, "x");
        jo.put(KEY_TOKENDATA, Base64.encode(tokendataJo.toString().getBytes()));
        
        new MasterToken(ctx, jo);
    }
    
    @Test
    public void missingSequenceNumber() throws JSONException, MslException, UnsupportedEncodingException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MASTERTOKEN_TOKENDATA_PARSE_ERROR);

        final MasterToken masterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final String jsonString = masterToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);
        
        final byte[] tokendata = Base64.decode(jo.getString(KEY_TOKENDATA));
        final JSONObject tokendataJo = new JSONObject(new String(tokendata, MslConstants.DEFAULT_CHARSET));
        assertNotNull(tokendataJo.remove(KEY_SEQUENCE_NUMBER));
        jo.put(KEY_TOKENDATA, Base64.encode(tokendataJo.toString().getBytes()));
        
        new MasterToken(ctx, jo);
    }
    
    @Test
    public void invalidSequenceNumber() throws JSONException, MslException, UnsupportedEncodingException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MASTERTOKEN_TOKENDATA_PARSE_ERROR);

        final MasterToken masterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final String jsonString = masterToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);
        
        final byte[] tokendata = Base64.decode(jo.getString(KEY_TOKENDATA));
        final JSONObject tokendataJo = new JSONObject(new String(tokendata, MslConstants.DEFAULT_CHARSET));
        tokendataJo.put(KEY_SEQUENCE_NUMBER, "x");
        jo.put(KEY_TOKENDATA, Base64.encode(tokendataJo.toString().getBytes()));
        
        new MasterToken(ctx, jo);
    }
    
    @Test
    public void negativeSequenceNumber() throws MslEncodingException, MslCryptoException, JSONException, MslException {
        thrown.expect(MslException.class);
        thrown.expectMslError(MslError.MASTERTOKEN_SEQUENCE_NUMBER_OUT_OF_RANGE);

        final MasterToken masterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final String jsonString = masterToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);
        
        final byte[] tokendata = Base64.decode(jo.getString(KEY_TOKENDATA));
        final JSONObject tokendataJo = new JSONObject(new String(tokendata, MslConstants.DEFAULT_CHARSET));
        tokendataJo.put(KEY_SEQUENCE_NUMBER, -1);
        jo.put(KEY_TOKENDATA, Base64.encode(tokendataJo.toString().getBytes()));
        
        new MasterToken(ctx, jo);
    }
    
    @Test
    public void tooLargeSequenceNumber() throws MslEncodingException, MslCryptoException, JSONException, MslException {
        thrown.expect(MslException.class);
        thrown.expectMslError(MslError.MASTERTOKEN_SEQUENCE_NUMBER_OUT_OF_RANGE);

        final MasterToken masterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final String jsonString = masterToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);
        
        final byte[] tokendata = Base64.decode(jo.getString(KEY_TOKENDATA));
        final JSONObject tokendataJo = new JSONObject(new String(tokendata, MslConstants.DEFAULT_CHARSET));
        tokendataJo.put(KEY_SEQUENCE_NUMBER, MslConstants.MAX_LONG_VALUE + 1);
        jo.put(KEY_TOKENDATA, Base64.encode(tokendataJo.toString().getBytes()));
        
        new MasterToken(ctx, jo);
    }
    
    @Test
    public void missingSerialNumber() throws JSONException, MslException, UnsupportedEncodingException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MASTERTOKEN_TOKENDATA_PARSE_ERROR);

        final MasterToken masterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final String jsonString = masterToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);
        
        final byte[] tokendata = Base64.decode(jo.getString(KEY_TOKENDATA));
        final JSONObject tokendataJo = new JSONObject(new String(tokendata, MslConstants.DEFAULT_CHARSET));
        assertNotNull(tokendataJo.remove(KEY_SERIAL_NUMBER));
        jo.put(KEY_TOKENDATA, Base64.encode(tokendataJo.toString().getBytes()));
        
        new MasterToken(ctx, jo);
    }
    
    @Test
    public void invalidSerialNumber() throws JSONException, MslException, UnsupportedEncodingException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MASTERTOKEN_TOKENDATA_PARSE_ERROR);

        final MasterToken masterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final String jsonString = masterToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);
        
        final byte[] tokendata = Base64.decode(jo.getString(KEY_TOKENDATA));
        final JSONObject tokendataJo = new JSONObject(new String(tokendata, MslConstants.DEFAULT_CHARSET));
        tokendataJo.put(KEY_SERIAL_NUMBER, "x");
        jo.put(KEY_TOKENDATA, Base64.encode(tokendataJo.toString().getBytes()));
        
        new MasterToken(ctx, jo);
    }
    
    @Test
    public void negativeSerialNumber() throws MslEncodingException, MslCryptoException, JSONException, MslException {
        thrown.expect(MslException.class);
        thrown.expectMslError(MslError.MASTERTOKEN_SERIAL_NUMBER_OUT_OF_RANGE);

        final MasterToken masterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final String jsonString = masterToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);
        
        final byte[] tokendata = Base64.decode(jo.getString(KEY_TOKENDATA));
        final JSONObject tokendataJo = new JSONObject(new String(tokendata, MslConstants.DEFAULT_CHARSET));
        tokendataJo.put(KEY_SERIAL_NUMBER, -1);
        jo.put(KEY_TOKENDATA, Base64.encode(tokendataJo.toString().getBytes()));
        
        new MasterToken(ctx, jo);
    }
    
    @Test
    public void tooLargeSerialNumber() throws MslEncodingException, MslCryptoException, JSONException, MslException {
        thrown.expect(MslException.class);
        thrown.expectMslError(MslError.MASTERTOKEN_SERIAL_NUMBER_OUT_OF_RANGE);

        final MasterToken masterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final String jsonString = masterToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);
        
        final byte[] tokendata = Base64.decode(jo.getString(KEY_TOKENDATA));
        final JSONObject tokendataJo = new JSONObject(new String(tokendata, MslConstants.DEFAULT_CHARSET));
        tokendataJo.put(KEY_SERIAL_NUMBER, MslConstants.MAX_LONG_VALUE + 1);
        jo.put(KEY_TOKENDATA, Base64.encode(tokendataJo.toString().getBytes()));
        
        new MasterToken(ctx, jo);
    }
    
    @Test
    public void missingSessiondata() throws JSONException, MslException, UnsupportedEncodingException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MASTERTOKEN_TOKENDATA_PARSE_ERROR);

        final MasterToken masterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final String jsonString = masterToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);
        
        final byte[] tokendata = Base64.decode(jo.getString(KEY_TOKENDATA));
        final JSONObject tokendataJo = new JSONObject(new String(tokendata, MslConstants.DEFAULT_CHARSET));
        assertNotNull(tokendataJo.remove(KEY_SESSIONDATA));
        jo.put(KEY_TOKENDATA, Base64.encode(tokendataJo.toString().getBytes()));
        
        new MasterToken(ctx, jo);
    }
    
    @Test
    public void invalidSessiondata() throws UnsupportedEncodingException, JSONException, MslException {
        thrown.expect(MslException.class);
        thrown.expectMslError(MslError.MASTERTOKEN_SESSIONDATA_INVALID);

        final MasterToken masterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final String jsonString = masterToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);
        
        final byte[] tokendata = Base64.decode(jo.getString(KEY_TOKENDATA));
        final JSONObject tokendataJo = new JSONObject(new String(tokendata, MslConstants.DEFAULT_CHARSET));
        tokendataJo.put(KEY_SESSIONDATA, "x");
        
        final ICryptoContext cryptoContext = ctx.getMslCryptoContext();
        final byte[] modifiedTokendata = tokendataJo.toString().getBytes(MslConstants.DEFAULT_CHARSET);
        final byte[] signature = cryptoContext.sign(modifiedTokendata);
        jo.put(KEY_TOKENDATA, Base64.encode(modifiedTokendata));
        jo.put(KEY_SIGNATURE, Base64.encode(signature));
        
        new MasterToken(ctx, jo);
    }
    
    @Test
    public void emptySessiondata() throws UnsupportedEncodingException, JSONException, MslException {
        thrown.expect(MslException.class);
        thrown.expectMslError(MslError.MASTERTOKEN_SESSIONDATA_MISSING);

        final MasterToken masterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final String jsonString = masterToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);
        
        final byte[] tokendata = Base64.decode(jo.getString(KEY_TOKENDATA));
        final JSONObject tokendataJo = new JSONObject(new String(tokendata, MslConstants.DEFAULT_CHARSET));
        
        final ICryptoContext cryptoContext = ctx.getMslCryptoContext();
        final byte[] ciphertext = new byte[0];
        tokendataJo.put(KEY_SESSIONDATA, Base64.encode(ciphertext));
        final byte[] modifiedTokendata = tokendataJo.toString().getBytes(MslConstants.DEFAULT_CHARSET);
        final byte[] signature = cryptoContext.sign(modifiedTokendata);
        jo.put(KEY_TOKENDATA, Base64.encode(modifiedTokendata));
        jo.put(KEY_SIGNATURE, Base64.encode(signature));
        
        new MasterToken(ctx, jo);
    }
    
    @Test(expected = MslCryptoException.class)
    public void corruptSessiondata() throws JSONException, MslException, UnsupportedEncodingException {
        final MasterToken masterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final String jsonString = masterToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);
        
        // This is testing session data that is verified but corrupt.
        final byte[] tokendata = Base64.decode(jo.getString(KEY_TOKENDATA));
        final JSONObject tokendataJo = new JSONObject(new String(tokendata, MslConstants.DEFAULT_CHARSET));
        final byte[] sessiondata = Base64.decode(tokendataJo.getString(KEY_SESSIONDATA));
        ++sessiondata[sessiondata.length-1];
        tokendataJo.put(KEY_SESSIONDATA, Base64.encode(sessiondata));
        
        final ICryptoContext cryptoContext = ctx.getMslCryptoContext();
        final byte[] modifiedTokendata = tokendataJo.toString().getBytes(MslConstants.DEFAULT_CHARSET);
        final byte[] signature = cryptoContext.sign(modifiedTokendata);
        jo.put(KEY_TOKENDATA, Base64.encode(modifiedTokendata));
        jo.put(KEY_SIGNATURE, Base64.encode(signature));
        
        new MasterToken(ctx, jo);
    }
    
    @Test
    public void notVerified() throws JSONException, MslException {
        final MasterToken masterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final String jsonString = masterToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);
        
        final byte[] signature = Base64.decode(jo.getString(KEY_SIGNATURE));
        ++signature[0];
        jo.put(KEY_SIGNATURE, Base64.encode(signature));
        
        final MasterToken joMasterToken = new MasterToken(ctx, jo);
        assertFalse(joMasterToken.isDecrypted());
        assertFalse(joMasterToken.isVerified());
        assertTrue(joMasterToken.isRenewable(null));
        assertFalse(joMasterToken.isExpired(null));
        assertFalse(joMasterToken.isNewerThan(masterToken));
        assertFalse(masterToken.isNewerThan(joMasterToken));
        assertNull(joMasterToken.getEncryptionKey());
        assertEquals(masterToken.getExpiration().getTime() / MILLISECONDS_PER_SECOND, joMasterToken.getExpiration().getTime() / MILLISECONDS_PER_SECOND);
        assertNull(joMasterToken.getSignatureKey());
        assertNull(joMasterToken.getIdentity());
        assertNull(joMasterToken.getIssuerData());
        assertEquals(masterToken.getRenewalWindow().getTime() / MILLISECONDS_PER_SECOND, joMasterToken.getRenewalWindow().getTime() / MILLISECONDS_PER_SECOND);
        assertEquals(masterToken.getSequenceNumber(), joMasterToken.getSequenceNumber());
        assertEquals(masterToken.getSerialNumber(), joMasterToken.getSerialNumber());
        final String joJsonString = joMasterToken.toJSONString();
        assertNotNull(joJsonString);
        assertFalse(jsonString.equals(joJsonString));   
    }
    
    @Test
    public void invalidIssuerData() throws JSONException, MslException, UnsupportedEncodingException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MASTERTOKEN_SESSIONDATA_PARSE_ERROR);

        final MasterToken masterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final String jsonString = masterToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);
        
        final ICryptoContext cryptoContext = ctx.getMslCryptoContext();
        
        // Before modifying the session data we need to decrypt it.
        final byte[] tokendata = Base64.decode(jo.getString(KEY_TOKENDATA));
        final JSONObject tokendataJo = new JSONObject(new String(tokendata, MslConstants.DEFAULT_CHARSET));
        final byte[] ciphertext = Base64.decode(tokendataJo.getString(KEY_SESSIONDATA));
        final byte[] plaintext = cryptoContext.decrypt(ciphertext);
        final JSONObject sessiondataJo = new JSONObject(new String(plaintext, MslConstants.DEFAULT_CHARSET));
        
        // After modifying the session data we need to encrypt it.
        sessiondataJo.put(KEY_ISSUER_DATA, "x");
        final byte[] sessiondata = cryptoContext.encrypt(sessiondataJo.toString().getBytes(MslConstants.DEFAULT_CHARSET));
        tokendataJo.put(KEY_SESSIONDATA, Base64.encode(sessiondata));
        
        // The tokendata must be signed otherwise the session data will not be
        // processed.
        final byte[] modifiedTokendata = tokendataJo.toString().getBytes(MslConstants.DEFAULT_CHARSET);
        final byte[] signature = cryptoContext.sign(modifiedTokendata);
        jo.put(KEY_TOKENDATA, Base64.encode(modifiedTokendata));
        jo.put(KEY_SIGNATURE, Base64.encode(signature));
        
        new MasterToken(ctx, jo);
    }
    
    @Test
    public void missingIdentity() throws JSONException, MslException, UnsupportedEncodingException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MASTERTOKEN_SESSIONDATA_PARSE_ERROR);

        final MasterToken masterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final String jsonString = masterToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);
        
        final ICryptoContext cryptoContext = ctx.getMslCryptoContext();
        
        // Before modifying the session data we need to decrypt it.
        final byte[] tokendata = Base64.decode(jo.getString(KEY_TOKENDATA));
        final JSONObject tokendataJo = new JSONObject(new String(tokendata, MslConstants.DEFAULT_CHARSET));
        final byte[] ciphertext = Base64.decode(tokendataJo.getString(KEY_SESSIONDATA));
        final byte[] plaintext = cryptoContext.decrypt(ciphertext);
        final JSONObject sessiondataJo = new JSONObject(new String(plaintext, MslConstants.DEFAULT_CHARSET));
        
        // After modifying the session data we need to encrypt it.
        assertNotNull(sessiondataJo.remove(KEY_IDENTITY));
        final byte[] sessiondata = cryptoContext.encrypt(sessiondataJo.toString().getBytes(MslConstants.DEFAULT_CHARSET));
        tokendataJo.put(KEY_SESSIONDATA, Base64.encode(sessiondata));
        
        // The tokendata must be signed otherwise the session data will not be
        // processed.
        final byte[] modifiedTokendata = tokendataJo.toString().getBytes(MslConstants.DEFAULT_CHARSET);
        final byte[] signature = cryptoContext.sign(modifiedTokendata);
        jo.put(KEY_TOKENDATA, Base64.encode(modifiedTokendata));
        jo.put(KEY_SIGNATURE, Base64.encode(signature));
        
        new MasterToken(ctx, jo);
    }
    
    @Test
    public void missingEncryptionKey() throws JSONException, MslException, UnsupportedEncodingException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MASTERTOKEN_SESSIONDATA_PARSE_ERROR);

        final MasterToken masterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final String jsonString = masterToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);
        
        final ICryptoContext cryptoContext = ctx.getMslCryptoContext();
        
        // Before modifying the session data we need to decrypt it.
        final byte[] tokendata = Base64.decode(jo.getString(KEY_TOKENDATA));
        final JSONObject tokendataJo = new JSONObject(new String(tokendata, MslConstants.DEFAULT_CHARSET));
        final byte[] ciphertext = Base64.decode(tokendataJo.getString(KEY_SESSIONDATA));
        final byte[] plaintext = cryptoContext.decrypt(ciphertext);
        final JSONObject sessiondataJo = new JSONObject(new String(plaintext, MslConstants.DEFAULT_CHARSET));
        
        // After modifying the session data we need to encrypt it.
        assertNotNull(sessiondataJo.remove(KEY_ENCRYPTION_KEY));
        final byte[] sessiondata = cryptoContext.encrypt(sessiondataJo.toString().getBytes(MslConstants.DEFAULT_CHARSET));
        tokendataJo.put(KEY_SESSIONDATA, Base64.encode(sessiondata));
        
        // The tokendata must be signed otherwise the session data will not be
        // processed.
        final byte[] modifiedTokendata = tokendataJo.toString().getBytes(MslConstants.DEFAULT_CHARSET);
        final byte[] signature = cryptoContext.sign(modifiedTokendata);
        jo.put(KEY_TOKENDATA, Base64.encode(modifiedTokendata));
        jo.put(KEY_SIGNATURE, Base64.encode(signature));
        
        new MasterToken(ctx, jo);
    }

    @Test
    public void invalidEncryptionKey() throws JSONException, MslException, UnsupportedEncodingException {
        thrown.expect(MslCryptoException.class);
        thrown.expectMslError(MslError.MASTERTOKEN_KEY_CREATION_ERROR);

        final MasterToken masterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final String jsonString = masterToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);
        
        final ICryptoContext cryptoContext = ctx.getMslCryptoContext();
        
        // Before modifying the session data we need to decrypt it.
        final byte[] tokendata = Base64.decode(jo.getString(KEY_TOKENDATA));
        final JSONObject tokendataJo = new JSONObject(new String(tokendata, MslConstants.DEFAULT_CHARSET));
        final byte[] ciphertext = Base64.decode(tokendataJo.getString(KEY_SESSIONDATA));
        final byte[] plaintext = cryptoContext.decrypt(ciphertext);
        final JSONObject sessiondataJo = new JSONObject(new String(plaintext, MslConstants.DEFAULT_CHARSET));
        
        // After modifying the session data we need to encrypt it.
        sessiondataJo.put(KEY_ENCRYPTION_KEY, "");
        final byte[] sessiondata = cryptoContext.encrypt(sessiondataJo.toString().getBytes(MslConstants.DEFAULT_CHARSET));
        tokendataJo.put(KEY_SESSIONDATA, Base64.encode(sessiondata));
        
        // The tokendata must be signed otherwise the session data will not be
        // processed.
        final byte[] modifiedTokendata = tokendataJo.toString().getBytes(MslConstants.DEFAULT_CHARSET);
        final byte[] signature = cryptoContext.sign(modifiedTokendata);
        jo.put(KEY_TOKENDATA, Base64.encode(modifiedTokendata));
        jo.put(KEY_SIGNATURE, Base64.encode(signature));
        
        new MasterToken(ctx, jo);
    }
    
    @Test
    public void missingEncryptionAlgorithm() throws MslEncodingException, MslCryptoException, MslException {
        final MasterToken masterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final String jsonString = masterToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);
        
        final ICryptoContext cryptoContext = ctx.getMslCryptoContext();
        
        // Before modifying the session data we need to decrypt it.
        final byte[] tokendata = Base64.decode(jo.getString(KEY_TOKENDATA));
        final JSONObject tokendataJo = new JSONObject(new String(tokendata, MslConstants.DEFAULT_CHARSET));
        final byte[] ciphertext = Base64.decode(tokendataJo.getString(KEY_SESSIONDATA));
        final byte[] plaintext = cryptoContext.decrypt(ciphertext);
        final JSONObject sessiondataJo = new JSONObject(new String(plaintext, MslConstants.DEFAULT_CHARSET));
        
        // After modifying the session data we need to encrypt it.
        assertNotNull(sessiondataJo.remove(KEY_ENCRYPTION_ALGORITHM));
        final byte[] sessiondata = cryptoContext.encrypt(sessiondataJo.toString().getBytes(MslConstants.DEFAULT_CHARSET));
        tokendataJo.put(KEY_SESSIONDATA, Base64.encode(sessiondata));
        
        // The tokendata must be signed otherwise the session data will not be
        // processed.
        final byte[] modifiedTokendata = tokendataJo.toString().getBytes(MslConstants.DEFAULT_CHARSET);
        final byte[] signature = cryptoContext.sign(modifiedTokendata);
        jo.put(KEY_TOKENDATA, Base64.encode(modifiedTokendata));
        jo.put(KEY_SIGNATURE, Base64.encode(signature));
        
        // Confirm default algorithm.
        final MasterToken joMasterToken = new MasterToken(ctx, jo);
        final SecretKey joEncryptionKey = joMasterToken.getEncryptionKey();
        assertEquals(JcaAlgorithm.AES, joEncryptionKey.getAlgorithm());
    }
    
    @Test
    public void invalidEncryptionAlgorithm() throws MslEncodingException, MslCryptoException, MslException {
        thrown.expect(MslCryptoException.class);
        thrown.expectMslError(MslError.UNIDENTIFIED_ALGORITHM);
        
        final MasterToken masterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final String jsonString = masterToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);
        
        final ICryptoContext cryptoContext = ctx.getMslCryptoContext();
        
        // Before modifying the session data we need to decrypt it.
        final byte[] tokendata = Base64.decode(jo.getString(KEY_TOKENDATA));
        final JSONObject tokendataJo = new JSONObject(new String(tokendata, MslConstants.DEFAULT_CHARSET));
        final byte[] ciphertext = Base64.decode(tokendataJo.getString(KEY_SESSIONDATA));
        final byte[] plaintext = cryptoContext.decrypt(ciphertext);
        final JSONObject sessiondataJo = new JSONObject(new String(plaintext, MslConstants.DEFAULT_CHARSET));
        
        // After modifying the session data we need to encrypt it.
        sessiondataJo.put(KEY_ENCRYPTION_ALGORITHM, "x");
        final byte[] sessiondata = cryptoContext.encrypt(sessiondataJo.toString().getBytes(MslConstants.DEFAULT_CHARSET));
        tokendataJo.put(KEY_SESSIONDATA, Base64.encode(sessiondata));
        
        // The tokendata must be signed otherwise the session data will not be
        // processed.
        final byte[] modifiedTokendata = tokendataJo.toString().getBytes(MslConstants.DEFAULT_CHARSET);
        final byte[] signature = cryptoContext.sign(modifiedTokendata);
        jo.put(KEY_TOKENDATA, Base64.encode(modifiedTokendata));
        jo.put(KEY_SIGNATURE, Base64.encode(signature));
        
        new MasterToken(ctx, jo);
    }
    
    @Test
    public void missingHmacKey() throws MslEncodingException, MslCryptoException, MslException {
        final MasterToken masterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final String jsonString = masterToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);
        
        final ICryptoContext cryptoContext = ctx.getMslCryptoContext();
        
        // Before modifying the session data we need to decrypt it.
        final byte[] tokendata = Base64.decode(jo.getString(KEY_TOKENDATA));
        final JSONObject tokendataJo = new JSONObject(new String(tokendata, MslConstants.DEFAULT_CHARSET));
        final byte[] ciphertext = Base64.decode(tokendataJo.getString(KEY_SESSIONDATA));
        final byte[] plaintext = cryptoContext.decrypt(ciphertext);
        final JSONObject sessiondataJo = new JSONObject(new String(plaintext, MslConstants.DEFAULT_CHARSET));
        
        // After modifying the session data we need to encrypt it.
        assertNotNull(sessiondataJo.remove(KEY_HMAC_KEY));
        final byte[] sessiondata = cryptoContext.encrypt(sessiondataJo.toString().getBytes(MslConstants.DEFAULT_CHARSET));
        tokendataJo.put(KEY_SESSIONDATA, Base64.encode(sessiondata));
        
        // The tokendata must be signed otherwise the session data will not be
        // processed.
        final byte[] modifiedTokendata = tokendataJo.toString().getBytes(MslConstants.DEFAULT_CHARSET);
        final byte[] signature = cryptoContext.sign(modifiedTokendata);
        jo.put(KEY_TOKENDATA, Base64.encode(modifiedTokendata));
        jo.put(KEY_SIGNATURE, Base64.encode(signature));
        
        // Confirm signature key.
        final MasterToken joMasterToken = new MasterToken(ctx, jo);
        final SecretKey joSignatureKey = joMasterToken.getSignatureKey();
        assertArrayEquals(masterToken.getSignatureKey().getEncoded(), joSignatureKey.getEncoded());
    }
    
    @Test
    public void missingSignatureKey() throws MslEncodingException, MslCryptoException, MslException {
        final MasterToken masterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final String jsonString = masterToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);
        
        final ICryptoContext cryptoContext = ctx.getMslCryptoContext();
        
        // Before modifying the session data we need to decrypt it.
        final byte[] tokendata = Base64.decode(jo.getString(KEY_TOKENDATA));
        final JSONObject tokendataJo = new JSONObject(new String(tokendata, MslConstants.DEFAULT_CHARSET));
        final byte[] ciphertext = Base64.decode(tokendataJo.getString(KEY_SESSIONDATA));
        final byte[] plaintext = cryptoContext.decrypt(ciphertext);
        final JSONObject sessiondataJo = new JSONObject(new String(plaintext, MslConstants.DEFAULT_CHARSET));
        
        // After modifying the session data we need to encrypt it.
        assertNotNull(sessiondataJo.remove(KEY_SIGNATURE_KEY));
        final byte[] sessiondata = cryptoContext.encrypt(sessiondataJo.toString().getBytes(MslConstants.DEFAULT_CHARSET));
        tokendataJo.put(KEY_SESSIONDATA, Base64.encode(sessiondata));
        
        // The tokendata must be signed otherwise the session data will not be
        // processed.
        final byte[] modifiedTokendata = tokendataJo.toString().getBytes(MslConstants.DEFAULT_CHARSET);
        final byte[] signature = cryptoContext.sign(modifiedTokendata);
        jo.put(KEY_TOKENDATA, Base64.encode(modifiedTokendata));
        jo.put(KEY_SIGNATURE, Base64.encode(signature));
        
        // Confirm signature key.
        final MasterToken joMasterToken = new MasterToken(ctx, jo);
        final SecretKey joSignatureKey = joMasterToken.getSignatureKey();
        assertArrayEquals(masterToken.getSignatureKey().getEncoded(), joSignatureKey.getEncoded());
    }
    
    @Test
    public void missingSignatureAlgorithm() throws MslEncodingException, MslCryptoException, MslException {
        final MasterToken masterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final String jsonString = masterToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);
        
        final ICryptoContext cryptoContext = ctx.getMslCryptoContext();
        
        // Before modifying the session data we need to decrypt it.
        final byte[] tokendata = Base64.decode(jo.getString(KEY_TOKENDATA));
        final JSONObject tokendataJo = new JSONObject(new String(tokendata, MslConstants.DEFAULT_CHARSET));
        final byte[] ciphertext = Base64.decode(tokendataJo.getString(KEY_SESSIONDATA));
        final byte[] plaintext = cryptoContext.decrypt(ciphertext);
        final JSONObject sessiondataJo = new JSONObject(new String(plaintext, MslConstants.DEFAULT_CHARSET));
        
        // After modifying the session data we need to encrypt it.
        assertNotNull(sessiondataJo.remove(KEY_SIGNATURE_ALGORITHM));
        final byte[] sessiondata = cryptoContext.encrypt(sessiondataJo.toString().getBytes(MslConstants.DEFAULT_CHARSET));
        tokendataJo.put(KEY_SESSIONDATA, Base64.encode(sessiondata));
        
        // The tokendata must be signed otherwise the session data will not be
        // processed.
        final byte[] modifiedTokendata = tokendataJo.toString().getBytes(MslConstants.DEFAULT_CHARSET);
        final byte[] signature = cryptoContext.sign(modifiedTokendata);
        jo.put(KEY_TOKENDATA, Base64.encode(modifiedTokendata));
        jo.put(KEY_SIGNATURE, Base64.encode(signature));
        
        // Confirm default algorithm.
        final MasterToken joMasterToken = new MasterToken(ctx, jo);
        final SecretKey joSignatureKey = joMasterToken.getSignatureKey();
        assertEquals(JcaAlgorithm.HMAC_SHA256, joSignatureKey.getAlgorithm());
    }
    
    @Test
    public void invalidSignatureAlgorithm() throws MslEncodingException, MslCryptoException, MslException {
        thrown.expect(MslCryptoException.class);
        thrown.expectMslError(MslError.UNIDENTIFIED_ALGORITHM);
        
        final MasterToken masterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final String jsonString = masterToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);
        
        final ICryptoContext cryptoContext = ctx.getMslCryptoContext();
        
        // Before modifying the session data we need to decrypt it.
        final byte[] tokendata = Base64.decode(jo.getString(KEY_TOKENDATA));
        final JSONObject tokendataJo = new JSONObject(new String(tokendata, MslConstants.DEFAULT_CHARSET));
        final byte[] ciphertext = Base64.decode(tokendataJo.getString(KEY_SESSIONDATA));
        final byte[] plaintext = cryptoContext.decrypt(ciphertext);
        final JSONObject sessiondataJo = new JSONObject(new String(plaintext, MslConstants.DEFAULT_CHARSET));
        
        // After modifying the session data we need to encrypt it.
        sessiondataJo.put(KEY_SIGNATURE_ALGORITHM, "x");
        final byte[] sessiondata = cryptoContext.encrypt(sessiondataJo.toString().getBytes(MslConstants.DEFAULT_CHARSET));
        tokendataJo.put(KEY_SESSIONDATA, Base64.encode(sessiondata));
        
        // The tokendata must be signed otherwise the session data will not be
        // processed.
        final byte[] modifiedTokendata = tokendataJo.toString().getBytes(MslConstants.DEFAULT_CHARSET);
        final byte[] signature = cryptoContext.sign(modifiedTokendata);
        jo.put(KEY_TOKENDATA, Base64.encode(modifiedTokendata));
        jo.put(KEY_SIGNATURE, Base64.encode(signature));
        
        new MasterToken(ctx, jo);
    }
    
    @Test
    public void missingHmacAndSignatureKey() throws JSONException, MslException, UnsupportedEncodingException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MASTERTOKEN_SESSIONDATA_PARSE_ERROR);

        final MasterToken masterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final String jsonString = masterToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);
        
        final ICryptoContext cryptoContext = ctx.getMslCryptoContext();
        
        // Before modifying the session data we need to decrypt it.
        final byte[] tokendata = Base64.decode(jo.getString(KEY_TOKENDATA));
        final JSONObject tokendataJo = new JSONObject(new String(tokendata, MslConstants.DEFAULT_CHARSET));
        final byte[] ciphertext = Base64.decode(tokendataJo.getString(KEY_SESSIONDATA));
        final byte[] plaintext = cryptoContext.decrypt(ciphertext);
        final JSONObject sessiondataJo = new JSONObject(new String(plaintext, MslConstants.DEFAULT_CHARSET));
        
        // After modifying the session data we need to encrypt it.
        assertNotNull(sessiondataJo.remove(KEY_HMAC_KEY));
        assertNotNull(sessiondataJo.remove(KEY_SIGNATURE_KEY));
        final byte[] sessiondata = cryptoContext.encrypt(sessiondataJo.toString().getBytes(MslConstants.DEFAULT_CHARSET));
        tokendataJo.put(KEY_SESSIONDATA, Base64.encode(sessiondata));
        
        // The tokendata must be signed otherwise the session data will not be
        // processed.
        final byte[] modifiedTokendata = tokendataJo.toString().getBytes(MslConstants.DEFAULT_CHARSET);
        final byte[] signature = cryptoContext.sign(modifiedTokendata);
        jo.put(KEY_TOKENDATA, Base64.encode(modifiedTokendata));
        jo.put(KEY_SIGNATURE, Base64.encode(signature));
        
        new MasterToken(ctx, jo);
    }
    
    @Test
    public void invalidHmacAndSignatureKey() throws JSONException, MslException, UnsupportedEncodingException {
        thrown.expect(MslCryptoException.class);
        thrown.expectMslError(MslError.MASTERTOKEN_KEY_CREATION_ERROR);

        final MasterToken masterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final String jsonString = masterToken.toJSONString();
        final JSONObject jo = new JSONObject(jsonString);
        
        final ICryptoContext cryptoContext = ctx.getMslCryptoContext();
        
        // Before modifying the session data we need to decrypt it.
        final byte[] tokendata = Base64.decode(jo.getString(KEY_TOKENDATA));
        final JSONObject tokendataJo = new JSONObject(new String(tokendata, MslConstants.DEFAULT_CHARSET));
        final byte[] ciphertext = Base64.decode(tokendataJo.getString(KEY_SESSIONDATA));
        final byte[] plaintext = cryptoContext.decrypt(ciphertext);
        final JSONObject sessiondataJo = new JSONObject(new String(plaintext, MslConstants.DEFAULT_CHARSET));
        
        // After modifying the session data we need to encrypt it.
        sessiondataJo.put(KEY_HMAC_KEY, "");
        sessiondataJo.put(KEY_SIGNATURE_KEY, "");
        final byte[] sessiondata = cryptoContext.encrypt(sessiondataJo.toString().getBytes(MslConstants.DEFAULT_CHARSET));
        tokendataJo.put(KEY_SESSIONDATA, Base64.encode(sessiondata));
        
        // The tokendata must be signed otherwise the session data will not be
        // processed.
        final byte[] modifiedTokendata = tokendataJo.toString().getBytes(MslConstants.DEFAULT_CHARSET);
        final byte[] signature = cryptoContext.sign(modifiedTokendata);
        jo.put(KEY_TOKENDATA, Base64.encode(modifiedTokendata));
        jo.put(KEY_SIGNATURE, Base64.encode(signature));
        
        new MasterToken(ctx, jo);
    }
    
    @Test
    public void isRenewable() throws MslEncodingException, MslCryptoException {
        final Date renewalWindow = new Date();
        final Date expiration = new Date(System.currentTimeMillis() + 1000);
        final MasterToken masterToken = new MasterToken(ctx, renewalWindow, expiration, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        
        final Date now = new Date();
        assertTrue(masterToken.isRenewable(null));
        assertTrue(masterToken.isRenewable(now));
        assertFalse(masterToken.isExpired(null));
        assertFalse(masterToken.isExpired(now));
        
        final Date before = new Date(renewalWindow.getTime() - 1000);
        assertFalse(masterToken.isRenewable(before));
        assertFalse(masterToken.isExpired(before));
        
        final Date after = new Date(expiration.getTime() + 1000);
        assertTrue(masterToken.isRenewable(after));
        assertTrue(masterToken.isExpired(after));
    }
    
    @Test
    public void isExpired() throws MslEncodingException, MslCryptoException {
        final Date renewalWindow = new Date(System.currentTimeMillis() - 1000);
        final Date expiration = new Date();
        final MasterToken masterToken = new MasterToken(ctx, renewalWindow, expiration, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        
        final Date now = new Date();
        assertTrue(masterToken.isRenewable(null));
        assertTrue(masterToken.isRenewable(now));
        assertTrue(masterToken.isExpired(null));
        assertTrue(masterToken.isExpired(now));
        
        final Date before = new Date(renewalWindow.getTime() - 1000);
        assertFalse(masterToken.isRenewable(before));
        assertFalse(masterToken.isExpired(before));
        
        final Date after = new Date(expiration.getTime() + 1000);
        assertTrue(masterToken.isRenewable(after));
        assertTrue(masterToken.isExpired(after));
    }
    
    @Test
    public void notRenewableOrExpired() throws MslEncodingException, MslCryptoException {
        final Date renewalWindow = new Date(System.currentTimeMillis() + 1000);
        final Date expiration = new Date(System.currentTimeMillis() + 2000);
        final MasterToken masterToken = new MasterToken(ctx, renewalWindow, expiration, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        
        final Date now = new Date();
        assertFalse(masterToken.isRenewable(null));
        assertFalse(masterToken.isRenewable(now));
        assertFalse(masterToken.isExpired(null));
        assertFalse(masterToken.isExpired(now));
        
        final Date before = new Date(renewalWindow.getTime() - 1000);
        assertFalse(masterToken.isRenewable(before));
        assertFalse(masterToken.isExpired(before));
        
        final Date after = new Date(expiration.getTime() + 1000);
        assertTrue(masterToken.isRenewable(after));
        assertTrue(masterToken.isExpired(after));
    }
    
    @Test
    public void isNewerThanSequenceNumbers() throws MslEncodingException, MslCryptoException {
        final long sequenceNumberA = 1;
        final long sequenceNumberB = 2;
        final MasterToken masterTokenA = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, sequenceNumberA, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final MasterToken masterTokenB = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, sequenceNumberB, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        
        assertTrue(masterTokenB.isNewerThan(masterTokenA));
        assertFalse(masterTokenA.isNewerThan(masterTokenB));
        assertFalse(masterTokenA.isNewerThan(masterTokenA));
    }
    
    @Test
    public void isNewerThanSequenceNumbersWrapAround() throws MslEncodingException, MslCryptoException {
        // Anything within 128 is newer.
        for (long seqNo = MslConstants.MAX_LONG_VALUE - 127; seqNo <= MslConstants.MAX_LONG_VALUE && seqNo != 0; seqNo = incrementSequenceNumber(seqNo, 1)) {
            final long minus1 = decrementSequenceNumber(seqNo, 1);
            final long plus1 = incrementSequenceNumber(seqNo, 1);
            final long plus127 = incrementSequenceNumber(seqNo, 127); 
            final long plus128 = incrementSequenceNumber(seqNo, 128);

            final MasterToken masterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, seqNo, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
            final MasterToken minus1MasterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, minus1, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
            final MasterToken plus1MasterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, plus1, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
            final MasterToken plus127MasterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, plus127, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
            final MasterToken plus128MasterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, plus128, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);

            assertFalse("seqNo = " + seqNo, minus1MasterToken.isNewerThan(masterToken));
            assertTrue("seqNo = " + seqNo, masterToken.isNewerThan(minus1MasterToken));
            assertTrue("seqNo = " + seqNo, plus1MasterToken.isNewerThan(masterToken));
            assertFalse("seqNo = " + seqNo, masterToken.isNewerThan(plus1MasterToken));
            assertTrue("seqNo = " + seqNo, plus127MasterToken.isNewerThan(masterToken));
            assertFalse("seqNo = " + seqNo, masterToken.isNewerThan(plus127MasterToken));
            assertFalse("seqNo = " + seqNo, plus128MasterToken.isNewerThan(masterToken));
            assertTrue("seqNo = " + seqNo, masterToken.isNewerThan(plus128MasterToken));
        }
    }
    
    @Test
    public void isNewerThanExpiration() throws MslEncodingException, MslCryptoException {
        final Date expirationA = new Date(EXPIRATION.getTime());
        final Date expirationB = new Date(EXPIRATION.getTime() + 10000);
        final MasterToken masterTokenA = new MasterToken(ctx, RENEWAL_WINDOW, expirationA, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final MasterToken masterTokenB = new MasterToken(ctx, RENEWAL_WINDOW, expirationB, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        
        assertTrue(masterTokenB.isNewerThan(masterTokenA));
        assertFalse(masterTokenA.isNewerThan(masterTokenB));
        assertFalse(masterTokenA.isNewerThan(masterTokenA));
    }
    
    @Test
    public void isNewerSerialNumber() throws MslEncodingException, MslCryptoException {
        final long serialNumberA = 1;
        final long serialNumberB = 2;
        final long sequenceNumberA = 1;
        final long sequenceNumberB = 2;
        final MasterToken masterTokenA = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, sequenceNumberA, serialNumberA, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final MasterToken masterTokenB = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, sequenceNumberB, serialNumberB, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        
        assertTrue(masterTokenB.isNewerThan(masterTokenA));
        assertFalse(masterTokenA.isNewerThan(masterTokenB));
    }
    
    @Test
    public void equalsTrustedUntrusted() throws JSONException, MslException {
        final Date renewalWindow = new Date(System.currentTimeMillis() + 1000);
        final Date expiration = new Date(System.currentTimeMillis() + 2000);
        final String identity = MockPresharedAuthenticationFactory.PSK_ESN;
        final SecretKey encryptionKey = MockPresharedAuthenticationFactory.KPE;
        final SecretKey hmacKey = MockPresharedAuthenticationFactory.KPH;
        final MasterToken masterToken = new MasterToken(ctx, renewalWindow, expiration, 1L, 1L, null, identity, encryptionKey, hmacKey);
        
        final String json = masterToken.toJSONString();
        final JSONObject jo = new JSONObject(json);
        final byte[] signature = Base64.decode(jo.getString("signature"));
        ++signature[1];
        jo.put("signature", Base64.encode(signature));
        final MasterToken untrustedMasterToken = new MasterToken(ctx, jo);
        
        assertTrue(masterToken.equals(untrustedMasterToken));
        assertEquals(masterToken.hashCode(), untrustedMasterToken.hashCode());
    }
    
    @Test
    public void equalsSerialNumber() throws MslException, JSONException {
        final long serialNumberA = 1;
        final long serialNumberB = 2;
        final MasterToken masterTokenA = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, serialNumberA, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final MasterToken masterTokenB = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, serialNumberB, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final MasterToken masterTokenA2 = new MasterToken(ctx, new JSONObject(masterTokenA.toJSONString()));
        
        assertTrue(masterTokenA.equals(masterTokenA));
        assertEquals(masterTokenA.hashCode(), masterTokenA.hashCode());
        
        assertFalse(masterTokenA.equals(masterTokenB));
        assertFalse(masterTokenB.equals(masterTokenA));
        assertTrue(masterTokenA.hashCode() != masterTokenB.hashCode());
        
        assertTrue(masterTokenA.equals(masterTokenA2));
        assertTrue(masterTokenA2.equals(masterTokenA));
        assertEquals(masterTokenA.hashCode(), masterTokenA2.hashCode());
    }
    
    @Test
    public void equalsSequenceNumber() throws MslEncodingException, MslCryptoException, MslException, JSONException {
        final long sequenceNumberA = 1;
        final long sequenceNumberB = 2;
        final MasterToken masterTokenA = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, sequenceNumberA, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final MasterToken masterTokenB = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, sequenceNumberB, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final MasterToken masterTokenA2 = new MasterToken(ctx, new JSONObject(masterTokenA.toJSONString()));
        
        assertTrue(masterTokenA.equals(masterTokenA));
        assertEquals(masterTokenA.hashCode(), masterTokenA.hashCode());
        
        assertFalse(masterTokenA.equals(masterTokenB));
        assertFalse(masterTokenB.equals(masterTokenA));
        assertTrue(masterTokenA.hashCode() != masterTokenB.hashCode());
        
        assertTrue(masterTokenA.equals(masterTokenA2));
        assertTrue(masterTokenA2.equals(masterTokenA));
        assertEquals(masterTokenA.hashCode(), masterTokenA2.hashCode());
    }
    
    @Test
    public void equalsExpiration() throws MslEncodingException, MslCryptoException, MslException, JSONException {
        final Date expirationA = new Date(EXPIRATION.getTime());
        final Date expirationB = new Date(EXPIRATION.getTime() + 10000);
        final MasterToken masterTokenA = new MasterToken(ctx, RENEWAL_WINDOW, expirationA, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final MasterToken masterTokenB = new MasterToken(ctx, RENEWAL_WINDOW, expirationB, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final MasterToken masterTokenA2 = new MasterToken(ctx, new JSONObject(masterTokenA.toJSONString()));
        
        assertTrue(masterTokenA.equals(masterTokenA));
        assertEquals(masterTokenA.hashCode(), masterTokenA.hashCode());
        
        assertFalse(masterTokenA.equals(masterTokenB));
        assertFalse(masterTokenB.equals(masterTokenA));
        assertTrue(masterTokenA.hashCode() != masterTokenB.hashCode());
        
        assertTrue(masterTokenA.equals(masterTokenA2));
        assertTrue(masterTokenA2.equals(masterTokenA));
        assertEquals(masterTokenA.hashCode(), masterTokenA2.hashCode());
    }
    
    @Test
    public void equalsObject() throws MslEncodingException, MslCryptoException {
        final MasterToken masterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        assertFalse(masterToken.equals(null));
        assertFalse(masterToken.equals(IDENTITY));
        assertTrue(masterToken.hashCode() != IDENTITY.hashCode());
    }
    
    /** MSL context. */
    private static MslContext ctx;
}
